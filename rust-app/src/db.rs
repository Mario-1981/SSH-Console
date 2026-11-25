use crate::crypto::Vault;
use crate::mariadb::{
    self, DbConfigFile, StoredMariaDbConfig,
};
use crate::models::{
    AdminAuthSettingsPatchRequest, AuthPolicySettings, CertInspection, CertificateAuthorityPublic,
    CertificateAutoRenewConfig, CommandStep, DatabaseStatusResponse, DatabaseTableCount,
    ExecutionLog, GroupPermissions, MariaDbConfigInput, MariaDbConfigPublic, MariaDbTestResponse,
    MigrateDatabaseRequest, MigrateDatabaseResult, ServerCategory, SshCommand,
    StoredCertificateAuthorityForEdit, StoredCertificateForEdit, StoredCertificateForSigning,
    UserApiKeyPublic, UserCertificatePublic, UserCertificateSecret, UserGroup, UserPublic,
    UserServer, WebAuthnCredentialPublic, WebAuthnCredentialStored,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashSet;
use std::fs;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Instant;
use uuid::Uuid;

pub enum MigrationError {
    BadRequest(String),
    Conflict {
        message: String,
        existing_row_count: u64,
        existing_tables: Vec<DatabaseTableCount>,
    },
    Internal(String),
}

struct SyncedDbMutex {
    inner: Mutex<Connection>,
    dirty_tables: Arc<Mutex<HashSet<String>>>,
    mariadb_pool: Arc<RwLock<Option<mysql::Pool>>>,
    last_synced_at: Arc<Mutex<Option<String>>>,
    last_sync_error: Arc<Mutex<Option<String>>>,
}

struct SyncedConnGuard<'a> {
    guard: Option<MutexGuard<'a, Connection>>,
    dirty_tables: &'a Arc<Mutex<HashSet<String>>>,
    mariadb_pool: &'a Arc<RwLock<Option<mysql::Pool>>>,
    last_synced_at: &'a Arc<Mutex<Option<String>>>,
    last_sync_error: &'a Arc<Mutex<Option<String>>>,
    changes_before: u64,
}

impl<'a> Deref for SyncedConnGuard<'a> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.guard.as_ref().expect("DB-Guard bereits freigegeben")
    }
}

impl<'a> DerefMut for SyncedConnGuard<'a> {
    fn deref_mut(&mut self) -> &mut Connection {
        self.guard.as_mut().expect("DB-Guard bereits freigegeben")
    }
}

impl<'a> Drop for SyncedConnGuard<'a> {
    fn drop(&mut self) {
        if let Some(conn) = self.guard.as_ref() {
            let pool_opt = self.mariadb_pool.read().ok().and_then(|g| g.clone());
            if let Some(pool) = pool_opt {
                let mut tables: Vec<String> = {
                    let mut dirty = self.dirty_tables.lock().unwrap_or_else(|e| e.into_inner());
                    dirty.drain().collect()
                };
                if tables.is_empty() && conn.total_changes() != self.changes_before {
                    tables = mariadb::ALL_TABLES
                        .iter()
                        .map(|t| t.name.to_string())
                        .collect();
                }
                if !tables.is_empty() {
                    match mariadb::sync_tables_to_mariadb(conn, &pool, &tables) {
                        Ok(()) => {
                            if let Ok(mut ts) = self.last_synced_at.lock() {
                                *ts = Some(Utc::now().to_rfc3339());
                            }
                            if let Ok(mut err) = self.last_sync_error.lock() {
                                *err = None;
                            }
                        }
                        Err(e) => {
                            tracing::error!("MariaDB-Synchronisierung fehlgeschlagen ({:?}): {}", tables, e);
                            if let Ok(mut err) = self.last_sync_error.lock() {
                                *err = Some(e);
                            }
                        }
                    }
                }
            } else if let Ok(mut dirty) = self.dirty_tables.lock() {
                dirty.clear();
            }
        }
        let _ = self.guard.take();
    }
}

impl SyncedDbMutex {
    fn lock(&self) -> Result<SyncedConnGuard<'_>, PoisonError<MutexGuard<'_, Connection>>> {
        let guard = self.inner.lock()?;
        let changes_before = guard.total_changes();
        Ok(SyncedConnGuard {
            guard: Some(guard),
            dirty_tables: &self.dirty_tables,
            mariadb_pool: &self.mariadb_pool,
            last_synced_at: &self.last_synced_at,
            last_sync_error: &self.last_sync_error,
            changes_before,
        })
    }

    fn lock_raw(&self) -> Result<MutexGuard<'_, Connection>, PoisonError<MutexGuard<'_, Connection>>> {
        self.inner.lock()
    }
}

fn attach_update_hook(conn: &mut Connection, dirty: Arc<Mutex<HashSet<String>>>) {
    let _ = conn.update_hook(Some(move |_action, _db: &str, table: &str, _rowid: i64| {
        if let Ok(mut set) = dirty.lock() {
            set.insert(table.to_string());
        }
    }));
}

pub struct Database {
    conn: SyncedDbMutex,
    data_dir: PathBuf,
    db_config: Mutex<DbConfigFile>,
    mariadb_version: Mutex<Option<String>>,
}

impl Database {
    fn init_sqlite_schema(conn: &Connection) -> Result<(), String> {
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT '',
                is_system INTEGER NOT NULL DEFAULT 0,
                is_immutable INTEGER NOT NULL DEFAULT 0,
                is_admin INTEGER NOT NULL DEFAULT 0,
                permissions_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
                group_id TEXT NOT NULL DEFAULT 'user',
                default_ssh_user TEXT NOT NULL DEFAULT 'root',
                active INTEGER NOT NULL DEFAULT 1,
                ping_enabled INTEGER NOT NULL DEFAULT 1,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login_at TEXT
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_api_keys (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                last_used_at TEXT
            );

            CREATE TABLE IF NOT EXISTS ssh_commands (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL DEFAULT '',
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'single',
                command TEXT NOT NULL,
                steps_json TEXT NOT NULL DEFAULT '[]',
                workflow_json TEXT NOT NULL DEFAULT '',
                stop_on_error INTEGER NOT NULL DEFAULT 1,
                description TEXT NOT NULL,
                timeout_sec INTEGER NOT NULL DEFAULT 30,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_by TEXT NOT NULL,
                shared_with_all INTEGER NOT NULL DEFAULT 0,
                shared_with_user_ids TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS user_servers (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                owner_username TEXT NOT NULL DEFAULT '',
                label TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                bmc_ip_address TEXT NOT NULL DEFAULT '',
                bmc_ip_address2 TEXT NOT NULL DEFAULT '',
                port INTEGER NOT NULL DEFAULT 22,
                ssh_user TEXT NOT NULL DEFAULT 'root',
                notes TEXT NOT NULL DEFAULT '',
                ping_enabled INTEGER NOT NULL DEFAULT 1,
                ignore_host_key INTEGER NOT NULL DEFAULT 0,
                categories_json TEXT NOT NULL DEFAULT '[]',
                last_online_at TEXT,
                shared_with_all INTEGER NOT NULL DEFAULT 0,
                shared_with_user_ids TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_server_categories (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_certificates (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                owner_username TEXT NOT NULL DEFAULT '',
                name TEXT NOT NULL,
                private_key_file TEXT NOT NULL,
                public_key_file TEXT NOT NULL,
                cert_file TEXT NOT NULL,
                private_key_enc BLOB NOT NULL,
                private_key_nonce BLOB NOT NULL,
                passphrase_enc BLOB,
                passphrase_nonce BLOB,
                public_key TEXT NOT NULL,
                certificate TEXT NOT NULL,
                inspection_json TEXT NOT NULL,
                auto_renew_json TEXT,
                shared_with_all INTEGER NOT NULL DEFAULT 0,
                shared_with_user_ids TEXT NOT NULL DEFAULT '[]',
                uploaded_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS certificate_authorities (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                private_key_file TEXT NOT NULL DEFAULT 'ca',
                public_key_file TEXT NOT NULL DEFAULT 'ca.pub',
                private_key_enc BLOB NOT NULL,
                private_key_nonce BLOB NOT NULL,
                passphrase_enc BLOB,
                passphrase_nonce BLOB,
                public_key TEXT NOT NULL,
                key_type TEXT NOT NULL DEFAULT 'ssh-ed25519',
                fingerprint TEXT NOT NULL DEFAULT '',
                private_key_format TEXT NOT NULL DEFAULT 'openssh-v1',
                private_key_encrypted INTEGER NOT NULL DEFAULT 1,
                created_by TEXT NOT NULL DEFAULT '',
                created_by_username TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS execution_logs (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                command_id TEXT NOT NULL DEFAULT '',
                command_name TEXT NOT NULL,
                command_text TEXT NOT NULL,
                target_ip TEXT NOT NULL,
                target_port INTEGER NOT NULL,
                ssh_user TEXT NOT NULL,
                server_label TEXT NOT NULL DEFAULT '',
                certificate_id TEXT NOT NULL DEFAULT '',
                certificate_key_id TEXT NOT NULL,
                mode TEXT NOT NULL DEFAULT 'openssh-live',
                ssh_invocation TEXT NOT NULL DEFAULT '',
                exit_code INTEGER NOT NULL,
                stdout TEXT NOT NULL,
                stderr TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                executed_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_webauthn_credentials (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                kind TEXT NOT NULL CHECK (kind IN ('security-key', 'passkey')),
                name TEXT NOT NULL,
                credential_id TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                counter INTEGER NOT NULL DEFAULT 0,
                transports_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                last_used_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
            CREATE INDEX IF NOT EXISTS idx_logs_user_executed ON execution_logs(user_id, executed_at DESC);
            CREATE INDEX IF NOT EXISTS idx_logs_executed_at ON execution_logs(executed_at DESC);
            CREATE INDEX IF NOT EXISTS idx_servers_user_id ON user_servers(user_id);
            CREATE INDEX IF NOT EXISTS idx_certs_user_id ON user_certificates(user_id);
            CREATE INDEX IF NOT EXISTS idx_commands_user_id ON ssh_commands(user_id);
            CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON user_api_keys(user_id);
            ",
        )
        .map_err(|e| format!("Schema-Initialisierung fehlgeschlagen: {e}"))?;

        // Migrationen für bestehende Datenbanken
        let _ = conn.execute(
            "ALTER TABLE user_servers ADD COLUMN bmc_ip_address TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE user_servers ADD COLUMN bmc_ip_address2 TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE user_servers ADD COLUMN ping_enabled INTEGER NOT NULL DEFAULT 1",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE user_servers ADD COLUMN ignore_host_key INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE user_servers ADD COLUMN categories_json TEXT NOT NULL DEFAULT '[]'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE user_servers ADD COLUMN last_online_at TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE users ADD COLUMN ping_enabled INTEGER NOT NULL DEFAULT 1",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE users ADD COLUMN auth_provider TEXT NOT NULL DEFAULT 'local'",
            [],
        );
        let _ = conn.execute("ALTER TABLE users ADD COLUMN sso_subject TEXT", []);
        let _ = conn.execute(
            "ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE user_certificates ADD COLUMN auto_renew_json TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = conn.execute("ALTER TABLE users ADD COLUMN totp_secret_enc BLOB", []);
        let _ = conn.execute("ALTER TABLE users ADD COLUMN totp_secret_nonce BLOB", []);
        let _ = conn.execute(
            "ALTER TABLE users ADD COLUMN totp_recovery_hashes_json TEXT NOT NULL DEFAULT '[]'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE ssh_commands ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE execution_logs ADD COLUMN command_id TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE execution_logs ADD COLUMN server_label TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE execution_logs ADD COLUMN certificate_id TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE execution_logs ADD COLUMN mode TEXT NOT NULL DEFAULT 'openssh-live'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE execution_logs ADD COLUMN ssh_invocation TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE user_certificates ADD COLUMN passphrase_enc BLOB",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE user_certificates ADD COLUMN passphrase_nonce BLOB",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE ssh_commands ADD COLUMN workflow_json TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE users ADD COLUMN group_id TEXT NOT NULL DEFAULT 'user'",
            [],
        );

        // Seed built-in system groups (Administratoren immutable, Benutzer editable default)
        let now = Utc::now().to_rfc3339();
        let all_perms_json =
            serde_json::to_string(&GroupPermissions::all()).unwrap_or_else(|_| "{}".into());
        let user_perms_json =
            serde_json::to_string(&GroupPermissions::default_user()).unwrap_or_else(|_| "{}".into());
        let _ = conn.execute(
            "INSERT OR IGNORE INTO user_groups (id, name, description, is_system, is_immutable, is_admin, permissions_json, created_at, updated_at)
             VALUES ('admin', 'Administratoren', 'Vollzugriff auf alle Systemfunktionen, Benutzer-, Gruppen- und Sicherheitseinstellungen. Aus Sicherheitsgründen nicht veränderbar.', 1, 1, 1, ?1, ?2, ?2)",
            params![&all_perms_json, &now],
        );
        // Ensure Administratoren remains immutable and retains full permissions even if tampered on disk
        let _ = conn.execute(
            "UPDATE user_groups SET name = 'Administratoren', is_system = 1, is_immutable = 1, is_admin = 1, permissions_json = ?1 WHERE id = 'admin'",
            params![&all_perms_json],
        );
        let _ = conn.execute(
            "INSERT OR IGNORE INTO user_groups (id, name, description, is_system, is_immutable, is_admin, permissions_json, created_at, updated_at)
             VALUES ('user', 'Benutzer', 'Standardgruppe für reguläre Benutzer mit allen gewohnten Arbeitsbereichsrechten (ohne Administration und ohne Freigabe).', 1, 0, 0, ?1, ?2, ?2)",
            params![&user_perms_json, &now],
        );
        // Migrate existing admin users whose group_id was defaulted to 'user'
        let _ = conn.execute(
            "UPDATE users SET group_id = 'admin' WHERE role = 'admin' AND (group_id = '' OR group_id = 'user')",
            [],
        );
        let _ = conn.execute(
            "UPDATE users SET group_id = 'user' WHERE group_id = '' OR group_id NOT IN (SELECT id FROM user_groups)",
            [],
        );

        Ok(())
    }

    pub fn open_with_vault(data_dir: &Path, vault: &Vault) -> Result<Self, String> {
        let cfg = mariadb::load_config_file(data_dir);
        let dirty_tables = Arc::new(Mutex::new(HashSet::<String>::new()));
        let mariadb_pool: Arc<RwLock<Option<mysql::Pool>>> = Arc::new(RwLock::new(None));
        let last_synced_at = Arc::new(Mutex::new(None::<String>));
        let last_sync_error = Arc::new(Mutex::new(None::<String>));
        let mut detected_version: Option<String> = None;

        let mut conn = if cfg.engine == "mariadb" && cfg.mariadb.is_some() {
            let mut mem = Connection::open_in_memory()
                .map_err(|e| format!("SQLite-In-Memory-Fehler: {e}"))?;
            Self::init_sqlite_schema(&mem)?;

            let resolved = mariadb::resolve_mariadb_config(cfg.mariadb.as_ref(), None, vault)?;
            let pool = mariadb::build_pool(&resolved)?;
            let version = mariadb::query_mariadb_version(&pool)?;
            mariadb::load_mariadb_into_sqlite(&pool, &mut mem)?;
            Self::init_sqlite_schema(&mem)?;

            tracing::info!(
                "SSH Console: MariaDB aktiv ({}:{}/{}, {})",
                resolved.host,
                resolved.port,
                resolved.database,
                version
            );
            detected_version = Some(version);
            if let Ok(mut g) = mariadb_pool.write() {
                *g = Some(pool);
            }
            if let Ok(mut ts) = last_synced_at.lock() {
                *ts = Some(Utc::now().to_rfc3339());
            }
            mem
        } else {
            let sqlite_path = data_dir.join("ssh-console.sqlite");
            let file_conn =
                Connection::open(&sqlite_path).map_err(|e| format!("SQLite-Fehler: {e}"))?;
            Self::init_sqlite_schema(&file_conn)?;
            file_conn
        };

        attach_update_hook(&mut conn, Arc::clone(&dirty_tables));

        Ok(Self {
            conn: SyncedDbMutex {
                inner: Mutex::new(conn),
                dirty_tables,
                mariadb_pool,
                last_synced_at,
                last_sync_error,
            },
            data_dir: data_dir.to_path_buf(),
            db_config: Mutex::new(cfg),
            mariadb_version: Mutex::new(detected_version),
        })
    }

    fn setting_str_locked(conn: &Connection, key: &str, default: &str) -> String {
        conn.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |r| r.get::<_, String>(0),
        )
        .unwrap_or_else(|_| default.to_string())
    }

    fn setting_bool_locked(conn: &Connection, key: &str, default: bool) -> bool {
        let def_str = if default { "1" } else { "0" };
        let val = Self::setting_str_locked(conn, key, def_str);
        val == "1" || val.eq_ignore_ascii_case("true")
    }

    fn set_setting_locked(conn: &Connection, key: &str, value: &str) -> Result<(), String> {
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn read_auth_policy_locked(conn: &Connection) -> AuthPolicySettings {
        let secret_enc_b64 = Self::setting_str_locked(conn, "sso_client_secret_enc", "");
        let secret_nonce_b64 = Self::setting_str_locked(conn, "sso_client_secret_nonce", "");
        let sso_client_secret_enc = if !secret_enc_b64.is_empty() && !secret_nonce_b64.is_empty() {
            match (
                STANDARD.decode(&secret_enc_b64),
                STANDARD.decode(&secret_nonce_b64),
            ) {
                (Ok(enc), Ok(nonce)) => Some((enc, nonce)),
                _ => None,
            }
        } else {
            None
        };
        let tested_raw = Self::setting_str_locked(conn, "sso_tested_at", "");
        let sso_tested_at = if tested_raw.trim().is_empty() {
            None
        } else {
            Some(tested_raw)
        };
        let provider = Self::setting_str_locked(conn, "sso_provider_name", "SSO");
        let scopes = Self::setting_str_locked(conn, "sso_scopes", "openid profile email");

        AuthPolicySettings {
            sso_enabled: Self::setting_bool_locked(conn, "sso_enabled", false),
            sso_provider_name: if provider.trim().is_empty() {
                "SSO".into()
            } else {
                provider
            },
            sso_issuer_url: Self::setting_str_locked(conn, "sso_issuer_url", ""),
            sso_auth_url: Self::setting_str_locked(conn, "sso_auth_url", ""),
            sso_token_url: Self::setting_str_locked(conn, "sso_token_url", ""),
            sso_userinfo_url: Self::setting_str_locked(conn, "sso_userinfo_url", ""),
            sso_client_id: Self::setting_str_locked(conn, "sso_client_id", ""),
            sso_client_secret_enc,
            sso_scopes: if scopes.trim().is_empty() {
                "openid profile email".into()
            } else {
                scopes
            },
            sso_auto_create_users: Self::setting_bool_locked(conn, "sso_auto_create_users", true),
            sso_tested_at,
            local_login_disabled: Self::setting_bool_locked(conn, "local_login_disabled", false),
            two_factor_enabled: Self::setting_bool_locked(conn, "two_factor_enabled", false),
            two_factor_enforced: Self::setting_bool_locked(conn, "two_factor_enforced", false),
            passkey_enabled: Self::setting_bool_locked(conn, "passkey_enabled", false),
            passkey_enforced: Self::setting_bool_locked(conn, "passkey_enforced", false),
            allow_insecure_host_key: Self::setting_bool_locked(conn, "allow_insecure_host_key", false),
            public_url: Self::setting_str_locked(conn, "public_url", ""),
        }
    }

    fn count_webauthn_locked(conn: &Connection, user_id: &str, kind: &str) -> usize {
        conn.query_row(
            "SELECT COUNT(*) FROM user_webauthn_credentials WHERE user_id = ?1 AND kind = ?2",
            params![user_id, kind],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        .max(0) as usize
    }

    fn resolve_group_locked(conn: &Connection, group_id: &str, role: &str) -> (String, String, bool, GroupPermissions) {
        let lookup_id = if !group_id.trim().is_empty() {
            group_id.trim()
        } else if role == "admin" {
            "admin"
        } else {
            "user"
        };
        let row: Option<(String, String, bool, String)> = conn
            .query_row(
                "SELECT id, name, is_admin, permissions_json FROM user_groups WHERE id = ?1",
                params![lookup_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)? == 1,
                        r.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()
            .unwrap_or(None);

        if let Some((gid, gname, is_admin, pjson)) = row {
            let perms = if is_admin {
                GroupPermissions::all()
            } else {
                serde_json::from_str::<GroupPermissions>(&pjson)
                    .unwrap_or_else(|_| GroupPermissions::default_user())
            };
            return (gid, gname, is_admin, perms);
        }

        if role == "admin" {
            (
                "admin".to_string(),
                "Administratoren".to_string(),
                true,
                GroupPermissions::all(),
            )
        } else {
            (
                "user".to_string(),
                "Benutzer".to_string(),
                false,
                GroupPermissions::default_user(),
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_user_public(
        conn: &Connection,
        policy: &AuthPolicySettings,
        id: String,
        username: String,
        display_name: String,
        role: String,
        group_id: String,
        auth_provider: String,
        email: String,
        default_ssh_user: String,
        active: bool,
        ping_enabled: bool,
        totp_enabled: bool,
        created_at: String,
        last_login_at: Option<String>,
    ) -> UserPublic {
        let (resolved_group_id, group_name, is_admin, permissions) =
            Self::resolve_group_locked(conn, &group_id, &role);
        let resolved_role = if is_admin {
            "admin".to_string()
        } else {
            "user".to_string()
        };
        let security_key_count = Self::count_webauthn_locked(conn, &id, "security-key");
        let passkey_count = Self::count_webauthn_locked(conn, &id, "passkey");
        let has_two_factor = totp_enabled || security_key_count > 0;
        let is_local = auth_provider != "sso";
        let must_setup_two_factor =
            is_local && policy.two_factor_enabled && policy.two_factor_enforced && !has_two_factor;
        let must_setup_passkey =
            is_local && policy.passkey_enabled && policy.passkey_enforced && passkey_count == 0;

        UserPublic {
            id,
            username,
            display_name,
            role: resolved_role,
            group_id: resolved_group_id,
            group_name,
            permissions,
            auth_provider,
            email,
            default_ssh_user,
            active,
            ping_enabled,
            totp_enabled,
            security_key_count,
            passkey_count,
            has_two_factor,
            must_setup_two_factor,
            must_setup_passkey,
            created_at,
            last_login_at,
        }
    }

    pub fn is_initialized(&self) -> Result<bool, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM users WHERE role = 'admin'", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        Ok(count > 0)
    }

    pub fn get_instance_name(&self) -> String {
        let Ok(conn) = self.conn.lock() else {
            return "SSH Console".into();
        };
        let raw: String = conn
            .query_row(
                "SELECT value FROM settings WHERE key = 'instance_name'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| "SSH Console".into());
        if raw.trim().is_empty() || raw == "TrixieSSH" {
            "SSH Console".into()
        } else {
            raw
        }
    }

    pub fn get_initialized_at(&self) -> Option<String> {
        let Ok(conn) = self.conn.lock() else {
            return None;
        };
        conn.query_row(
            "SELECT value FROM settings WHERE key = 'initialized_at'",
            [],
            |r| r.get(0),
        )
        .ok()
    }

    pub fn set_instance_name(&self, name: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let clean = if name.trim().is_empty() { "SSH Console" } else { name.trim() };
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('instance_name', ?1)",
            params![clean],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn set_initialized_at(&self, iso: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('initialized_at', ?1)",
            params![iso],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_ping_allowed(&self) -> bool {
        let Ok(conn) = self.conn.lock() else {
            return true;
        };
        let raw: String = conn
            .query_row(
                "SELECT value FROM settings WHERE key = 'ping_allowed'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| "1".into());
        raw != "0" && !raw.eq_ignore_ascii_case("false")
    }

    pub fn get_ping_interval_sec(&self) -> u64 {
        let Ok(conn) = self.conn.lock() else {
            return 60;
        };
        let raw: String = conn
            .query_row(
                "SELECT value FROM settings WHERE key = 'ping_interval_sec'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| "60".into());
        raw.parse::<u64>().unwrap_or(60).clamp(10, 3600)
    }

    pub fn get_ping_offline_threshold(&self) -> u32 {
        let Ok(conn) = self.conn.lock() else {
            return 5;
        };
        let raw: String = conn
            .query_row(
                "SELECT value FROM settings WHERE key = 'ping_offline_threshold'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| "5".into());
        raw.parse::<u32>().unwrap_or(5).clamp(0, 100)
    }

    pub fn get_ping_offline_multiplier(&self) -> u64 {
        let Ok(conn) = self.conn.lock() else {
            return 5;
        };
        let raw: String = conn
            .query_row(
                "SELECT value FROM settings WHERE key = 'ping_offline_multiplier'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| "5".into());
        raw.parse::<u64>().unwrap_or(5).clamp(2, 60)
    }

    pub fn set_global_ping_settings(
        &self,
        ping_allowed: Option<bool>,
        ping_interval_sec: Option<i64>,
        ping_offline_threshold: Option<i64>,
        ping_offline_multiplier: Option<i64>,
    ) -> Result<(bool, u64), String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        if let Some(allowed) = ping_allowed {
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('ping_allowed', ?1)",
                params![if allowed { "1" } else { "0" }],
            )
            .map_err(|e| e.to_string())?;
        }
        if let Some(sec) = ping_interval_sec {
            if !(10..=3600).contains(&sec) {
                return Err("Ping-Intervall muss zwischen 10 und 3600 Sekunden liegen.".into());
            }
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('ping_interval_sec', ?1)",
                params![sec.to_string()],
            )
            .map_err(|e| e.to_string())?;
        }
        if let Some(threshold) = ping_offline_threshold {
            if !(0..=100).contains(&threshold) {
                return Err(
                    "Offline-Schwellwert muss zwischen 0 und 100 Fehlversuchen liegen.".into(),
                );
            }
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('ping_offline_threshold', ?1)",
                params![threshold.to_string()],
            )
            .map_err(|e| e.to_string())?;
        }
        if let Some(multiplier) = ping_offline_multiplier {
            if !(2..=60).contains(&multiplier) {
                return Err("Offline-Intervall-Faktor muss zwischen 2 und 60 liegen.".into());
            }
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('ping_offline_multiplier', ?1)",
                params![multiplier.to_string()],
            )
            .map_err(|e| e.to_string())?;
        }
        drop(conn);
        Ok((self.get_ping_allowed(), self.get_ping_interval_sec()))
    }

    pub fn get_max_background_jobs(&self) -> usize {
        let Ok(conn) = self.conn.lock() else {
            return 5;
        };
        let raw: String = conn
            .query_row(
                "SELECT value FROM settings WHERE key = 'max_background_jobs'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| "5".into());
        raw.parse::<usize>().unwrap_or(5).clamp(1, 50)
    }

    pub fn set_max_background_jobs(&self, max_jobs: i64) -> Result<usize, String> {
        if !(1..=50).contains(&max_jobs) {
            return Err("Das Limit für Hintergrundprozesse muss zwischen 1 und 50 liegen.".into());
        }
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('max_background_jobs', ?1)",
            params![max_jobs.to_string()],
        )
        .map_err(|e| e.to_string())?;
        drop(conn);
        Ok(self.get_max_background_jobs())
    }

    pub fn set_user_ping_enabled(&self, user_id: &str, enabled: bool) -> Result<Option<UserPublic>, String> {
        {
            let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
            conn.execute(
                "UPDATE users SET ping_enabled = ?1 WHERE id = ?2",
                params![if enabled { 1i64 } else { 0i64 }, user_id],
            )
            .map_err(|e| e.to_string())?;
        }
        self.get_user_by_id(user_id)
    }

    pub fn should_ping_server(&self, server: &UserServer) -> bool {
        if !self.get_ping_allowed() || !server.ping_enabled {
            return false;
        }
        let Ok(users) = self.list_users() else {
            return true;
        };
        if users.iter().any(|u| u.id == server.user_id && u.active && u.ping_enabled) {
            return true;
        }
        if server.shared_with_all {
            return users.iter().any(|u| u.active && u.ping_enabled);
        }
        if !server.shared_with_user_ids.is_empty() {
            return users.iter().any(|u| {
                u.active
                    && u.ping_enabled
                    && server.shared_with_user_ids.iter().any(|sid| sid == &u.id)
            });
        }
        false
    }

    // ── User Groups & Granular Permissions ──────────────────────────────────

    pub fn list_groups(&self) -> Result<Vec<UserGroup>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT g.id, g.name, g.description, g.is_system, g.is_immutable, g.is_admin, g.permissions_json, g.created_at, g.updated_at,
                        (SELECT COUNT(*) FROM users u WHERE u.group_id = g.id) AS member_count
                 FROM user_groups g
                 ORDER BY CASE g.id WHEN 'admin' THEN 0 WHEN 'user' THEN 1 ELSE 2 END, LOWER(g.name) ASC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                let is_admin = r.get::<_, i64>(5)? == 1;
                let pjson: String = r.get(6)?;
                let perms = if is_admin {
                    GroupPermissions::all()
                } else {
                    serde_json::from_str::<GroupPermissions>(&pjson)
                        .unwrap_or_else(|_| GroupPermissions::default_user())
                };
                Ok(UserGroup {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    description: r.get(2)?,
                    is_system: r.get::<_, i64>(3)? == 1,
                    is_immutable: r.get::<_, i64>(4)? == 1,
                    is_admin,
                    permissions: perms,
                    created_at: r.get(7)?,
                    updated_at: r.get(8)?,
                    member_count: r.get::<_, i64>(9)?.max(0) as usize,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    pub fn get_group(&self, id: &str) -> Result<Option<UserGroup>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.query_row(
            "SELECT g.id, g.name, g.description, g.is_system, g.is_immutable, g.is_admin, g.permissions_json, g.created_at, g.updated_at,
                    (SELECT COUNT(*) FROM users u WHERE u.group_id = g.id) AS member_count
             FROM user_groups g WHERE g.id = ?1",
            params![id],
            |r| {
                let is_admin = r.get::<_, i64>(5)? == 1;
                let pjson: String = r.get(6)?;
                let perms = if is_admin {
                    GroupPermissions::all()
                } else {
                    serde_json::from_str::<GroupPermissions>(&pjson)
                        .unwrap_or_else(|_| GroupPermissions::default_user())
                };
                Ok(UserGroup {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    description: r.get(2)?,
                    is_system: r.get::<_, i64>(3)? == 1,
                    is_immutable: r.get::<_, i64>(4)? == 1,
                    is_admin,
                    permissions: perms,
                    created_at: r.get(7)?,
                    updated_at: r.get(8)?,
                    member_count: r.get::<_, i64>(9)?.max(0) as usize,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn create_group(
        &self,
        name: &str,
        description: &str,
        permissions: GroupPermissions,
    ) -> Result<UserGroup, String> {
        let clean_name: String = name
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(64)
            .collect();
        if clean_name.chars().count() < 2 {
            return Err("Der Gruppenname muss mindestens 2 Zeichen lang sein.".into());
        }
        let lower = clean_name.to_lowercase();
        if lower == "administratoren" || lower == "administrator" {
            return Err(format!(
                "Eine Benutzergruppe mit dem Namen „{clean_name}“ existiert bereits."
            ));
        }
        let clean_desc: String = description.trim().chars().take(240).collect();
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM user_groups WHERE LOWER(name) = LOWER(?1)",
                params![&clean_name],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if exists > 0 {
            return Err(format!(
                "Eine Benutzergruppe mit dem Namen „{clean_name}“ existiert bereits."
            ));
        }
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let perms_json = serde_json::to_string(&permissions).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO user_groups (id, name, description, is_system, is_immutable, is_admin, permissions_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, 0, 0, 0, ?4, ?5, ?5)",
            params![&id, &clean_name, &clean_desc, &perms_json, &now],
        )
        .map_err(|e| format!("Benutzergruppe konnte nicht gespeichert werden: {e}"))?;
        Ok(UserGroup {
            id,
            name: clean_name,
            description: clean_desc,
            is_system: false,
            is_immutable: false,
            is_admin: false,
            permissions,
            member_count: 0,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn update_group(
        &self,
        id: &str,
        name: Option<&str>,
        description: Option<&str>,
        permissions: Option<GroupPermissions>,
    ) -> Result<Option<UserGroup>, String> {
        let Some(existing) = self.get_group(id)? else {
            return Ok(None);
        };
        if existing.is_immutable || existing.id == "admin" {
            return Err(
                "Die Systemgruppe „Administratoren“ ist aus Sicherheitsgründen geschützt und kann nicht verändert werden."
                    .into(),
            );
        }
        let next_name = if let Some(n) = name {
            if existing.is_system {
                existing.name.clone()
            } else {
                let clean: String = n
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .chars()
                    .take(64)
                    .collect();
                if clean.chars().count() < 2 {
                    return Err("Der Gruppenname muss mindestens 2 Zeichen lang sein.".into());
                }
                let lower = clean.to_lowercase();
                if lower == "administratoren" || lower == "administrator" {
                    return Err(format!(
                        "Eine Benutzergruppe mit dem Namen „{clean}“ existiert bereits."
                    ));
                }
                clean
            }
        } else {
            existing.name.clone()
        };
        let next_desc: String = description
            .map(|d| d.trim().chars().take(240).collect())
            .unwrap_or_else(|| existing.description.clone());
        let next_perms = permissions.unwrap_or(existing.permissions);
        let perms_json = serde_json::to_string(&next_perms).map_err(|e| e.to_string())?;
        let now = Utc::now().to_rfc3339();

        {
            let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
            if !existing.is_system {
                let dup: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM user_groups WHERE id != ?1 AND LOWER(name) = LOWER(?2)",
                        params![id, &next_name],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);
                if dup > 0 {
                    return Err(format!(
                        "Eine Benutzergruppe mit dem Namen „{next_name}“ existiert bereits."
                    ));
                }
            }
            conn.execute(
                "UPDATE user_groups SET name = ?1, description = ?2, permissions_json = ?3, updated_at = ?4 WHERE id = ?5",
                params![&next_name, &next_desc, &perms_json, &now, id],
            )
            .map_err(|e| e.to_string())?;
        }
        self.get_group(id)
    }

    pub fn delete_group(&self, id: &str) -> Result<usize, String> {
        let Some(existing) = self.get_group(id)? else {
            return Err("Benutzergruppe nicht gefunden.".into());
        };
        if existing.is_system || existing.is_immutable || existing.id == "admin" || existing.id == "user" {
            return Err(
                "Systemgruppen („Administratoren“ und „Benutzer“) können nicht gelöscht werden."
                    .into(),
            );
        }
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let reassigned = conn
            .execute(
                "UPDATE users SET group_id = 'user', role = 'user' WHERE group_id = ?1",
                params![id],
            )
            .map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM user_groups WHERE id = ?1", params![id])
            .map_err(|e| e.to_string())?;
        Ok(reassigned)
    }

    pub fn create_user(
        &self,
        username: &str,
        display_name: &str,
        role: &str,
        group_id: Option<&str>,
        default_ssh_user: &str,
        password_hash: &str,
    ) -> Result<UserPublic, String> {
        let target_group_id = match group_id.map(str::trim).filter(|s| !s.is_empty()) {
            Some(gid) => gid.to_string(),
            None => {
                if role == "admin" {
                    "admin".to_string()
                } else {
                    "user".to_string()
                }
            }
        };
        let group = self
            .get_group(&target_group_id)?
            .ok_or_else(|| "Die ausgewählte Benutzergruppe existiert nicht.".to_string())?;
        let resolved_role = if group.is_admin { "admin" } else { "user" };

        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO users (id, username, display_name, role, group_id, default_ssh_user, active, ping_enabled, password_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 1, ?7, ?8)",
            params![id, username, display_name, resolved_role, &group.id, default_ssh_user, password_hash, now],
        )
        .map_err(|e| format!("Benutzer konnte nicht gespeichert werden: {e}"))?;

        let policy = Self::read_auth_policy_locked(&conn);
        Ok(Self::build_user_public(
            &conn,
            &policy,
            id,
            username.to_string(),
            display_name.to_string(),
            resolved_role.to_string(),
            group.id,
            "local".to_string(),
            String::new(),
            default_ssh_user.to_string(),
            true,
            true,
            false,
            now,
            None,
        ))
    }

    pub fn get_user_by_id(&self, id: &str) -> Result<Option<UserPublic>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let policy = Self::read_auth_policy_locked(&conn);
        let raw = conn
            .query_row(
                "SELECT id, username, display_name, role, group_id, auth_provider, email, default_ssh_user, active, ping_enabled, totp_enabled, created_at, last_login_at
                 FROM users WHERE id = ?1",
                params![id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, i64>(8)? == 1,
                        r.get::<_, i64>(9)? == 1,
                        r.get::<_, i64>(10)? == 1,
                        r.get::<_, String>(11)?,
                        r.get::<_, Option<String>>(12)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;

        Ok(raw.map(|t| {
            Self::build_user_public(
                &conn, &policy, t.0, t.1, t.2, t.3, t.4, t.5, t.6, t.7, t.8, t.9, t.10, t.11, t.12,
            )
        }))
    }

    pub fn update_user(
        &self,
        id: &str,
        display_name: Option<&str>,
        role: Option<&str>,
        group_id: Option<&str>,
        default_ssh_user: Option<&str>,
        active: Option<bool>,
        new_password_hash: Option<&str>,
    ) -> Result<Option<UserPublic>, String> {
        let Some(existing) = self.get_user_by_id(id)? else {
            return Ok(None);
        };
        let (next_group_id, next_role) = if let Some(gid) = group_id.map(str::trim).filter(|s| !s.is_empty()) {
            let grp = self
                .get_group(gid)?
                .ok_or_else(|| "Die ausgewählte Benutzergruppe existiert nicht.".to_string())?;
            (grp.id, if grp.is_admin { "admin".to_string() } else { "user".to_string() })
        } else if let Some(r) = role {
            let gid = if r == "admin" { "admin" } else { "user" };
            (gid.to_string(), gid.to_string())
        } else {
            (existing.group_id.clone(), existing.role.clone())
        };

        let next_display = display_name.unwrap_or(&existing.display_name).trim();
        let next_ssh_user = default_ssh_user.unwrap_or(&existing.default_ssh_user).trim();
        let next_active = active.unwrap_or(existing.active);

        {
            let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
            // Protect against disabling or demoting the last active admin
            if existing.role == "admin" && existing.active && (!next_active || next_role != "admin") {
                let active_admins: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);
                if active_admins <= 1 {
                    return Err(
                        "Der letzte aktive Administrator kann nicht deaktiviert oder herabgestuft werden."
                            .into(),
                    );
                }
            }
            conn.execute(
                "UPDATE users SET display_name = ?1, role = ?2, group_id = ?3, default_ssh_user = ?4, active = ?5 WHERE id = ?6",
                params![
                    if next_display.is_empty() { &existing.username } else { next_display },
                    &next_role,
                    &next_group_id,
                    if next_ssh_user.is_empty() { "root" } else { next_ssh_user },
                    if next_active { 1i64 } else { 0i64 },
                    id
                ],
            )
            .map_err(|e| e.to_string())?;

            if let Some(hash) = new_password_hash {
                conn.execute(
                    "UPDATE users SET password_hash = ?1 WHERE id = ?2",
                    params![hash, id],
                )
                .map_err(|e| e.to_string())?;
                let _ = conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![id]);
            }
            if !next_active {
                let _ = conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![id]);
            }
        }
        self.get_user_by_id(id)
    }

    pub fn find_user_for_login(&self, username: &str) -> Result<Option<(UserPublic, String)>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let policy = Self::read_auth_policy_locked(&conn);
        let raw = conn
            .query_row(
                "SELECT id, username, display_name, role, group_id, auth_provider, email, default_ssh_user, active, ping_enabled, totp_enabled, created_at, last_login_at, password_hash
                 FROM users WHERE username = ?1",
                params![username],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, i64>(8)? == 1,
                        r.get::<_, i64>(9)? == 1,
                        r.get::<_, i64>(10)? == 1,
                        r.get::<_, String>(11)?,
                        r.get::<_, Option<String>>(12)?,
                        r.get::<_, String>(13)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;

        Ok(raw.map(|t| {
            let user = Self::build_user_public(
                &conn, &policy, t.0, t.1, t.2, t.3, t.4, t.5, t.6, t.7, t.8, t.9, t.10, t.11, t.12,
            );
            (user, t.13)
        }))
    }

    pub fn create_session(&self, user_id: &str) -> Result<String, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let now = Utc::now();
        let now_str = now.to_rfc3339();
        let expires = now + Duration::hours(24);
        let _ = conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", params![now_str]);
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![token, user_id, now_str, expires.to_rfc3339()],
        )
        .map_err(|e| e.to_string())?;
        let _ = conn.execute(
            "UPDATE users SET last_login_at = ?1 WHERE id = ?2",
            params![now_str, user_id],
        );
        Ok(token)
    }

    pub fn user_by_session(&self, token: &str) -> Result<Option<UserPublic>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let policy = Self::read_auth_policy_locked(&conn);
        let now = Utc::now().to_rfc3339();
        let raw = conn
            .query_row(
                "SELECT u.id, u.username, u.display_name, u.role, u.group_id, u.auth_provider, u.email, u.default_ssh_user, u.active, u.ping_enabled, u.totp_enabled, u.created_at, u.last_login_at
                 FROM sessions s
                 JOIN users u ON u.id = s.user_id
                 WHERE s.token = ?1 AND s.expires_at > ?2 AND u.active = 1",
                params![token, now],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, i64>(8)? == 1,
                        r.get::<_, i64>(9)? == 1,
                        r.get::<_, i64>(10)? == 1,
                        r.get::<_, String>(11)?,
                        r.get::<_, Option<String>>(12)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;

        Ok(raw.map(|t| {
            Self::build_user_public(
                &conn, &policy, t.0, t.1, t.2, t.3, t.4, t.5, t.6, t.7, t.8, t.9, t.10, t.11, t.12,
            )
        }))
    }

    pub fn delete_session(&self, token: &str) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute("DELETE FROM sessions WHERE token = ?1", params![token]);
        }
    }

    pub fn list_api_keys(&self, user_id: &str) -> Result<Vec<UserApiKeyPublic>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, name, key_prefix, created_at, last_used_at
                 FROM user_api_keys WHERE user_id = ?1 ORDER BY created_at DESC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![user_id], |r| {
                Ok(UserApiKeyPublic {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    key_prefix: r.get(2)?,
                    created_at: r.get(3)?,
                    last_used_at: r.get(4)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    pub fn create_api_key(
        &self,
        user_id: &str,
        name: &str,
        key_prefix: &str,
        key_hash: &str,
    ) -> Result<UserApiKeyPublic, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO user_api_keys (id, user_id, name, key_prefix, key_hash, created_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            params![id, user_id, name, key_prefix, key_hash, now],
        )
        .map_err(|e| e.to_string())?;
        Ok(UserApiKeyPublic {
            id,
            name: name.to_string(),
            key_prefix: key_prefix.to_string(),
            created_at: now,
            last_used_at: None,
        })
    }

    pub fn delete_api_key(&self, id: &str, user_id: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.execute(
            "DELETE FROM user_api_keys WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn user_by_api_key_hash(&self, key_hash: &str) -> Result<Option<UserPublic>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let policy = Self::read_auth_policy_locked(&conn);
        let found = conn
            .query_row(
                "SELECT k.id, u.id, u.username, u.display_name, u.role, u.group_id, u.auth_provider, u.email, u.default_ssh_user, u.active, u.ping_enabled, u.totp_enabled, u.created_at, u.last_login_at
                 FROM user_api_keys k
                 JOIN users u ON u.id = k.user_id
                 WHERE k.key_hash = ?1 AND u.active = 1",
                params![key_hash],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, String>(8)?,
                        r.get::<_, i64>(9)? == 1,
                        r.get::<_, i64>(10)? == 1,
                        r.get::<_, i64>(11)? == 1,
                        r.get::<_, String>(12)?,
                        r.get::<_, Option<String>>(13)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;

        if let Some(t) = found {
            let now = Utc::now().to_rfc3339();
            let _ = conn.execute(
                "UPDATE user_api_keys SET last_used_at = ?1 WHERE id = ?2",
                params![now, &t.0],
            );
            let user = Self::build_user_public(
                &conn, &policy, t.1, t.2, t.3, t.4, t.5, t.6, t.7, t.8, t.9, t.10, t.11, t.12, t.13,
            );
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    pub fn list_users(&self) -> Result<Vec<UserPublic>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let policy = Self::read_auth_policy_locked(&conn);
        let mut stmt = conn
            .prepare(
                "SELECT id, username, display_name, role, group_id, auth_provider, email, default_ssh_user, active, ping_enabled, totp_enabled, created_at, last_login_at
                 FROM users ORDER BY created_at ASC",
            )
            .map_err(|e| e.to_string())?;
        let raw_rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, i64>(8)? == 1,
                    r.get::<_, i64>(9)? == 1,
                    r.get::<_, i64>(10)? == 1,
                    r.get::<_, String>(11)?,
                    r.get::<_, Option<String>>(12)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;

        Ok(raw_rows
            .into_iter()
            .map(|t| {
                Self::build_user_public(
                    &conn, &policy, t.0, t.1, t.2, t.3, t.4, t.5, t.6, t.7, t.8, t.9, t.10, t.11, t.12,
                )
            })
            .collect())
    }

    pub fn delete_user(&self, id: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let _ = conn.execute("DELETE FROM ssh_commands WHERE user_id = ?1", params![id]);
        conn.execute("DELETE FROM users WHERE id = ?1", params![id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn update_user_password(
        &self,
        user_id: &str,
        new_hash: &str,
        keep_session_token: Option<&str>,
    ) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.execute(
            "UPDATE users SET password_hash = ?1 WHERE id = ?2",
            params![new_hash, user_id],
        )
        .map_err(|e| e.to_string())?;
        if let Some(tok) = keep_session_token {
            let _ = conn.execute(
                "DELETE FROM sessions WHERE user_id = ?1 AND token != ?2",
                params![user_id, tok],
            );
        } else {
            let _ = conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id]);
        }
        Ok(())
    }

    fn map_command_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SshCommand> {
        let steps_json: String = r.get(6)?;
        let steps: Vec<CommandStep> = serde_json::from_str(&steps_json).unwrap_or_default();
        let workflow_json: String = r.get(7)?;
        let shared_json: String = r.get(14)?;
        let shared_with_user_ids: Vec<String> =
            serde_json::from_str(&shared_json).unwrap_or_default();
        let created_at: String = r.get(15)?;
        let updated_raw: String = r.get(16)?;
        let updated_at = if updated_raw.is_empty() {
            created_at.clone()
        } else {
            updated_raw
        };
        Ok(SshCommand {
            id: r.get(0)?,
            user_id: r.get(1)?,
            name: r.get(2)?,
            category: r.get(3)?,
            kind: r.get(4)?,
            command: r.get(5)?,
            steps,
            workflow_json,
            stop_on_error: r.get::<_, i64>(8)? == 1,
            description: r.get(9)?,
            timeout_sec: r.get::<_, i64>(10)? as u64,
            enabled: r.get::<_, i64>(11)? == 1,
            created_by: r.get(12)?,
            shared_with_all: r.get::<_, i64>(13)? == 1,
            shared_with_user_ids,
            created_at,
            updated_at,
        })
    }

    pub fn list_accessible_commands(
        &self,
        user_id: &str,
        include_disabled_own: bool,
    ) -> Result<Vec<SshCommand>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, user_id, name, category, kind, command, steps_json, workflow_json, stop_on_error, description, timeout_sec, enabled, created_by, shared_with_all, shared_with_user_ids, created_at, updated_at
                 FROM ssh_commands ORDER BY category ASC, name ASC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], Self::map_command_row)
            .map_err(|e| e.to_string())?;
        let all = rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
        Ok(all
            .into_iter()
            .filter(|c| {
                if c.user_id == user_id {
                    include_disabled_own || c.enabled
                } else {
                    c.enabled
                        && (c.shared_with_all || c.shared_with_user_ids.iter().any(|u| u == user_id))
                }
            })
            .collect())
    }

    pub fn list_own_commands(&self, user_id: &str) -> Result<Vec<SshCommand>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, user_id, name, category, kind, command, steps_json, workflow_json, stop_on_error, description, timeout_sec, enabled, created_by, shared_with_all, shared_with_user_ids, created_at, updated_at
                 FROM ssh_commands WHERE user_id = ?1 ORDER BY category ASC, name ASC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![user_id], Self::map_command_row)
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    pub fn get_command(&self, id: &str) -> Result<Option<SshCommand>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.query_row(
            "SELECT id, user_id, name, category, kind, command, steps_json, workflow_json, stop_on_error, description, timeout_sec, enabled, created_by, shared_with_all, shared_with_user_ids, created_at, updated_at
             FROM ssh_commands WHERE id = ?1",
            params![id],
            Self::map_command_row,
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn get_accessible_command(&self, id: &str, user_id: &str) -> Result<Option<SshCommand>, String> {
        let Some(cmd) = self.get_command(id)? else {
            return Ok(None);
        };
        if !cmd.enabled {
            return Ok(None);
        }
        if cmd.user_id == user_id
            || cmd.shared_with_all
            || cmd.shared_with_user_ids.iter().any(|u| u == user_id)
        {
            Ok(Some(cmd))
        } else {
            Ok(None)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_command(
        &self,
        user_id: &str,
        name: &str,
        category: &str,
        kind: &str,
        command: &str,
        steps: &[CommandStep],
        workflow_json: &str,
        stop_on_error: bool,
        description: &str,
        timeout_sec: u64,
        enabled: bool,
        created_by: &str,
        shared_with_all: bool,
        shared_with_user_ids: &[String],
    ) -> Result<SshCommand, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let steps_json = serde_json::to_string(steps).map_err(|e| e.to_string())?;
        let clean_shared: Vec<String> = if shared_with_all {
            vec![]
        } else {
            shared_with_user_ids.to_vec()
        };
        let shared_json = serde_json::to_string(&clean_shared).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO ssh_commands (id, user_id, name, category, kind, command, steps_json, workflow_json, stop_on_error, description, timeout_sec, enabled, created_by, shared_with_all, shared_with_user_ids, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                id,
                user_id,
                name,
                category,
                kind,
                command,
                steps_json,
                workflow_json,
                if stop_on_error { 1i64 } else { 0i64 },
                description,
                timeout_sec as i64,
                if enabled { 1i64 } else { 0i64 },
                created_by,
                if shared_with_all { 1i64 } else { 0i64 },
                shared_json,
                now,
                now
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(SshCommand {
            id,
            user_id: user_id.to_string(),
            name: name.to_string(),
            category: category.to_string(),
            kind: kind.to_string(),
            command: command.to_string(),
            steps: steps.to_vec(),
            workflow_json: workflow_json.to_string(),
            stop_on_error,
            description: description.to_string(),
            timeout_sec,
            enabled,
            created_by: created_by.to_string(),
            shared_with_all,
            shared_with_user_ids: clean_shared,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_command(
        &self,
        id: &str,
        owner_user_id: &str,
        name: &str,
        category: &str,
        kind: &str,
        command: &str,
        steps: &[CommandStep],
        workflow_json: &str,
        stop_on_error: bool,
        description: &str,
        timeout_sec: u64,
        enabled: bool,
    ) -> Result<Option<SshCommand>, String> {
        let now = Utc::now().to_rfc3339();
        let steps_json = serde_json::to_string(steps).map_err(|e| e.to_string())?;
        {
            let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
            let changed = conn
                .execute(
                    "UPDATE ssh_commands
                     SET name = ?1, category = ?2, kind = ?3, command = ?4, steps_json = ?5,
                         workflow_json = ?6, stop_on_error = ?7, description = ?8, timeout_sec = ?9, enabled = ?10, updated_at = ?11
                     WHERE id = ?12 AND user_id = ?13",
                    params![
                        name,
                        category,
                        kind,
                        command,
                        steps_json,
                        workflow_json,
                        if stop_on_error { 1i64 } else { 0i64 },
                        description,
                        timeout_sec as i64,
                        if enabled { 1i64 } else { 0i64 },
                        now,
                        id,
                        owner_user_id
                    ],
                )
                .map_err(|e| e.to_string())?;
            if changed == 0 {
                return Ok(None);
            }
        }
        self.get_command(id)
    }

    pub fn update_command_sharing(
        &self,
        id: &str,
        owner_user_id: &str,
        shared_with_all: bool,
        shared_with_user_ids: &[String],
    ) -> Result<Option<SshCommand>, String> {
        let clean_shared: Vec<String> = if shared_with_all {
            vec![]
        } else {
            shared_with_user_ids
                .iter()
                .filter(|u| u.as_str() != owner_user_id)
                .cloned()
                .collect()
        };
        let shared_json = serde_json::to_string(&clean_shared).map_err(|e| e.to_string())?;
        let now = Utc::now().to_rfc3339();
        {
            let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
            let changed = conn
                .execute(
                    "UPDATE ssh_commands SET shared_with_all = ?1, shared_with_user_ids = ?2, updated_at = ?3 WHERE id = ?4 AND user_id = ?5",
                    params![
                        if shared_with_all { 1i64 } else { 0i64 },
                        shared_json,
                        now,
                        id,
                        owner_user_id
                    ],
                )
                .map_err(|e| e.to_string())?;
            if changed == 0 {
                return Ok(None);
            }
        }
        self.get_command(id)
    }

    pub fn bulk_update_commands(
        &self,
        command_ids: &[String],
        owner_user_id: &str,
        is_admin: bool,
        category: Option<&str>,
        enabled: Option<bool>,
        sharing: Option<(bool, &[String])>,
    ) -> Result<Vec<SshCommand>, String> {
        let mut unique_ids: Vec<String> = Vec::new();
        for raw in command_ids {
            let trimmed = raw.trim();
            if !trimmed.is_empty() && !unique_ids.iter().any(|x| x == trimmed) {
                unique_ids.push(trimmed.to_string());
                if unique_ids.len() >= 500 {
                    break;
                }
            }
        }
        if unique_ids.is_empty() {
            return Err("Bitte wählen Sie mindestens einen SSH-Befehl aus.".into());
        }

        let clean_cat = category.map(|c| {
            let t = c.trim();
            if t.is_empty() {
                "Allgemein".to_string()
            } else {
                t.chars().take(48).collect()
            }
        });
        let sharing_prepared: Option<(i64, String)> = if is_admin {
            if let Some((all, user_ids)) = sharing {
                let clean_shared: Vec<String> = if all {
                    vec![]
                } else {
                    user_ids
                        .iter()
                        .filter(|u| u.as_str() != owner_user_id)
                        .cloned()
                        .collect()
                };
                let json_str = serde_json::to_string(&clean_shared).map_err(|e| e.to_string())?;
                Some((if all { 1 } else { 0 }, json_str))
            } else {
                None
            }
        } else {
            None
        };

        let now = Utc::now().to_rfc3339();
        let mut verified_ids: Vec<String> = Vec::new();
        {
            let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
            for id in &unique_ids {
                let owner_opt: Option<String> = conn
                    .query_row(
                        "SELECT user_id FROM ssh_commands WHERE id = ?1",
                        params![id],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| e.to_string())?;
                let Some(found_owner) = owner_opt else {
                    continue;
                };
                if found_owner != owner_user_id {
                    return Err("Sie können nur selbst angelegte SSH-Befehle bearbeiten.".into());
                }
                verified_ids.push(id.clone());
            }
            if verified_ids.is_empty() {
                return Err("Keine passenden eigenen SSH-Befehle gefunden.".into());
            }
            for id in &verified_ids {
                if let Some(ref cat) = clean_cat {
                    conn.execute(
                        "UPDATE ssh_commands SET category = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4",
                        params![cat, now, id, owner_user_id],
                    )
                    .map_err(|e| e.to_string())?;
                }
                if let Some(en) = enabled {
                    conn.execute(
                        "UPDATE ssh_commands SET enabled = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4",
                        params![if en { 1i64 } else { 0i64 }, now, id, owner_user_id],
                    )
                    .map_err(|e| e.to_string())?;
                }
                if let Some((all_flag, ref shared_json)) = sharing_prepared {
                    conn.execute(
                        "UPDATE ssh_commands SET shared_with_all = ?1, shared_with_user_ids = ?2, updated_at = ?3 WHERE id = ?4 AND user_id = ?5",
                        params![all_flag, shared_json, now, id, owner_user_id],
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
        }
        let mut out = Vec::with_capacity(verified_ids.len());
        for id in verified_ids {
            if let Some(cmd) = self.get_command(&id)? {
                out.push(cmd);
            }
        }
        Ok(out)
    }

    pub fn delete_command(&self, id: &str, owner_user_id: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.execute(
            "DELETE FROM ssh_commands WHERE id = ?1 AND user_id = ?2",
            params![id, owner_user_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn normalize_server_categories(input: &[String]) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for raw in input {
            let collapsed = raw
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let clean: String = collapsed.chars().take(48).collect();
            if clean.is_empty() {
                continue;
            }
            let key = clean.to_lowercase();
            if seen.insert(key) {
                out.push(clean);
                if out.len() >= 20 {
                    break;
                }
            }
        }
        out
    }

    fn ensure_user_categories_locked(
        conn: &Connection,
        user_id: &str,
        names: &[String],
    ) -> Result<(), String> {
        let clean_names = Self::normalize_server_categories(names);
        if clean_names.is_empty() {
            return Ok(());
        }
        let mut existing = std::collections::HashSet::new();
        {
            let mut stmt = conn
                .prepare("SELECT name FROM user_server_categories WHERE user_id = ?1")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![user_id], |r| r.get::<_, String>(0))
                .map_err(|e| e.to_string())?;
            for row in rows {
                if let Ok(name) = row {
                    existing.insert(name.to_lowercase());
                }
            }
        }
        let now = Utc::now().to_rfc3339();
        for name in clean_names {
            let key = name.to_lowercase();
            if existing.insert(key) {
                let id = Uuid::new_v4().to_string();
                conn.execute(
                    "INSERT INTO user_server_categories (id, user_id, name, created_at) VALUES (?1, ?2, ?3, ?4)",
                    params![id, user_id, name, now],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    pub fn list_server_categories(&self, user_id: &str) -> Result<Vec<ServerCategory>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, user_id, name, created_at
                 FROM user_server_categories
                 WHERE user_id = ?1
                 ORDER BY LOWER(name) ASC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![user_id], |r| {
                Ok(ServerCategory {
                    id: r.get(0)?,
                    user_id: r.get(1)?,
                    name: r.get(2)?,
                    created_at: r.get(3)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    pub fn create_server_category(
        &self,
        user_id: &str,
        raw_name: &str,
    ) -> Result<ServerCategory, String> {
        let normalized = Self::normalize_server_categories(&[raw_name.to_string()]);
        let Some(name) = normalized.into_iter().next() else {
            return Err("Kategoriename darf nicht leer sein.".to_string());
        };
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let existing = conn
            .query_row(
                "SELECT id, user_id, name, created_at
                 FROM user_server_categories
                 WHERE user_id = ?1 AND LOWER(name) = LOWER(?2)
                 LIMIT 1",
                params![user_id, name],
                |r| {
                    Ok(ServerCategory {
                        id: r.get(0)?,
                        user_id: r.get(1)?,
                        name: r.get(2)?,
                        created_at: r.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if let Some(cat) = existing {
            return Ok(cat);
        }
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO user_server_categories (id, user_id, name, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, user_id, name, now],
        )
        .map_err(|e| e.to_string())?;
        Ok(ServerCategory {
            id,
            user_id: user_id.to_string(),
            name,
            created_at: now,
        })
    }

    pub fn delete_server_category(
        &self,
        id: &str,
        user_id: &str,
    ) -> Result<Option<ServerCategory>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let existing = conn
            .query_row(
                "SELECT id, user_id, name, created_at
                 FROM user_server_categories
                 WHERE id = ?1 AND user_id = ?2",
                params![id, user_id],
                |r| {
                    Ok(ServerCategory {
                        id: r.get(0)?,
                        user_id: r.get(1)?,
                        name: r.get(2)?,
                        created_at: r.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let Some(cat) = existing else {
            return Ok(None);
        };
        conn.execute(
            "DELETE FROM user_server_categories WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )
        .map_err(|e| e.to_string())?;

        // Remove the deleted category from all servers owned by this user
        let target_lower = cat.name.to_lowercase();
        let server_rows: Vec<(String, String)> = {
            let mut stmt = conn
                .prepare("SELECT id, categories_json FROM user_servers WHERE user_id = ?1")
                .map_err(|e| e.to_string())?;
            let mapped = stmt
                .query_map(params![user_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(|e| e.to_string())?;
            mapped.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?
        };
        for (srv_id, cats_json) in server_rows {
            let current: Vec<String> = serde_json::from_str(&cats_json).unwrap_or_default();
            let filtered: Vec<String> = current
                .iter()
                .filter(|c| c.to_lowercase() != target_lower)
                .cloned()
                .collect();
            if filtered.len() != current.len() {
                let next_json = serde_json::to_string(&filtered).map_err(|e| e.to_string())?;
                conn.execute(
                    "UPDATE user_servers SET categories_json = ?1 WHERE id = ?2 AND user_id = ?3",
                    params![next_json, srv_id, user_id],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        Ok(Some(cat))
    }

    pub fn list_all_servers(&self) -> Result<Vec<UserServer>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, user_id, owner_username, label, ip_address, bmc_ip_address, bmc_ip_address2, port, ssh_user, notes, ping_enabled, ignore_host_key, categories_json, shared_with_all, shared_with_user_ids, created_at, last_online_at
                 FROM user_servers ORDER BY label ASC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                let categories_json: String = r.get(12)?;
                let raw_categories: Vec<String> =
                    serde_json::from_str(&categories_json).unwrap_or_default();
                let categories = Self::normalize_server_categories(&raw_categories);
                let shared_json: String = r.get(14)?;
                let shared_with_user_ids: Vec<String> =
                    serde_json::from_str(&shared_json).unwrap_or_default();
                Ok(UserServer {
                    id: r.get(0)?,
                    user_id: r.get(1)?,
                    owner_username: r.get(2)?,
                    label: r.get(3)?,
                    ip_address: r.get(4)?,
                    bmc_ip_address: r.get(5)?,
                    bmc_ip_address2: r.get(6)?,
                    port: r.get::<_, i64>(7)? as u16,
                    ssh_user: r.get(8)?,
                    notes: r.get(9)?,
                    ping_enabled: r.get::<_, i64>(10)? == 1,
                    ignore_host_key: r.get::<_, i64>(11)? == 1,
                    categories,
                    last_online_at: r.get(16)?,
                    shared_with_all: r.get::<_, i64>(13)? == 1,
                    shared_with_user_ids,
                    created_at: r.get(15)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    pub fn list_accessible_servers(&self, user_id: &str) -> Result<Vec<UserServer>, String> {
        let all = self.list_all_servers()?;
        Ok(all
            .into_iter()
            .filter(|s| {
                s.user_id == user_id
                    || s.shared_with_all
                    || s.shared_with_user_ids.iter().any(|u| u == user_id)
            })
            .collect())
    }

    pub fn get_accessible_server(&self, id: &str, user_id: &str) -> Result<Option<UserServer>, String> {
        let all = self.list_accessible_servers(user_id)?;
        Ok(all.into_iter().find(|s| s.id == id))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_server(
        &self,
        user_id: &str,
        owner_username: &str,
        label: &str,
        ip: &str,
        bmc_ip: &str,
        bmc_ip2: &str,
        port: u16,
        ssh_user: &str,
        notes: &str,
        ping_enabled: bool,
        ignore_host_key: bool,
        categories: &[String],
        shared_with_all: bool,
        shared_with_user_ids: &[String],
    ) -> Result<UserServer, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let clean_categories = Self::normalize_server_categories(categories);
        let categories_json = serde_json::to_string(&clean_categories).map_err(|e| e.to_string())?;
        let clean_shared: Vec<String> = if shared_with_all {
            vec![]
        } else {
            shared_with_user_ids.to_vec()
        };
        let shared_json = serde_json::to_string(&clean_shared).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO user_servers (id, user_id, owner_username, label, ip_address, bmc_ip_address, bmc_ip_address2, port, ssh_user, notes, ping_enabled, ignore_host_key, categories_json, shared_with_all, shared_with_user_ids, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                id,
                user_id,
                owner_username,
                label,
                ip,
                bmc_ip,
                bmc_ip2,
                port as i64,
                ssh_user,
                notes,
                if ping_enabled { 1i64 } else { 0i64 },
                if ignore_host_key { 1i64 } else { 0i64 },
                categories_json,
                if shared_with_all { 1i64 } else { 0i64 },
                shared_json,
                now
            ],
        )
        .map_err(|e| e.to_string())?;
        Self::ensure_user_categories_locked(&conn, user_id, &clean_categories)?;
        Ok(UserServer {
            id,
            user_id: user_id.to_string(),
            owner_username: owner_username.to_string(),
            label: label.to_string(),
            ip_address: ip.to_string(),
            bmc_ip_address: bmc_ip.to_string(),
            bmc_ip_address2: bmc_ip2.to_string(),
            port,
            ssh_user: ssh_user.to_string(),
            notes: notes.to_string(),
            ping_enabled,
            ignore_host_key,
            categories: clean_categories,
            last_online_at: None,
            shared_with_all,
            shared_with_user_ids: clean_shared,
            created_at: now,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_server(
        &self,
        id: &str,
        owner_user_id: &str,
        label: &str,
        ip: &str,
        bmc_ip: &str,
        bmc_ip2: &str,
        port: u16,
        ssh_user: &str,
        notes: &str,
        ping_enabled: bool,
        ignore_host_key: bool,
        categories: &[String],
    ) -> Result<Option<UserServer>, String> {
        let clean_categories = Self::normalize_server_categories(categories);
        let categories_json = serde_json::to_string(&clean_categories).map_err(|e| e.to_string())?;
        {
            let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
            let changed = conn
                .execute(
                    "UPDATE user_servers
                     SET label = ?1, ip_address = ?2, bmc_ip_address = ?3, bmc_ip_address2 = ?4, port = ?5, ssh_user = ?6, notes = ?7, ping_enabled = ?8, ignore_host_key = ?9, categories_json = ?10,
                         last_online_at = CASE WHEN ip_address != ?2 THEN NULL ELSE last_online_at END
                     WHERE id = ?11 AND user_id = ?12",
                    params![
                        label,
                        ip,
                        bmc_ip,
                        bmc_ip2,
                        port as i64,
                        ssh_user,
                        notes,
                        if ping_enabled { 1i64 } else { 0i64 },
                        if ignore_host_key { 1i64 } else { 0i64 },
                        categories_json,
                        id,
                        owner_user_id
                    ],
                )
                .map_err(|e| e.to_string())?;
            if changed == 0 {
                return Ok(None);
            }
            Self::ensure_user_categories_locked(&conn, owner_user_id, &clean_categories)?;
        }
        self.get_accessible_server(id, owner_user_id)
    }

    pub fn record_server_last_online(
        &self,
        server_id: &str,
        iso_timestamp: &str,
    ) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.execute(
            "UPDATE user_servers SET last_online_at = ?1 WHERE id = ?2",
            params![iso_timestamp, server_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn update_server_sharing(
        &self,
        id: &str,
        owner_user_id: &str,
        shared_with_all: bool,
        shared_with_user_ids: &[String],
    ) -> Result<Option<UserServer>, String> {
        let clean_shared: Vec<String> = if shared_with_all {
            vec![]
        } else {
            shared_with_user_ids
                .iter()
                .filter(|u| u.as_str() != owner_user_id)
                .cloned()
                .collect()
        };
        let shared_json = serde_json::to_string(&clean_shared).map_err(|e| e.to_string())?;
        {
            let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
            let changed = conn
                .execute(
                    "UPDATE user_servers SET shared_with_all = ?1, shared_with_user_ids = ?2 WHERE id = ?3 AND user_id = ?4",
                    params![
                        if shared_with_all { 1i64 } else { 0i64 },
                        shared_json,
                        id,
                        owner_user_id
                    ],
                )
                .map_err(|e| e.to_string())?;
            if changed == 0 {
                return Ok(None);
            }
        }
        self.get_accessible_server(id, owner_user_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bulk_update_servers(
        &self,
        server_ids: &[String],
        owner_user_id: &str,
        is_admin: bool,
        ping_enabled: Option<bool>,
        ignore_host_key: Option<bool>,
        categories_action: Option<&str>,
        categories: &[String],
        sharing: Option<(bool, &[String])>,
    ) -> Result<Vec<UserServer>, String> {
        let mut unique_ids: Vec<String> = Vec::new();
        for raw in server_ids {
            let trimmed = raw.trim();
            if !trimmed.is_empty() && !unique_ids.iter().any(|x| x == trimmed) {
                unique_ids.push(trimmed.to_string());
                if unique_ids.len() >= 500 {
                    break;
                }
            }
        }
        if unique_ids.is_empty() {
            return Err("Bitte wählen Sie mindestens einen Server (IP) aus.".into());
        }

        let norm_cats = Self::normalize_server_categories(categories);
        let remove_set: std::collections::HashSet<String> =
            norm_cats.iter().map(|c| c.to_lowercase()).collect();
        let sharing_prepared: Option<(i64, String)> = if is_admin {
            if let Some((all, user_ids)) = sharing {
                let clean_shared: Vec<String> = if all {
                    vec![]
                } else {
                    user_ids
                        .iter()
                        .filter(|u| u.as_str() != owner_user_id)
                        .cloned()
                        .collect()
                };
                let json_str = serde_json::to_string(&clean_shared).map_err(|e| e.to_string())?;
                Some((if all { 1 } else { 0 }, json_str))
            } else {
                None
            }
        } else {
            None
        };

        let mut verified_targets: Vec<(String, String)> = Vec::new();
        {
            let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
            for id in &unique_ids {
                let row_opt: Option<(String, String)> = conn
                    .query_row(
                        "SELECT user_id, categories_json FROM user_servers WHERE id = ?1",
                        params![id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()
                    .map_err(|e| e.to_string())?;
                let Some((found_owner, existing_cats_json)) = row_opt else {
                    continue;
                };
                if found_owner != owner_user_id {
                    return Err("Sie können nur selbst angelegte Server (IPs) bearbeiten.".into());
                }
                verified_targets.push((id.clone(), existing_cats_json));
            }
            if verified_targets.is_empty() {
                return Err("Keine passenden eigenen Server gefunden.".into());
            }
            if matches!(categories_action, Some("add") | Some("replace")) && !norm_cats.is_empty() {
                Self::ensure_user_categories_locked(&conn, owner_user_id, &norm_cats)?;
            }
            for (id, existing_cats_json) in &verified_targets {
                if let Some(ping) = ping_enabled {
                    conn.execute(
                        "UPDATE user_servers SET ping_enabled = ?1 WHERE id = ?2 AND user_id = ?3",
                        params![if ping { 1i64 } else { 0i64 }, id, owner_user_id],
                    )
                    .map_err(|e| e.to_string())?;
                }
                if let Some(ignore_hk) = ignore_host_key {
                    conn.execute(
                        "UPDATE user_servers SET ignore_host_key = ?1 WHERE id = ?2 AND user_id = ?3",
                        params![if ignore_hk { 1i64 } else { 0i64 }, id, owner_user_id],
                    )
                    .map_err(|e| e.to_string())?;
                }
                if let Some(action) = categories_action {
                    let current_cats: Vec<String> =
                        serde_json::from_str(existing_cats_json).unwrap_or_default();
                    let next_cats = match action {
                        "replace" => norm_cats.clone(),
                        "add" => {
                            let mut merged = current_cats;
                            merged.extend(norm_cats.iter().cloned());
                            Self::normalize_server_categories(&merged)
                        }
                        "remove" => current_cats
                            .into_iter()
                            .filter(|c| !remove_set.contains(&c.to_lowercase()))
                            .collect(),
                        _ => current_cats,
                    };
                    let next_json = serde_json::to_string(&next_cats).map_err(|e| e.to_string())?;
                    conn.execute(
                        "UPDATE user_servers SET categories_json = ?1 WHERE id = ?2 AND user_id = ?3",
                        params![next_json, id, owner_user_id],
                    )
                    .map_err(|e| e.to_string())?;
                }
                if let Some((all_flag, ref shared_json)) = sharing_prepared {
                    conn.execute(
                        "UPDATE user_servers SET shared_with_all = ?1, shared_with_user_ids = ?2 WHERE id = ?3 AND user_id = ?4",
                        params![all_flag, shared_json, id, owner_user_id],
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
        }
        let mut out = Vec::with_capacity(verified_targets.len());
        for (id, _) in verified_targets {
            if let Some(srv) = self.get_accessible_server(&id, owner_user_id)? {
                out.push(srv);
            }
        }
        Ok(out)
    }

    pub fn delete_server(&self, id: &str, user_id: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.execute(
            "DELETE FROM user_servers WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn find_owned_certificate_name(
        &self,
        user_id: &str,
        name: &str,
    ) -> Result<Option<String>, String> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.query_row(
            "SELECT name FROM user_certificates WHERE user_id = ?1 AND LOWER(TRIM(name)) = LOWER(TRIM(?2)) LIMIT 1",
            params![user_id, trimmed],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn save_certificate(
        &self,
        user_id: &str,
        owner_username: &str,
        name: &str,
        priv_file: &str,
        pub_file: &str,
        cert_file: &str,
        priv_enc: &[u8],
        priv_nonce: &[u8],
        passphrase_enc: Option<&[u8]>,
        passphrase_nonce: Option<&[u8]>,
        pub_key: &str,
        cert: &str,
        inspection: &CertInspection,
        shared_with_all: bool,
        shared_with_user_ids: &[String],
    ) -> Result<(UserCertificatePublic, bool), String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let clean_name = name.trim();
        let effective_name = if clean_name.is_empty() {
            "SSH-Zertifikat"
        } else {
            clean_name
        };
        let now = Utc::now().to_rfc3339();
        let inspection_json = serde_json::to_string(inspection).map_err(|e| e.to_string())?;
        let has_stored_passphrase = passphrase_enc.is_some() && passphrase_nonce.is_some();
        let explicit_shared_ids: Vec<String> = if shared_with_all {
            vec![]
        } else {
            shared_with_user_ids
                .iter()
                .filter(|u| u.as_str() != user_id)
                .cloned()
                .collect()
        };

        let existing: Option<(String, bool, Vec<String>, Option<String>)> = conn
            .query_row(
                "SELECT id, shared_with_all, shared_with_user_ids, auto_renew_json
                 FROM user_certificates
                 WHERE user_id = ?1 AND LOWER(TRIM(name)) = LOWER(TRIM(?2))
                 ORDER BY uploaded_at DESC
                 LIMIT 1",
                params![user_id, effective_name],
                |r| {
                    let existing_id: String = r.get(0)?;
                    let existing_all = r.get::<_, i64>(1)? == 1;
                    let shared_json: String = r.get(2)?;
                    let existing_ids: Vec<String> =
                        serde_json::from_str(&shared_json).unwrap_or_default();
                    let existing_ar: Option<String> = r.get(3)?;
                    Ok((existing_id, existing_all, existing_ids, existing_ar))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;

        if let Some((existing_id, existing_all, existing_ids, existing_ar_raw)) = existing {
            let keep_existing_sharing = !shared_with_all && explicit_shared_ids.is_empty();
            let next_all = if keep_existing_sharing {
                existing_all
            } else {
                shared_with_all
            };
            let next_ids = if next_all {
                vec![]
            } else if keep_existing_sharing {
                existing_ids
            } else {
                explicit_shared_ids
            };
            let shared_json = serde_json::to_string(&next_ids).map_err(|e| e.to_string())?;

            let next_auto_renew: Option<CertificateAutoRenewConfig> = existing_ar_raw
                .and_then(|s| serde_json::from_str::<CertificateAutoRenewConfig>(&s).ok())
                .map(|mut ar| {
                    if ar.enabled {
                        ar.enabled = false;
                        ar.revoked_at = Some(now.clone());
                        ar.revoked_reason =
                            Some("Zertifikatspaket wurde manuell ersetzt".to_string());
                        ar.last_error = None;
                    }
                    ar
                });
            let next_auto_renew_json: Option<String> = next_auto_renew
                .as_ref()
                .and_then(|ar| serde_json::to_string(ar).ok());

            conn.execute(
                "UPDATE user_certificates
                 SET owner_username = ?1, name = ?2, private_key_file = ?3, public_key_file = ?4, cert_file = ?5,
                     private_key_enc = ?6, private_key_nonce = ?7, passphrase_enc = ?8, passphrase_nonce = ?9,
                     public_key = ?10, certificate = ?11,
                     inspection_json = ?12, auto_renew_json = ?13, shared_with_all = ?14, shared_with_user_ids = ?15, uploaded_at = ?16
                 WHERE id = ?17 AND user_id = ?18",
                params![
                    owner_username,
                    effective_name,
                    priv_file,
                    pub_file,
                    cert_file,
                    priv_enc,
                    priv_nonce,
                    passphrase_enc,
                    passphrase_nonce,
                    pub_key,
                    cert,
                    inspection_json,
                    next_auto_renew_json,
                    if next_all { 1i64 } else { 0i64 },
                    shared_json,
                    now,
                    existing_id,
                    user_id
                ],
            )
            .map_err(|e| e.to_string())?;

            let _ = conn.execute(
                "DELETE FROM user_certificates
                 WHERE user_id = ?1 AND LOWER(TRIM(name)) = LOWER(TRIM(?2)) AND id != ?3",
                params![user_id, effective_name, existing_id],
            );

            return Ok((
                UserCertificatePublic {
                    id: existing_id,
                    user_id: user_id.to_string(),
                    owner_username: owner_username.to_string(),
                    name: effective_name.to_string(),
                    private_key_file_name: priv_file.to_string(),
                    public_key_file_name: pub_file.to_string(),
                    cert_file_name: cert_file.to_string(),
                    metadata: inspection.clone(),
                    has_stored_passphrase,
                    auto_renew: next_auto_renew,
                    shared_with_all: next_all,
                    shared_with_user_ids: next_ids,
                    uploaded_at: now,
                },
                true,
            ));
        }

        let id = Uuid::new_v4().to_string();
        let shared_json = serde_json::to_string(&explicit_shared_ids).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO user_certificates
             (id, user_id, owner_username, name, private_key_file, public_key_file, cert_file, private_key_enc, private_key_nonce, passphrase_enc, passphrase_nonce, public_key, certificate, inspection_json, auto_renew_json, shared_with_all, shared_with_user_ids, uploaded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, NULL, ?15, ?16, ?17)",
            params![
                id,
                user_id,
                owner_username,
                effective_name,
                priv_file,
                pub_file,
                cert_file,
                priv_enc,
                priv_nonce,
                passphrase_enc,
                passphrase_nonce,
                pub_key,
                cert,
                inspection_json,
                if shared_with_all { 1i64 } else { 0i64 },
                shared_json,
                now
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok((
            UserCertificatePublic {
                id,
                user_id: user_id.to_string(),
                owner_username: owner_username.to_string(),
                name: effective_name.to_string(),
                private_key_file_name: priv_file.to_string(),
                public_key_file_name: pub_file.to_string(),
                cert_file_name: cert_file.to_string(),
                metadata: inspection.clone(),
                has_stored_passphrase,
                auto_renew: None,
                shared_with_all,
                shared_with_user_ids: explicit_shared_ids,
                uploaded_at: now,
            },
            false,
        ))
    }

    pub fn list_accessible_certificates(&self, user_id: &str) -> Result<Vec<UserCertificatePublic>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, user_id, owner_username, name, private_key_file, public_key_file, cert_file, inspection_json, shared_with_all, shared_with_user_ids, uploaded_at,
                        CASE WHEN passphrase_enc IS NOT NULL AND passphrase_nonce IS NOT NULL THEN 1 ELSE 0 END,
                        auto_renew_json
                 FROM user_certificates ORDER BY uploaded_at DESC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                let json: String = r.get(7)?;
                let metadata: CertInspection = serde_json::from_str(&json).unwrap_or_default();
                let shared_json: String = r.get(9)?;
                let shared_with_user_ids: Vec<String> =
                    serde_json::from_str(&shared_json).unwrap_or_default();
                let ar_json: Option<String> = r.get(12)?;
                let auto_renew: Option<CertificateAutoRenewConfig> =
                    ar_json.and_then(|s| serde_json::from_str(&s).ok());
                Ok(UserCertificatePublic {
                    id: r.get(0)?,
                    user_id: r.get(1)?,
                    owner_username: r.get(2)?,
                    name: r.get(3)?,
                    private_key_file_name: r.get(4)?,
                    public_key_file_name: r.get(5)?,
                    cert_file_name: r.get(6)?,
                    metadata,
                    has_stored_passphrase: r.get::<_, i64>(11)? == 1,
                    auto_renew,
                    shared_with_all: r.get::<_, i64>(8)? == 1,
                    shared_with_user_ids,
                    uploaded_at: r.get(10)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let all = rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
        Ok(all
            .into_iter()
            .filter(|c| {
                c.user_id == user_id
                    || c.shared_with_all
                    || c.shared_with_user_ids.iter().any(|u| u == user_id)
            })
            .collect())
    }

    pub fn list_all_certificates(&self) -> Result<Vec<UserCertificatePublic>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, user_id, owner_username, name, private_key_file, public_key_file, cert_file, inspection_json, shared_with_all, shared_with_user_ids, uploaded_at,
                        CASE WHEN passphrase_enc IS NOT NULL AND passphrase_nonce IS NOT NULL THEN 1 ELSE 0 END,
                        auto_renew_json
                 FROM user_certificates ORDER BY uploaded_at DESC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                let json: String = r.get(7)?;
                let metadata: CertInspection = serde_json::from_str(&json).unwrap_or_default();
                let shared_json: String = r.get(9)?;
                let shared_with_user_ids: Vec<String> =
                    serde_json::from_str(&shared_json).unwrap_or_default();
                let ar_json: Option<String> = r.get(12)?;
                let auto_renew: Option<CertificateAutoRenewConfig> =
                    ar_json.and_then(|s| serde_json::from_str(&s).ok());
                Ok(UserCertificatePublic {
                    id: r.get(0)?,
                    user_id: r.get(1)?,
                    owner_username: r.get(2)?,
                    name: r.get(3)?,
                    private_key_file_name: r.get(4)?,
                    public_key_file_name: r.get(5)?,
                    cert_file_name: r.get(6)?,
                    metadata,
                    has_stored_passphrase: r.get::<_, i64>(11)? == 1,
                    auto_renew,
                    shared_with_all: r.get::<_, i64>(8)? == 1,
                    shared_with_user_ids,
                    uploaded_at: r.get(10)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    pub fn update_certificate_sharing(
        &self,
        id: &str,
        owner_user_id: &str,
        shared_with_all: bool,
        shared_with_user_ids: &[String],
    ) -> Result<Option<UserCertificatePublic>, String> {
        let clean_shared: Vec<String> = if shared_with_all {
            vec![]
        } else {
            shared_with_user_ids
                .iter()
                .filter(|u| u.as_str() != owner_user_id)
                .cloned()
                .collect()
        };
        let shared_json = serde_json::to_string(&clean_shared).map_err(|e| e.to_string())?;
        {
            let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
            let changed = conn
                .execute(
                    "UPDATE user_certificates SET shared_with_all = ?1, shared_with_user_ids = ?2 WHERE id = ?3 AND user_id = ?4",
                    params![
                        if shared_with_all { 1i64 } else { 0i64 },
                        shared_json,
                        id,
                        owner_user_id
                    ],
                )
                .map_err(|e| e.to_string())?;
            if changed == 0 {
                return Ok(None);
            }
        }
        let certs = self.list_accessible_certificates(owner_user_id)?;
        Ok(certs.into_iter().find(|c| c.id == id))
    }

    pub fn get_accessible_certificate_secret(
        &self,
        id: &str,
        user_id: &str,
    ) -> Result<Option<UserCertificateSecret>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let found = conn
            .query_row(
                "SELECT id, user_id, name, private_key_enc, private_key_nonce, passphrase_enc, passphrase_nonce, public_key, certificate, inspection_json, shared_with_all, shared_with_user_ids
                 FROM user_certificates WHERE id = ?1",
                params![id],
                |r| {
                    let owner_id: String = r.get(1)?;
                    let json: String = r.get(9)?;
                    let parsed_meta = serde_json::from_str::<CertInspection>(&json).unwrap_or_default();
                    let shared_all = r.get::<_, i64>(10)? == 1;
                    let shared_json: String = r.get(11)?;
                    let shared_ids: Vec<String> =
                        serde_json::from_str(&shared_json).unwrap_or_default();
                    let secret = UserCertificateSecret {
                        id: r.get(0)?,
                        name: r.get(2)?,
                        private_key_enc: r.get(3)?,
                        private_key_nonce: r.get(4)?,
                        passphrase_enc: r.get(5)?,
                        passphrase_nonce: r.get(6)?,
                        private_key_encrypted: parsed_meta.private_key_encrypted,
                        public_key: r.get(7)?,
                        certificate: r.get(8)?,
                        key_id: parsed_meta.key_id,
                    };
                    Ok((owner_id, shared_all, shared_ids, secret))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;

        Ok(found.and_then(|(owner_id, shared_all, shared_ids, secret)| {
            if owner_id == user_id || shared_all || shared_ids.iter().any(|u| u == user_id) {
                Some(secret)
            } else {
                None
            }
        }))
    }

    pub fn get_certificate_owner(&self, id: &str) -> Result<Option<String>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.query_row(
            "SELECT user_id FROM user_certificates WHERE id = ?1",
            params![id],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn get_owned_certificate_by_id_or_name(
        &self,
        user_id: &str,
        id_or_name: &str,
    ) -> Result<Option<StoredCertificateForEdit>, String> {
        let clean = id_or_name.trim();
        if clean.is_empty() {
            return Ok(None);
        }
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let map_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<StoredCertificateForEdit> {
            let shared_json: String = r.get(12)?;
            let shared_ids: Vec<String> = serde_json::from_str(&shared_json).unwrap_or_default();
            Ok(StoredCertificateForEdit {
                id: r.get(0)?,
                name: r.get(1)?,
                private_key_file_name: r.get(2)?,
                public_key_file_name: r.get(3)?,
                cert_file_name: r.get(4)?,
                private_key_enc: r.get(5)?,
                private_key_nonce: r.get(6)?,
                passphrase_enc: r.get(7)?,
                passphrase_nonce: r.get(8)?,
                public_key: r.get(9)?,
                certificate: r.get(10)?,
                shared_with_all: r.get::<_, i64>(11)? == 1,
                shared_with_user_ids: shared_ids,
            })
        };

        if let Some(found) = conn
            .query_row(
                "SELECT id, name, private_key_file, public_key_file, cert_file,
                        private_key_enc, private_key_nonce, passphrase_enc, passphrase_nonce, public_key, certificate, shared_with_all, shared_with_user_ids
                 FROM user_certificates
                 WHERE user_id = ?1 AND id = ?2
                 LIMIT 1",
                params![user_id, clean],
                map_row,
            )
            .optional()
            .map_err(|e| e.to_string())?
        {
            return Ok(Some(found));
        }

        conn.query_row(
            "SELECT id, name, private_key_file, public_key_file, cert_file,
                    private_key_enc, private_key_nonce, passphrase_enc, passphrase_nonce, public_key, certificate, shared_with_all, shared_with_user_ids
             FROM user_certificates
             WHERE user_id = ?1 AND LOWER(TRIM(name)) = LOWER(TRIM(?2))
             ORDER BY uploaded_at DESC
             LIMIT 1",
            params![user_id, clean],
            map_row,
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_certificate_bundle(
        &self,
        id: &str,
        owner_user_id: &str,
        owner_username: &str,
        name: &str,
        priv_file: &str,
        pub_file: &str,
        cert_file: &str,
        priv_enc: &[u8],
        priv_nonce: &[u8],
        passphrase_enc: Option<&[u8]>,
        passphrase_nonce: Option<&[u8]>,
        pub_key: &str,
        cert: &str,
        inspection: &CertInspection,
        shared_with_all: bool,
        shared_with_user_ids: &[String],
    ) -> Result<UserCertificatePublic, String> {
        let clean_name = name.trim();
        if clean_name.is_empty() {
            return Err("Die Bezeichnung darf nicht leer sein.".to_string());
        }
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let conflict: Option<String> = conn
            .query_row(
                "SELECT id FROM user_certificates
                 WHERE user_id = ?1 AND id != ?2 AND LOWER(TRIM(name)) = LOWER(TRIM(?3))
                 LIMIT 1",
                params![owner_user_id, id, clean_name],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if conflict.is_some() {
            return Err(format!(
                "Ein anderes Zertifikatspaket mit der Bezeichnung „{clean_name}“ existiert bereits."
            ));
        }

        let now = Utc::now().to_rfc3339();
        let inspection_json = serde_json::to_string(inspection).map_err(|e| e.to_string())?;
        let has_stored_passphrase = passphrase_enc.is_some() && passphrase_nonce.is_some();

        let prev_cert_and_ar: Option<(String, Option<String>)> = conn
            .query_row(
                "SELECT certificate, auto_renew_json FROM user_certificates WHERE id = ?1 AND user_id = ?2 LIMIT 1",
                params![id, owner_user_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;

        let (prev_cert, prev_ar_raw) = match prev_cert_and_ar {
            Some(pair) => pair,
            None => {
                return Err("Zertifikatspaket nicht gefunden oder keine Berechtigung.".to_string());
            }
        };

        let cert_changed = prev_cert.trim() != cert.trim();
        let next_auto_renew: Option<CertificateAutoRenewConfig> = prev_ar_raw
            .and_then(|s| serde_json::from_str::<CertificateAutoRenewConfig>(&s).ok())
            .map(|mut ar| {
                if cert_changed && ar.enabled {
                    ar.enabled = false;
                    ar.revoked_at = Some(now.clone());
                    ar.revoked_reason = Some(
                        "Zertifikat (zertifikat-cert.pub) wurde manuell geändert".to_string(),
                    );
                    ar.last_error = None;
                }
                ar
            });
        let next_auto_renew_json: Option<String> = next_auto_renew
            .as_ref()
            .and_then(|ar| serde_json::to_string(ar).ok());

        let changed = conn
            .execute(
                "UPDATE user_certificates
                 SET owner_username = ?1, name = ?2, private_key_file = ?3, public_key_file = ?4, cert_file = ?5,
                     private_key_enc = ?6, private_key_nonce = ?7, passphrase_enc = ?8, passphrase_nonce = ?9,
                     public_key = ?10, certificate = ?11,
                     inspection_json = ?12, auto_renew_json = ?13, uploaded_at = ?14
                 WHERE id = ?15 AND user_id = ?16",
                params![
                    owner_username,
                    clean_name,
                    priv_file,
                    pub_file,
                    cert_file,
                    priv_enc,
                    priv_nonce,
                    passphrase_enc,
                    passphrase_nonce,
                    pub_key,
                    cert,
                    inspection_json,
                    next_auto_renew_json,
                    now,
                    id,
                    owner_user_id
                ],
            )
            .map_err(|e| e.to_string())?;
        if changed == 0 {
            return Err("Zertifikatspaket nicht gefunden oder keine Berechtigung.".to_string());
        }

        Ok(UserCertificatePublic {
            id: id.to_string(),
            user_id: owner_user_id.to_string(),
            owner_username: owner_username.to_string(),
            name: clean_name.to_string(),
            private_key_file_name: priv_file.to_string(),
            public_key_file_name: pub_file.to_string(),
            cert_file_name: cert_file.to_string(),
            metadata: inspection.clone(),
            has_stored_passphrase,
            auto_renew: next_auto_renew,
            shared_with_all,
            shared_with_user_ids: shared_with_user_ids.to_vec(),
            uploaded_at: now,
        })
    }

    pub fn delete_certificate(&self, id: &str, user_id: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.execute(
            "DELETE FROM user_certificates WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn delete_certificate_as_admin(&self, id: &str) -> Result<bool, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let changed = conn
            .execute("DELETE FROM user_certificates WHERE id = ?1", params![id])
            .map_err(|e| e.to_string())?;
        Ok(changed > 0)
    }

    pub fn get_certificate_for_signing(
        &self,
        id: &str,
    ) -> Result<Option<StoredCertificateForSigning>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.query_row(
            "SELECT id, user_id, owner_username, name, private_key_file, public_key_file, cert_file,
                    private_key_enc, private_key_nonce, public_key, certificate, inspection_json, auto_renew_json
             FROM user_certificates WHERE id = ?1 LIMIT 1",
            params![id],
            |r| {
                let inspection_json: String = r.get(11)?;
                let metadata: CertInspection =
                    serde_json::from_str(&inspection_json).unwrap_or_default();
                let certificate: String = r.get(10)?;
                let ar_json: Option<String> = r.get(12)?;
                let auto_renew: Option<CertificateAutoRenewConfig> =
                    ar_json.and_then(|s| serde_json::from_str(&s).ok());
                Ok(StoredCertificateForSigning {
                    id: r.get(0)?,
                    user_id: r.get(1)?,
                    owner_username: r.get(2)?,
                    name: r.get(3)?,
                    private_key_file_name: r.get(4)?,
                    public_key_file_name: r.get(5)?,
                    cert_file_name: r.get(6)?,
                    private_key_enc: r.get(7)?,
                    private_key_nonce: r.get(8)?,
                    public_key: r.get(9)?,
                    has_certificate: metadata.has_certificate && !certificate.trim().is_empty(),
                    existing_ca_fingerprint: metadata.ca_fingerprint,
                    valid_after_unix: metadata.valid_after_unix,
                    valid_before_unix: metadata.valid_before_unix,
                    auto_renew,
                    certificate,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn list_certificates_with_auto_renew(
        &self,
    ) -> Result<Vec<StoredCertificateForSigning>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, user_id, owner_username, name, private_key_file, public_key_file, cert_file,
                        private_key_enc, private_key_nonce, public_key, certificate, inspection_json, auto_renew_json
                 FROM user_certificates WHERE auto_renew_json IS NOT NULL",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                let inspection_json: String = r.get(11)?;
                let metadata: CertInspection =
                    serde_json::from_str(&inspection_json).unwrap_or_default();
                let certificate: String = r.get(10)?;
                let ar_json: Option<String> = r.get(12)?;
                let auto_renew: Option<CertificateAutoRenewConfig> =
                    ar_json.and_then(|s| serde_json::from_str(&s).ok());
                Ok(StoredCertificateForSigning {
                    id: r.get(0)?,
                    user_id: r.get(1)?,
                    owner_username: r.get(2)?,
                    name: r.get(3)?,
                    private_key_file_name: r.get(4)?,
                    public_key_file_name: r.get(5)?,
                    cert_file_name: r.get(6)?,
                    private_key_enc: r.get(7)?,
                    private_key_nonce: r.get(8)?,
                    public_key: r.get(9)?,
                    has_certificate: metadata.has_certificate && !certificate.trim().is_empty(),
                    existing_ca_fingerprint: metadata.ca_fingerprint,
                    valid_after_unix: metadata.valid_after_unix,
                    valid_before_unix: metadata.valid_before_unix,
                    auto_renew,
                    certificate,
                })
            })
            .map_err(|e| e.to_string())?;
        let all = rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
        Ok(all
            .into_iter()
            .filter(|c| c.auto_renew.as_ref().map(|a| a.enabled).unwrap_or(false))
            .collect())
    }

    pub fn update_certificate_signed_cert(
        &self,
        id: &str,
        cert_file_name: &str,
        cert_content: &str,
        inspection: &CertInspection,
        auto_renew: Option<&CertificateAutoRenewConfig>,
    ) -> Result<UserCertificatePublic, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let now = Utc::now().to_rfc3339();
        let inspection_json = serde_json::to_string(inspection).map_err(|e| e.to_string())?;
        let auto_renew_json: Option<String> = match auto_renew {
            Some(cfg) => Some(serde_json::to_string(cfg).map_err(|e| e.to_string())?),
            None => None,
        };
        let changed = conn
            .execute(
                "UPDATE user_certificates
                 SET cert_file = ?1, certificate = ?2, inspection_json = ?3, auto_renew_json = ?4, uploaded_at = ?5
                 WHERE id = ?6",
                params![
                    cert_file_name,
                    cert_content.trim(),
                    inspection_json,
                    auto_renew_json,
                    now,
                    id
                ],
            )
            .map_err(|e| e.to_string())?;
        if changed == 0 {
            return Err("Zertifikatspaket nicht gefunden.".to_string());
        }
        conn.query_row(
            "SELECT id, user_id, owner_username, name, private_key_file, public_key_file, cert_file, inspection_json, shared_with_all, shared_with_user_ids, uploaded_at,
                    CASE WHEN passphrase_enc IS NOT NULL AND passphrase_nonce IS NOT NULL THEN 1 ELSE 0 END,
                    auto_renew_json
             FROM user_certificates WHERE id = ?1 LIMIT 1",
            params![id],
            |r| {
                let json: String = r.get(7)?;
                let metadata: CertInspection = serde_json::from_str(&json).unwrap_or_default();
                let shared_json: String = r.get(9)?;
                let shared_with_user_ids: Vec<String> =
                    serde_json::from_str(&shared_json).unwrap_or_default();
                let ar_json: Option<String> = r.get(12)?;
                let ar: Option<CertificateAutoRenewConfig> =
                    ar_json.and_then(|s| serde_json::from_str(&s).ok());
                Ok(UserCertificatePublic {
                    id: r.get(0)?,
                    user_id: r.get(1)?,
                    owner_username: r.get(2)?,
                    name: r.get(3)?,
                    private_key_file_name: r.get(4)?,
                    public_key_file_name: r.get(5)?,
                    cert_file_name: r.get(6)?,
                    metadata,
                    has_stored_passphrase: r.get::<_, i64>(11)? == 1,
                    auto_renew: ar,
                    shared_with_all: r.get::<_, i64>(8)? == 1,
                    shared_with_user_ids,
                    uploaded_at: r.get(10)?,
                })
            },
        )
        .map_err(|e| e.to_string())
    }

    pub fn update_certificate_auto_renew(
        &self,
        id: &str,
        auto_renew: Option<&CertificateAutoRenewConfig>,
    ) -> Result<UserCertificatePublic, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let auto_renew_json: Option<String> = match auto_renew {
            Some(cfg) => Some(serde_json::to_string(cfg).map_err(|e| e.to_string())?),
            None => None,
        };
        let changed = conn
            .execute(
                "UPDATE user_certificates SET auto_renew_json = ?1 WHERE id = ?2",
                params![auto_renew_json, id],
            )
            .map_err(|e| e.to_string())?;
        if changed == 0 {
            return Err("Zertifikatspaket nicht gefunden.".to_string());
        }
        conn.query_row(
            "SELECT id, user_id, owner_username, name, private_key_file, public_key_file, cert_file, inspection_json, shared_with_all, shared_with_user_ids, uploaded_at,
                    CASE WHEN passphrase_enc IS NOT NULL AND passphrase_nonce IS NOT NULL THEN 1 ELSE 0 END,
                    auto_renew_json
             FROM user_certificates WHERE id = ?1 LIMIT 1",
            params![id],
            |r| {
                let json: String = r.get(7)?;
                let metadata: CertInspection = serde_json::from_str(&json).unwrap_or_default();
                let shared_json: String = r.get(9)?;
                let shared_with_user_ids: Vec<String> =
                    serde_json::from_str(&shared_json).unwrap_or_default();
                let ar_json: Option<String> = r.get(12)?;
                let ar: Option<CertificateAutoRenewConfig> =
                    ar_json.and_then(|s| serde_json::from_str(&s).ok());
                Ok(UserCertificatePublic {
                    id: r.get(0)?,
                    user_id: r.get(1)?,
                    owner_username: r.get(2)?,
                    name: r.get(3)?,
                    private_key_file_name: r.get(4)?,
                    public_key_file_name: r.get(5)?,
                    cert_file_name: r.get(6)?,
                    metadata,
                    has_stored_passphrase: r.get::<_, i64>(11)? == 1,
                    auto_renew: ar,
                    shared_with_all: r.get::<_, i64>(8)? == 1,
                    shared_with_user_ids,
                    uploaded_at: r.get(10)?,
                })
            },
        )
        .map_err(|e| e.to_string())
    }

    pub fn revoke_certificate_auto_renew(
        &self,
        id: &str,
        reason: &str,
    ) -> Result<Option<UserCertificatePublic>, String> {
        let current = self.get_certificate_for_signing(id)?;
        let Some(cert) = current else {
            return Ok(None);
        };
        let next_ar = match cert.auto_renew {
            Some(mut ar) => {
                ar.enabled = false;
                ar.revoked_at = Some(Utc::now().to_rfc3339());
                ar.revoked_reason = Some(reason.to_string());
                ar.last_error = None;
                Some(ar)
            }
            None => None,
        };
        let updated = self.update_certificate_auto_renew(id, next_ar.as_ref())?;
        Ok(Some(updated))
    }

    pub fn reconcile_auto_renewals(&self) -> Result<usize, String> {
        let active_certs = self.list_certificates_with_auto_renew()?;
        if active_certs.is_empty() {
            return Ok(0);
        }
        let mut changed_count = 0usize;
        for cert in active_certs {
            let Some(ar) = cert.auto_renew else {
                continue;
            };
            if !ar.enabled {
                continue;
            }
            let owner = self.get_user_by_id(&cert.user_id)?;
            let ca = self.get_certificate_authority_for_edit(&ar.ca_id)?;

            let mut synced_ar: Option<CertificateAutoRenewConfig> = None;
            let revoke_reason: Option<String> = match (owner, ca) {
                (None, _) => Some("Benutzerkonto deaktiviert oder entfernt".to_string()),
                (Some(ref u), _) if !u.active => {
                    Some("Benutzerkonto deaktiviert oder entfernt".to_string())
                }
                (_, None) => Some("Zugehörige CA wurde gelöscht".to_string()),
                (_, Some(ref c)) if c.passphrase_enc.is_none() || c.passphrase_nonce.is_none() => {
                    Some("Gespeichertes CA-Passwort wurde entfernt".to_string())
                }
                (Some(ref u), Some(_)) if ar.mode == "user" => {
                    if !u.permissions.self_sign_certificates || !u.permissions.auto_renew_certificates
                    {
                        Some("Rechteentzug: Selbstsignierung oder automatische Neuzertifizierung für Benutzergruppe deaktiviert".to_string())
                    } else {
                        match u
                            .permissions
                            .ca_signing_assignments
                            .iter()
                            .find(|a| a.ca_id == ar.ca_id)
                        {
                            None => Some(
                                "Rechteentzug: CA ist der Benutzergruppe nicht mehr zugewiesen"
                                    .to_string(),
                            ),
                            Some(assignment) => {
                                let val_lower = assignment.validity.trim().to_ascii_lowercase();
                                if val_lower == "forever"
                                    || val_lower == "always"
                                    || val_lower == "always:forever"
                                {
                                    Some("Rechteentzug: Gültigkeitsdauer für diese CA wurde auf unbegrenzt (forever) gesetzt".to_string())
                                } else {
                                    let has_principal = !assignment.principals.is_empty()
                                        || (assignment.include_owner_principal
                                            && crate::ssh::is_valid_principal_token(&u.username));
                                    if !has_principal {
                                        Some("Rechteentzug: Keine gültigen Principals (-n) mehr für diese CA zugewiesen".to_string())
                                    } else {
                                        let next_validity = if assignment.validity.trim().is_empty() {
                                            "+30d".to_string()
                                        } else {
                                            assignment.validity.clone()
                                        };
                                        let next_lead = if assignment.auto_renew_before_seconds == 0 {
                                            0
                                        } else {
                                            assignment.auto_renew_before_seconds.clamp(60, 180 * 86_400)
                                        };
                                        if ar.principals != assignment.principals
                                            || ar.include_owner_principal != assignment.include_owner_principal
                                            || ar.validity != next_validity
                                            || ar.renew_before_seconds != next_lead
                                        {
                                            let mut next = ar.clone();
                                            next.principals = assignment.principals.clone();
                                            next.include_owner_principal = assignment.include_owner_principal;
                                            next.validity = next_validity;
                                            next.renew_before_seconds = next_lead;
                                            synced_ar = Some(next);
                                        }
                                        None
                                    }
                                }
                            }
                        }
                    }
                }
                (Some(_), Some(_)) => {
                    if !ar.enabled_by_user_id.is_empty() {
                        match self.get_user_by_id(&ar.enabled_by_user_id)? {
                            Some(enabler) if enabler.active && enabler.role == "admin" => None,
                            _ => Some("Rechteentzug: Freigebender Administrator ist nicht mehr aktiv oder kein Administrator".to_string()),
                        }
                    } else {
                        None
                    }
                }
            };

            if let Some(reason) = revoke_reason {
                let _ = self.revoke_certificate_auto_renew(&cert.id, &reason);
                changed_count += 1;
            } else if let Some(ref next) = synced_ar {
                let _ = self.update_certificate_auto_renew(&cert.id, Some(next));
                changed_count += 1;
            }
        }
        Ok(changed_count)
    }

    pub fn insert_log(&self, log: &ExecutionLog) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.execute(
            "INSERT INTO execution_logs
             (id, user_id, username, command_id, command_name, command_text, target_ip, target_port, ssh_user, server_label, certificate_id, certificate_key_id, mode, ssh_invocation, exit_code, stdout, stderr, duration_ms, executed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            params![
                log.id,
                log.user_id,
                log.username,
                log.command_id,
                log.command_name,
                log.command_text,
                log.target_ip,
                log.target_port as i64,
                log.ssh_user,
                log.server_label,
                log.certificate_id,
                log.certificate_key_id,
                log.mode,
                log.ssh_invocation,
                log.exit_code,
                log.stdout,
                log.stderr,
                log.duration_ms as i64,
                log.executed_at
            ],
        )
        .map_err(|e| e.to_string())?;
        // Protokolltabelle auf die neuesten 5.000 Einträge begrenzen, damit SQLite dauerhaft kompakt bleibt
        let _ = conn.execute(
            "DELETE FROM execution_logs WHERE id IN (
                SELECT id FROM execution_logs ORDER BY executed_at DESC LIMIT -1 OFFSET 5000
            )",
            [],
        );
        Ok(())
    }

    pub fn list_logs(
        &self,
        user: &UserPublic,
        filter_user_id: Option<&str>,
    ) -> Result<Vec<ExecutionLog>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let effective_user_id = if user.role == "admin" {
            filter_user_id.map(str::trim).filter(|s| !s.is_empty())
        } else {
            Some(user.id.as_str())
        };

        let mut stmt = if effective_user_id.is_some() {
            conn.prepare(
                "SELECT id, user_id, username, command_id, command_name, command_text, target_ip, target_port, ssh_user, server_label, certificate_id, certificate_key_id, mode, ssh_invocation, exit_code, stdout, stderr, duration_ms, executed_at
                 FROM execution_logs WHERE user_id = ?1 ORDER BY executed_at DESC LIMIT 250",
            )
            .map_err(|e| e.to_string())?
        } else {
            conn.prepare(
                "SELECT id, user_id, username, command_id, command_name, command_text, target_ip, target_port, ssh_user, server_label, certificate_id, certificate_key_id, mode, ssh_invocation, exit_code, stdout, stderr, duration_ms, executed_at
                 FROM execution_logs ORDER BY executed_at DESC LIMIT 250",
            )
            .map_err(|e| e.to_string())?
        };

        let mapper = |r: &rusqlite::Row<'_>| {
            let target_ip: String = r.get(6)?;
            let label_raw: String = r.get(9)?;
            let server_label = if label_raw.is_empty() {
                target_ip.clone()
            } else {
                label_raw
            };
            Ok(ExecutionLog {
                id: r.get(0)?,
                user_id: r.get(1)?,
                username: r.get(2)?,
                command_id: r.get(3)?,
                command_name: r.get(4)?,
                command_text: r.get(5)?,
                target_ip,
                target_port: r.get::<_, i64>(7)? as u16,
                ssh_user: r.get(8)?,
                server_label,
                certificate_id: r.get(10)?,
                certificate_key_id: r.get(11)?,
                mode: r.get(12)?,
                ssh_invocation: r.get(13)?,
                exit_code: r.get(14)?,
                stdout: r.get(15)?,
                stderr: r.get(16)?,
                duration_ms: r.get::<_, i64>(17)? as u64,
                executed_at: r.get(18)?,
            })
        };

        let rows = if let Some(uid) = effective_user_id {
            stmt.query_map(params![uid], mapper)
        } else {
            stmt.query_map([], mapper)
        }
        .map_err(|e| e.to_string())?;

        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    // ── Auth Policies (SSO, 2FA, Passkeys) ──────────────────────────────────

    pub fn get_auth_policy(&self) -> AuthPolicySettings {
        let Ok(conn) = self.conn.lock() else {
            return AuthPolicySettings {
                sso_enabled: false,
                sso_provider_name: "SSO".into(),
                sso_issuer_url: String::new(),
                sso_auth_url: String::new(),
                sso_token_url: String::new(),
                sso_userinfo_url: String::new(),
                sso_client_id: String::new(),
                sso_client_secret_enc: None,
                sso_scopes: "openid profile email".into(),
                sso_auto_create_users: true,
                sso_tested_at: None,
                local_login_disabled: false,
                two_factor_enabled: false,
                two_factor_enforced: false,
                passkey_enabled: false,
                passkey_enforced: false,
                allow_insecure_host_key: false,
                public_url: String::new(),
            };
        };
        Self::read_auth_policy_locked(&conn)
    }

    fn normalize_public_url(raw: &str) -> Result<String, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(String::new());
        }
        if trimmed.len() > 255 {
            return Err("Öffentliche Domain / URL ist zu lang (max. 255 Zeichen).".into());
        }
        if trimmed.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || matches!(
                    c,
                    '"' | '\'' | '`' | '$' | '\\' | '<' | '>' | ';' | '&' | '|' | '?' | '#' | '@'
                )
        }) {
            return Err("Ungültige Zeichen in der öffentlichen Domain / Basis-URL.".into());
        }
        let lower = trimmed.to_ascii_lowercase();
        let (scheme, rest) = if lower.starts_with("https://") {
            ("https://", &trimmed[8..])
        } else if lower.starts_with("http://") {
            ("http://", &trimmed[7..])
        } else if trimmed.contains("://") {
            return Err("Die öffentliche URL muss mit http:// oder https:// beginnen.".into());
        } else {
            ("https://", trimmed)
        };

        let clean_rest = rest.trim_end_matches('/');
        let authority = clean_rest.split('/').next().unwrap_or("");
        if authority.is_empty() || authority.starts_with(':') || authority.starts_with('.') {
            return Err(
                "Ungültige öffentliche Domain / Basis-URL (z. B. https://ssh.example.net).".into(),
            );
        }
        Ok(format!("{scheme}{clean_rest}"))
    }

    pub fn update_auth_policy(
        &self,
        patch: &AdminAuthSettingsPatchRequest,
        encrypted_secret: Option<(Vec<u8>, Vec<u8>)>,
    ) -> Result<AuthPolicySettings, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let mut s = Self::read_auth_policy_locked(&conn);
        let mut sso_changed = false;

        if let Some(ref v) = patch.sso_provider_name {
            let clean = v.trim();
            s.sso_provider_name = if clean.is_empty() {
                "SSO".into()
            } else {
                clean.chars().take(64).collect()
            };
        }
        if let Some(ref v) = patch.sso_issuer_url {
            let next = v.trim().to_string();
            if next != s.sso_issuer_url {
                sso_changed = true;
            }
            s.sso_issuer_url = next;
        }
        if let Some(ref v) = patch.sso_auth_url {
            let next = v.trim().to_string();
            if next != s.sso_auth_url {
                sso_changed = true;
            }
            s.sso_auth_url = next;
        }
        if let Some(ref v) = patch.sso_token_url {
            let next = v.trim().to_string();
            if next != s.sso_token_url {
                sso_changed = true;
            }
            s.sso_token_url = next;
        }
        if let Some(ref v) = patch.sso_userinfo_url {
            let next = v.trim().to_string();
            if next != s.sso_userinfo_url {
                sso_changed = true;
            }
            s.sso_userinfo_url = next;
        }
        if let Some(ref v) = patch.sso_client_id {
            let next = v.trim().to_string();
            if next != s.sso_client_id {
                sso_changed = true;
            }
            s.sso_client_id = next;
        }
        if patch.clear_sso_client_secret.unwrap_or(false) {
            if s.sso_client_secret_enc.is_some() {
                sso_changed = true;
            }
            s.sso_client_secret_enc = None;
        } else if let Some(enc_pair) = encrypted_secret {
            s.sso_client_secret_enc = Some(enc_pair);
            sso_changed = true;
        }
        if let Some(ref v) = patch.sso_scopes {
            let next = if v.trim().is_empty() {
                "openid profile email".to_string()
            } else {
                v.trim().to_string()
            };
            if next != s.sso_scopes {
                sso_changed = true;
            }
            s.sso_scopes = next;
        }
        if let Some(v) = patch.sso_auto_create_users {
            s.sso_auto_create_users = v;
        }
        if let Some(v) = patch.sso_enabled {
            s.sso_enabled = v;
        }

        if sso_changed {
            s.sso_tested_at = None;
            s.local_login_disabled = false;
        }

        if !s.sso_enabled || !s.is_sso_configured() || s.sso_tested_at.is_none() {
            if patch.local_login_disabled == Some(true) {
                return Err(
                    "Die lokale Anmeldung kann erst abgeschaltet werden, wenn SSO aktiviert, vollständig konfiguriert und erfolgreich getestet wurde.".into(),
                );
            }
            s.local_login_disabled = false;
        } else if let Some(v) = patch.local_login_disabled {
            s.local_login_disabled = v;
        }

        if let Some(v) = patch.two_factor_enabled {
            s.two_factor_enabled = v;
            if !v {
                s.two_factor_enforced = false;
            }
        }
        if let Some(v) = patch.two_factor_enforced {
            if v && !s.two_factor_enabled {
                return Err("2FA muss zuerst eingeschaltet werden, bevor sie erzwungen werden kann.".into());
            }
            s.two_factor_enforced = v;
        }

        if let Some(v) = patch.passkey_enabled {
            s.passkey_enabled = v;
            if !v {
                s.passkey_enforced = false;
            }
        }
        if let Some(v) = patch.passkey_enforced {
            if v && !s.passkey_enabled {
                return Err("Passkeys müssen zuerst eingeschaltet werden, bevor sie erzwungen werden können.".into());
            }
            s.passkey_enforced = v;
        }
        if let Some(v) = patch.allow_insecure_host_key {
            s.allow_insecure_host_key = v;
        }
        if let Some(ref v) = patch.public_url {
            s.public_url = Self::normalize_public_url(v)?;
        }

        Self::set_setting_locked(&conn, "sso_enabled", if s.sso_enabled { "1" } else { "0" })?;
        Self::set_setting_locked(&conn, "sso_provider_name", &s.sso_provider_name)?;
        Self::set_setting_locked(&conn, "sso_issuer_url", &s.sso_issuer_url)?;
        Self::set_setting_locked(&conn, "sso_auth_url", &s.sso_auth_url)?;
        Self::set_setting_locked(&conn, "sso_token_url", &s.sso_token_url)?;
        Self::set_setting_locked(&conn, "sso_userinfo_url", &s.sso_userinfo_url)?;
        Self::set_setting_locked(&conn, "sso_client_id", &s.sso_client_id)?;
        if let Some((ref enc, ref nonce)) = s.sso_client_secret_enc {
            Self::set_setting_locked(&conn, "sso_client_secret_enc", &STANDARD.encode(enc))?;
            Self::set_setting_locked(&conn, "sso_client_secret_nonce", &STANDARD.encode(nonce))?;
        } else {
            Self::set_setting_locked(&conn, "sso_client_secret_enc", "")?;
            Self::set_setting_locked(&conn, "sso_client_secret_nonce", "")?;
        }
        Self::set_setting_locked(&conn, "sso_scopes", &s.sso_scopes)?;
        Self::set_setting_locked(
            &conn,
            "sso_auto_create_users",
            if s.sso_auto_create_users { "1" } else { "0" },
        )?;
        Self::set_setting_locked(
            &conn,
            "sso_tested_at",
            s.sso_tested_at.as_deref().unwrap_or(""),
        )?;
        Self::set_setting_locked(
            &conn,
            "local_login_disabled",
            if s.local_login_disabled { "1" } else { "0" },
        )?;
        Self::set_setting_locked(
            &conn,
            "two_factor_enabled",
            if s.two_factor_enabled { "1" } else { "0" },
        )?;
        Self::set_setting_locked(
            &conn,
            "two_factor_enforced",
            if s.two_factor_enforced { "1" } else { "0" },
        )?;
        Self::set_setting_locked(
            &conn,
            "passkey_enabled",
            if s.passkey_enabled { "1" } else { "0" },
        )?;
        Self::set_setting_locked(
            &conn,
            "passkey_enforced",
            if s.passkey_enforced { "1" } else { "0" },
        )?;
        Self::set_setting_locked(
            &conn,
            "allow_insecure_host_key",
            if s.allow_insecure_host_key { "1" } else { "0" },
        )?;
        Self::set_setting_locked(&conn, "public_url", &s.public_url)?;

        Ok(s)
    }

    pub fn mark_sso_tested(&self) -> Result<AuthPolicySettings, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let now = Utc::now().to_rfc3339();
        Self::set_setting_locked(&conn, "sso_tested_at", &now)?;
        Ok(Self::read_auth_policy_locked(&conn))
    }

    pub fn find_or_create_sso_user(
        &self,
        sub: &str,
        preferred_username: &str,
        display_name: &str,
        email: &str,
        dummy_password_hash: &str,
    ) -> Result<(UserPublic, bool), String> {
        let user_id = {
            let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
            let policy = Self::read_auth_policy_locked(&conn);
            let issuer_prefix = if !policy.sso_issuer_url.is_empty() {
                &policy.sso_issuer_url
            } else {
                &policy.sso_auth_url
            };
            let sso_key = format!("{issuer_prefix}::{sub}");

            let mut existing_id: Option<(String, bool)> = conn
                .query_row(
                    "SELECT id, active FROM users WHERE sso_subject = ?1",
                    params![&sso_key],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? == 1)),
                )
                .optional()
                .map_err(|e| e.to_string())?;

            if existing_id.is_none() && !email.is_empty() {
                existing_id = conn
                    .query_row(
                        "SELECT id, active FROM users WHERE LOWER(email) = LOWER(?1)",
                        params![email],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? == 1)),
                    )
                    .optional()
                    .map_err(|e| e.to_string())?;
            }

            if existing_id.is_none() {
                existing_id = conn
                    .query_row(
                        "SELECT id, active FROM users WHERE username = ?1",
                        params![preferred_username],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? == 1)),
                    )
                    .optional()
                    .map_err(|e| e.to_string())?;
            }

            if let Some((uid, active)) = existing_id {
                if !active {
                    return Err("Dieses Benutzerkonto ist gesperrt.".into());
                }
                let _ = conn.execute(
                    "UPDATE users SET sso_subject = COALESCE(sso_subject, ?1), email = CASE WHEN email = '' THEN ?2 ELSE email END WHERE id = ?3",
                    params![&sso_key, email, &uid],
                );
                (uid, false)
            } else {
                if !policy.sso_auto_create_users {
                    return Err(
                        "Für diesen SSO-Zugang existiert kein Benutzerkonto und die automatische Benutzeranlage ist deaktiviert.".into(),
                    );
                }
                let mut candidate = preferred_username.to_string();
                let mut suffix = 1u32;
                loop {
                    let exists: i64 = conn
                        .query_row(
                            "SELECT COUNT(*) FROM users WHERE username = ?1",
                            params![&candidate],
                            |r| r.get(0),
                        )
                        .unwrap_or(0);
                    if exists == 0 {
                        break;
                    }
                    let tag = format!("_{suffix}");
                    suffix += 1;
                    let prefix_len = 32usize.saturating_sub(tag.len());
                    let base: String = preferred_username.chars().take(prefix_len).collect();
                    candidate = format!("{base}{tag}");
                }
                let id = Uuid::new_v4().to_string();
                let now = Utc::now().to_rfc3339();
                conn.execute(
                    "INSERT INTO users (id, username, display_name, role, group_id, auth_provider, sso_subject, email, default_ssh_user, active, ping_enabled, password_hash, totp_enabled, created_at)
                     VALUES (?1, ?2, ?3, 'user', 'user', 'sso', ?4, ?5, 'root', 1, 1, ?6, 0, ?7)",
                    params![&id, &candidate, display_name, &sso_key, email, dummy_password_hash, &now],
                )
                .map_err(|e| format!("SSO-Benutzer konnte nicht angelegt werden: {e}"))?;
                (id, true)
            }
        };

        let user = self
            .get_user_by_id(&user_id.0)?
            .ok_or_else(|| "SSO-Benutzer konnte nicht geladen werden.".to_string())?;
        Ok((user, user_id.1))
    }

    // ── TOTP & WebAuthn ─────────────────────────────────────────────────────

    pub fn set_user_totp(
        &self,
        user_id: &str,
        secret_enc: &[u8],
        secret_nonce: &[u8],
        recovery_hashes: &[String],
    ) -> Result<Option<UserPublic>, String> {
        {
            let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
            let json_hashes = serde_json::to_string(recovery_hashes).unwrap_or_else(|_| "[]".into());
            conn.execute(
                "UPDATE users SET totp_enabled = 1, totp_secret_enc = ?1, totp_secret_nonce = ?2, totp_recovery_hashes_json = ?3 WHERE id = ?4",
                params![secret_enc, secret_nonce, json_hashes, user_id],
            )
            .map_err(|e| e.to_string())?;
        }
        self.get_user_by_id(user_id)
    }

    pub fn get_user_totp_secret_enc(&self, user_id: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.query_row(
            "SELECT totp_secret_enc, totp_secret_nonce FROM users WHERE id = ?1 AND totp_enabled = 1",
            params![user_id],
            |r| {
                let enc: Option<Vec<u8>> = r.get(0)?;
                let nonce: Option<Vec<u8>> = r.get(1)?;
                Ok(enc.zip(nonce))
            },
        )
        .optional()
        .map_err(|e| e.to_string())
        .map(|opt| opt.flatten())
    }

    pub fn get_user_recovery_count(&self, user_id: &str) -> usize {
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };
        let raw: String = conn
            .query_row(
                "SELECT totp_recovery_hashes_json FROM users WHERE id = ?1",
                params![user_id],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| "[]".into());
        serde_json::from_str::<Vec<String>>(&raw)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    pub fn consume_recovery_code(&self, user_id: &str, code_hash: &str) -> Result<bool, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let raw: Option<String> = conn
            .query_row(
                "SELECT totp_recovery_hashes_json FROM users WHERE id = ?1 AND totp_enabled = 1",
                params![user_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let Some(json_str) = raw else {
            return Ok(false);
        };
        let mut hashes: Vec<String> = serde_json::from_str(&json_str).unwrap_or_default();
        let Some(pos) = hashes.iter().position(|h| h == code_hash) else {
            return Ok(false);
        };
        hashes.remove(pos);
        let updated = serde_json::to_string(&hashes).unwrap_or_else(|_| "[]".into());
        conn.execute(
            "UPDATE users SET totp_recovery_hashes_json = ?1 WHERE id = ?2",
            params![updated, user_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(true)
    }

    pub fn disable_user_totp(&self, user_id: &str) -> Result<Option<UserPublic>, String> {
        {
            let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
            conn.execute(
                "UPDATE users SET totp_enabled = 0, totp_secret_enc = NULL, totp_secret_nonce = NULL, totp_recovery_hashes_json = '[]' WHERE id = ?1",
                params![user_id],
            )
            .map_err(|e| e.to_string())?;
        }
        self.get_user_by_id(user_id)
    }

    pub fn list_webauthn_credentials(
        &self,
        user_id: &str,
        kind: Option<&str>,
    ) -> Result<Vec<WebAuthnCredentialStored>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let sql = if kind.is_some() {
            "SELECT id, user_id, kind, name, credential_id, public_key, counter, transports_json, created_at, last_used_at
             FROM user_webauthn_credentials WHERE user_id = ?1 AND kind = ?2 ORDER BY created_at DESC"
        } else {
            "SELECT id, user_id, kind, name, credential_id, public_key, counter, transports_json, created_at, last_used_at
             FROM user_webauthn_credentials WHERE user_id = ?1 ORDER BY created_at DESC"
        };
        let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
        let mapper = |r: &rusqlite::Row<'_>| -> rusqlite::Result<WebAuthnCredentialStored> {
            let transports_raw: String = r.get(7)?;
            Ok(WebAuthnCredentialStored {
                id: r.get(0)?,
                user_id: r.get(1)?,
                kind: r.get(2)?,
                name: r.get(3)?,
                credential_id: r.get(4)?,
                public_key: r.get(5)?,
                counter: r.get::<_, i64>(6)?.max(0) as u32,
                transports: serde_json::from_str(&transports_raw).unwrap_or_default(),
                created_at: r.get(8)?,
                last_used_at: r.get(9)?,
            })
        };
        let rows = if let Some(k) = kind {
            stmt.query_map(params![user_id, k], mapper)
        } else {
            stmt.query_map(params![user_id], mapper)
        }
        .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    pub fn find_webauthn_by_cred_id(
        &self,
        cred_id: &str,
    ) -> Result<Option<WebAuthnCredentialStored>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.query_row(
            "SELECT id, user_id, kind, name, credential_id, public_key, counter, transports_json, created_at, last_used_at
             FROM user_webauthn_credentials WHERE credential_id = ?1",
            params![cred_id],
            |r| {
                let transports_raw: String = r.get(7)?;
                Ok(WebAuthnCredentialStored {
                    id: r.get(0)?,
                    user_id: r.get(1)?,
                    kind: r.get(2)?,
                    name: r.get(3)?,
                    credential_id: r.get(4)?,
                    public_key: r.get(5)?,
                    counter: r.get::<_, i64>(6)?.max(0) as u32,
                    transports: serde_json::from_str(&transports_raw).unwrap_or_default(),
                    created_at: r.get(8)?,
                    last_used_at: r.get(9)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_webauthn_credential(
        &self,
        user_id: &str,
        kind: &str,
        name: &str,
        credential_id: &str,
        public_key: &str,
        counter: u32,
        transports: &[String],
    ) -> Result<WebAuthnCredentialPublic, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let transports_json = serde_json::to_string(transports).unwrap_or_else(|_| "[]".into());
        conn.execute(
            "INSERT INTO user_webauthn_credentials (id, user_id, kind, name, credential_id, public_key, counter, transports_json, created_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
            params![
                &id,
                user_id,
                kind,
                name,
                credential_id,
                public_key,
                counter as i64,
                &transports_json,
                &now
            ],
        )
        .map_err(|e| format!("Schlüssel konnte nicht gespeichert werden: {e}"))?;
        Ok(WebAuthnCredentialPublic {
            id,
            kind: kind.to_string(),
            name: name.to_string(),
            transports: transports.to_vec(),
            created_at: now,
            last_used_at: None,
        })
    }

    pub fn update_webauthn_usage(&self, id: &str, new_counter: u32) {
        if let Ok(conn) = self.conn.lock() {
            let now = Utc::now().to_rfc3339();
            let _ = conn.execute(
                "UPDATE user_webauthn_credentials SET counter = ?1, last_used_at = ?2 WHERE id = ?3",
                params![new_counter as i64, now, id],
            );
        }
    }

    pub fn delete_webauthn_credential(&self, id: &str, user_id: &str) -> Result<bool, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let changed = conn
            .execute(
                "DELETE FROM user_webauthn_credentials WHERE id = ?1 AND user_id = ?2",
                params![id, user_id],
            )
            .map_err(|e| e.to_string())?;
        Ok(changed > 0)
    }

    pub fn reset_user_second_factors(&self, user_id: &str) -> Result<Option<UserPublic>, String> {
        {
            let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
            conn.execute(
                "UPDATE users SET totp_enabled = 0, totp_secret_enc = NULL, totp_secret_nonce = NULL, totp_recovery_hashes_json = '[]' WHERE id = ?1",
                params![user_id],
            )
            .map_err(|e| e.to_string())?;
            conn.execute(
                "DELETE FROM user_webauthn_credentials WHERE user_id = ?1",
                params![user_id],
            )
            .map_err(|e| e.to_string())?;
        }
        self.get_user_by_id(user_id)
    }

    // ------------------------------------------------------------------
    // SSH Certificate Authorities (ca & ca.pub)
    // ------------------------------------------------------------------
    pub fn list_certificate_authorities(&self) -> Result<Vec<CertificateAuthorityPublic>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, name, description, private_key_file, public_key_file, public_key,
                        key_type, fingerprint, private_key_format, private_key_encrypted,
                        passphrase_enc IS NOT NULL, created_by, created_by_username,
                        created_at, updated_at
                 FROM certificate_authorities
                 ORDER BY updated_at DESC, created_at DESC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(CertificateAuthorityPublic {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    private_key_file_name: row.get(3)?,
                    public_key_file_name: row.get(4)?,
                    public_key: row.get(5)?,
                    key_type: row.get(6)?,
                    fingerprint: row.get(7)?,
                    private_key_format: row.get(8)?,
                    private_key_encrypted: row.get::<_, i64>(9)? != 0,
                    has_stored_passphrase: row.get::<_, i64>(10)? != 0,
                    created_by: row.get(11)?,
                    created_by_username: row.get(12)?,
                    created_at: row.get(13)?,
                    updated_at: row.get(14)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn find_certificate_authority_name(&self, name: &str) -> Result<Option<String>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.query_row(
            "SELECT name FROM certificate_authorities WHERE lower(trim(name)) = lower(trim(?1)) LIMIT 1",
            params![name],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn get_certificate_authority_for_edit(
        &self,
        id: &str,
    ) -> Result<Option<StoredCertificateAuthorityForEdit>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.query_row(
            "SELECT id, name, description, private_key_file, public_key_file,
                    private_key_enc, private_key_nonce, passphrase_enc, passphrase_nonce,
                    public_key, key_type, fingerprint, private_key_format
             FROM certificate_authorities WHERE id = ?1",
            params![id],
            |row| {
                Ok(StoredCertificateAuthorityForEdit {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    private_key_file_name: row.get(3)?,
                    public_key_file_name: row.get(4)?,
                    private_key_enc: row.get(5)?,
                    private_key_nonce: row.get(6)?,
                    passphrase_enc: row.get(7)?,
                    passphrase_nonce: row.get(8)?,
                    public_key: row.get(9)?,
                    key_type: row.get(10)?,
                    fingerprint: row.get(11)?,
                    private_key_format: row.get(12)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn save_certificate_authority(
        &self,
        name: &str,
        description: &str,
        private_key_file: &str,
        public_key_file: &str,
        private_key_enc: &[u8],
        private_key_nonce: &[u8],
        passphrase_enc: Option<&[u8]>,
        passphrase_nonce: Option<&[u8]>,
        public_key: &str,
        key_type: &str,
        fingerprint: &str,
        private_key_format: &str,
        created_by: &str,
        created_by_username: &str,
    ) -> Result<(CertificateAuthorityPublic, bool), String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let now = Utc::now().to_rfc3339();
        let existing: Option<(String, String, String, String)> = conn
            .query_row(
                "SELECT id, created_by, created_by_username, created_at
                 FROM certificate_authorities
                 WHERE lower(trim(name)) = lower(trim(?1)) LIMIT 1",
                params![name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;

        let has_stored_passphrase = passphrase_enc.is_some();
        if let Some((existing_id, orig_created_by, orig_created_by_username, orig_created_at)) =
            existing
        {
            conn.execute(
                "UPDATE certificate_authorities
                 SET name = ?1, description = ?2, private_key_file = ?3, public_key_file = ?4,
                     private_key_enc = ?5, private_key_nonce = ?6,
                     passphrase_enc = ?7, passphrase_nonce = ?8,
                     public_key = ?9, key_type = ?10, fingerprint = ?11,
                     private_key_format = ?12, private_key_encrypted = 1, updated_at = ?13
                 WHERE id = ?14",
                params![
                    name,
                    description,
                    private_key_file,
                    public_key_file,
                    private_key_enc,
                    private_key_nonce,
                    passphrase_enc,
                    passphrase_nonce,
                    public_key.trim(),
                    key_type,
                    fingerprint,
                    private_key_format,
                    now,
                    existing_id
                ],
            )
            .map_err(|e| format!("CA konnte nicht aktualisiert werden: {e}"))?;

            return Ok((
                CertificateAuthorityPublic {
                    id: existing_id,
                    name: name.to_string(),
                    description: description.to_string(),
                    private_key_file_name: private_key_file.to_string(),
                    public_key_file_name: public_key_file.to_string(),
                    public_key: public_key.trim().to_string(),
                    key_type: key_type.to_string(),
                    fingerprint: fingerprint.to_string(),
                    private_key_format: private_key_format.to_string(),
                    private_key_encrypted: true,
                    has_stored_passphrase,
                    created_by: orig_created_by,
                    created_by_username: orig_created_by_username,
                    created_at: orig_created_at,
                    updated_at: now,
                },
                true,
            ));
        }

        let id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO certificate_authorities
             (id, name, description, private_key_file, public_key_file,
              private_key_enc, private_key_nonce, passphrase_enc, passphrase_nonce,
              public_key, key_type, fingerprint, private_key_format, private_key_encrypted,
              created_by, created_by_username, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 1, ?14, ?15, ?16, ?17)",
            params![
                id,
                name,
                description,
                private_key_file,
                public_key_file,
                private_key_enc,
                private_key_nonce,
                passphrase_enc,
                passphrase_nonce,
                public_key.trim(),
                key_type,
                fingerprint,
                private_key_format,
                created_by,
                created_by_username,
                now,
                now
            ],
        )
        .map_err(|e| format!("CA konnte nicht gespeichert werden: {e}"))?;

        Ok((
            CertificateAuthorityPublic {
                id,
                name: name.to_string(),
                description: description.to_string(),
                private_key_file_name: private_key_file.to_string(),
                public_key_file_name: public_key_file.to_string(),
                public_key: public_key.trim().to_string(),
                key_type: key_type.to_string(),
                fingerprint: fingerprint.to_string(),
                private_key_format: private_key_format.to_string(),
                private_key_encrypted: true,
                has_stored_passphrase,
                created_by: created_by.to_string(),
                created_by_username: created_by_username.to_string(),
                created_at: now.clone(),
                updated_at: now,
            },
            false,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_certificate_authority(
        &self,
        id: &str,
        name: &str,
        description: &str,
        private_key_file: &str,
        public_key_file: &str,
        private_key_enc: &[u8],
        private_key_nonce: &[u8],
        passphrase_enc: Option<&[u8]>,
        passphrase_nonce: Option<&[u8]>,
        public_key: &str,
        key_type: &str,
        fingerprint: &str,
        private_key_format: &str,
    ) -> Result<CertificateAuthorityPublic, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let conflict: Option<String> = conn
            .query_row(
                "SELECT name FROM certificate_authorities
                 WHERE id != ?1 AND lower(trim(name)) = lower(trim(?2)) LIMIT 1",
                params![id, name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if let Some(existing_name) = conflict {
            return Err(format!(
                "Eine CA mit dem Namen „{existing_name}“ existiert bereits."
            ));
        }

        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE certificate_authorities
             SET name = ?1, description = ?2, private_key_file = ?3, public_key_file = ?4,
                 private_key_enc = ?5, private_key_nonce = ?6,
                 passphrase_enc = ?7, passphrase_nonce = ?8,
                 public_key = ?9, key_type = ?10, fingerprint = ?11,
                 private_key_format = ?12, private_key_encrypted = 1, updated_at = ?13
             WHERE id = ?14",
            params![
                name,
                description,
                private_key_file,
                public_key_file,
                private_key_enc,
                private_key_nonce,
                passphrase_enc,
                passphrase_nonce,
                public_key.trim(),
                key_type,
                fingerprint,
                private_key_format,
                now,
                id
            ],
        )
        .map_err(|e| format!("CA konnte nicht aktualisiert werden: {e}"))?;

        conn.query_row(
            "SELECT id, name, description, private_key_file, public_key_file, public_key,
                    key_type, fingerprint, private_key_format, private_key_encrypted,
                    passphrase_enc IS NOT NULL, created_by, created_by_username,
                    created_at, updated_at
             FROM certificate_authorities WHERE id = ?1",
            params![id],
            |row| {
                Ok(CertificateAuthorityPublic {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    private_key_file_name: row.get(3)?,
                    public_key_file_name: row.get(4)?,
                    public_key: row.get(5)?,
                    key_type: row.get(6)?,
                    fingerprint: row.get(7)?,
                    private_key_format: row.get(8)?,
                    private_key_encrypted: row.get::<_, i64>(9)? != 0,
                    has_stored_passphrase: row.get::<_, i64>(10)? != 0,
                    created_by: row.get(11)?,
                    created_by_username: row.get(12)?,
                    created_at: row.get(13)?,
                    updated_at: row.get(14)?,
                })
            },
        )
        .map_err(|e| e.to_string())
    }

    pub fn delete_certificate_authority(&self, id: &str) -> Result<bool, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let changed = conn
            .execute(
                "DELETE FROM certificate_authorities WHERE id = ?1",
                params![id],
            )
            .map_err(|e| e.to_string())?;
        if changed > 0 {
            let mut stmt = conn
                .prepare("SELECT id, permissions_json FROM user_groups WHERE is_immutable = 0")
                .map_err(|e| e.to_string())?;
            let rows: Vec<(String, String)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|e| e.to_string())?
                .filter_map(Result::ok)
                .collect();
            for (gid, pjson) in rows {
                if let Ok(mut perms) = serde_json::from_str::<GroupPermissions>(&pjson) {
                    let before = perms.ca_signing_assignments.len();
                    perms.ca_signing_assignments.retain(|a| a.ca_id != id);
                    if perms.ca_signing_assignments.len() != before {
                        if let Ok(next_json) = serde_json::to_string(&perms) {
                            let _ = conn.execute(
                                "UPDATE user_groups SET permissions_json = ?1 WHERE id = ?2",
                                params![next_json, gid],
                            );
                        }
                    }
                }
            }
        }
        Ok(changed > 0)
    }

    pub fn get_database_status(&self) -> Result<DatabaseStatusResponse, String> {
        let cfg = self
            .db_config
            .lock()
            .map_err(|_| "DB-Config Lock Fehler".to_string())?
            .clone();
        let sqlite_path = self.data_dir.join("ssh-console.sqlite");
        let (sqlite_exists, sqlite_size_bytes) = match fs::metadata(&sqlite_path) {
            Ok(m) => (true, m.len()),
            Err(_) => (false, 0),
        };

        let mut connected = true;
        let mut version = self.mariadb_version.lock().ok().and_then(|g| g.clone());
        if cfg.engine == "mariadb" {
            let pool_opt = self
                .conn
                .mariadb_pool
                .read()
                .ok()
                .and_then(|g| g.clone());
            if let Some(pool) = pool_opt {
                match mariadb::query_mariadb_version(&pool) {
                    Ok(v) => {
                        connected = true;
                        version = Some(v.clone());
                        if let Ok(mut g) = self.mariadb_version.lock() {
                            *g = Some(v);
                        }
                    }
                    Err(e) => {
                        connected = false;
                        if let Ok(mut g) = self.conn.last_sync_error.lock() {
                            *g = Some(e);
                        }
                    }
                }
            } else {
                connected = false;
            }
        }

        let tables = {
            let raw = self
                .conn
                .lock_raw()
                .map_err(|_| "DB Lock Fehler".to_string())?;
            mariadb::get_sqlite_table_counts(&raw)?
        };
        let total_rows: u64 = tables.iter().map(|t| t.rows).sum();

        let last_synced_at = self.conn.last_synced_at.lock().ok().and_then(|g| g.clone());
        let last_sync_error = self
            .conn
            .last_sync_error
            .lock()
            .ok()
            .and_then(|g| g.clone());

        let m_pub = match &cfg.mariadb {
            Some(m) => MariaDbConfigPublic {
                configured: !m.host.is_empty() && !m.database.is_empty() && !m.username.is_empty(),
                host: m.host.clone(),
                port: m.port,
                database: m.database.clone(),
                username: m.username.clone(),
                has_password: m.password_enc_b64.is_some() && m.password_nonce_b64.is_some(),
                ssl: m.ssl,
                ssl_reject_unauthorized: m.ssl_reject_unauthorized,
            },
            None => MariaDbConfigPublic {
                configured: false,
                host: String::new(),
                port: 3306,
                database: "ssh_console".to_string(),
                username: String::new(),
                has_password: false,
                ssl: false,
                ssl_reject_unauthorized: true,
            },
        };

        Ok(DatabaseStatusResponse {
            engine: cfg.engine.clone(),
            runtime: "rust".to_string(),
            connected,
            mariadb_version: if cfg.engine == "mariadb" { version } else { None },
            sqlite_path: sqlite_path.to_string_lossy().to_string(),
            sqlite_exists,
            sqlite_size_bytes,
            mariadb: m_pub,
            tables,
            total_rows,
            last_migrated_at: cfg.last_migrated_at,
            last_migration_direction: cfg.last_migration_direction,
            last_synced_at,
            last_sync_error,
        })
    }

    pub fn save_mariadb_config(
        &self,
        vault: &Vault,
        input: &MariaDbConfigInput,
    ) -> Result<(), String> {
        let mut cfg = self
            .db_config
            .lock()
            .map_err(|_| "DB-Config Lock Fehler".to_string())?;
        let resolved = mariadb::resolve_mariadb_config(cfg.mariadb.as_ref(), Some(input), vault)?;

        let explicit_pass = input.password.as_deref().filter(|p| !p.is_empty());
        let (pass_enc_b64, pass_nonce_b64) = if let Some(p) = explicit_pass {
            let (e, n) = mariadb::encrypt_password(vault, p)?;
            (Some(e), Some(n))
        } else if let Some(existing) = &cfg.mariadb {
            (
                existing.password_enc_b64.clone(),
                existing.password_nonce_b64.clone(),
            )
        } else {
            let (e, n) = mariadb::encrypt_password(vault, resolved.password.as_str())?;
            (Some(e), Some(n))
        };

        cfg.mariadb = Some(StoredMariaDbConfig {
            host: resolved.host,
            port: resolved.port,
            database: resolved.database,
            username: resolved.username,
            password_enc_b64: pass_enc_b64,
            password_nonce_b64: pass_nonce_b64,
            ssl: resolved.ssl,
            ssl_reject_unauthorized: resolved.ssl_reject_unauthorized,
        });
        mariadb::save_config_file(&self.data_dir, &cfg)?;
        Ok(())
    }

    pub fn clear_mariadb_config(&self) -> Result<(), String> {
        let mut cfg = self
            .db_config
            .lock()
            .map_err(|_| "DB-Config Lock Fehler".to_string())?;
        if cfg.engine == "mariadb" {
            return Err("Die MariaDB-Konfiguration kann nicht gelöscht werden, solange MariaDB die aktive Datenbank ist. Bitte migrieren Sie zuerst zurück zu SQLite.".into());
        }
        cfg.mariadb = None;
        mariadb::save_config_file(&self.data_dir, &cfg)?;
        Ok(())
    }

    pub fn test_mariadb(
        &self,
        vault: &Vault,
        input: &MariaDbConfigInput,
    ) -> Result<MariaDbTestResponse, String> {
        let existing = self
            .db_config
            .lock()
            .map_err(|_| "DB-Config Lock Fehler".to_string())?
            .mariadb
            .clone();
        let resolved = mariadb::resolve_mariadb_config(existing.as_ref(), Some(input), vault)?;
        mariadb::test_connection(&resolved)
    }

    pub fn migrate_database(
        &self,
        vault: &Vault,
        req: &MigrateDatabaseRequest,
    ) -> Result<MigrateDatabaseResult, MigrationError> {
        let started = Instant::now();
        let mut raw_conn = self
            .conn
            .lock_raw()
            .map_err(|_| MigrationError::Internal("DB Lock Fehler".into()))?;
        let mut cfg = self
            .db_config
            .lock()
            .map_err(|_| MigrationError::Internal("DB-Config Lock Fehler".into()))?;

        match req.direction.as_str() {
            "sqlite-to-mariadb" => {
                if cfg.engine == "mariadb" {
                    return Err(MigrationError::BadRequest(
                        "MariaDB ist bereits als aktive Datenbank eingerichtet.".into(),
                    ));
                }
                let resolved = mariadb::resolve_mariadb_config(
                    cfg.mariadb.as_ref(),
                    req.mariadb.as_ref(),
                    vault,
                )
                .map_err(MigrationError::BadRequest)?;

                let test = mariadb::test_connection(&resolved).map_err(MigrationError::BadRequest)?;
                if test.existing_row_count > 0 && !req.confirm_overwrite {
                    return Err(MigrationError::Conflict {
                        message: format!(
                            "Die Ziel-MariaDB enthält bereits {} Datensätze in bestehenden SSH-Console-Tabellen. Bitte bestätigen Sie das Überschreiben.",
                            test.existing_row_count
                        ),
                        existing_row_count: test.existing_row_count,
                        existing_tables: test.existing_tables,
                    });
                }

                let pool = mariadb::build_pool(&resolved).map_err(MigrationError::BadRequest)?;
                let migrated_tables = mariadb::migrate_sqlite_to_mariadb(&raw_conn, &pool)
                    .map_err(MigrationError::Internal)?;
                let total_rows: u64 = migrated_tables.iter().map(|t| t.rows).sum();

                let mut mem_conn = Connection::open_in_memory()
                    .map_err(|e| MigrationError::Internal(format!("SQLite-In-Memory-Fehler: {e}")))?;
                Self::init_sqlite_schema(&mem_conn).map_err(MigrationError::Internal)?;
                mariadb::load_mariadb_into_sqlite(&pool, &mut mem_conn)
                    .map_err(MigrationError::Internal)?;
                Self::init_sqlite_schema(&mem_conn).map_err(MigrationError::Internal)?;
                attach_update_hook(&mut mem_conn, Arc::clone(&self.conn.dirty_tables));

                let explicit_pass = req
                    .mariadb
                    .as_ref()
                    .and_then(|m| m.password.as_deref())
                    .filter(|p| !p.is_empty());
                let (pass_enc_b64, pass_nonce_b64) = if let Some(p) = explicit_pass {
                    let (e, n) =
                        mariadb::encrypt_password(vault, p).map_err(MigrationError::Internal)?;
                    (Some(e), Some(n))
                } else if let Some(existing) = &cfg.mariadb {
                    (
                        existing.password_enc_b64.clone(),
                        existing.password_nonce_b64.clone(),
                    )
                } else {
                    let (e, n) = mariadb::encrypt_password(vault, resolved.password.as_str())
                        .map_err(MigrationError::Internal)?;
                    (Some(e), Some(n))
                };

                let now_iso = Utc::now().to_rfc3339();
                cfg.engine = "mariadb".to_string();
                cfg.mariadb = Some(StoredMariaDbConfig {
                    host: resolved.host,
                    port: resolved.port,
                    database: resolved.database,
                    username: resolved.username,
                    password_enc_b64: pass_enc_b64,
                    password_nonce_b64: pass_nonce_b64,
                    ssl: resolved.ssl,
                    ssl_reject_unauthorized: resolved.ssl_reject_unauthorized,
                });
                cfg.last_migrated_at = Some(now_iso.clone());
                cfg.last_migration_direction = Some("sqlite-to-mariadb".to_string());
                mariadb::save_config_file(&self.data_dir, &cfg)
                    .map_err(MigrationError::Internal)?;

                *raw_conn = mem_conn;
                if let Ok(mut dirty) = self.conn.dirty_tables.lock() {
                    dirty.clear();
                }
                if let Ok(mut g) = self.conn.mariadb_pool.write() {
                    *g = Some(pool);
                }
                if let Ok(mut v) = self.mariadb_version.lock() {
                    *v = Some(test.version.clone());
                }
                if let Ok(mut ts) = self.conn.last_synced_at.lock() {
                    *ts = Some(now_iso);
                }
                if let Ok(mut err) = self.conn.last_sync_error.lock() {
                    *err = None;
                }

                Ok(MigrateDatabaseResult {
                    direction: "sqlite-to-mariadb".to_string(),
                    engine: "mariadb".to_string(),
                    migrated_tables,
                    total_rows,
                    duration_ms: started.elapsed().as_millis().max(1) as u64,
                    backup_file_name: None,
                    mariadb_version: Some(test.version),
                })
            }
            "mariadb-to-sqlite" => {
                if cfg.engine != "mariadb" {
                    return Err(MigrationError::BadRequest(
                        "SQLite ist bereits als aktive Datenbank eingerichtet.".into(),
                    ));
                }

                let pool = {
                    let active_opt = self
                        .conn
                        .mariadb_pool
                        .read()
                        .ok()
                        .and_then(|g| g.clone());
                    if let Some(p) = active_opt {
                        p
                    } else {
                        let resolved =
                            mariadb::resolve_mariadb_config(cfg.mariadb.as_ref(), None, vault)
                                .map_err(MigrationError::BadRequest)?;
                        mariadb::build_pool(&resolved).map_err(MigrationError::BadRequest)?
                    }
                };

                let sqlite_path = self.data_dir.join("ssh-console.sqlite");
                let tmp_path = self.data_dir.join("ssh-console.sqlite.migrating");
                let _ = fs::remove_file(&tmp_path);
                let _ = fs::remove_file(self.data_dir.join("ssh-console.sqlite.migrating-wal"));
                let _ = fs::remove_file(self.data_dir.join("ssh-console.sqlite.migrating-shm"));

                let migrated_tables = {
                    let mut tmp_conn = Connection::open(&tmp_path).map_err(|e| {
                        MigrationError::Internal(format!("Temporäre SQLite-Datei konnte nicht erstellt werden: {e}"))
                    })?;
                    Self::init_sqlite_schema(&tmp_conn).map_err(MigrationError::Internal)?;
                    let counts = mariadb::load_mariadb_into_sqlite(&pool, &mut tmp_conn)
                        .map_err(MigrationError::Internal)?;
                    let _ = tmp_conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
                    counts
                };
                let _ = fs::remove_file(self.data_dir.join("ssh-console.sqlite.migrating-wal"));
                let _ = fs::remove_file(self.data_dir.join("ssh-console.sqlite.migrating-shm"));

                let mut backup_file_name: Option<String> = None;
                if sqlite_path.exists() {
                    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
                    let bak_name = format!("ssh-console.sqlite.bak-{stamp}");
                    let bak_path = self.data_dir.join(&bak_name);
                    fs::copy(&sqlite_path, &bak_path).map_err(|e| {
                        MigrationError::Internal(format!(
                            "Backup der bisherigen SQLite-Datenbank fehlgeschlagen: {e}"
                        ))
                    })?;
                    backup_file_name = Some(bak_name);
                }

                let _ = fs::remove_file(self.data_dir.join("ssh-console.sqlite-wal"));
                let _ = fs::remove_file(self.data_dir.join("ssh-console.sqlite-shm"));
                fs::rename(&tmp_path, &sqlite_path).map_err(|e| {
                    MigrationError::Internal(format!(
                        "Migrierte SQLite-Datei konnte nicht aktiviert werden: {e}"
                    ))
                })?;

                let mut reopened = Connection::open(&sqlite_path).map_err(|e| {
                    MigrationError::Internal(format!("Migrierte SQLite-Datei konnte nicht geöffnet werden: {e}"))
                })?;
                Self::init_sqlite_schema(&reopened).map_err(MigrationError::Internal)?;
                attach_update_hook(&mut reopened, Arc::clone(&self.conn.dirty_tables));

                let now_iso = Utc::now().to_rfc3339();
                cfg.engine = "sqlite".to_string();
                cfg.last_migrated_at = Some(now_iso);
                cfg.last_migration_direction = Some("mariadb-to-sqlite".to_string());
                mariadb::save_config_file(&self.data_dir, &cfg)
                    .map_err(MigrationError::Internal)?;

                *raw_conn = reopened;
                if let Ok(mut dirty) = self.conn.dirty_tables.lock() {
                    dirty.clear();
                }
                if let Ok(mut g) = self.conn.mariadb_pool.write() {
                    *g = None;
                }
                if let Ok(mut v) = self.mariadb_version.lock() {
                    *v = None;
                }
                if let Ok(mut err) = self.conn.last_sync_error.lock() {
                    *err = None;
                }

                let total_rows: u64 = migrated_tables.iter().map(|t| t.rows).sum();
                Ok(MigrateDatabaseResult {
                    direction: "mariadb-to-sqlite".to_string(),
                    engine: "sqlite".to_string(),
                    migrated_tables,
                    total_rows,
                    duration_ms: started.elapsed().as_millis().max(1) as u64,
                    backup_file_name,
                    mariadb_version: None,
                })
            }
            _ => Err(MigrationError::BadRequest(
                "Ungültige Migrationsrichtung. Erlaubt: sqlite-to-mariadb oder mariadb-to-sqlite."
                    .into(),
            )),
        }
    }
}
