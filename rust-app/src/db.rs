use crate::models::{
    AdminAuthSettingsPatchRequest, AuthPolicySettings, CertInspection, CommandStep, ExecutionLog,
    ServerCategory, SshCommand, StoredCertificateForEdit, UserApiKeyPublic, UserCertificatePublic,
    UserCertificateSecret, UserPublic, UserServer, WebAuthnCredentialPublic,
    WebAuthnCredentialStored,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use uuid::Uuid;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(db_path: &Path) -> Result<Self, String> {
        let conn = Connection::open(db_path).map_err(|e| format!("SQLite-Fehler: {e}"))?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
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
                shared_with_all INTEGER NOT NULL DEFAULT 0,
                shared_with_user_ids TEXT NOT NULL DEFAULT '[]',
                uploaded_at TEXT NOT NULL
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

        Ok(Self {
            conn: Mutex::new(conn),
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

    #[allow(clippy::too_many_arguments)]
    fn build_user_public(
        conn: &Connection,
        policy: &AuthPolicySettings,
        id: String,
        username: String,
        display_name: String,
        role: String,
        auth_provider: String,
        email: String,
        default_ssh_user: String,
        active: bool,
        ping_enabled: bool,
        totp_enabled: bool,
        created_at: String,
        last_login_at: Option<String>,
    ) -> UserPublic {
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
            role,
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

    pub fn create_user(
        &self,
        username: &str,
        display_name: &str,
        role: &str,
        default_ssh_user: &str,
        password_hash: &str,
    ) -> Result<UserPublic, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO users (id, username, display_name, role, default_ssh_user, active, ping_enabled, password_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, 1, ?6, ?7)",
            params![id, username, display_name, role, default_ssh_user, password_hash, now],
        )
        .map_err(|e| format!("Benutzer konnte nicht gespeichert werden: {e}"))?;

        let policy = Self::read_auth_policy_locked(&conn);
        Ok(Self::build_user_public(
            &conn,
            &policy,
            id,
            username.to_string(),
            display_name.to_string(),
            role.to_string(),
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
                "SELECT id, username, display_name, role, auth_provider, email, default_ssh_user, active, ping_enabled, totp_enabled, created_at, last_login_at
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
                        r.get::<_, i64>(7)? == 1,
                        r.get::<_, i64>(8)? == 1,
                        r.get::<_, i64>(9)? == 1,
                        r.get::<_, String>(10)?,
                        r.get::<_, Option<String>>(11)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;

        Ok(raw.map(|t| {
            Self::build_user_public(
                &conn, &policy, t.0, t.1, t.2, t.3, t.4, t.5, t.6, t.7, t.8, t.9, t.10, t.11,
            )
        }))
    }

    pub fn update_user(
        &self,
        id: &str,
        display_name: Option<&str>,
        role: Option<&str>,
        default_ssh_user: Option<&str>,
        active: Option<bool>,
        new_password_hash: Option<&str>,
    ) -> Result<Option<UserPublic>, String> {
        let Some(existing) = self.get_user_by_id(id)? else {
            return Ok(None);
        };
        let next_display = display_name.unwrap_or(&existing.display_name).trim();
        let next_role = role.unwrap_or(&existing.role);
        let next_ssh_user = default_ssh_user.unwrap_or(&existing.default_ssh_user).trim();
        let next_active = active.unwrap_or(existing.active);

        {
            let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
            conn.execute(
                "UPDATE users SET display_name = ?1, role = ?2, default_ssh_user = ?3, active = ?4 WHERE id = ?5",
                params![
                    if next_display.is_empty() { &existing.username } else { next_display },
                    next_role,
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
                "SELECT id, username, display_name, role, auth_provider, email, default_ssh_user, active, ping_enabled, totp_enabled, created_at, last_login_at, password_hash
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
                        r.get::<_, i64>(7)? == 1,
                        r.get::<_, i64>(8)? == 1,
                        r.get::<_, i64>(9)? == 1,
                        r.get::<_, String>(10)?,
                        r.get::<_, Option<String>>(11)?,
                        r.get::<_, String>(12)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;

        Ok(raw.map(|t| {
            let user = Self::build_user_public(
                &conn, &policy, t.0, t.1, t.2, t.3, t.4, t.5, t.6, t.7, t.8, t.9, t.10, t.11,
            );
            (user, t.12)
        }))
    }

    pub fn create_session(&self, user_id: &str) -> Result<String, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let now = Utc::now();
        let expires = now + Duration::hours(24);
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![token, user_id, now.to_rfc3339(), expires.to_rfc3339()],
        )
        .map_err(|e| e.to_string())?;
        let _ = conn.execute(
            "UPDATE users SET last_login_at = ?1 WHERE id = ?2",
            params![now.to_rfc3339(), user_id],
        );
        Ok(token)
    }

    pub fn user_by_session(&self, token: &str) -> Result<Option<UserPublic>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let policy = Self::read_auth_policy_locked(&conn);
        let now = Utc::now().to_rfc3339();
        let raw = conn
            .query_row(
                "SELECT u.id, u.username, u.display_name, u.role, u.auth_provider, u.email, u.default_ssh_user, u.active, u.ping_enabled, u.totp_enabled, u.created_at, u.last_login_at
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
                        r.get::<_, i64>(7)? == 1,
                        r.get::<_, i64>(8)? == 1,
                        r.get::<_, i64>(9)? == 1,
                        r.get::<_, String>(10)?,
                        r.get::<_, Option<String>>(11)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;

        Ok(raw.map(|t| {
            Self::build_user_public(
                &conn, &policy, t.0, t.1, t.2, t.3, t.4, t.5, t.6, t.7, t.8, t.9, t.10, t.11,
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
                "SELECT k.id, u.id, u.username, u.display_name, u.role, u.auth_provider, u.email, u.default_ssh_user, u.active, u.ping_enabled, u.totp_enabled, u.created_at, u.last_login_at
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

        if let Some(t) = found {
            let now = Utc::now().to_rfc3339();
            let _ = conn.execute(
                "UPDATE user_api_keys SET last_used_at = ?1 WHERE id = ?2",
                params![now, &t.0],
            );
            let user = Self::build_user_public(
                &conn, &policy, t.1, t.2, t.3, t.4, t.5, t.6, t.7, t.8, t.9, t.10, t.11, t.12,
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
                "SELECT id, username, display_name, role, auth_provider, email, default_ssh_user, active, ping_enabled, totp_enabled, created_at, last_login_at
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
                    r.get::<_, i64>(7)? == 1,
                    r.get::<_, i64>(8)? == 1,
                    r.get::<_, i64>(9)? == 1,
                    r.get::<_, String>(10)?,
                    r.get::<_, Option<String>>(11)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;

        Ok(raw_rows
            .into_iter()
            .map(|t| {
                Self::build_user_public(
                    &conn, &policy, t.0, t.1, t.2, t.3, t.4, t.5, t.6, t.7, t.8, t.9, t.10, t.11,
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
        let shared_json: String = r.get(13)?;
        let shared_with_user_ids: Vec<String> =
            serde_json::from_str(&shared_json).unwrap_or_default();
        let created_at: String = r.get(14)?;
        let updated_raw: String = r.get(15)?;
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
            stop_on_error: r.get::<_, i64>(7)? == 1,
            description: r.get(8)?,
            timeout_sec: r.get::<_, i64>(9)? as u64,
            enabled: r.get::<_, i64>(10)? == 1,
            created_by: r.get(11)?,
            shared_with_all: r.get::<_, i64>(12)? == 1,
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
                "SELECT id, user_id, name, category, kind, command, steps_json, stop_on_error, description, timeout_sec, enabled, created_by, shared_with_all, shared_with_user_ids, created_at, updated_at
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
                "SELECT id, user_id, name, category, kind, command, steps_json, stop_on_error, description, timeout_sec, enabled, created_by, shared_with_all, shared_with_user_ids, created_at, updated_at
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
            "SELECT id, user_id, name, category, kind, command, steps_json, stop_on_error, description, timeout_sec, enabled, created_by, shared_with_all, shared_with_user_ids, created_at, updated_at
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
            "INSERT INTO ssh_commands (id, user_id, name, category, kind, command, steps_json, stop_on_error, description, timeout_sec, enabled, created_by, shared_with_all, shared_with_user_ids, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                id,
                user_id,
                name,
                category,
                kind,
                command,
                steps_json,
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
                         stop_on_error = ?6, description = ?7, timeout_sec = ?8, enabled = ?9, updated_at = ?10
                     WHERE id = ?11 AND user_id = ?12",
                    params![
                        name,
                        category,
                        kind,
                        command,
                        steps_json,
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

    pub fn delete_server(&self, id: &str, user_id: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.execute(
            "DELETE FROM user_servers WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
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

        let existing: Option<(String, bool, Vec<String>)> = conn
            .query_row(
                "SELECT id, shared_with_all, shared_with_user_ids
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
                    Ok((existing_id, existing_all, existing_ids))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;

        if let Some((existing_id, existing_all, existing_ids)) = existing {
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

            conn.execute(
                "UPDATE user_certificates
                 SET owner_username = ?1, name = ?2, private_key_file = ?3, public_key_file = ?4, cert_file = ?5,
                     private_key_enc = ?6, private_key_nonce = ?7, passphrase_enc = ?8, passphrase_nonce = ?9,
                     public_key = ?10, certificate = ?11,
                     inspection_json = ?12, shared_with_all = ?13, shared_with_user_ids = ?14, uploaded_at = ?15
                 WHERE id = ?16 AND user_id = ?17",
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
             (id, user_id, owner_username, name, private_key_file, public_key_file, cert_file, private_key_enc, private_key_nonce, passphrase_enc, passphrase_nonce, public_key, certificate, inspection_json, shared_with_all, shared_with_user_ids, uploaded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
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
                        CASE WHEN passphrase_enc IS NOT NULL AND passphrase_nonce IS NOT NULL THEN 1 ELSE 0 END
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
        let changed = conn
            .execute(
                "UPDATE user_certificates
                 SET owner_username = ?1, name = ?2, private_key_file = ?3, public_key_file = ?4, cert_file = ?5,
                     private_key_enc = ?6, private_key_nonce = ?7, passphrase_enc = ?8, passphrase_nonce = ?9,
                     public_key = ?10, certificate = ?11,
                     inspection_json = ?12, uploaded_at = ?13
                 WHERE id = ?14 AND user_id = ?15",
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
                    "INSERT INTO users (id, username, display_name, role, auth_provider, sso_subject, email, default_ssh_user, active, ping_enabled, password_hash, totp_enabled, created_at)
                     VALUES (?1, ?2, ?3, 'user', 'sso', ?4, ?5, 'root', 1, 1, ?6, 0, ?7)",
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
}
