use crate::models::{
    CertInspection, CommandStep, ExecutionLog, SshCommand, UserCertificatePublic,
    UserCertificateSecret, UserPublic, UserServer,
};
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
                port INTEGER NOT NULL DEFAULT 22,
                ssh_user TEXT NOT NULL DEFAULT 'root',
                notes TEXT NOT NULL DEFAULT '',
                shared_with_all INTEGER NOT NULL DEFAULT 0,
                shared_with_user_ids TEXT NOT NULL DEFAULT '[]',
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
            ",
        )
        .map_err(|e| format!("Schema-Initialisierung fehlgeschlagen: {e}"))?;

        // Migrationen für bestehende Datenbanken
        let _ = conn.execute(
            "ALTER TABLE user_servers ADD COLUMN bmc_ip_address TEXT NOT NULL DEFAULT ''",
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

        Ok(Self {
            conn: Mutex::new(conn),
        })
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
            return "TrixieSSH".into();
        };
        conn.query_row(
            "SELECT value FROM settings WHERE key = 'instance_name'",
            [],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| "TrixieSSH".into())
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
        let clean = if name.trim().is_empty() { "TrixieSSH" } else { name.trim() };
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
            "INSERT INTO users (id, username, display_name, role, default_ssh_user, active, password_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7)",
            params![id, username, display_name, role, default_ssh_user, password_hash, now],
        )
        .map_err(|e| format!("Benutzer konnte nicht gespeichert werden: {e}"))?;

        Ok(UserPublic {
            id,
            username: username.to_string(),
            display_name: display_name.to_string(),
            role: role.to_string(),
            default_ssh_user: default_ssh_user.to_string(),
            active: true,
            created_at: now,
            last_login_at: None,
        })
    }

    pub fn get_user_by_id(&self, id: &str) -> Result<Option<UserPublic>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        conn.query_row(
            "SELECT id, username, display_name, role, default_ssh_user, active, created_at, last_login_at
             FROM users WHERE id = ?1",
            params![id],
            |r| {
                Ok(UserPublic {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    display_name: r.get(2)?,
                    role: r.get(3)?,
                    default_ssh_user: r.get(4)?,
                    active: r.get::<_, i64>(5)? == 1,
                    created_at: r.get(6)?,
                    last_login_at: r.get(7)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
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
        conn.query_row(
            "SELECT id, username, display_name, role, default_ssh_user, active, created_at, last_login_at, password_hash
             FROM users WHERE username = ?1",
            params![username],
            |r| {
                let user = UserPublic {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    display_name: r.get(2)?,
                    role: r.get(3)?,
                    default_ssh_user: r.get(4)?,
                    active: r.get::<_, i64>(5)? == 1,
                    created_at: r.get(6)?,
                    last_login_at: r.get(7)?,
                };
                let hash: String = r.get(8)?;
                Ok((user, hash))
            },
        )
        .optional()
        .map_err(|e| e.to_string())
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
        let now = Utc::now().to_rfc3339();
        conn.query_row(
            "SELECT u.id, u.username, u.display_name, u.role, u.default_ssh_user, u.active, u.created_at, u.last_login_at
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token = ?1 AND s.expires_at > ?2 AND u.active = 1",
            params![token, now],
            |r| {
                Ok(UserPublic {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    display_name: r.get(2)?,
                    role: r.get(3)?,
                    default_ssh_user: r.get(4)?,
                    active: r.get::<_, i64>(5)? == 1,
                    created_at: r.get(6)?,
                    last_login_at: r.get(7)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn delete_session(&self, token: &str) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute("DELETE FROM sessions WHERE token = ?1", params![token]);
        }
    }

    pub fn list_users(&self) -> Result<Vec<UserPublic>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, username, display_name, role, default_ssh_user, active, created_at, last_login_at
                 FROM users ORDER BY created_at ASC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok(UserPublic {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    display_name: r.get(2)?,
                    role: r.get(3)?,
                    default_ssh_user: r.get(4)?,
                    active: r.get::<_, i64>(5)? == 1,
                    created_at: r.get(6)?,
                    last_login_at: r.get(7)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
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

    pub fn list_all_servers(&self) -> Result<Vec<UserServer>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, user_id, owner_username, label, ip_address, bmc_ip_address, port, ssh_user, notes, shared_with_all, shared_with_user_ids, created_at
                 FROM user_servers ORDER BY label ASC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                let shared_json: String = r.get(10)?;
                let shared_with_user_ids: Vec<String> =
                    serde_json::from_str(&shared_json).unwrap_or_default();
                Ok(UserServer {
                    id: r.get(0)?,
                    user_id: r.get(1)?,
                    owner_username: r.get(2)?,
                    label: r.get(3)?,
                    ip_address: r.get(4)?,
                    bmc_ip_address: r.get(5)?,
                    port: r.get::<_, i64>(6)? as u16,
                    ssh_user: r.get(7)?,
                    notes: r.get(8)?,
                    shared_with_all: r.get::<_, i64>(9)? == 1,
                    shared_with_user_ids,
                    created_at: r.get(11)?,
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
        port: u16,
        ssh_user: &str,
        notes: &str,
        shared_with_all: bool,
        shared_with_user_ids: &[String],
    ) -> Result<UserServer, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let clean_shared: Vec<String> = if shared_with_all {
            vec![]
        } else {
            shared_with_user_ids.to_vec()
        };
        let shared_json = serde_json::to_string(&clean_shared).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO user_servers (id, user_id, owner_username, label, ip_address, bmc_ip_address, port, ssh_user, notes, shared_with_all, shared_with_user_ids, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                id,
                user_id,
                owner_username,
                label,
                ip,
                bmc_ip,
                port as i64,
                ssh_user,
                notes,
                if shared_with_all { 1i64 } else { 0i64 },
                shared_json,
                now
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(UserServer {
            id,
            user_id: user_id.to_string(),
            owner_username: owner_username.to_string(),
            label: label.to_string(),
            ip_address: ip.to_string(),
            bmc_ip_address: bmc_ip.to_string(),
            port,
            ssh_user: ssh_user.to_string(),
            notes: notes.to_string(),
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
        port: u16,
        ssh_user: &str,
        notes: &str,
    ) -> Result<Option<UserServer>, String> {
        {
            let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
            let changed = conn
                .execute(
                    "UPDATE user_servers
                     SET label = ?1, ip_address = ?2, bmc_ip_address = ?3, port = ?4, ssh_user = ?5, notes = ?6
                     WHERE id = ?7 AND user_id = ?8",
                    params![label, ip, bmc_ip, port as i64, ssh_user, notes, id, owner_user_id],
                )
                .map_err(|e| e.to_string())?;
            if changed == 0 {
                return Ok(None);
            }
        }
        self.get_accessible_server(id, owner_user_id)
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
                     private_key_enc = ?6, private_key_nonce = ?7, public_key = ?8, certificate = ?9,
                     inspection_json = ?10, shared_with_all = ?11, shared_with_user_ids = ?12, uploaded_at = ?13
                 WHERE id = ?14 AND user_id = ?15",
                params![
                    owner_username,
                    effective_name,
                    priv_file,
                    pub_file,
                    cert_file,
                    priv_enc,
                    priv_nonce,
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
             (id, user_id, owner_username, name, private_key_file, public_key_file, cert_file, private_key_enc, private_key_nonce, public_key, certificate, inspection_json, shared_with_all, shared_with_user_ids, uploaded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
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
                "SELECT id, user_id, owner_username, name, private_key_file, public_key_file, cert_file, inspection_json, shared_with_all, shared_with_user_ids, uploaded_at
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
                "SELECT id, user_id, name, private_key_enc, private_key_nonce, public_key, certificate, inspection_json, shared_with_all, shared_with_user_ids
                 FROM user_certificates WHERE id = ?1",
                params![id],
                |r| {
                    let owner_id: String = r.get(1)?;
                    let json: String = r.get(7)?;
                    let key_id = serde_json::from_str::<CertInspection>(&json)
                        .map(|i| i.key_id)
                        .unwrap_or_default();
                    let shared_all = r.get::<_, i64>(8)? == 1;
                    let shared_json: String = r.get(9)?;
                    let shared_ids: Vec<String> =
                        serde_json::from_str(&shared_json).unwrap_or_default();
                    let secret = UserCertificateSecret {
                        id: r.get(0)?,
                        name: r.get(2)?,
                        private_key_enc: r.get(3)?,
                        private_key_nonce: r.get(4)?,
                        public_key: r.get(5)?,
                        certificate: r.get(6)?,
                        key_id,
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

    pub fn list_logs(&self, user: &UserPublic) -> Result<Vec<ExecutionLog>, String> {
        let conn = self.conn.lock().map_err(|_| "DB Lock Fehler".to_string())?;
        let mut stmt = if user.role == "admin" {
            conn.prepare(
                "SELECT id, user_id, username, command_id, command_name, command_text, target_ip, target_port, ssh_user, server_label, certificate_id, certificate_key_id, mode, ssh_invocation, exit_code, stdout, stderr, duration_ms, executed_at
                 FROM execution_logs ORDER BY executed_at DESC LIMIT 250",
            )
            .map_err(|e| e.to_string())?
        } else {
            conn.prepare(
                "SELECT id, user_id, username, command_id, command_name, command_text, target_ip, target_port, ssh_user, server_label, certificate_id, certificate_key_id, mode, ssh_invocation, exit_code, stdout, stderr, duration_ms, executed_at
                 FROM execution_logs WHERE user_id = ?1 ORDER BY executed_at DESC LIMIT 250",
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

        let rows = if user.role == "admin" {
            stmt.query_map([], mapper)
        } else {
            stmt.query_map(params![user.id], mapper)
        }
        .map_err(|e| e.to_string())?;

        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }
}
