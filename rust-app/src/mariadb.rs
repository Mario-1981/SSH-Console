use crate::crypto::Vault;
use crate::models::{DatabaseTableCount, MariaDbConfigInput, MariaDbTestResponse};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use mysql::prelude::*;
use mysql::{OptsBuilder, Params, Pool, PooledConn, Row, SslOpts, TxOpts, Value as MySqlValue};
use rusqlite::types::{Value as SqliteValue, ValueRef};
use rusqlite::{params_from_iter, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredMariaDbConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password_enc_b64: Option<String>,
    pub password_nonce_b64: Option<String>,
    #[serde(default)]
    pub ssl: bool,
    #[serde(default = "default_true")]
    pub ssl_reject_unauthorized: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbConfigFile {
    pub engine: String,
    pub mariadb: Option<StoredMariaDbConfig>,
    pub last_migrated_at: Option<String>,
    pub last_migration_direction: Option<String>,
}

impl Default for DbConfigFile {
    fn default() -> Self {
        Self {
            engine: "sqlite".to_string(),
            mariadb: None,
            last_migrated_at: None,
            last_migration_direction: None,
        }
    }
}

pub struct ResolvedMariaDbConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: zeroize::Zeroizing<String>,
    pub ssl: bool,
    pub ssl_reject_unauthorized: bool,
}

#[derive(Clone, Copy)]
pub enum ColKind {
    Text,
    Int,
    Blob,
}

pub struct TableSpec {
    pub name: &'static str,
    pub label: &'static str,
    pub columns: &'static [(&'static str, ColKind)],
}

pub const ALL_TABLES: &[TableSpec] = &[
    TableSpec {
        name: "settings",
        label: "Einstellungen",
        columns: &[("key", ColKind::Text), ("value", ColKind::Text)],
    },
    TableSpec {
        name: "user_groups",
        label: "Benutzergruppen",
        columns: &[
            ("id", ColKind::Text),
            ("name", ColKind::Text),
            ("description", ColKind::Text),
            ("is_system", ColKind::Int),
            ("is_immutable", ColKind::Int),
            ("is_admin", ColKind::Int),
            ("permissions_json", ColKind::Text),
            ("created_at", ColKind::Text),
            ("updated_at", ColKind::Text),
        ],
    },
    TableSpec {
        name: "users",
        label: "Benutzer",
        columns: &[
            ("id", ColKind::Text),
            ("username", ColKind::Text),
            ("display_name", ColKind::Text),
            ("role", ColKind::Text),
            ("group_id", ColKind::Text),
            ("default_ssh_user", ColKind::Text),
            ("active", ColKind::Int),
            ("ping_enabled", ColKind::Int),
            ("password_hash", ColKind::Text),
            ("created_at", ColKind::Text),
            ("last_login_at", ColKind::Text),
            ("auth_provider", ColKind::Text),
            ("sso_subject", ColKind::Text),
            ("email", ColKind::Text),
            ("totp_enabled", ColKind::Int),
            ("totp_secret_enc", ColKind::Blob),
            ("totp_secret_nonce", ColKind::Blob),
            ("totp_recovery_hashes_json", ColKind::Text),
        ],
    },
    TableSpec {
        name: "sessions",
        label: "Sitzungen",
        columns: &[
            ("token", ColKind::Text),
            ("user_id", ColKind::Text),
            ("created_at", ColKind::Text),
            ("expires_at", ColKind::Text),
        ],
    },
    TableSpec {
        name: "user_api_keys",
        label: "API-Schlüssel",
        columns: &[
            ("id", ColKind::Text),
            ("user_id", ColKind::Text),
            ("name", ColKind::Text),
            ("key_prefix", ColKind::Text),
            ("key_hash", ColKind::Text),
            ("created_at", ColKind::Text),
            ("last_used_at", ColKind::Text),
        ],
    },
    TableSpec {
        name: "ssh_commands",
        label: "SSH-Befehle & Workflows",
        columns: &[
            ("id", ColKind::Text),
            ("user_id", ColKind::Text),
            ("name", ColKind::Text),
            ("category", ColKind::Text),
            ("kind", ColKind::Text),
            ("command", ColKind::Text),
            ("steps_json", ColKind::Text),
            ("workflow_json", ColKind::Text),
            ("stop_on_error", ColKind::Int),
            ("description", ColKind::Text),
            ("timeout_sec", ColKind::Int),
            ("enabled", ColKind::Int),
            ("created_by", ColKind::Text),
            ("shared_with_all", ColKind::Int),
            ("shared_with_user_ids", ColKind::Text),
            ("created_at", ColKind::Text),
            ("updated_at", ColKind::Text),
        ],
    },
    TableSpec {
        name: "user_servers",
        label: "Server (IPs & BMC)",
        columns: &[
            ("id", ColKind::Text),
            ("user_id", ColKind::Text),
            ("owner_username", ColKind::Text),
            ("label", ColKind::Text),
            ("ip_address", ColKind::Text),
            ("bmc_ip_address", ColKind::Text),
            ("bmc_ip_address2", ColKind::Text),
            ("port", ColKind::Int),
            ("ssh_user", ColKind::Text),
            ("notes", ColKind::Text),
            ("ping_enabled", ColKind::Int),
            ("ignore_host_key", ColKind::Int),
            ("categories_json", ColKind::Text),
            ("last_online_at", ColKind::Text),
            ("shared_with_all", ColKind::Int),
            ("shared_with_user_ids", ColKind::Text),
            ("created_at", ColKind::Text),
        ],
    },
    TableSpec {
        name: "user_server_categories",
        label: "Server-Kategorien",
        columns: &[
            ("id", ColKind::Text),
            ("user_id", ColKind::Text),
            ("name", ColKind::Text),
            ("created_at", ColKind::Text),
        ],
    },
    TableSpec {
        name: "user_certificates",
        label: "SSH-Zertifikate",
        columns: &[
            ("id", ColKind::Text),
            ("user_id", ColKind::Text),
            ("owner_username", ColKind::Text),
            ("name", ColKind::Text),
            ("private_key_file", ColKind::Text),
            ("public_key_file", ColKind::Text),
            ("cert_file", ColKind::Text),
            ("private_key_enc", ColKind::Blob),
            ("private_key_nonce", ColKind::Blob),
            ("passphrase_enc", ColKind::Blob),
            ("passphrase_nonce", ColKind::Blob),
            ("public_key", ColKind::Text),
            ("certificate", ColKind::Text),
            ("inspection_json", ColKind::Text),
            ("auto_renew_json", ColKind::Text),
            ("shared_with_all", ColKind::Int),
            ("shared_with_user_ids", ColKind::Text),
            ("uploaded_at", ColKind::Text),
        ],
    },
    TableSpec {
        name: "certificate_authorities",
        label: "CA-Zertifikate",
        columns: &[
            ("id", ColKind::Text),
            ("name", ColKind::Text),
            ("description", ColKind::Text),
            ("private_key_file", ColKind::Text),
            ("public_key_file", ColKind::Text),
            ("private_key_enc", ColKind::Blob),
            ("private_key_nonce", ColKind::Blob),
            ("passphrase_enc", ColKind::Blob),
            ("passphrase_nonce", ColKind::Blob),
            ("public_key", ColKind::Text),
            ("key_type", ColKind::Text),
            ("fingerprint", ColKind::Text),
            ("private_key_format", ColKind::Text),
            ("private_key_encrypted", ColKind::Int),
            ("created_by", ColKind::Text),
            ("created_by_username", ColKind::Text),
            ("created_at", ColKind::Text),
            ("updated_at", ColKind::Text),
        ],
    },
    TableSpec {
        name: "execution_logs",
        label: "Ausführungsprotokolle",
        columns: &[
            ("id", ColKind::Text),
            ("user_id", ColKind::Text),
            ("username", ColKind::Text),
            ("command_id", ColKind::Text),
            ("command_name", ColKind::Text),
            ("command_text", ColKind::Text),
            ("target_ip", ColKind::Text),
            ("target_port", ColKind::Int),
            ("ssh_user", ColKind::Text),
            ("server_label", ColKind::Text),
            ("certificate_id", ColKind::Text),
            ("certificate_key_id", ColKind::Text),
            ("mode", ColKind::Text),
            ("ssh_invocation", ColKind::Text),
            ("exit_code", ColKind::Int),
            ("stdout", ColKind::Text),
            ("stderr", ColKind::Text),
            ("duration_ms", ColKind::Int),
            ("executed_at", ColKind::Text),
        ],
    },
    TableSpec {
        name: "user_webauthn_credentials",
        label: "Passkeys & Security Keys",
        columns: &[
            ("id", ColKind::Text),
            ("user_id", ColKind::Text),
            ("kind", ColKind::Text),
            ("name", ColKind::Text),
            ("credential_id", ColKind::Text),
            ("public_key", ColKind::Text),
            ("counter", ColKind::Int),
            ("transports_json", ColKind::Text),
            ("created_at", ColKind::Text),
            ("last_used_at", ColKind::Text),
        ],
    },
];

const MARIADB_DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS `settings` (
        `key` VARCHAR(191) NOT NULL PRIMARY KEY,
        `value` LONGTEXT NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    "CREATE TABLE IF NOT EXISTS `user_groups` (
        `id` VARCHAR(191) NOT NULL PRIMARY KEY,
        `name` VARCHAR(191) NOT NULL,
        `description` TEXT NOT NULL,
        `is_system` TINYINT(1) NOT NULL DEFAULT 0,
        `is_immutable` TINYINT(1) NOT NULL DEFAULT 0,
        `is_admin` TINYINT(1) NOT NULL DEFAULT 0,
        `permissions_json` LONGTEXT NOT NULL,
        `created_at` VARCHAR(64) NOT NULL,
        `updated_at` VARCHAR(64) NOT NULL,
        UNIQUE KEY `uq_user_groups_name` (`name`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    "CREATE TABLE IF NOT EXISTS `users` (
        `id` VARCHAR(191) NOT NULL PRIMARY KEY,
        `username` VARCHAR(191) NOT NULL,
        `display_name` VARCHAR(255) NOT NULL,
        `role` VARCHAR(32) NOT NULL,
        `group_id` VARCHAR(191) NOT NULL DEFAULT 'user',
        `default_ssh_user` VARCHAR(128) NOT NULL DEFAULT 'root',
        `active` TINYINT(1) NOT NULL DEFAULT 1,
        `ping_enabled` TINYINT(1) NOT NULL DEFAULT 1,
        `password_hash` TEXT NOT NULL,
        `created_at` VARCHAR(64) NOT NULL,
        `last_login_at` VARCHAR(64) NULL,
        `auth_provider` VARCHAR(32) NOT NULL DEFAULT 'local',
        `sso_subject` VARCHAR(255) NULL,
        `email` VARCHAR(255) NOT NULL DEFAULT '',
        `totp_enabled` TINYINT(1) NOT NULL DEFAULT 0,
        `totp_secret_enc` LONGBLOB NULL,
        `totp_secret_nonce` VARBINARY(64) NULL,
        `totp_recovery_hashes_json` LONGTEXT NOT NULL,
        UNIQUE KEY `uq_users_username` (`username`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    "CREATE TABLE IF NOT EXISTS `sessions` (
        `token` VARCHAR(191) NOT NULL PRIMARY KEY,
        `user_id` VARCHAR(191) NOT NULL,
        `created_at` VARCHAR(64) NOT NULL,
        `expires_at` VARCHAR(64) NOT NULL,
        KEY `idx_sessions_user_id` (`user_id`),
        KEY `idx_sessions_expires_at` (`expires_at`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    "CREATE TABLE IF NOT EXISTS `user_api_keys` (
        `id` VARCHAR(191) NOT NULL PRIMARY KEY,
        `user_id` VARCHAR(191) NOT NULL,
        `name` VARCHAR(255) NOT NULL,
        `key_prefix` VARCHAR(64) NOT NULL,
        `key_hash` VARCHAR(191) NOT NULL,
        `created_at` VARCHAR(64) NOT NULL,
        `last_used_at` VARCHAR(64) NULL,
        UNIQUE KEY `uq_user_api_keys_hash` (`key_hash`),
        KEY `idx_api_keys_user_id` (`user_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    "CREATE TABLE IF NOT EXISTS `ssh_commands` (
        `id` VARCHAR(191) NOT NULL PRIMARY KEY,
        `user_id` VARCHAR(191) NOT NULL DEFAULT '',
        `name` VARCHAR(255) NOT NULL,
        `category` VARCHAR(191) NOT NULL,
        `kind` VARCHAR(32) NOT NULL DEFAULT 'single',
        `command` LONGTEXT NOT NULL,
        `steps_json` LONGTEXT NOT NULL,
        `workflow_json` LONGTEXT NOT NULL,
        `stop_on_error` TINYINT(1) NOT NULL DEFAULT 1,
        `description` TEXT NOT NULL,
        `timeout_sec` INT NOT NULL DEFAULT 30,
        `enabled` TINYINT(1) NOT NULL DEFAULT 1,
        `created_by` VARCHAR(191) NOT NULL,
        `shared_with_all` TINYINT(1) NOT NULL DEFAULT 0,
        `shared_with_user_ids` LONGTEXT NOT NULL,
        `created_at` VARCHAR(64) NOT NULL,
        `updated_at` VARCHAR(64) NOT NULL DEFAULT '',
        KEY `idx_commands_user_id` (`user_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    "CREATE TABLE IF NOT EXISTS `user_servers` (
        `id` VARCHAR(191) NOT NULL PRIMARY KEY,
        `user_id` VARCHAR(191) NOT NULL,
        `owner_username` VARCHAR(191) NOT NULL DEFAULT '',
        `label` VARCHAR(255) NOT NULL,
        `ip_address` VARCHAR(255) NOT NULL,
        `bmc_ip_address` VARCHAR(255) NOT NULL DEFAULT '',
        `bmc_ip_address2` VARCHAR(255) NOT NULL DEFAULT '',
        `port` INT NOT NULL DEFAULT 22,
        `ssh_user` VARCHAR(128) NOT NULL DEFAULT 'root',
        `notes` LONGTEXT NOT NULL,
        `ping_enabled` TINYINT(1) NOT NULL DEFAULT 1,
        `ignore_host_key` TINYINT(1) NOT NULL DEFAULT 0,
        `categories_json` LONGTEXT NOT NULL,
        `last_online_at` VARCHAR(64) NULL,
        `shared_with_all` TINYINT(1) NOT NULL DEFAULT 0,
        `shared_with_user_ids` LONGTEXT NOT NULL,
        `created_at` VARCHAR(64) NOT NULL,
        KEY `idx_servers_user_id` (`user_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    "CREATE TABLE IF NOT EXISTS `user_server_categories` (
        `id` VARCHAR(191) NOT NULL PRIMARY KEY,
        `user_id` VARCHAR(191) NOT NULL,
        `name` VARCHAR(191) NOT NULL,
        `created_at` VARCHAR(64) NOT NULL,
        KEY `idx_server_categories_user_id` (`user_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    "CREATE TABLE IF NOT EXISTS `user_certificates` (
        `id` VARCHAR(191) NOT NULL PRIMARY KEY,
        `user_id` VARCHAR(191) NOT NULL,
        `owner_username` VARCHAR(191) NOT NULL DEFAULT '',
        `name` VARCHAR(255) NOT NULL,
        `private_key_file` VARCHAR(255) NOT NULL,
        `public_key_file` VARCHAR(255) NOT NULL,
        `cert_file` VARCHAR(255) NOT NULL,
        `private_key_enc` LONGBLOB NOT NULL,
        `private_key_nonce` VARBINARY(64) NOT NULL,
        `passphrase_enc` LONGBLOB NULL,
        `passphrase_nonce` VARBINARY(64) NULL,
        `public_key` LONGTEXT NOT NULL,
        `certificate` LONGTEXT NOT NULL,
        `inspection_json` LONGTEXT NOT NULL,
        `auto_renew_json` LONGTEXT NULL,
        `shared_with_all` TINYINT(1) NOT NULL DEFAULT 0,
        `shared_with_user_ids` LONGTEXT NOT NULL,
        `uploaded_at` VARCHAR(64) NOT NULL,
        KEY `idx_certs_user_id` (`user_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    "CREATE TABLE IF NOT EXISTS `certificate_authorities` (
        `id` VARCHAR(191) NOT NULL PRIMARY KEY,
        `name` VARCHAR(255) NOT NULL,
        `description` TEXT NOT NULL,
        `private_key_file` VARCHAR(255) NOT NULL DEFAULT 'ca',
        `public_key_file` VARCHAR(255) NOT NULL DEFAULT 'ca.pub',
        `private_key_enc` LONGBLOB NOT NULL,
        `private_key_nonce` VARBINARY(64) NOT NULL,
        `passphrase_enc` LONGBLOB NULL,
        `passphrase_nonce` VARBINARY(64) NULL,
        `public_key` LONGTEXT NOT NULL,
        `key_type` VARCHAR(64) NOT NULL DEFAULT 'ssh-ed25519',
        `fingerprint` VARCHAR(255) NOT NULL DEFAULT '',
        `private_key_format` VARCHAR(64) NOT NULL DEFAULT 'openssh-v1',
        `private_key_encrypted` TINYINT(1) NOT NULL DEFAULT 1,
        `created_by` VARCHAR(191) NOT NULL DEFAULT '',
        `created_by_username` VARCHAR(191) NOT NULL DEFAULT '',
        `created_at` VARCHAR(64) NOT NULL,
        `updated_at` VARCHAR(64) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    "CREATE TABLE IF NOT EXISTS `execution_logs` (
        `id` VARCHAR(191) NOT NULL PRIMARY KEY,
        `user_id` VARCHAR(191) NOT NULL,
        `username` VARCHAR(191) NOT NULL,
        `command_id` VARCHAR(191) NOT NULL DEFAULT '',
        `command_name` VARCHAR(255) NOT NULL,
        `command_text` LONGTEXT NOT NULL,
        `target_ip` VARCHAR(255) NOT NULL,
        `target_port` INT NOT NULL,
        `ssh_user` VARCHAR(128) NOT NULL,
        `server_label` VARCHAR(255) NOT NULL DEFAULT '',
        `certificate_id` VARCHAR(191) NOT NULL DEFAULT '',
        `certificate_key_id` VARCHAR(255) NOT NULL,
        `mode` VARCHAR(64) NOT NULL DEFAULT 'openssh-live',
        `ssh_invocation` LONGTEXT NOT NULL,
        `exit_code` INT NOT NULL,
        `stdout` LONGTEXT NOT NULL,
        `stderr` LONGTEXT NOT NULL,
        `duration_ms` BIGINT NOT NULL,
        `executed_at` VARCHAR(64) NOT NULL,
        KEY `idx_logs_user_executed` (`user_id`, `executed_at`),
        KEY `idx_logs_executed_at` (`executed_at`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    "CREATE TABLE IF NOT EXISTS `user_webauthn_credentials` (
        `id` VARCHAR(191) NOT NULL PRIMARY KEY,
        `user_id` VARCHAR(191) NOT NULL,
        `kind` VARCHAR(32) NOT NULL,
        `name` VARCHAR(255) NOT NULL,
        `credential_id` VARCHAR(512) NOT NULL,
        `public_key` LONGTEXT NOT NULL,
        `counter` BIGINT NOT NULL DEFAULT 0,
        `transports_json` TEXT NOT NULL,
        `created_at` VARCHAR(64) NOT NULL,
        `last_used_at` VARCHAR(64) NULL,
        KEY `idx_webauthn_user_id` (`user_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
];

pub fn config_path(data_dir: &Path) -> PathBuf {
    data_dir.join("db-config.json")
}

pub fn load_config_file(data_dir: &Path) -> DbConfigFile {
    let path = config_path(data_dir);
    let Ok(raw) = fs::read_to_string(&path) else {
        return DbConfigFile::default();
    };
    let Ok(mut parsed) = serde_json::from_str::<DbConfigFile>(&raw) else {
        return DbConfigFile::default();
    };
    if parsed.engine != "mariadb" || parsed.mariadb.is_none() {
        parsed.engine = "sqlite".to_string();
    }
    parsed
}

pub fn save_config_file(data_dir: &Path, cfg: &DbConfigFile) -> Result<(), String> {
    let path = config_path(data_dir);
    let tmp = data_dir.join("db-config.json.tmp");
    let json = serde_json::to_string_pretty(cfg)
        .map_err(|e| format!("DB-Konfiguration konnte nicht serialisiert werden: {e}"))?;
    fs::write(&tmp, json)
        .map_err(|e| format!("DB-Konfiguration konnte nicht geschrieben werden: {e}"))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Dateirechte für db-config.json konnten nicht gesetzt werden: {e}"))?;
    fs::rename(&tmp, &path)
        .map_err(|e| format!("DB-Konfiguration konnte nicht gespeichert werden: {e}"))?;
    Ok(())
}

fn is_valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']'))
}

fn is_valid_db_name(db: &str) -> bool {
    !db.is_empty()
        && db.len() <= 64
        && db
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'$'))
}

pub fn encrypt_password(vault: &Vault, password: &str) -> Result<(String, String), String> {
    let (enc, nonce) = vault.encrypt(password.as_bytes())?;
    Ok((STANDARD.encode(enc), STANDARD.encode(nonce)))
}

pub fn decrypt_password(
    vault: &Vault,
    enc_b64: &str,
    nonce_b64: &str,
) -> Result<zeroize::Zeroizing<String>, String> {
    let enc = STANDARD
        .decode(enc_b64)
        .map_err(|_| "Gespeichertes MariaDB-Passwort ist beschädigt.".to_string())?;
    let nonce = STANDARD
        .decode(nonce_b64)
        .map_err(|_| "Gespeicherte MariaDB-Nonce ist beschädigt.".to_string())?;
    let plain = vault.decrypt(&enc, &nonce).map_err(|_| {
        "Das gespeicherte MariaDB-Passwort konnte nicht entschlüsselt werden. Bitte geben Sie es erneut ein.".to_string()
    })?;
    let text = String::from_utf8(plain.to_vec())
        .map_err(|_| "Entschlüsseltes MariaDB-Passwort ist kein gültiges UTF-8.".to_string())?;
    Ok(zeroize::Zeroizing::new(text))
}

pub fn resolve_mariadb_config(
    existing: Option<&StoredMariaDbConfig>,
    override_input: Option<&MariaDbConfigInput>,
    vault: &Vault,
) -> Result<ResolvedMariaDbConfig, String> {
    let host = override_input
        .and_then(|i| i.host.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| existing.map(|e| e.host.as_str()))
        .unwrap_or("")
        .to_string();
    if !is_valid_host(&host) {
        return Err("Bitte einen gültigen MariaDB-Hostnamen oder eine IP-Adresse angeben.".into());
    }

    let port = override_input
        .and_then(|i| i.port)
        .or_else(|| existing.map(|e| e.port))
        .unwrap_or(3306);
    if port == 0 {
        return Err("Der MariaDB-Port muss zwischen 1 und 65535 liegen.".into());
    }

    let database = override_input
        .and_then(|i| i.database.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| existing.map(|e| e.database.as_str()))
        .unwrap_or("")
        .to_string();
    if !is_valid_db_name(&database) {
        return Err(
            "Ungültiger Datenbankname (erlaubt sind Buchstaben, Ziffern, Unterstrich, Bindestrich und $, max. 64 Zeichen)."
                .into(),
        );
    }

    let username = override_input
        .and_then(|i| i.username.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| existing.map(|e| e.username.as_str()))
        .unwrap_or("")
        .to_string();
    if username.is_empty() || username.len() > 128 || username.contains('\n') || username.contains('\r') {
        return Err("Bitte einen gültigen MariaDB-Benutzernamen angeben.".into());
    }

    let explicit_pass = override_input
        .and_then(|i| i.password.as_deref())
        .filter(|p| !p.is_empty());

    let password = if let Some(p) = explicit_pass {
        zeroize::Zeroizing::new(p.to_string())
    } else if let Some(stored) = existing {
        match (&stored.password_enc_b64, &stored.password_nonce_b64) {
            (Some(enc), Some(nonce)) => decrypt_password(vault, enc, nonce)?,
            _ => return Err("Bitte das Passwort für den MariaDB-Benutzer angeben.".into()),
        }
    } else {
        return Err("Bitte das Passwort für den MariaDB-Benutzer angeben.".into());
    };

    let ssl = override_input
        .and_then(|i| i.ssl)
        .or_else(|| existing.map(|e| e.ssl))
        .unwrap_or(false);
    let ssl_reject_unauthorized = override_input
        .and_then(|i| i.ssl_reject_unauthorized)
        .or_else(|| existing.map(|e| e.ssl_reject_unauthorized))
        .unwrap_or(true);

    Ok(ResolvedMariaDbConfig {
        host,
        port,
        database,
        username,
        password,
        ssl,
        ssl_reject_unauthorized,
    })
}

pub fn build_pool(cfg: &ResolvedMariaDbConfig) -> Result<Pool, String> {
    let mut builder = OptsBuilder::new()
        .ip_or_hostname(Some(cfg.host.as_str()))
        .tcp_port(cfg.port)
        .user(Some(cfg.username.as_str()))
        .pass(Some(cfg.password.as_str()))
        .db_name(Some(cfg.database.as_str()))
        .tcp_connect_timeout(Some(Duration::from_secs(8)));

    if cfg.ssl {
        let ssl_opts = if cfg.ssl_reject_unauthorized {
            SslOpts::default()
        } else {
            SslOpts::default()
                .with_danger_accept_invalid_certs(true)
                .with_danger_skip_domain_validation(true)
        };
        builder = builder.ssl_opts(Some(ssl_opts));
    }

    Pool::new(builder).map_err(|e| format!("MariaDB-Verbindungspool fehlgeschlagen: {e}"))
}

pub fn ensure_mariadb_schema(conn: &mut PooledConn) -> Result<(), String> {
    for ddl in MARIADB_DDL {
        conn.query_drop(*ddl)
            .map_err(|e| format!("MariaDB-Schema konnte nicht erstellt werden: {e}"))?;
    }
    Ok(())
}

pub fn inspect_mariadb_existing_tables(
    conn: &mut PooledConn,
) -> Result<(Vec<DatabaseTableCount>, u64), String> {
    let existing_names = conn
        .query::<String, _>("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()")
        .map_err(|e| format!("MariaDB-Tabellenprüfung fehlgeschlagen: {e}"))?;
    let existing_set: HashSet<String> = existing_names
        .into_iter()
        .map(|s| s.to_lowercase())
        .collect();

    let mut tables = Vec::new();
    let mut total: u64 = 0;

    for spec in ALL_TABLES {
        if !existing_set.contains(spec.name) {
            continue;
        }
        let sql = format!("SELECT COUNT(*) FROM `{}`", spec.name);
        let cnt = conn
            .query_first::<u64, _>(sql)
            .map_err(|e| format!("Zählung für Tabelle {} fehlgeschlagen: {e}", spec.name))?
            .unwrap_or(0);
        total = total.saturating_add(cnt);
        tables.push(DatabaseTableCount {
            table: spec.name.to_string(),
            label: spec.label.to_string(),
            rows: cnt,
        });
    }

    Ok((tables, total))
}

pub fn test_connection(cfg: &ResolvedMariaDbConfig) -> Result<MariaDbTestResponse, String> {
    let started = Instant::now();
    let pool = build_pool(cfg)?;
    let mut conn = pool
        .get_conn()
        .map_err(|e| format!("MariaDB-Verbindung fehlgeschlagen: {e}"))?;

    let (version, db_opt) = conn
        .query_first::<(String, Option<String>), _>("SELECT VERSION(), DATABASE()")
        .map_err(|e| format!("MariaDB-Versionsabfrage fehlgeschlagen: {e}"))?
        .unwrap_or_else(|| ("MariaDB".to_string(), Some(cfg.database.clone())));

    let (existing_tables, existing_row_count) = inspect_mariadb_existing_tables(&mut conn)?;
    let latency_ms = started.elapsed().as_millis().max(1) as u64;

    Ok(MariaDbTestResponse {
        ok: true,
        version,
        database: db_opt.unwrap_or_else(|| cfg.database.clone()),
        latency_ms,
        existing_tables,
        existing_row_count,
    })
}

pub fn query_mariadb_version(pool: &Pool) -> Result<String, String> {
    let mut conn = pool
        .get_conn()
        .map_err(|e| format!("MariaDB-Verbindung fehlgeschlagen: {e}"))?;
    let version = conn
        .query_first::<String, _>("SELECT VERSION()")
        .map_err(|e| format!("MariaDB-Ping fehlgeschlagen: {e}"))?
        .unwrap_or_else(|| "MariaDB".to_string());
    Ok(version)
}

pub fn get_sqlite_table_counts(conn: &Connection) -> Result<Vec<DatabaseTableCount>, String> {
    let mut out = Vec::with_capacity(ALL_TABLES.len());
    for spec in ALL_TABLES {
        let sql = format!("SELECT COUNT(*) FROM \"{}\"", spec.name);
        let cnt: i64 = conn
            .query_row(&sql, [], |r| r.get(0))
            .map_err(|e| format!("SQLite-Zählung für {} fehlgeschlagen: {e}", spec.name))?;
        out.push(DatabaseTableCount {
            table: spec.name.to_string(),
            label: spec.label.to_string(),
            rows: cnt.max(0) as u64,
        });
    }
    Ok(out)
}

fn read_sqlite_table_rows(
    sqlite_conn: &Connection,
    spec: &TableSpec,
) -> Result<Vec<Vec<MySqlValue>>, String> {
    let col_list = spec
        .columns
        .iter()
        .map(|(c, _)| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let select_sql = format!("SELECT {col_list} FROM \"{}\"", spec.name);
    let mut stmt = sqlite_conn
        .prepare(&select_sql)
        .map_err(|e| format!("SQLite-Abfrage für {} fehlgeschlagen: {e}", spec.name))?;

    let col_count = spec.columns.len();
    let iter = stmt
        .query_map([], |row| {
            let mut vals = Vec::with_capacity(col_count);
            for i in 0..col_count {
                let v = match row.get_ref(i)? {
                    ValueRef::Null => MySqlValue::NULL,
                    ValueRef::Integer(n) => MySqlValue::Int(n),
                    ValueRef::Real(f) => MySqlValue::Double(f),
                    ValueRef::Text(b) => MySqlValue::Bytes(b.to_vec()),
                    ValueRef::Blob(b) => MySqlValue::Bytes(b.to_vec()),
                };
                vals.push(v);
            }
            Ok(vals)
        })
        .map_err(|e| format!("SQLite-Lesefehler für {}: {e}", spec.name))?;

    let mut rows = Vec::new();
    for r in iter {
        rows.push(r.map_err(|e| format!("SQLite-Zeilenfehler in {}: {e}", spec.name))?);
    }
    Ok(rows)
}

pub fn sync_tables_to_mariadb(
    sqlite_conn: &Connection,
    pool: &Pool,
    table_names: &[String],
) -> Result<(), String> {
    let requested: HashSet<&str> = table_names.iter().map(String::as_str).collect();
    let specs: Vec<&TableSpec> = ALL_TABLES
        .iter()
        .filter(|s| requested.contains(s.name))
        .collect();
    if specs.is_empty() {
        return Ok(());
    }

    let mut snapshots: Vec<(&TableSpec, Vec<Vec<MySqlValue>>)> = Vec::with_capacity(specs.len());
    for spec in specs {
        let rows = read_sqlite_table_rows(sqlite_conn, spec)?;
        snapshots.push((spec, rows));
    }

    let mut mconn = pool
        .get_conn()
        .map_err(|e| format!("MariaDB-Verbindung fehlgeschlagen: {e}"))?;
    let mut tx = mconn
        .start_transaction(TxOpts::default())
        .map_err(|e| format!("MariaDB-Transaktion konnte nicht gestartet werden: {e}"))?;

    tx.query_drop("SET FOREIGN_KEY_CHECKS = 0")
        .map_err(|e| format!("MariaDB FK-Deaktivierung fehlgeschlagen: {e}"))?;

    let sync_result: Result<(), String> = (|| {
        for (spec, rows) in snapshots {
            let del_sql = format!("DELETE FROM `{}`", spec.name);
            tx.query_drop(del_sql)
                .map_err(|e| format!("MariaDB-Tabelle {} konnte nicht geleert werden: {e}", spec.name))?;

            if rows.is_empty() {
                continue;
            }

            let col_list = spec
                .columns
                .iter()
                .map(|(c, _)| format!("`{c}`"))
                .collect::<Vec<_>>()
                .join(", ");
            let row_placeholder = format!(
                "({})",
                vec!["?"; spec.columns.len()].join(", ")
            );

            for chunk in rows.chunks(25) {
                let placeholders = vec![row_placeholder.as_str(); chunk.len()].join(", ");
                let insert_sql = format!(
                    "INSERT INTO `{}` ({col_list}) VALUES {placeholders}",
                    spec.name
                );
                let mut flat_params = Vec::with_capacity(chunk.len() * spec.columns.len());
                for r in chunk {
                    flat_params.extend(r.iter().cloned());
                }
                tx.exec_drop(&insert_sql, Params::Positional(flat_params))
                    .map_err(|e| {
                        format!(
                            "MariaDB-Einfügen in Tabelle {} fehlgeschlagen: {e}",
                            spec.name
                        )
                    })?;
            }
        }
        Ok(())
    })();

    let fk_restore = tx
        .query_drop("SET FOREIGN_KEY_CHECKS = 1")
        .map_err(|e| format!("MariaDB FK-Reaktivierung fehlgeschlagen: {e}"));

    if let Err(err) = sync_result {
        let _ = tx.rollback();
        return Err(err);
    }
    fk_restore?;

    tx.commit()
        .map_err(|e| format!("MariaDB-Commit fehlgeschlagen: {e}"))?;

    Ok(())
}

pub fn migrate_sqlite_to_mariadb(
    sqlite_conn: &Connection,
    pool: &Pool,
) -> Result<Vec<DatabaseTableCount>, String> {
    let mut mconn = pool
        .get_conn()
        .map_err(|e| format!("MariaDB-Verbindung fehlgeschlagen: {e}"))?;
    ensure_mariadb_schema(&mut mconn)?;
    drop(mconn);

    let all_names: Vec<String> = ALL_TABLES.iter().map(|s| s.name.to_string()).collect();
    sync_tables_to_mariadb(sqlite_conn, pool, &all_names)?;

    let expected = get_sqlite_table_counts(sqlite_conn)?;
    let mut verify_conn = pool
        .get_conn()
        .map_err(|e| format!("MariaDB-Verifikationsverbindung fehlgeschlagen: {e}"))?;
    let (actual, actual_total) = inspect_mariadb_existing_tables(&mut verify_conn)?;
    let expected_total: u64 = expected.iter().map(|t| t.rows).sum();
    if expected_total != actual_total {
        return Err(format!(
            "Integritätsprüfung fehlgeschlagen: Erwartet {expected_total} Datensätze, in MariaDB gefunden: {actual_total}."
        ));
    }

    Ok(actual)
}

fn mysql_val_to_sqlite(val: Option<&MySqlValue>, kind: ColKind) -> SqliteValue {
    match val {
        None | Some(MySqlValue::NULL) => SqliteValue::Null,
        Some(MySqlValue::Int(i)) => SqliteValue::Integer(*i),
        Some(MySqlValue::UInt(u)) => SqliteValue::Integer(*u as i64),
        Some(MySqlValue::Float(f)) => SqliteValue::Real(*f as f64),
        Some(MySqlValue::Double(d)) => SqliteValue::Real(*d),
        Some(MySqlValue::Bytes(b)) => match kind {
            ColKind::Blob => SqliteValue::Blob(b.clone()),
            ColKind::Int => {
                let s = String::from_utf8_lossy(b);
                SqliteValue::Integer(s.trim().parse::<i64>().unwrap_or(0))
            }
            ColKind::Text => SqliteValue::Text(String::from_utf8_lossy(b).into_owned()),
        },
        Some(other) => SqliteValue::Text(other.as_sql(false)),
    }
}

pub fn load_mariadb_into_sqlite(
    pool: &Pool,
    sqlite_conn: &mut Connection,
) -> Result<Vec<DatabaseTableCount>, String> {
    let mut mconn = pool
        .get_conn()
        .map_err(|e| format!("MariaDB-Verbindung fehlgeschlagen: {e}"))?;
    ensure_mariadb_schema(&mut mconn)?;

    let mut fetched: Vec<(&TableSpec, Vec<Vec<SqliteValue>>)> = Vec::with_capacity(ALL_TABLES.len());
    for spec in ALL_TABLES {
        let col_list = spec
            .columns
            .iter()
            .map(|(c, _)| format!("`{c}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let select_sql = format!("SELECT {col_list} FROM `{}`", spec.name);
        let rows = mconn
            .query::<Row, _>(select_sql)
            .map_err(|e| format!("MariaDB-Lesefehler für {}: {e}", spec.name))?;
        let mut converted = Vec::with_capacity(rows.len());
        for row in rows {
            let mut vals = Vec::with_capacity(spec.columns.len());
            for (idx, (_, kind)) in spec.columns.iter().enumerate() {
                vals.push(mysql_val_to_sqlite(row.as_ref(idx), *kind));
            }
            converted.push(vals);
        }
        fetched.push((spec, converted));
    }

    sqlite_conn
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .map_err(|e| format!("SQLite PRAGMA fehlgeschlagen: {e}"))?;

    let write_res: Result<(), String> = (|| {
        let tx = sqlite_conn
            .transaction()
            .map_err(|e| format!("SQLite-Transaktion konnte nicht gestartet werden: {e}"))?;

        for (spec, _) in fetched.iter().rev() {
            let del_sql = format!("DELETE FROM \"{}\"", spec.name);
            tx.execute(&del_sql, [])
                .map_err(|e| format!("SQLite-Tabelle {} konnte nicht geleert werden: {e}", spec.name))?;
        }

        for (spec, rows) in &fetched {
            if rows.is_empty() {
                continue;
            }
            let col_list = spec
                .columns
                .iter()
                .map(|(c, _)| format!("\"{c}\""))
                .collect::<Vec<_>>()
                .join(", ");
            let placeholders = vec!["?"; spec.columns.len()].join(", ");
            let insert_sql = format!(
                "INSERT INTO \"{}\" ({col_list}) VALUES ({placeholders})",
                spec.name
            );
            let mut stmt = tx
                .prepare(&insert_sql)
                .map_err(|e| format!("SQLite-Prepare für {} fehlgeschlagen: {e}", spec.name))?;
            for r in rows {
                stmt.execute(params_from_iter(r.iter()))
                    .map_err(|e| format!("SQLite-Einfügen in {} fehlgeschlagen: {e}", spec.name))?;
            }
        }

        tx.commit()
            .map_err(|e| format!("SQLite-Commit fehlgeschlagen: {e}"))?;
        Ok(())
    })();

    let _ = sqlite_conn.execute_batch("PRAGMA foreign_keys = ON;");
    write_res?;

    get_sqlite_table_counts(sqlite_conn)
}
