mod auth;
mod crypto;
mod db;
mod models;
mod ping;
mod ssh;

use axum::{
    extract::{FromRequest, Multipart, Path as AxumPath, Query, Request as AxumRequest, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, patch, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::Utc;
use crypto::Vault;
use db::Database;
use models::*;
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Notify;
use tower_http::services::{ServeDir, ServeFile};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const SESSION_COOKIE: &str = "ssh_console_session";

struct AppState {
    db: Database,
    vault: Vault,
    ping: ping::SharedPingState,
    ping_notify: Arc<Notify>,
}

type SharedState = Arc<AppState>;
type ApiError = (StatusCode, Json<serde_json::Value>);

#[derive(Debug, Deserialize, Default)]
struct ListCommandsQuery {
    all: Option<String>,
}

fn err_resp(status: StatusCode, msg: impl Into<String>) -> ApiError {
    (status, Json(json!({ "error": msg.into() })))
}

fn extract_session_token(jar: &CookieJar, headers: &HeaderMap) -> Option<String> {
    if let Some(auth_val) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if auth_val.len() > 7 && auth_val[..7].eq_ignore_ascii_case("bearer ") {
            let tok = auth_val[7..].trim();
            if !tok.is_empty() {
                return Some(tok.to_string());
            }
        }
    }
    jar.get(SESSION_COOKIE).map(|c| c.value().to_string())
}

fn generate_api_key() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("sshc_{}", hex::encode(bytes))
}

fn hash_api_key(plain: &str) -> String {
    let digest = Sha256::digest(plain.as_bytes());
    hex::encode(digest)
}

fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    if let Some(val) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Some(auth_val) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if auth_val.len() > 7 && auth_val[..7].eq_ignore_ascii_case("bearer ") {
            let tok = auth_val[7..].trim();
            if tok.starts_with("sshc_") {
                return Some(tok.to_string());
            }
        }
    }
    None
}

fn current_user(
    state: &SharedState,
    jar: &CookieJar,
    headers: &HeaderMap,
) -> Result<(UserPublic, String), ApiError> {
    let token = extract_session_token(jar, headers)
        .ok_or_else(|| err_resp(StatusCode::UNAUTHORIZED, "Anmeldung erforderlich."))?;
    let user = state
        .db
        .user_by_session(&token)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::UNAUTHORIZED, "Sitzung abgelaufen."))?;
    Ok((user, token))
}

fn require_admin(
    state: &SharedState,
    jar: &CookieJar,
    headers: &HeaderMap,
) -> Result<UserPublic, ApiError> {
    let (user, _token) = current_user(state, jar, headers)?;
    if user.role != "admin" {
        return Err(err_resp(StatusCode::FORBIDDEN, "Administratorrechte erforderlich."));
    }
    Ok(user)
}

fn build_session_cookie(token: String) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build()
}

async fn api_status(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> impl IntoResponse {
    let initialized = state.db.is_initialized().unwrap_or(false);
    let user = current_user(&state, &jar, &headers).ok().map(|(u, _)| u);
    Json(json!({
        "initialized": initialized,
        "settings": {
            "instanceName": state.db.get_instance_name(),
            "initializedAt": state.db.get_initialized_at(),
            "pingAllowed": state.db.get_ping_allowed(),
            "pingIntervalSec": state.db.get_ping_interval_sec()
        },
        "user": user,
        "opensshAvailable": Path::new("/usr/bin/ssh").exists()
    }))
}

async fn api_setup(
    State(state): State<SharedState>,
    jar: CookieJar,
    Json(req): Json<SetupRequest>,
) -> Result<(CookieJar, Json<serde_json::Value>), ApiError> {
    if state.db.is_initialized().unwrap_or(true) {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "Ersteinrichtung bereits abgeschlossen. Registrierung ist deaktiviert.",
        ));
    }
    let username =
        auth::validate_username(&req.username).map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
    if req.password.len() < 8 {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Passwort muss mindestens 8 Zeichen lang sein.",
        ));
    }
    let hash =
        auth::hash_password(&req.password).map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let display = req.display_name.unwrap_or_else(|| username.clone());
    let user = state
        .db
        .create_user(&username, &display, "admin", "root", &hash)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;

    if let Some(inst) = req.instance_name {
        let _ = state.db.set_instance_name(inst.trim());
    }
    let now = Utc::now().to_rfc3339();
    let _ = state.db.set_initialized_at(&now);

    let token = state
        .db
        .create_session(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok((
        jar.add(build_session_cookie(token.clone())),
        Json(json!({
            "user": user,
            "settings": {
                "instanceName": state.db.get_instance_name(),
                "initializedAt": state.db.get_initialized_at(),
                "pingAllowed": state.db.get_ping_allowed(),
                "pingIntervalSec": state.db.get_ping_interval_sec()
            },
            "sessionToken": token
        })),
    ))
}

async fn api_login(
    State(state): State<SharedState>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<serde_json::Value>), ApiError> {
    let clean = req.username.trim().to_lowercase();
    let Some((user, hash)) = state
        .db
        .find_user_for_login(&clean)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
    else {
        return Err(err_resp(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten."));
    };

    if !auth::verify_password(&req.password, &hash) {
        return Err(err_resp(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten."));
    }
    if !user.active {
        return Err(err_resp(StatusCode::FORBIDDEN, "Benutzerkonto ist deaktiviert."));
    }

    let token = state
        .db
        .create_session(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok((
        jar.add(build_session_cookie(token.clone())),
        Json(json!({ "user": user, "sessionToken": token })),
    ))
}

async fn api_logout(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(tok) = extract_session_token(&jar, &headers) {
        state.db.delete_session(&tok);
    }
    (jar.remove(Cookie::from(SESSION_COOKIE)), Json(json!({ "ok": true })))
}

async fn api_change_password(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, token) = current_user(&state, &jar, &headers)?;
    let Some((_u, current_hash)) = state
        .db
        .find_user_for_login(&user.username)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
    else {
        return Err(err_resp(StatusCode::NOT_FOUND, "Benutzer nicht gefunden."));
    };
    if !auth::verify_password(&req.current_password, &current_hash) {
        return Err(err_resp(StatusCode::BAD_REQUEST, "Das aktuelle Passwort ist nicht korrekt."));
    }
    if req.new_password.len() < 8 {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Das neue Passwort muss mindestens 8 Zeichen lang sein.",
        ));
    }
    if req.new_password == req.current_password {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Das neue Passwort muss sich vom aktuellen Passwort unterscheiden.",
        ));
    }
    let new_hash = auth::hash_password(&req.new_password)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    state
        .db
        .update_user_password(&user.id, &new_hash, Some(&token))
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "ok": true })))
}

async fn api_list_api_keys(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let api_keys = state
        .db
        .list_api_keys(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "apiKeys": api_keys })))
}

async fn api_create_api_key(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let clean_name: String = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(64).collect())
        .unwrap_or_else(|| "API-Schlüssel".to_string());
    let plain_key = generate_api_key();
    let key_prefix = format!("{}…", &plain_key[..12]);
    let key_hash = hash_api_key(&plain_key);
    let api_key = state
        .db
        .create_api_key(&user.id, &clean_name, &key_prefix, &key_hash)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "apiKey": api_key, "plainKey": plain_key })),
    ))
}

async fn api_delete_api_key(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    state
        .db
        .delete_api_key(&id, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "ok": true })))
}

async fn api_admin_list_users(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _admin = require_admin(&state, &jar, &headers)?;
    let users = state
        .db
        .list_users()
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "users": users })))
}

async fn api_admin_create_user(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _admin = require_admin(&state, &jar, &headers)?;
    let username =
        auth::validate_username(&req.username).map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
    if req.password.len() < 8 {
        return Err(err_resp(StatusCode::BAD_REQUEST, "Passwort mindestens 8 Zeichen."));
    }
    let role = if req.role == "admin" { "admin" } else { "user" };
    let hash =
        auth::hash_password(&req.password).map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let user = state
        .db
        .create_user(
            &username,
            req.display_name.as_deref().unwrap_or(&username),
            role,
            req.default_ssh_user.as_deref().unwrap_or("root"),
            &hash,
        )
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({ "user": user })))
}

async fn api_admin_update_user(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _admin = require_admin(&state, &jar, &headers)?;
    let new_hash = match req.new_password.as_deref() {
        Some(pw) => {
            if pw.len() < 8 {
                return Err(err_resp(
                    StatusCode::BAD_REQUEST,
                    "Das neue Passwort muss mindestens 8 Zeichen lang sein.",
                ));
            }
            Some(
                auth::hash_password(pw)
                    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?,
            )
        }
        None => None,
    };
    let role = match req.role.as_deref() {
        Some("admin") => Some("admin"),
        Some("user") => Some("user"),
        _ => None,
    };
    let updated = state
        .db
        .update_user(
            &id,
            req.display_name.as_deref(),
            role,
            req.default_ssh_user.as_deref(),
            req.active,
            new_hash.as_deref(),
        )
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "Benutzer nicht gefunden."))?;
    Ok(Json(json!({ "user": updated })))
}

async fn api_admin_delete_user(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let admin = require_admin(&state, &jar, &headers)?;
    if admin.id == id {
        return Err(err_resp(StatusCode::BAD_REQUEST, "Eigenes Admin-Konto nicht löschbar."));
    }
    state
        .db
        .delete_user(&id)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({ "ok": true })))
}

async fn api_list_commands(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(query): Query<ListCommandsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let include_disabled_own = query.all.as_deref() == Some("1");
    let commands = state
        .db
        .list_accessible_commands(&user.id, include_disabled_own)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "commands": commands })))
}

async fn api_create_command(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<CreateCommandRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    if req.name.trim().is_empty() {
        return Err(err_resp(StatusCode::BAD_REQUEST, "Bezeichnung ist ein Pflichtfeld."));
    }

    let is_chain = req.kind.as_deref() == Some("chain");
    let stop_on_error = req.stop_on_error.unwrap_or(true);

    let (kind, compiled_cmd, steps, min_timeout) = if is_chain {
        let raw_steps = req.steps.unwrap_or_default();
        let (compiled, cleaned_steps, total_sleep) =
            ssh::compile_command_chain(&raw_steps, stop_on_error)
                .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
        ("chain", compiled, cleaned_steps, total_sleep.saturating_add(10))
    } else {
        let single = req.command.unwrap_or_default();
        if single.trim().is_empty() {
            return Err(err_resp(StatusCode::BAD_REQUEST, "SSH-Befehl ist ein Pflichtfeld."));
        }
        ("single", single.trim().to_string(), Vec::new(), 5)
    };

    let is_admin = user.role == "admin";
    let shared_all = is_admin && req.shared_with_all.unwrap_or(false);
    let shared_ids = if is_admin {
        req.shared_with_user_ids.unwrap_or_default()
    } else {
        Vec::new()
    };

    let timeout = req.timeout_sec.unwrap_or(30).max(min_timeout).clamp(5, 3600);
    let enabled = req.enabled.unwrap_or(true);
    let cmd = state
        .db
        .create_command(
            &user.id,
            req.name.trim(),
            req.category.as_deref().unwrap_or("Allgemein").trim(),
            kind,
            &compiled_cmd,
            &steps,
            stop_on_error,
            req.description.as_deref().unwrap_or("").trim(),
            timeout,
            enabled,
            &user.username,
            shared_all,
            &shared_ids,
        )
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "command": cmd })))
}

async fn api_update_command(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<UpdateCommandRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let Some(existing) = state
        .db
        .get_command(&id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
    else {
        return Err(err_resp(StatusCode::NOT_FOUND, "Befehl nicht gefunden."));
    };
    if existing.user_id != user.id {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "Sie können nur selbst angelegte SSH-Befehle bearbeiten.",
        ));
    }

    let next_name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&existing.name);
    let next_category = req
        .category
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&existing.category);
    let next_kind = req.kind.as_deref().unwrap_or(&existing.kind);
    let next_stop = req.stop_on_error.unwrap_or(existing.stop_on_error);
    let next_desc = req
        .description
        .as_deref()
        .map(str::trim)
        .unwrap_or(&existing.description);
    let next_enabled = req.enabled.unwrap_or(existing.enabled);

    let (compiled_cmd, cleaned_steps, min_timeout) = if next_kind == "chain" {
        let raw_steps = req.steps.unwrap_or(existing.steps);
        let (compiled, steps, total_sleep) = ssh::compile_command_chain(&raw_steps, next_stop)
            .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
        (compiled, steps, total_sleep.saturating_add(10))
    } else {
        let cmd_text = req
            .command
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(&existing.command)
            .to_string();
        (cmd_text, Vec::new(), 5)
    };

    let next_timeout = req
        .timeout_sec
        .unwrap_or(existing.timeout_sec)
        .max(min_timeout)
        .clamp(5, 3600);

    let updated = state
        .db
        .update_command(
            &id,
            &user.id,
            next_name,
            next_category,
            next_kind,
            &compiled_cmd,
            &cleaned_steps,
            next_stop,
            next_desc,
            next_timeout,
            next_enabled,
        )
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::FORBIDDEN, "Befehl konnte nicht aktualisiert werden."))?;

    Ok(Json(json!({ "command": updated })))
}

async fn api_load_presets(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let own = state
        .db
        .list_own_commands(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let existing_names: HashSet<String> = own.iter().map(|c| c.name.to_lowercase()).collect();

    let single_presets: [(&str, &str, &str, &str, u64); 5] = [
        (
            "Systemstatus & Laufzeit",
            "Diagnose",
            "hostnamectl --static && uptime && free -h",
            "Zeigt Hostname, Systemlaufzeit, Load-Average und Arbeitsspeicherbelegung an.",
            15,
        ),
        (
            "Festplattenbelegung prüfen",
            "Diagnose",
            "df -h --output=source,fstype,size,used,avail,pcent,target -x tmpfs -x devtmpfs",
            "Listet die Belegung aller lokalen Dateisysteme ohne temporäre Laufwerke auf.",
            15,
        ),
        (
            "Fehlgeschlagene Systemd-Dienste",
            "Dienste",
            "systemctl --failed --no-pager",
            "Prüft, ob unter Debian Systemd-Units im Fehlerzustand stehen.",
            20,
        ),
        (
            "Verfügbare APT-Updates prüfen",
            "Wartung",
            "apt list --upgradable 2>/dev/null",
            "Listet ausstehende Paketaktualisierungen auf dem Debian-Zielserver auf.",
            30,
        ),
        (
            "Offene Netzwerk-Ports (ss)",
            "Netzwerk",
            "ss -tulpen",
            "Zeigt alle aktiven TCP- und UDP-Listener-Sockets samt Prozesszuordnung an.",
            15,
        ),
    ];

    let mut added = Vec::new();
    for (name, category, cmd_text, desc, timeout_sec) in single_presets {
        if !existing_names.contains(&name.to_lowercase()) {
            if let Ok(created) = state.db.create_command(
                &user.id,
                name,
                category,
                "single",
                cmd_text,
                &[],
                true,
                desc,
                timeout_sec,
                true,
                &user.username,
                false,
                &[],
            ) {
                added.push(created);
            }
        }
    }

    let chain_presets = [
        (
            "Nginx prüfen, neu laden & verifizieren",
            "Dienste",
            vec![
                CommandStep { command: "nginx -t".into(), sleep_after_sec: 2 },
                CommandStep { command: "systemctl reload nginx".into(), sleep_after_sec: 3 },
                CommandStep { command: "systemctl is-active nginx".into(), sleep_after_sec: 0 },
            ],
            "Befehlskette: Prüft die Nginx-Konfiguration, wartet 2 s, lädt neu, wartet 3 s und verifiziert den Dienststatus.",
            30u64,
        ),
        (
            "APT-Paketlisten aktualisieren & Updates prüfen",
            "Wartung",
            vec![
                CommandStep { command: "apt-get update -qq".into(), sleep_after_sec: 2 },
                CommandStep { command: "apt list --upgradable 2>/dev/null".into(), sleep_after_sec: 0 },
            ],
            "Befehlskette: Aktualisiert den APT-Index, pausiert 2 s und listet verfügbare Debian-Updates auf.",
            60u64,
        ),
    ];

    for (name, category, steps, desc, timeout_sec) in chain_presets {
        if !existing_names.contains(&name.to_lowercase()) {
            if let Ok((compiled, cleaned, _)) = ssh::compile_command_chain(&steps, true) {
                if let Ok(created) = state.db.create_command(
                    &user.id,
                    name,
                    category,
                    "chain",
                    &compiled,
                    &cleaned,
                    true,
                    desc,
                    timeout_sec,
                    true,
                    &user.username,
                    false,
                    &[],
                ) {
                    added.push(created);
                }
            }
        }
    }

    let commands = state
        .db
        .list_accessible_commands(&user.id, true)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "added": added, "commands": commands })))
}

async fn api_share_command(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<ShareUpdateRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let admin = require_admin(&state, &jar, &headers)?;
    let updated = state
        .db
        .update_command_sharing(&id, &admin.id, req.shared_with_all, &req.shared_with_user_ids)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::FORBIDDEN, "Sie können nur eigene SSH-Befehle teilen."))?;
    Ok(Json(json!({ "command": updated })))
}

async fn api_delete_command(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    if let Some(existing) = state
        .db
        .get_command(&id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
    {
        if existing.user_id != user.id {
            return Err(err_resp(
                StatusCode::FORBIDDEN,
                "Sie können nur selbst angelegte SSH-Befehle löschen.",
            ));
        }
    }
    state
        .db
        .delete_command(&id, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "ok": true })))
}

async fn api_list_servers(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let servers = state
        .db
        .list_accessible_servers(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "servers": servers })))
}

async fn api_create_server(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<CreateServerRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let ip = ssh::validate_ip(&req.ip_address).map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
    let bmc_ip = match req.bmc_ip_address.as_deref().map(str::trim) {
        Some(v) if !v.is_empty() => {
            ssh::validate_ip(v).map_err(|e| err_resp(StatusCode::BAD_REQUEST, format!("BMC-IP 1: {e}")))?
        }
        _ => String::new(),
    };
    let bmc_ip2 = match req.bmc_ip_address2.as_deref().map(str::trim) {
        Some(v) if !v.is_empty() => {
            ssh::validate_ip(v).map_err(|e| err_resp(StatusCode::BAD_REQUEST, format!("BMC-IP 2: {e}")))?
        }
        _ => String::new(),
    };
    let ssh_user = ssh::validate_ssh_user(req.ssh_user.as_deref().unwrap_or(&user.default_ssh_user))
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
    let label = req
        .label
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| ip.clone());
    let is_admin = user.role == "admin";
    let shared_all = is_admin && req.shared_with_all.unwrap_or(false);
    let shared_ids = if is_admin {
        req.shared_with_user_ids.unwrap_or_default()
    } else {
        Vec::new()
    };
    let ping_enabled = req.ping_enabled.unwrap_or(true);
    let server = state
        .db
        .create_server(
            &user.id,
            &user.username,
            label.trim(),
            &ip,
            &bmc_ip,
            &bmc_ip2,
            req.port.unwrap_or(22),
            &ssh_user,
            req.notes.as_deref().unwrap_or(""),
            ping_enabled,
            shared_all,
            &shared_ids,
        )
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Initial-Ping nur auslösen, wenn global, für Benutzer und für diese IP aktiviert
    if server.ping_enabled && state.db.get_ping_allowed() && user.ping_enabled {
        let bg_state = Arc::clone(&state);
        let bg_srv = server.clone();
        tokio::spawn(async move {
            let st = ping::check_server_reachability(&bg_srv).await;
            if bg_state.db.get_ping_allowed() && bg_srv.ping_enabled {
                let mut guard = bg_state.ping.write().await;
                guard.statuses.insert(bg_srv.id, st);
            }
        });
    }

    Ok(Json(json!({ "server": server })))
}

async fn api_update_server(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<UpdateServerRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let Some(existing) = state
        .db
        .get_accessible_server(&id, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
    else {
        return Err(err_resp(StatusCode::NOT_FOUND, "Server nicht gefunden."));
    };
    if existing.user_id != user.id {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "Sie können nur selbst angelegte Server (IPs) bearbeiten.",
        ));
    }
    let ip = match req.ip_address.as_deref() {
        Some(v) => ssh::validate_ip(v).map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?,
        None => existing.ip_address,
    };
    let bmc_ip = match req.bmc_ip_address.as_deref().map(str::trim) {
        Some("") => String::new(),
        Some(v) => {
            ssh::validate_ip(v).map_err(|e| err_resp(StatusCode::BAD_REQUEST, format!("BMC-IP 1: {e}")))?
        }
        None => existing.bmc_ip_address,
    };
    let bmc_ip2 = match req.bmc_ip_address2.as_deref().map(str::trim) {
        Some("") => String::new(),
        Some(v) => {
            ssh::validate_ip(v).map_err(|e| err_resp(StatusCode::BAD_REQUEST, format!("BMC-IP 2: {e}")))?
        }
        None => existing.bmc_ip_address2,
    };
    let ssh_user = match req.ssh_user.as_deref() {
        Some(v) => ssh::validate_ssh_user(v).map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?,
        None => existing.ssh_user,
    };
    let label = req
        .label
        .map(|v| {
            let trimmed = v.trim().to_string();
            if trimmed.is_empty() {
                ip.clone()
            } else {
                trimmed
            }
        })
        .unwrap_or(existing.label);
    let port = req.port.unwrap_or(existing.port).clamp(1, 65535);
    let notes = req.notes.unwrap_or(existing.notes);
    let ping_enabled = req.ping_enabled.unwrap_or(existing.ping_enabled);

    let updated = state
        .db
        .update_server(
            &id,
            &user.id,
            &label,
            &ip,
            &bmc_ip,
            &bmc_ip2,
            port,
            &ssh_user,
            notes.trim(),
            ping_enabled,
        )
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::FORBIDDEN, "Server konnte nicht aktualisiert werden."))?;

    if !updated.ping_enabled {
        let mut guard = state.ping.write().await;
        guard.statuses.remove(&updated.id);
    } else if state.db.get_ping_allowed() && user.ping_enabled {
        let bg_state = Arc::clone(&state);
        let bg_srv = updated.clone();
        tokio::spawn(async move {
            let st = ping::check_server_reachability(&bg_srv).await;
            if bg_state.db.get_ping_allowed() && bg_srv.ping_enabled {
                let mut guard = bg_state.ping.write().await;
                guard.statuses.insert(bg_srv.id, st);
            }
        });
    }

    Ok(Json(json!({ "server": updated })))
}

async fn api_check_bmc(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    body: Option<Json<CheckBmcRequest>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let Some(server) = state
        .db
        .get_accessible_server(&id, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
    else {
        return Err(err_resp(StatusCode::NOT_FOUND, "Server nicht gefunden."));
    };
    let req_slot = body.and_then(|Json(b)| b.slot);
    let slot: u8 = match req_slot {
        Some(2) => 2,
        Some(1) => 1,
        _ => {
            if !server.bmc_ip_address.trim().is_empty() {
                1
            } else {
                2
            }
        }
    };
    let target_bmc = if slot == 2 {
        server.bmc_ip_address2.trim()
    } else {
        server.bmc_ip_address.trim()
    };
    if target_bmc.is_empty() {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            format!("Für diesen Server ist keine BMC-IP {slot} hinterlegt."),
        ));
    }
    let result = ping::check_bmc_https(&server.id, slot, target_bmc).await;
    Ok(Json(json!({ "result": result })))
}

async fn api_share_server(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<ShareUpdateRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let admin = require_admin(&state, &jar, &headers)?;
    let updated = state
        .db
        .update_server_sharing(&id, &admin.id, req.shared_with_all, &req.shared_with_user_ids)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::FORBIDDEN, "Sie können nur eigene Server (IPs) teilen."))?;
    Ok(Json(json!({ "server": updated })))
}

async fn api_delete_server(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    state
        .db
        .delete_server(&id, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "ok": true })))
}

async fn api_list_certs(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let certs = state
        .db
        .list_accessible_certificates(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "certificates": certs })))
}

async fn api_upload_cert(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<UploadCertBundleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let clean_cert = req.cert_content.as_deref().unwrap_or("").trim();
    let inspection = ssh::inspect_certificate_bundle(
        &req.private_key_content,
        &req.public_key_content,
        if clean_cert.is_empty() {
            None
        } else {
            Some(clean_cert)
        },
    )
    .await
    .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;

    let (enc, nonce) = state
        .vault
        .encrypt(req.private_key_content.as_bytes())
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let is_admin = user.role == "admin";
    let shared_all = is_admin && req.shared_with_all.unwrap_or(false);
    let shared_ids = if is_admin {
        req.shared_with_user_ids.unwrap_or_default()
    } else {
        Vec::new()
    };

    let cert_file_name = if clean_cert.is_empty() {
        ""
    } else {
        req.cert_file_name
            .as_deref()
            .unwrap_or("zertifikat-cert.pub")
    };

    let (saved, replaced) = state
        .db
        .save_certificate(
            &user.id,
            &user.username,
            req.name.as_deref().unwrap_or(&inspection.key_id),
            req.private_key_file_name
                .as_deref()
                .unwrap_or("zertifikat"),
            req.public_key_file_name
                .as_deref()
                .unwrap_or("zertifikat.pub"),
            cert_file_name,
            &enc,
            &nonce,
            &req.public_key_content,
            clean_cert,
            &inspection,
            shared_all,
            &shared_ids,
        )
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(json!({ "certificate": saved, "replaced": replaced })))
}

async fn api_generate_test_cert(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<GenerateTestCertRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let key_id = req
        .key_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(64).collect::<String>())
        .unwrap_or_else(|| format!("{}-trixie-cert", user.username));
    let principals = req.principals.unwrap_or_else(|| {
        let mut p = vec![user.default_ssh_user.clone()];
        if !p.iter().any(|x| x == "deploy") {
            p.push("deploy".into());
        }
        p
    });
    let generated = ssh::generate_test_cert_bundle(&key_id, &principals)
        .await
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({
        "privateKey": generated.private_key,
        "publicKey": generated.public_key,
        "certificate": generated.certificate,
        "caPublicKey": generated.ca_public_key
    })))
}

async fn api_share_cert(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<ShareUpdateRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let admin = require_admin(&state, &jar, &headers)?;
    let updated = state
        .db
        .update_certificate_sharing(&id, &admin.id, req.shared_with_all, &req.shared_with_user_ids)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::FORBIDDEN, "Sie können nur eigene Zertifikatspakete teilen."))?;
    Ok(Json(json!({ "certificate": updated })))
}

async fn api_delete_cert(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    state
        .db
        .delete_certificate(&id, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "ok": true })))
}

async fn api_v1_upload_cert(
    State(state): State<SharedState>,
    headers: HeaderMap,
    req: AxumRequest,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let api_key = extract_api_key(&headers).ok_or_else(|| {
        err_resp(
            StatusCode::UNAUTHORIZED,
            "Ungültiger oder fehlender API-Schlüssel. Senden Sie ihn als Header \"X-API-Key: sshc_...\" oder \"Authorization: Bearer sshc_...\".",
        )
    })?;
    if !api_key.starts_with("sshc_") || api_key.len() < 20 {
        return Err(err_resp(
            StatusCode::UNAUTHORIZED,
            "Ungültiger API-Schlüssel.",
        ));
    }
    let key_hash = hash_api_key(&api_key);
    let user = state
        .db
        .user_by_api_key_hash(&key_hash)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::UNAUTHORIZED, "Ungültiger oder widerrufener API-Schlüssel."))?;

    let mut bundle_name = String::new();
    let mut priv_file = "zertifikat".to_string();
    let mut pub_file = "zertifikat.pub".to_string();
    let mut cert_file = "zertifikat-cert.pub".to_string();
    let mut priv_content = String::new();
    let mut pub_content = String::new();
    let mut cert_content = String::new();

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    if content_type.contains("multipart/form-data") {
        let mut multipart = Multipart::from_request(req, &state)
            .await
            .map_err(|e| err_resp(StatusCode::BAD_REQUEST, format!("Ungültige Multipart-Anfrage: {e}")))?;
        while let Some(field) = multipart
            .next_field()
            .await
            .map_err(|e| err_resp(StatusCode::BAD_REQUEST, format!("Fehler beim Lesen des Uploads: {e}")))?
        {
            let field_name = field.name().unwrap_or("").to_string();
            let file_name = field.file_name().map(|f| {
                Path::new(f)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(f)
                    .to_string()
            });
            let text = field
                .text()
                .await
                .map_err(|e| err_resp(StatusCode::BAD_REQUEST, format!("Ungültige UTF-8-Datei: {e}")))?;

            match field_name.as_str() {
                "name" | "label" => {
                    if !text.trim().is_empty() {
                        bundle_name = text.trim().to_string();
                    }
                }
                "private_key" | "privateKey" | "zertifikat" | "key" => {
                    if !text.trim().is_empty() {
                        priv_content = text;
                        if let Some(f) = file_name {
                            if !f.is_empty() {
                                priv_file = f;
                            }
                        }
                    }
                }
                "public_key" | "publicKey" | "zertifikat_pub" | "pub" => {
                    if !text.trim().is_empty() {
                        pub_content = text;
                        if let Some(f) = file_name {
                            if !f.is_empty() {
                                pub_file = f;
                            }
                        }
                    }
                }
                "cert" | "certificate" | "cert_pub" | "zertifikat_cert" | "certContent" => {
                    if !text.trim().is_empty() {
                        cert_content = text;
                        if let Some(f) = file_name {
                            if !f.is_empty() {
                                cert_file = f;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    } else {
        let Json(body) = Json::<UploadCertBundleRequest>::from_request(req, &state)
            .await
            .map_err(|e| err_resp(StatusCode::BAD_REQUEST, format!("Ungültige JSON-Anfrage: {e}")))?;
        bundle_name = body.name.unwrap_or_default().trim().to_string();
        if let Some(f) = body.private_key_file_name {
            if !f.trim().is_empty() {
                priv_file = f.trim().to_string();
            }
        }
        if let Some(f) = body.public_key_file_name {
            if !f.trim().is_empty() {
                pub_file = f.trim().to_string();
            }
        }
        if let Some(f) = body.cert_file_name {
            if !f.trim().is_empty() {
                cert_file = f.trim().to_string();
            }
        }
        priv_content = body.private_key_content;
        pub_content = body.public_key_content;
        cert_content = body.cert_content.unwrap_or_default();
    }

    if priv_content.trim().is_empty() || pub_content.trim().is_empty() {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Erforderliche Felder fehlen: \"private_key\" (zertifikat) und \"public_key\" (zertifikat.pub). Optional: \"cert\" (zertifikat-cert.pub) und \"name\".",
        ));
    }

    let clean_cert = cert_content.trim();
    let inspection = ssh::inspect_certificate_bundle(
        &priv_content,
        &pub_content,
        if clean_cert.is_empty() {
            None
        } else {
            Some(clean_cert)
        },
    )
    .await
    .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;

    let (enc, nonce) = state
        .vault
        .encrypt(priv_content.as_bytes())
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let effective_name = if !bundle_name.is_empty() {
        bundle_name
    } else if !inspection.key_id.is_empty() {
        inspection.key_id.clone()
    } else {
        priv_file
            .trim_end_matches(".pem")
            .trim_end_matches(".key")
            .to_string()
    };

    let effective_cert_file = if clean_cert.is_empty() {
        ""
    } else {
        cert_file.as_str()
    };

    let (saved, replaced) = state
        .db
        .save_certificate(
            &user.id,
            &user.username,
            &effective_name,
            &priv_file,
            &pub_file,
            effective_cert_file,
            &enc,
            &nonce,
            &pub_content,
            clean_cert,
            &inspection,
            false,
            &[],
        )
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let status = if replaced {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((
        status,
        Json(json!({ "ok": true, "replaced": replaced, "certificate": saved })),
    ))
}

async fn api_execute(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<ExecuteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let cmd = state
        .db
        .get_accessible_command(&req.command_id, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "Befehl nicht gefunden oder deaktiviert."))?;

    let cert = state
        .db
        .get_accessible_certificate_secret(&req.certificate_id, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "Zertifikatspaket nicht gefunden."))?;

    if req.targets.is_empty() || req.targets.len() > 20 {
        return Err(err_resp(StatusCode::BAD_REQUEST, "1 bis 20 Ziel-IPs zulässig."));
    }

    let mut logs = Vec::new();
    for target in req.targets {
        let (ip, port, ssh_user, label) = if let Some(srv_id) = target.server_id {
            let srv = state
                .db
                .get_accessible_server(&srv_id, &user.id)
                .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
                .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "Server nicht gefunden."))?;
            (srv.ip_address, srv.port, srv.ssh_user, srv.label)
        } else {
            let ip = ssh::validate_ip(target.ip_address.as_deref().unwrap_or(""))
                .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
            let ssh_u = ssh::validate_ssh_user(
                target.ssh_user.as_deref().unwrap_or(&user.default_ssh_user),
            )
            .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
            let lbl = ip.clone();
            (ip, target.port.unwrap_or(22), ssh_u, lbl)
        };

        let plain_key = state
            .vault
            .decrypt(&cert.private_key_enc, &cert.private_key_nonce)
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

        let result = ssh::run_ssh_command(&ip, port, &ssh_user, &cmd, &cert, plain_key)
            .await
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

        let cert_key_id = if cert.key_id.is_empty() {
            cert.name.clone()
        } else {
            cert.key_id.clone()
        };

        let log = ExecutionLog {
            id: Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            username: user.username.clone(),
            command_id: cmd.id.clone(),
            command_name: cmd.name.clone(),
            command_text: cmd.command.clone(),
            target_ip: ip,
            target_port: port,
            ssh_user,
            server_label: label,
            certificate_id: cert.id.clone(),
            certificate_key_id: cert_key_id,
            mode: "openssh-live".into(),
            ssh_invocation: result.ssh_invocation,
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
            duration_ms: result.duration_ms,
            executed_at: Utc::now().to_rfc3339(),
        };
        let _ = state.db.insert_log(&log);
        logs.push(log);
    }

    Ok(Json(json!({ "results": logs })))
}

async fn api_list_logs(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let logs = state
        .db
        .list_logs(&user)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "logs": logs })))
}

async fn build_dashboard_status_json(
    state: &SharedState,
    user: &UserPublic,
) -> Result<serde_json::Value, ApiError> {
    let global_ping_allowed = state.db.get_ping_allowed();
    let interval_sec = state.db.get_ping_interval_sec();
    let user_ping_enabled = user.ping_enabled;
    let effective_active = global_ping_allowed && user_ping_enabled;

    let servers = state
        .db
        .list_accessible_servers(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let guard = state.ping.read().await;
    let mut user_statuses = serde_json::Map::new();
    if effective_active {
        for srv in servers {
            if !srv.ping_enabled {
                continue;
            }
            if let Some(st) = guard.statuses.get(&srv.id) {
                user_statuses.insert(
                    srv.id,
                    serde_json::to_value(st).unwrap_or(serde_json::Value::Null),
                );
            }
        }
    }
    let ping_mode = if Path::new("/bin/ping").exists() || Path::new("/usr/bin/ping").exists() {
        "icmp-ping"
    } else {
        "tcp-ping"
    };
    Ok(json!({
        "statuses": user_statuses,
        "intervalSec": interval_sec,
        "lastCycleAt": if effective_active { guard.last_cycle_at.clone() } else { None },
        "nextCycleAt": if effective_active { guard.next_cycle_at.clone() } else { None },
        "pingMode": ping_mode,
        "globalPingAllowed": global_ping_allowed,
        "userPingEnabled": user_ping_enabled
    }))
}

async fn api_dashboard_status(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    Ok(Json(build_dashboard_status_json(&state, &user).await?))
}

async fn api_dashboard_ping(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<ManualPingRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    if !state.db.get_ping_allowed() {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "Anpingen wurde vom Administrator global verboten.",
        ));
    }
    if !user.ping_enabled {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Anpingen ist für Ihr Konto deaktiviert.",
        ));
    }
    let servers = state
        .db
        .list_accessible_servers(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if let Some(ref id) = req.server_id {
        if let Some(srv) = servers.iter().find(|s| s.id == *id) {
            if !srv.ping_enabled {
                return Err(err_resp(
                    StatusCode::BAD_REQUEST,
                    "Anpingen ist für diese IP deaktiviert.",
                ));
            }
        }
    }
    let targets: Vec<UserServer> = match req.server_id {
        Some(ref id) => servers
            .into_iter()
            .filter(|s| s.id == *id && s.ping_enabled)
            .collect(),
        None => servers.into_iter().filter(|s| s.ping_enabled).collect(),
    };

    for srv in targets {
        let status = ping::check_server_reachability(&srv).await;
        if state.db.get_ping_allowed() && srv.ping_enabled {
            let mut guard = state.ping.write().await;
            guard.statuses.insert(srv.id.clone(), status);
        }
    }

    Ok(Json(build_dashboard_status_json(&state, &user).await?))
}

async fn api_user_ping_settings(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<UserPingSettingsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let updated_user = state
        .db
        .set_user_ping_enabled(&user.id, req.ping_enabled)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "Benutzer nicht gefunden."))?;
    if req.ping_enabled && state.db.get_ping_allowed() {
        let bg_state = Arc::clone(&state);
        let uid = updated_user.id.clone();
        tokio::spawn(async move {
            if let Ok(servers) = bg_state.db.list_accessible_servers(&uid) {
                for srv in servers.into_iter().filter(|s| s.ping_enabled) {
                    let st = ping::check_server_reachability(&srv).await;
                    if bg_state.db.get_ping_allowed() {
                        let mut guard = bg_state.ping.write().await;
                        guard.statuses.insert(srv.id, st);
                    }
                }
            }
        });
    }
    let dashboard_status = build_dashboard_status_json(&state, &updated_user).await?;
    Ok(Json(json!({
        "user": updated_user,
        "dashboardStatus": dashboard_status
    })))
}

async fn api_admin_ping_settings(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<AdminPingSettingsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let admin = require_admin(&state, &jar, &headers)?;
    let (ping_allowed, ping_interval_sec) = state
        .db
        .set_global_ping_settings(req.ping_allowed, req.ping_interval_sec)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;

    {
        let mut guard = state.ping.write().await;
        if !ping_allowed {
            guard.statuses.clear();
            guard.next_cycle_at = None;
        } else {
            guard.next_cycle_at =
                Some((Utc::now() + chrono::Duration::seconds(ping_interval_sec as i64)).to_rfc3339());
        }
    }
    state.ping_notify.notify_one();

    let dashboard_status = build_dashboard_status_json(&state, &admin).await?;
    Ok(Json(json!({
        "settings": {
            "instanceName": state.db.get_instance_name(),
            "initializedAt": state.db.get_initialized_at(),
            "pingAllowed": ping_allowed,
            "pingIntervalSec": ping_interval_sec
        },
        "dashboardStatus": dashboard_status
    })))
}

async fn api_execute_batch(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<BatchExecuteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let cert = state
        .db
        .get_accessible_certificate_secret(&req.certificate_id, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "Zertifikatspaket nicht gefunden."))?;

    if req.jobs.is_empty() || req.jobs.len() > 50 {
        return Err(err_resp(StatusCode::BAD_REQUEST, "1 bis 50 Aufträge zulässig."));
    }

    let mut logs = Vec::new();
    for job in req.jobs {
        let srv = state
            .db
            .get_accessible_server(&job.server_id, &user.id)
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
            .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "Server nicht gefunden."))?;
        let cmd = state
            .db
            .get_accessible_command(&job.command_id, &user.id)
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
            .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "Befehl nicht verfügbar."))?;

        let plain_key = state
            .vault
            .decrypt(&cert.private_key_enc, &cert.private_key_nonce)
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

        let result = ssh::run_ssh_command(&srv.ip_address, srv.port, &srv.ssh_user, &cmd, &cert, plain_key)
            .await
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

        let cert_key_id = if cert.key_id.is_empty() {
            cert.name.clone()
        } else {
            cert.key_id.clone()
        };

        let log = ExecutionLog {
            id: Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            username: user.username.clone(),
            command_id: cmd.id.clone(),
            command_name: cmd.name.clone(),
            command_text: cmd.command.clone(),
            target_ip: srv.ip_address,
            target_port: srv.port,
            ssh_user: srv.ssh_user,
            server_label: srv.label,
            certificate_id: cert.id.clone(),
            certificate_key_id: cert_key_id,
            mode: "openssh-live".into(),
            ssh_invocation: result.ssh_invocation,
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
            duration_ms: result.duration_ms,
            executed_at: Utc::now().to_rfc3339(),
        };
        let _ = state.db.insert_log(&log);
        logs.push(log);
    }

    Ok(Json(json!({ "results": logs })))
}

fn collect_source_files(root: &Path, dir: &Path, out: &mut Vec<serde_json::Value>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut items: Vec<_> = entries.flatten().collect();
    items.sort_by_key(|e| e.file_name());
    for entry in items {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("target") {
                continue;
            }
            collect_source_files(root, &path, out);
        } else if path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                let size = content.len();
                out.push(json!({ "path": rel, "size": size, "content": content }));
            }
        }
    }
}

async fn api_rust_project_files(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _ = current_user(&state, &jar, &headers)?;
    let src_root = PathBuf::from(
        std::env::var("SSH_CONSOLE_SRC_DIR")
            .or_else(|_| std::env::var("TRIXIESSH_SRC_DIR"))
            .unwrap_or_else(|_| "/opt/ssh-console/rust-src".into()),
    );
    let mut files = Vec::new();
    if src_root.exists() {
        collect_source_files(&src_root, &src_root, &mut files);
    }
    Ok(Json(json!({ "files": files })))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let data_dir = PathBuf::from(
        std::env::var("SSH_CONSOLE_DATA_DIR")
            .or_else(|_| std::env::var("TRIXIESSH_DATA_DIR"))
            .unwrap_or_else(|_| "/var/lib/ssh-console".into()),
    );
    std::fs::create_dir_all(&data_dir).expect("Datenverzeichnis konnte nicht erstellt werden");

    let db = Database::open(&data_dir.join("ssh-console.sqlite")).expect("SQLite-Datenbankfehler");
    let vault = Vault::load_or_create(&data_dir).expect("Vault-Initialisierungsfehler");
    let initial_allowed = db.get_ping_allowed();
    let initial_interval = db.get_ping_interval_sec();
    let ping_state = Arc::new(tokio::sync::RwLock::new(ping::PingState {
        statuses: std::collections::HashMap::new(),
        last_cycle_at: None,
        next_cycle_at: if initial_allowed {
            Some((Utc::now() + chrono::Duration::seconds(initial_interval as i64)).to_rfc3339())
        } else {
            None
        },
    }));
    let ping_notify = Arc::new(Notify::new());
    let state = Arc::new(AppState {
        db,
        vault,
        ping: ping_state,
        ping_notify,
    });

    // Hintergrund-Task: Dynamisches Ping-Intervall mit Admin-Sperre & Pro-IP-Steuerung
    let bg_state = Arc::clone(&state);
    tokio::spawn(async move {
        loop {
            let allowed = bg_state.db.get_ping_allowed();
            let interval_sec = bg_state.db.get_ping_interval_sec();

            if !allowed {
                {
                    let mut guard = bg_state.ping.write().await;
                    guard.statuses.clear();
                    guard.next_cycle_at = None;
                }
                bg_state.ping_notify.notified().await;
                continue;
            }

            if let Ok(servers) = bg_state.db.list_all_servers() {
                let now = Utc::now();
                let next = now + chrono::Duration::seconds(interval_sec as i64);
                let active_ids: HashSet<String> = servers
                    .iter()
                    .filter(|s| bg_state.db.should_ping_server(s))
                    .map(|s| s.id.clone())
                    .collect();
                {
                    let mut guard = bg_state.ping.write().await;
                    guard.last_cycle_at = Some(now.to_rfc3339());
                    guard.next_cycle_at = Some(next.to_rfc3339());
                    guard.statuses.retain(|k, _| active_ids.contains(k));
                }
                for srv in servers.into_iter().filter(|s| active_ids.contains(&s.id)) {
                    if !bg_state.db.get_ping_allowed() {
                        break;
                    }
                    let st = ping::check_server_reachability(&srv).await;
                    if bg_state.db.get_ping_allowed() && bg_state.db.should_ping_server(&srv) {
                        let mut guard = bg_state.ping.write().await;
                        guard.statuses.insert(srv.id, st);
                    }
                }
            }

            let sleep_sec = bg_state.db.get_ping_interval_sec();
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(sleep_sec)) => {}
                _ = bg_state.ping_notify.notified() => {}
            }
        }
    });

    let static_dir = PathBuf::from(
        std::env::var("SSH_CONSOLE_STATIC_DIR")
            .or_else(|_| std::env::var("TRIXIESSH_STATIC_DIR"))
            .unwrap_or_else(|_| "/opt/ssh-console/dist".into()),
    );
    let spa_service = ServeDir::new(&static_dir)
        .not_found_service(ServeFile::new(static_dir.join("index.html")));

    let app = Router::new()
        .route("/api/status", get(api_status))
        .route("/api/setup", post(api_setup))
        .route("/api/auth/login", post(api_login))
        .route("/api/auth/logout", post(api_logout))
        .route("/api/auth/change-password", post(api_change_password))
        .route("/api/auth/api-keys", get(api_list_api_keys).post(api_create_api_key))
        .route("/api/auth/api-keys/:id", delete(api_delete_api_key))
        .route("/api/admin/users", get(api_admin_list_users).post(api_admin_create_user))
        .route(
            "/api/admin/users/:id",
            patch(api_admin_update_user).delete(api_admin_delete_user),
        )
        .route("/api/admin/ping-settings", patch(api_admin_ping_settings))
        .route("/api/commands", get(api_list_commands).post(api_create_command))
        .route("/api/commands/presets", post(api_load_presets))
        .route(
            "/api/commands/:id",
            patch(api_update_command).delete(api_delete_command),
        )
        .route("/api/commands/:id/share", patch(api_share_command))
        .route("/api/admin/commands", post(api_create_command))
        .route("/api/admin/commands/presets", post(api_load_presets))
        .route(
            "/api/admin/commands/:id",
            patch(api_update_command).delete(api_delete_command),
        )
        .route("/api/servers", get(api_list_servers).post(api_create_server))
        .route("/api/servers/:id", patch(api_update_server).delete(api_delete_server))
        .route("/api/servers/:id/check-bmc", post(api_check_bmc))
        .route("/api/servers/:id/share", patch(api_share_server))
        .route("/api/certificates", get(api_list_certs).post(api_upload_cert))
        .route("/api/certificates/generate-test", post(api_generate_test_cert))
        .route("/api/certificates/:id", delete(api_delete_cert))
        .route("/api/certificates/:id/share", patch(api_share_cert))
        .route("/api/v1/certificates/upload", post(api_v1_upload_cert))
        .route("/api/execute", post(api_execute))
        .route("/api/execute/batch", post(api_execute_batch))
        .route("/api/dashboard/status", get(api_dashboard_status))
        .route("/api/dashboard/ping", post(api_dashboard_ping))
        .route("/api/dashboard/ping-settings", patch(api_user_ping_settings))
        .route("/api/logs", get(api_list_logs))
        .route("/api/rust-project/files", get(api_rust_project_files))
        .fallback_service(spa_service)
        .with_state(state);

    let bind = std::env::var("SSH_CONSOLE_BIND")
        .or_else(|_| std::env::var("TRIXIESSH_BIND"))
        .unwrap_or_else(|_| "0.0.0.0:3000".into());
    let addr: SocketAddr = bind.parse().expect("Ungültige Bind-Adresse");
    tracing::info!("SSH Console Rust-Server aktiv auf http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
