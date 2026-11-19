mod auth;
mod crypto;
mod db;
mod models;
mod ping;
mod ssh;

use axum::{
    extract::{Path as AxumPath, Query, State},
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
use serde::Deserialize;
use serde_json::json;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tower_http::services::{ServeDir, ServeFile};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const SESSION_COOKIE: &str = "trixiessh_session";

struct AppState {
    db: Database,
    vault: Vault,
    ping: ping::SharedPingState,
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
            "initializedAt": state.db.get_initialized_at()
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
                "initializedAt": state.db.get_initialized_at()
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
            ssh::validate_ip(v).map_err(|e| err_resp(StatusCode::BAD_REQUEST, format!("BMC-IP: {e}")))?
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
    let server = state
        .db
        .create_server(
            &user.id,
            &user.username,
            label.trim(),
            &ip,
            &bmc_ip,
            req.port.unwrap_or(22),
            &ssh_user,
            req.notes.as_deref().unwrap_or(""),
            shared_all,
            &shared_ids,
        )
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Initial-Ping im Hintergrund auslösen
    let bg_state = Arc::clone(&state);
    let bg_srv = server.clone();
    tokio::spawn(async move {
        let st = ping::check_server_reachability(&bg_srv).await;
        let mut guard = bg_state.ping.write().await;
        guard.statuses.insert(bg_srv.id, st);
    });

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
            ssh::validate_ip(v).map_err(|e| err_resp(StatusCode::BAD_REQUEST, format!("BMC-IP: {e}")))?
        }
        None => existing.bmc_ip_address,
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

    let updated = state
        .db
        .update_server(&id, &user.id, &label, &ip, &bmc_ip, port, &ssh_user, notes.trim())
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::FORBIDDEN, "Server konnte nicht aktualisiert werden."))?;
    Ok(Json(json!({ "server": updated })))
}

async fn api_check_bmc(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let Some(server) = state
        .db
        .get_accessible_server(&id, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
    else {
        return Err(err_resp(StatusCode::NOT_FOUND, "Server nicht gefunden."));
    };
    if server.bmc_ip_address.trim().is_empty() {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Für diesen Server ist keine BMC-IP hinterlegt.",
        ));
    }
    let result = ping::check_bmc_https(&server.id, &server.bmc_ip_address).await;
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

async fn api_dashboard_status(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let servers = state
        .db
        .list_accessible_servers(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let guard = state.ping.read().await;
    let mut user_statuses = serde_json::Map::new();
    for srv in servers {
        if let Some(st) = guard.statuses.get(&srv.id) {
            user_statuses.insert(srv.id, serde_json::to_value(st).unwrap_or(serde_json::Value::Null));
        }
    }
    let ping_mode = if Path::new("/bin/ping").exists() || Path::new("/usr/bin/ping").exists() {
        "icmp-ping"
    } else {
        "tcp-ping"
    };
    Ok(Json(json!({
        "statuses": user_statuses,
        "intervalSec": 60,
        "lastCycleAt": guard.last_cycle_at,
        "nextCycleAt": guard.next_cycle_at,
        "pingMode": ping_mode
    })))
}

async fn api_dashboard_ping(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<ManualPingRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let servers = state
        .db
        .list_accessible_servers(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let targets: Vec<UserServer> = match req.server_id {
        Some(ref id) => servers.into_iter().filter(|s| s.id == *id).collect(),
        None => servers,
    };

    for srv in targets {
        let status = ping::check_server_reachability(&srv).await;
        let mut guard = state.ping.write().await;
        guard.statuses.insert(srv.id.clone(), status);
    }

    api_dashboard_status(State(state), jar, headers).await
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
        std::env::var("TRIXIESSH_SRC_DIR").unwrap_or_else(|_| "/opt/trixiessh/rust-src".into()),
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
        std::env::var("TRIXIESSH_DATA_DIR").unwrap_or_else(|_| "/var/lib/trixiessh".into()),
    );
    std::fs::create_dir_all(&data_dir).expect("Datenverzeichnis konnte nicht erstellt werden");

    let db = Database::open(&data_dir.join("trixiessh.sqlite")).expect("SQLite-Datenbankfehler");
    let vault = Vault::load_or_create(&data_dir).expect("Vault-Initialisierungsfehler");
    let ping_state = Arc::new(tokio::sync::RwLock::new(ping::PingState {
        statuses: std::collections::HashMap::new(),
        last_cycle_at: None,
        next_cycle_at: (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(),
    }));
    let state = Arc::new(AppState {
        db,
        vault,
        ping: ping_state,
    });

    // Hintergrund-Task: Ping aller Server im 60-Sekunden-Takt
    let bg_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            ticker.tick().await;
            if let Ok(servers) = bg_state.db.list_all_servers() {
                let now = Utc::now();
                let next = now + chrono::Duration::seconds(60);
                {
                    let mut guard = bg_state.ping.write().await;
                    guard.last_cycle_at = Some(now.to_rfc3339());
                    guard.next_cycle_at = next.to_rfc3339();
                }
                for srv in servers {
                    let st = ping::check_server_reachability(&srv).await;
                    let mut guard = bg_state.ping.write().await;
                    guard.statuses.insert(srv.id, st);
                }
            }
        }
    });

    let static_dir = PathBuf::from(
        std::env::var("TRIXIESSH_STATIC_DIR").unwrap_or_else(|_| "/opt/trixiessh/dist".into()),
    );
    let spa_service = ServeDir::new(&static_dir)
        .not_found_service(ServeFile::new(static_dir.join("index.html")));

    let app = Router::new()
        .route("/api/status", get(api_status))
        .route("/api/setup", post(api_setup))
        .route("/api/auth/login", post(api_login))
        .route("/api/auth/logout", post(api_logout))
        .route("/api/auth/change-password", post(api_change_password))
        .route("/api/admin/users", get(api_admin_list_users).post(api_admin_create_user))
        .route(
            "/api/admin/users/:id",
            patch(api_admin_update_user).delete(api_admin_delete_user),
        )
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
        .route("/api/execute", post(api_execute))
        .route("/api/execute/batch", post(api_execute_batch))
        .route("/api/dashboard/status", get(api_dashboard_status))
        .route("/api/dashboard/ping", post(api_dashboard_ping))
        .route("/api/logs", get(api_list_logs))
        .route("/api/rust-project/files", get(api_rust_project_files))
        .fallback_service(spa_service)
        .with_state(state);

    let bind = std::env::var("TRIXIESSH_BIND").unwrap_or_else(|_| "0.0.0.0:3000".into());
    let addr: SocketAddr = bind.parse().expect("Ungültige Bind-Adresse");
    tracing::info!("TrixieSSH Rust-Server aktiv auf http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
