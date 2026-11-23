mod auth;
mod auth_extra;
mod crypto;
mod db;
mod models;
mod ping;
mod shell;
mod ssh;

use axum::{
    extract::{
        FromRequest, Multipart, Path as AxumPath, Query, Request as AxumRequest, State,
        WebSocketUpgrade,
    },
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse},
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
use tokio::sync::{Mutex as AsyncMutex, Notify, Semaphore};
use tower_http::services::{ServeDir, ServeFile};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const SESSION_COOKIE: &str = "ssh_console_session";
const MAX_CONCURRENT_AUTO_PINGS: usize = 32;
const MAX_CONCURRENT_MANUAL_PINGS: usize = 24;
const MANUAL_PING_STAGGER_MS: u64 = 15;

pub(crate) struct AppState {
    pub(crate) data_dir: PathBuf,
    pub(crate) db: Database,
    vault: Vault,
    ping: ping::SharedPingState,
    ping_notify: Arc<Notify>,
    shell_tickets: shell::ShellTicketStore,
    auth_challenges: auth_extra::AuthChallengeStore,
}

type SharedState = Arc<AppState>;
type ApiError = (StatusCode, Json<serde_json::Value>);

#[derive(Debug, Deserialize, Default)]
struct ListCommandsQuery {
    all: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct SsoUrlQuery {
    mode: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct SsoCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
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

fn require_security_compliant(user: &UserPublic) -> Result<(), ApiError> {
    if user.must_setup_two_factor || user.must_setup_passkey {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Bitte richten Sie zuerst die vom Administrator vorgeschriebene 2FA bzw. den Passkey in Ihren Kontoeinstellungen ein.",
                "code": "SECURITY_SETUP_REQUIRED",
                "mustSetupTwoFactor": user.must_setup_two_factor,
                "mustSetupPasskey": user.must_setup_passkey
            })),
        ));
    }
    Ok(())
}

fn current_compliant_user(
    state: &SharedState,
    jar: &CookieJar,
    headers: &HeaderMap,
) -> Result<(UserPublic, String), ApiError> {
    let (user, token) = current_user(state, jar, headers)?;
    require_security_compliant(&user)?;
    Ok((user, token))
}

fn get_public_origin(headers: &HeaderMap) -> String {
    if let Ok(env_url) = std::env::var("SSH_CONSOLE_PUBLIC_URL")
        .or_else(|_| std::env::var("APP_URL"))
    {
        let clean = env_url.trim().trim_end_matches('/');
        if clean.starts_with("http://") || clean.starts_with("https://") {
            return clean.to_string();
        }
    }
    if let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| s.starts_with("http://") || s.starts_with("https://"))
    {
        return origin.trim_end_matches('/').to_string();
    }
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(str::trim)
        .filter(|s| *s == "http" || *s == "https")
        .unwrap_or("http");
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("localhost:3000");
    format!("{proto}://{host}")
}

fn get_sso_callback_url(headers: &HeaderMap) -> String {
    format!("{}/api/auth/sso/callback", get_public_origin(headers))
}

fn get_webauthn_context(headers: &HeaderMap) -> (String, String) {
    let origin = get_public_origin(headers);
    let after_scheme = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .unwrap_or("localhost");
    let host_port = after_scheme.split('/').next().unwrap_or("localhost");
    let rp_id = if host_port.starts_with('[') {
        host_port
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or("localhost")
            .to_lowercase()
    } else {
        host_port
            .split(':')
            .next()
            .unwrap_or("localhost")
            .to_lowercase()
    };
    (origin, rp_id)
}

fn serialize_public_settings(state: &SharedState) -> serde_json::Value {
    let policy = state.db.get_auth_policy();
    let sso_configured = policy.is_sso_configured();
    let local_disabled =
        policy.local_login_disabled && policy.sso_enabled && sso_configured && policy.sso_tested_at.is_some();
    json!({
        "instanceName": state.db.get_instance_name(),
        "initializedAt": state.db.get_initialized_at(),
        "pingAllowed": state.db.get_ping_allowed(),
        "pingIntervalSec": state.db.get_ping_interval_sec(),
        "pingOfflineThreshold": state.db.get_ping_offline_threshold(),
        "pingOfflineMultiplier": state.db.get_ping_offline_multiplier(),
        "ssoEnabled": policy.sso_enabled,
        "ssoProviderName": policy.sso_provider_name,
        "ssoAutoCreateUsers": policy.sso_auto_create_users,
        "ssoConfigured": sso_configured,
        "ssoTestedAt": policy.sso_tested_at,
        "localLoginDisabled": local_disabled,
        "twoFactorEnabled": policy.two_factor_enabled,
        "twoFactorEnforced": policy.two_factor_enabled && policy.two_factor_enforced,
        "passkeyEnabled": policy.passkey_enabled,
        "passkeyEnforced": policy.passkey_enabled && policy.passkey_enforced,
        "allowInsecureHostKey": policy.allow_insecure_host_key,
        "publicUrl": policy.public_url
    })
}

fn serialize_admin_auth_settings(state: &SharedState, headers: &HeaderMap) -> serde_json::Value {
    let policy = state.db.get_auth_policy();
    let sso_configured = policy.is_sso_configured();
    let local_disabled =
        policy.local_login_disabled && policy.sso_enabled && sso_configured && policy.sso_tested_at.is_some();
    json!({
        "ssoEnabled": policy.sso_enabled,
        "ssoProviderName": policy.sso_provider_name,
        "ssoIssuerUrl": policy.sso_issuer_url,
        "ssoAuthUrl": policy.sso_auth_url,
        "ssoTokenUrl": policy.sso_token_url,
        "ssoUserinfoUrl": policy.sso_userinfo_url,
        "ssoClientId": policy.sso_client_id,
        "ssoHasClientSecret": policy.sso_client_secret_enc.is_some(),
        "ssoScopes": policy.sso_scopes,
        "ssoAutoCreateUsers": policy.sso_auto_create_users,
        "ssoConfigured": sso_configured,
        "ssoTestedAt": policy.sso_tested_at,
        "localLoginDisabled": local_disabled,
        "twoFactorEnabled": policy.two_factor_enabled,
        "twoFactorEnforced": policy.two_factor_enabled && policy.two_factor_enforced,
        "passkeyEnabled": policy.passkey_enabled,
        "passkeyEnforced": policy.passkey_enabled && policy.passkey_enforced,
        "allowInsecureHostKey": policy.allow_insecure_host_key,
        "publicUrl": policy.public_url,
        "callbackUrl": get_sso_callback_url(headers)
    })
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn render_sso_callback_html(payload: serde_json::Value, title: &str, msg: &str) -> Html<String> {
    let safe_json = serde_json::to_string(&payload)
        .unwrap_or_else(|_| "{}".into())
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    let t = escape_html(title);
    let m = escape_html(msg);
    Html(format!(
        r#"<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{t}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 24px; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px 28px; max-width: 460px; width: 100%; box-shadow: 0 20px 50px rgba(0,0,0,0.4); }}
    h1 {{ font-size: 18px; margin: 0 0 8px 0; }}
    p {{ font-size: 14px; color: #94a3b8; margin: 0; line-height: 1.5; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{t}</h1>
    <p>{m}</p>
  </div>
  <script>
    (function () {{
      var data = {safe_json};
      try {{
        if (window.opener && !window.opener.closed) {{
          window.opener.postMessage(data, window.location.origin);
          window.close();
          return;
        }}
      }} catch (e) {{}}
      setTimeout(function () {{ window.location.replace('/'); }}, 900);
    }})();
  </script>
</body>
</html>"#
    ))
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
        "settings": serialize_public_settings(&state),
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
            "settings": serialize_public_settings(&state),
            "sessionToken": token
        })),
    ))
}

async fn api_login(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<serde_json::Value>), ApiError> {
    let policy = state.db.get_auth_policy();
    let local_disabled = policy.local_login_disabled
        && policy.sso_enabled
        && policy.is_sso_configured()
        && policy.sso_tested_at.is_some();
    if local_disabled {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "Die lokale Anmeldung wurde vom Administrator deaktiviert. Bitte melden Sie sich über SSO an.",
        ));
    }

    let clean = req.username.trim().to_lowercase();
    let Some((user, hash)) = state
        .db
        .find_user_for_login(&clean)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
    else {
        return Err(err_resp(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten."));
    };

    if user.auth_provider == "sso" {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "Dieses Konto nutzt SSO. Bitte melden Sie sich über den SSO-Anbieter an.",
        ));
    }

    if !auth::verify_password(&req.password, &hash) {
        return Err(err_resp(StatusCode::UNAUTHORIZED, "Ungültige Zugangsdaten."));
    }
    if !user.active {
        return Err(err_resp(StatusCode::FORBIDDEN, "Benutzerkonto ist deaktiviert."));
    }

    if policy.passkey_enabled && policy.passkey_enforced && user.passkey_count > 0 {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Passkey-Anmeldung ist vorgeschrieben. Bitte nutzen Sie die Schaltfläche „Mit Passkey anmelden“.",
                "code": "PASSKEY_REQUIRED"
            })),
        ));
    }

    if policy.two_factor_enabled && user.has_two_factor {
        let sec_keys = state
            .db
            .list_webauthn_credentials(&user.id, Some("security-key"))
            .unwrap_or_default();
        let has_totp = user.totp_enabled;
        let has_security_key = !sec_keys.is_empty();
        let (origin, rp_id) = get_webauthn_context(&headers);
        let (webauthn_challenge, webauthn_options) = if has_security_key {
            let (_cid, challenge) = state.auth_challenges.store_webauthn_challenge(
                Some(user.id.clone()),
                "security-key",
                "",
                &rp_id,
                &origin,
            );
            let allow_ids: Vec<String> = sec_keys.iter().map(|c| c.credential_id.clone()).collect();
            let opts = auth_extra::build_webauthn_auth_options(
                &rp_id,
                &challenge,
                Some(&allow_ids),
                false,
            );
            (Some(challenge), Some(opts))
        } else {
            (None, None)
        };
        let ticket = state
            .auth_challenges
            .create_2fa_ticket(&user.id, webauthn_challenge);
        return Ok((
            jar,
            Json(json!({
                "requiresTwoFactor": true,
                "ticket": ticket,
                "methods": {
                    "totp": has_totp,
                    "securityKey": has_security_key
                },
                "webauthnOptions": webauthn_options
            })),
        ));
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

async fn api_login_2fa(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<TwoFactorLoginRequest>,
) -> Result<(CookieJar, Json<serde_json::Value>), ApiError> {
    let ticket_clean = req.ticket.trim();
    if ticket_clean.is_empty() {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "2FA-Anmeldeticket fehlt oder ist abgelaufen.",
        ));
    }
    let Some(pending) = state.auth_challenges.peek_2fa_ticket(ticket_clean) else {
        return Err(err_resp(
            StatusCode::UNAUTHORIZED,
            "Die 2FA-Sitzung ist abgelaufen. Bitte melden Sie sich erneut an.",
        ));
    };
    let Some(user) = state
        .db
        .get_user_by_id(&pending.user_id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
    else {
        state.auth_challenges.consume_2fa_ticket(ticket_clean);
        return Err(err_resp(StatusCode::FORBIDDEN, "Benutzerkonto ist nicht verfügbar."));
    };
    if !user.active {
        state.auth_challenges.consume_2fa_ticket(ticket_clean);
        return Err(err_resp(StatusCode::FORBIDDEN, "Benutzerkonto ist deaktiviert."));
    }

    match req.method.as_str() {
        "totp" => {
            let code = req.code.as_deref().unwrap_or("");
            let Some((enc, nonce)) = state
                .db
                .get_user_totp_secret_enc(&user.id)
                .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
            else {
                return Err(err_resp(
                    StatusCode::UNAUTHORIZED,
                    "Authenticator-App ist nicht eingerichtet.",
                ));
            };
            let plain_bytes = state
                .vault
                .decrypt(&enc, &nonce)
                .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
            let secret = String::from_utf8(plain_bytes.to_vec())
                .map_err(|_| err_resp(StatusCode::INTERNAL_SERVER_ERROR, "TOTP-Schlüssel defekt."))?;
            if !auth_extra::verify_totp_code(&secret, code) {
                return Err(err_resp(
                    StatusCode::UNAUTHORIZED,
                    "Ungültiger Authenticator-Code. Bitte erneut versuchen.",
                ));
            }
        }
        "recovery" => {
            let code = req.code.as_deref().unwrap_or("").trim();
            if code.is_empty() {
                return Err(err_resp(
                    StatusCode::BAD_REQUEST,
                    "Bitte geben Sie einen Wiederherstellungscode ein.",
                ));
            }
            let hash = auth_extra::hash_recovery_code(code);
            let ok = state
                .db
                .consume_recovery_code(&user.id, &hash)
                .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
            if !ok {
                return Err(err_resp(
                    StatusCode::UNAUTHORIZED,
                    "Ungültiger oder bereits verwendeter Wiederherstellungscode.",
                ));
            }
        }
        "security-key" => {
            let Some(expected_challenge) = pending.webauthn_challenge.as_deref() else {
                return Err(err_resp(
                    StatusCode::BAD_REQUEST,
                    "Keine Sicherheitsschlüssel-Anfrage aktiv.",
                ));
            };
            let Some(assertion) = req.assertion.as_ref() else {
                return Err(err_resp(
                    StatusCode::BAD_REQUEST,
                    "Ungültige Sicherheitsschlüssel-Antwort.",
                ));
            };
            let cred_id = assertion
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if cred_id.is_empty() {
                return Err(err_resp(
                    StatusCode::BAD_REQUEST,
                    "Sicherheitsschlüssel-ID fehlt.",
                ));
            }
            let Some(cred) = state
                .db
                .find_webauthn_by_cred_id(cred_id)
                .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
            else {
                return Err(err_resp(
                    StatusCode::UNAUTHORIZED,
                    "Unbekannter Sicherheitsschlüssel.",
                ));
            };
            if cred.user_id != user.id || cred.kind != "security-key" {
                return Err(err_resp(
                    StatusCode::UNAUTHORIZED,
                    "Sicherheitsschlüssel gehört nicht zu diesem Benutzerkonto.",
                ));
            }
            let (origin, rp_id) = get_webauthn_context(&headers);
            let new_counter = auth_extra::verify_webauthn_authentication(
                assertion,
                expected_challenge,
                &origin,
                &rp_id,
                &cred.public_key,
                cred.counter,
                false,
            )
            .await
            .map_err(|e| err_resp(StatusCode::UNAUTHORIZED, e))?;
            state.db.update_webauthn_usage(&cred.id, new_counter);
        }
        _ => {
            return Err(err_resp(StatusCode::BAD_REQUEST, "Unbekannte 2FA-Methode."));
        }
    }

    state.auth_challenges.consume_2fa_ticket(ticket_clean);
    let token = state
        .db
        .create_session(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok((
        jar.add(build_session_cookie(token.clone())),
        Json(json!({ "user": user, "sessionToken": token })),
    ))
}

async fn api_passkey_login_options(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.db.is_initialized().unwrap_or(false) {
        return Err(err_resp(
            StatusCode::CONFLICT,
            "Bitte schließen Sie zuerst die Admin-Ersteinrichtung ab.",
        ));
    }
    let policy = state.db.get_auth_policy();
    let local_disabled = policy.local_login_disabled
        && policy.sso_enabled
        && policy.is_sso_configured()
        && policy.sso_tested_at.is_some();
    if local_disabled {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "Die lokale Anmeldung wurde deaktiviert. Bitte nutzen Sie SSO.",
        ));
    }
    if !policy.passkey_enabled {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "Passkey-Anmeldung ist vom Administrator nicht aktiviert.",
        ));
    }
    let (origin, rp_id) = get_webauthn_context(&headers);
    let (challenge_id, challenge) = state.auth_challenges.store_webauthn_challenge(
        None,
        "passkey-login",
        "",
        &rp_id,
        &origin,
    );
    let options = auth_extra::build_webauthn_auth_options(&rp_id, &challenge, None, true);
    Ok(Json(json!({
        "challengeId": challenge_id,
        "options": options
    })))
}

async fn api_passkey_login_verify(
    State(state): State<SharedState>,
    jar: CookieJar,
    Json(req): Json<PasskeyLoginVerifyRequest>,
) -> Result<(CookieJar, Json<serde_json::Value>), ApiError> {
    let policy = state.db.get_auth_policy();
    let local_disabled = policy.local_login_disabled
        && policy.sso_enabled
        && policy.is_sso_configured()
        && policy.sso_tested_at.is_some();
    if local_disabled {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "Die lokale Anmeldung wurde deaktiviert. Bitte nutzen Sie SSO.",
        ));
    }
    if !policy.passkey_enabled {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "Passkey-Anmeldung ist nicht aktiviert.",
        ));
    }
    let Some(entry) = state
        .auth_challenges
        .consume_webauthn_challenge(req.challenge_id.trim())
    else {
        return Err(err_resp(
            StatusCode::UNAUTHORIZED,
            "Passkey-Anfrage ist abgelaufen. Bitte erneut versuchen.",
        ));
    };
    if entry.kind != "passkey-login" {
        return Err(err_resp(StatusCode::BAD_REQUEST, "Ungültige Passkey-Anfrage."));
    }
    let cred_id = req
        .response
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some(cred) = state
        .db
        .find_webauthn_by_cred_id(cred_id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
    else {
        return Err(err_resp(
            StatusCode::UNAUTHORIZED,
            "Dieser Passkey ist auf diesem Server nicht bekannt.",
        ));
    };
    if cred.kind != "passkey" {
        return Err(err_resp(
            StatusCode::UNAUTHORIZED,
            "Dieser Schlüssel ist kein Passkey.",
        ));
    }
    let Some(user) = state
        .db
        .get_user_by_id(&cred.user_id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
    else {
        return Err(err_resp(StatusCode::FORBIDDEN, "Benutzerkonto nicht gefunden."));
    };
    if !user.active {
        return Err(err_resp(StatusCode::FORBIDDEN, "Benutzerkonto ist deaktiviert."));
    }
    let new_counter = auth_extra::verify_webauthn_authentication(
        &req.response,
        &entry.challenge,
        &entry.origin,
        &entry.rp_id,
        &cred.public_key,
        cred.counter,
        true,
    )
    .await
    .map_err(|e| err_resp(StatusCode::UNAUTHORIZED, e))?;

    state.db.update_webauthn_usage(&cred.id, new_counter);
    let token = state
        .db
        .create_session(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok((
        jar.add(build_session_cookie(token.clone())),
        Json(json!({ "user": user, "sessionToken": token })),
    ))
}

async fn api_sso_url(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<SsoUrlQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mode = if q.mode.as_deref() == Some("test") {
        "test"
    } else {
        "login"
    };
    let policy = state.db.get_auth_policy();
    if mode == "test" {
        let _admin = require_admin(&state, &jar, &headers)?;
    } else if !policy.sso_enabled {
        return Err(err_resp(StatusCode::FORBIDDEN, "SSO ist nicht aktiviert."));
    }
    if !policy.is_sso_configured() {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "SSO ist nicht vollständig konfiguriert (Authorization-URL, Token-URL und Client-ID erforderlich).",
        ));
    }
    let auth_ep = auth_extra::validate_external_url(&policy.sso_auth_url)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
    let redirect_uri = get_sso_callback_url(&headers);
    let (sso_state, code_challenge) = state
        .auth_challenges
        .create_sso_state(mode, &redirect_uri);

    let sep = if auth_ep.contains('?') { '&' } else { '?' };
    let scopes = if policy.sso_scopes.trim().is_empty() {
        "openid profile email"
    } else {
        policy.sso_scopes.trim()
    };
    let full_url = format!(
        "{auth_ep}{sep}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        auth_extra::url_encode(&policy.sso_client_id),
        auth_extra::url_encode(&redirect_uri),
        auth_extra::url_encode(scopes),
        auth_extra::url_encode(&sso_state),
        auth_extra::url_encode(&code_challenge),
    );
    Ok(Json(json!({
        "url": full_url,
        "callbackUrl": redirect_uri
    })))
}

async fn api_sso_callback(
    State(state): State<SharedState>,
    jar: CookieJar,
    Query(q): Query<SsoCallbackQuery>,
) -> (CookieJar, Html<String>) {
    if let Some(err_code) = q.error.as_deref().filter(|s| !s.is_empty()) {
        let msg = q.error_description.as_deref().unwrap_or(err_code);
        return (
            jar,
            render_sso_callback_html(
                json!({ "type": "SSO_ERROR", "error": format!("SSO-Anbieter meldete Fehler: {msg}") }),
                "SSO-Anmeldung fehlgeschlagen",
                msg,
            ),
        );
    }

    let code = q.code.as_deref().unwrap_or("");
    let st = q.state.as_deref().unwrap_or("");
    if code.is_empty() || st.is_empty() {
        return (
            jar,
            render_sso_callback_html(
                json!({ "type": "SSO_ERROR", "error": "Ungültige SSO-Callback-Parameter (code/state fehlt)." }),
                "SSO-Callback ungültig",
                "Fehlende Parameter.",
            ),
        );
    }

    let Some(state_entry) = state.auth_challenges.consume_sso_state(st) else {
        return (
            jar,
            render_sso_callback_html(
                json!({ "type": "SSO_ERROR", "error": "SSO-Anfrage ist abgelaufen oder wurde bereits verwendet." }),
                "SSO-Sitzung abgelaufen",
                "Bitte starten Sie die Anmeldung erneut.",
            ),
        );
    };

    let policy = state.db.get_auth_policy();
    let client_secret = match policy.sso_client_secret_enc {
        Some((ref enc, ref nonce)) => match state.vault.decrypt(enc, nonce) {
            Ok(bytes) => String::from_utf8(bytes.to_vec()).unwrap_or_default(),
            Err(_) => String::new(),
        },
        None => String::new(),
    };

    let profile = match auth_extra::exchange_sso_code_for_profile(
        &policy.sso_token_url,
        &policy.sso_userinfo_url,
        &policy.sso_client_id,
        &client_secret,
        code,
        &state_entry.code_verifier,
        &state_entry.redirect_uri,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            return (
                jar,
                render_sso_callback_html(
                    json!({ "type": "SSO_ERROR", "error": e }),
                    "SSO fehlgeschlagen",
                    &e,
                ),
            );
        }
    };

    if state_entry.mode == "test" {
        match state.db.mark_sso_tested() {
            Ok(updated) => {
                let info = format!(
                    "Verbindung bestätigt für {} ({}). Dieses Fenster schließt sich automatisch.",
                    profile.display_name,
                    if profile.email.is_empty() {
                        &profile.username
                    } else {
                        &profile.email
                    }
                );
                return (
                    jar,
                    render_sso_callback_html(
                        json!({
                            "type": "SSO_TEST_SUCCESS",
                            "testedAt": updated.sso_tested_at,
                            "profile": {
                                "username": profile.username,
                                "displayName": profile.display_name,
                                "email": profile.email
                            }
                        }),
                        "SSO-Test erfolgreich",
                        &info,
                    ),
                );
            }
            Err(e) => {
                return (
                    jar,
                    render_sso_callback_html(
                        json!({ "type": "SSO_ERROR", "error": e }),
                        "SSO-Test fehlgeschlagen",
                        &e,
                    ),
                );
            }
        }
    }

    let mut rand_pw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut rand_pw);
    let dummy_hash = auth::hash_password(&hex::encode(rand_pw)).unwrap_or_default();
    let (user, created) = match state.db.find_or_create_sso_user(
        &profile.sub,
        &profile.username,
        &profile.display_name,
        &profile.email,
        &dummy_hash,
    ) {
        Ok(res) => res,
        Err(e) => {
            return (
                jar,
                render_sso_callback_html(
                    json!({ "type": "SSO_ERROR", "error": e }),
                    "SSO-Anmeldung abgelehnt",
                    &e,
                ),
            );
        }
    };

    match state.db.create_session(&user.id) {
        Ok(token) => (
            jar.add(build_session_cookie(token.clone())),
            render_sso_callback_html(
                json!({
                    "type": "SSO_LOGIN_SUCCESS",
                    "sessionToken": token,
                    "created": created
                }),
                "SSO-Anmeldung erfolgreich",
                &format!(
                    "Angemeldet als {}. Dieses Fenster schließt sich automatisch.",
                    user.display_name
                ),
            ),
        ),
        Err(e) => (
            jar,
            render_sso_callback_html(
                json!({ "type": "SSO_ERROR", "error": e }),
                "Sitzungsfehler",
                &e,
            ),
        ),
    }
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

async fn api_user_security(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let sec_keys: Vec<WebAuthnCredentialPublic> = state
        .db
        .list_webauthn_credentials(&user.id, Some("security-key"))
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .into_iter()
        .map(|c| WebAuthnCredentialPublic {
            id: c.id,
            kind: c.kind,
            name: c.name,
            transports: c.transports,
            created_at: c.created_at,
            last_used_at: c.last_used_at,
        })
        .collect();
    let passkeys: Vec<WebAuthnCredentialPublic> = state
        .db
        .list_webauthn_credentials(&user.id, Some("passkey"))
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .into_iter()
        .map(|c| WebAuthnCredentialPublic {
            id: c.id,
            kind: c.kind,
            name: c.name,
            transports: c.transports,
            created_at: c.created_at,
            last_used_at: c.last_used_at,
        })
        .collect();
    let remaining = state.db.get_user_recovery_count(&user.id);
    Ok(Json(json!({
        "totpEnabled": user.totp_enabled,
        "recoveryCodesRemaining": remaining,
        "securityKeys": sec_keys,
        "passkeys": passkeys
    })))
}

async fn api_totp_setup(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let policy = state.db.get_auth_policy();
    if !policy.two_factor_enabled {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "2FA wurde vom Administrator nicht aktiviert.",
        ));
    }
    if user.auth_provider == "sso" {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Lokale 2FA gilt nur für lokale Konten.",
        ));
    }
    let secret = auth_extra::generate_totp_secret();
    state.auth_challenges.store_pending_totp(&user.id, &secret);
    let issuer = state.db.get_instance_name();
    let uri = auth_extra::build_otpauth_uri(&issuer, &user.username, &secret);
    Ok(Json(json!({
        "secret": secret,
        "otpauthUri": uri
    })))
}

async fn api_totp_verify(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<TotpVerifyRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let Some(secret) = state.auth_challenges.consume_pending_totp(&user.id) else {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Die 2FA-Einrichtung ist abgelaufen. Bitte starten Sie den Vorgang erneut.",
        ));
    };
    if !auth_extra::verify_totp_code(&secret, &req.code) {
        // Put secret back so user can retry without rescanning
        state.auth_challenges.store_pending_totp(&user.id, &secret);
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Der eingegebene 6-stellige Code ist ungültig.",
        ));
    }
    let (enc, nonce) = state
        .vault
        .encrypt(secret.as_bytes())
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let (plain_codes, hashes) = auth_extra::generate_recovery_codes(8);
    let updated = state
        .db
        .set_user_totp(&user.id, &enc, &nonce, &hashes)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "Benutzer nicht gefunden."))?;

    Ok(Json(json!({
        "ok": true,
        "recoveryCodes": plain_codes,
        "user": updated
    })))
}

async fn api_totp_disable(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let policy = state.db.get_auth_policy();
    if policy.two_factor_enabled && policy.two_factor_enforced && user.security_key_count == 0 {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "2FA ist vom Administrator vorgeschrieben. Registrieren Sie zuerst einen Sicherheitsschlüssel, bevor Sie die Authenticator-App entfernen.",
        ));
    }
    let updated = state
        .db
        .disable_user_totp(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "Benutzer nicht gefunden."))?;
    Ok(Json(json!({ "ok": true, "user": updated })))
}

async fn api_webauthn_register_options(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<WebAuthnRegisterOptionsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let policy = state.db.get_auth_policy();
    let kind = if req.kind.as_deref() == Some("passkey") {
        "passkey"
    } else {
        "security-key"
    };
    if kind == "security-key" && !policy.two_factor_enabled {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "2FA ist vom Administrator nicht aktiviert.",
        ));
    }
    if kind == "passkey" && !policy.passkey_enabled {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "Passkeys sind vom Administrator nicht aktiviert.",
        ));
    }
    if user.auth_provider == "sso" {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Hardware-Schlüssel und Passkeys stehen nur für lokale Konten zur Verfügung.",
        ));
    }
    let (origin, rp_id) = get_webauthn_context(&headers);
    let existing = state
        .db
        .list_webauthn_credentials(&user.id, None)
        .unwrap_or_default();
    let exclude_ids: Vec<String> = existing.iter().map(|c| c.credential_id.clone()).collect();
    let default_name = if kind == "passkey" {
        "Passkey"
    } else {
        "Sicherheitsschlüssel"
    };
    let clean_name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(default_name);
    let (challenge_id, challenge) = state.auth_challenges.store_webauthn_challenge(
        Some(user.id.clone()),
        kind,
        clean_name,
        &rp_id,
        &origin,
    );
    let rp_name = state.db.get_instance_name();
    let options = auth_extra::build_webauthn_register_options(
        &rp_name,
        &rp_id,
        &user.id,
        &user.username,
        &user.display_name,
        &challenge,
        kind,
        &exclude_ids,
    );
    Ok(Json(json!({
        "challengeId": challenge_id,
        "options": options
    })))
}

async fn api_webauthn_register_verify(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<WebAuthnRegisterVerifyRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let Some(entry) = state
        .auth_challenges
        .consume_webauthn_challenge(req.challenge_id.trim())
    else {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Die Registrierungsanfrage ist abgelaufen. Bitte starten Sie erneut.",
        ));
    };
    if entry.user_id.as_deref() != Some(user.id.as_str()) {
        return Err(err_resp(StatusCode::FORBIDDEN, "Ungültige Challenge-Zuordnung."));
    }
    let is_passkey = entry.kind == "passkey";
    let verified = auth_extra::verify_webauthn_registration(
        &req.response,
        &entry.challenge,
        &entry.origin,
        &entry.rp_id,
        is_passkey,
    )
    .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;

    let final_name: String = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&entry.name)
        .chars()
        .take(64)
        .collect();

    let saved = state
        .db
        .add_webauthn_credential(
            &user.id,
            &entry.kind,
            &final_name,
            &verified.credential_id,
            &verified.public_key_b64,
            verified.counter,
            &verified.transports,
        )
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;

    let updated_user = state
        .db
        .get_user_by_id(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .unwrap_or(user);

    Ok(Json(json!({
        "ok": true,
        "credential": saved,
        "user": updated_user
    })))
}

async fn api_webauthn_delete(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_user(&state, &jar, &headers)?;
    let policy = state.db.get_auth_policy();
    let creds = state
        .db
        .list_webauthn_credentials(&user.id, None)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let Some(target) = creds.iter().find(|c| c.id == id) else {
        return Err(err_resp(StatusCode::NOT_FOUND, "Schlüssel nicht gefunden."));
    };
    if target.kind == "security-key"
        && policy.two_factor_enabled
        && policy.two_factor_enforced
        && !user.totp_enabled
        && user.security_key_count <= 1
    {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "2FA ist vorgeschrieben. Der letzte Sicherheitsschlüssel kann nicht entfernt werden, solange keine Authenticator-App aktiv ist.",
        ));
    }
    if target.kind == "passkey"
        && policy.passkey_enabled
        && policy.passkey_enforced
        && user.passkey_count <= 1
    {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Passkeys sind vorgeschrieben. Der letzte Passkey kann nicht entfernt werden.",
        ));
    }
    let removed = state
        .db
        .delete_webauthn_credential(&id, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if !removed {
        return Err(err_resp(StatusCode::NOT_FOUND, "Schlüssel nicht gefunden."));
    }
    let updated_user = state
        .db
        .get_user_by_id(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .unwrap_or(user);
    Ok(Json(json!({ "ok": true, "user": updated_user })))
}

async fn api_admin_reset_user_auth(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _admin = require_admin(&state, &jar, &headers)?;
    let Some(updated) = state
        .db
        .reset_user_second_factors(&id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
    else {
        return Err(err_resp(StatusCode::NOT_FOUND, "Benutzer nicht gefunden."));
    };
    Ok(Json(json!({ "ok": true, "user": updated })))
}

async fn api_admin_get_auth_settings(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _admin = require_admin(&state, &jar, &headers)?;
    Ok(Json(json!({
        "authSettings": serialize_admin_auth_settings(&state, &headers),
        "settings": serialize_public_settings(&state)
    })))
}

async fn api_admin_patch_auth_settings(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<AdminAuthSettingsPatchRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let admin = require_admin(&state, &jar, &headers)?;
    for url_opt in [
        req.sso_issuer_url.as_deref(),
        req.sso_auth_url.as_deref(),
        req.sso_token_url.as_deref(),
        req.sso_userinfo_url.as_deref(),
    ] {
        if let Some(u) = url_opt {
            if !u.trim().is_empty() {
                auth_extra::validate_external_url(u)
                    .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
            }
        }
    }
    let encrypted_secret = match req.sso_client_secret.as_deref() {
        Some(secret) if !secret.is_empty() => Some(
            state
                .vault
                .encrypt(secret.as_bytes())
                .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?,
        ),
        _ => None,
    };
    state
        .db
        .update_auth_policy(&req, encrypted_secret)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;

    let refreshed_user = state.db.get_user_by_id(&admin.id).ok().flatten();
    Ok(Json(json!({
        "authSettings": serialize_admin_auth_settings(&state, &headers),
        "settings": serialize_public_settings(&state),
        "user": refreshed_user
    })))
}

async fn api_admin_sso_discover(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<OidcDiscoverRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _admin = require_admin(&state, &jar, &headers)?;
    let discovered = auth_extra::discover_oidc(&req.issuer_url)
        .await
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({ "discovered": discovered })))
}

async fn api_change_password(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, token) = current_user(&state, &jar, &headers)?;
    if user.auth_provider == "sso" {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Für SSO-Konten wird das Passwort beim Identity-Provider verwaltet.",
        ));
    }
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
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
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
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
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
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
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
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
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
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
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
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
    let servers = state
        .db
        .list_accessible_servers(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "servers": servers })))
}

async fn api_list_server_categories(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
    let categories = state
        .db
        .list_server_categories(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "categories": categories })))
}

async fn api_create_server_category(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<CreateServerCategoryRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
    let category = state
        .db
        .create_server_category(&user.id, &req.name)
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(json!({ "category": category })))
}

async fn api_delete_server_category(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
    let deleted = state
        .db
        .delete_server_category(&id, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if deleted.is_none() {
        return Err(err_resp(StatusCode::NOT_FOUND, "Kategorie nicht gefunden."));
    }
    Ok(Json(json!({ "ok": true })))
}

async fn api_create_server(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<CreateServerRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
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
    let policy = state.db.get_auth_policy();
    if req.ignore_host_key == Some(true) && !policy.allow_insecure_host_key {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "Das Deaktivieren der Host-Key-Prüfung (StrictHostKeyChecking=no) ist global vom Administrator verboten.",
        ));
    }
    let ignore_host_key = policy.allow_insecure_host_key && req.ignore_host_key.unwrap_or(false);
    let categories = req.categories.unwrap_or_default();
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
            ignore_host_key,
            &categories,
            shared_all,
            &shared_ids,
        )
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Initial-Ping nur auslösen, wenn global, für Benutzer und für diese IP aktiviert
    if server.ping_enabled && state.db.get_ping_allowed() && user.ping_enabled {
        let bg_state = Arc::clone(&state);
        let bg_srv = server.clone();
        tokio::spawn(async move {
            let prev_ok = known_last_online_at(&bg_state, &bg_srv).await;
            let st = ping::check_server_reachability(&bg_srv, prev_ok).await;
            if bg_state.db.get_ping_allowed() && bg_srv.ping_enabled {
                record_ping_result(&bg_state, &bg_srv, st).await;
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
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
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
    let policy = state.db.get_auth_policy();
    if req.ignore_host_key == Some(true)
        && !existing.ignore_host_key
        && !policy.allow_insecure_host_key
    {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "Das Deaktivieren der Host-Key-Prüfung (StrictHostKeyChecking=no) ist global vom Administrator verboten.",
        ));
    }
    let ignore_host_key = req.ignore_host_key.unwrap_or(existing.ignore_host_key);
    let categories = req.categories.unwrap_or(existing.categories);

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
            ignore_host_key,
            &categories,
        )
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::FORBIDDEN, "Server konnte nicht aktualisiert werden."))?;

    if updated.ping_enabled && state.db.get_ping_allowed() && user.ping_enabled {
        let bg_state = Arc::clone(&state);
        let bg_srv = updated.clone();
        tokio::spawn(async move {
            let prev_ok = known_last_online_at(&bg_state, &bg_srv).await;
            let st = ping::check_server_reachability(&bg_srv, prev_ok).await;
            if bg_state.db.get_ping_allowed() && bg_srv.ping_enabled {
                record_ping_result(&bg_state, &bg_srv, st).await;
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
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
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
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
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
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
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
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
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

    let (pass_enc, pass_nonce) = match req.passphrase.as_deref().filter(|p| !p.is_empty()) {
        Some(pass) => {
            let (pe, pn) = state
                .vault
                .encrypt(pass.as_bytes())
                .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
            (Some(pe), Some(pn))
        }
        None => (None, None),
    };

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
            pass_enc.as_deref(),
            pass_nonce.as_deref(),
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
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
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
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
    state
        .db
        .delete_certificate(&id, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Default)]
struct ParsedCertPayload {
    id: Option<String>,
    name: Option<String>,
    private_key_content: Option<String>,
    private_key_file_name: Option<String>,
    public_key_content: Option<String>,
    public_key_file_name: Option<String>,
    cert_content: Option<String>,
    cert_file_name: Option<String>,
    remove_cert: bool,
    passphrase: Option<String>,
    clear_passphrase: bool,
}

async fn parse_cert_payload(
    headers: &HeaderMap,
    req: AxumRequest,
    state: &SharedState,
) -> Result<ParsedCertPayload, ApiError> {
    let mut out = ParsedCertPayload::default();
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    if content_type.contains("multipart/form-data") {
        let mut multipart = Multipart::from_request(req, state)
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
                "id" | "certificate_id" | "certificateId" => {
                    if !text.trim().is_empty() {
                        out.id = Some(text.trim().to_string());
                    }
                }
                "name" | "label" => {
                    if !text.trim().is_empty() {
                        out.name = Some(text.trim().to_string());
                    }
                }
                "remove_cert" | "removeCert" => {
                    let v = text.trim().to_lowercase();
                    if v == "true" || v == "1" || v == "yes" {
                        out.remove_cert = true;
                    }
                }
                "passphrase" | "key_passphrase" | "keyPassphrase" => {
                    if !text.is_empty() {
                        out.passphrase = Some(text);
                    }
                }
                "clear_passphrase" | "clearPassphrase" => {
                    let v = text.trim().to_lowercase();
                    if v == "true" || v == "1" || v == "yes" {
                        out.clear_passphrase = true;
                    }
                }
                "private_key" | "privateKey" | "privateKeyContent" | "zertifikat" | "key" => {
                    if !text.trim().is_empty() {
                        out.private_key_content = Some(text);
                        if let Some(f) = file_name.filter(|f| !f.is_empty()) {
                            out.private_key_file_name = Some(f);
                        }
                    }
                }
                "public_key" | "publicKey" | "publicKeyContent" | "zertifikat_pub" | "pub" => {
                    if !text.trim().is_empty() {
                        out.public_key_content = Some(text);
                        if let Some(f) = file_name.filter(|f| !f.is_empty()) {
                            out.public_key_file_name = Some(f);
                        }
                    }
                }
                "cert" | "certificate" | "cert_pub" | "zertifikat_cert" | "certContent" => {
                    if !text.trim().is_empty() {
                        out.cert_content = Some(text);
                        if let Some(f) = file_name.filter(|f| !f.is_empty()) {
                            out.cert_file_name = Some(f);
                        }
                    }
                }
                _ => {}
            }
        }
        return Ok(out);
    }

    let Json(body) = Json::<UpdateCertBundleRequest>::from_request(req, state)
        .await
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, format!("Ungültige JSON-Anfrage: {e}")))?;

    out.id = body.id.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    out.name = body.name.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    out.private_key_file_name = body
        .private_key_file_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    out.public_key_file_name = body
        .public_key_file_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    out.cert_file_name = body
        .cert_file_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    out.private_key_content = body.private_key_content.filter(|s| !s.trim().is_empty());
    out.public_key_content = body.public_key_content.filter(|s| !s.trim().is_empty());
    out.cert_content = body.cert_content.filter(|s| !s.trim().is_empty());
    out.remove_cert = body.remove_cert.unwrap_or(false);
    out.passphrase = body.passphrase.filter(|s| !s.is_empty());
    out.clear_passphrase = body.clear_passphrase.unwrap_or(false);
    Ok(out)
}

async fn apply_partial_cert_update(
    state: &SharedState,
    user: &UserPublic,
    existing: &StoredCertificateForEdit,
    payload: &ParsedCertPayload,
    allow_rename: bool,
) -> Result<UserCertificatePublic, ApiError> {
    let effective_rename = if allow_rename {
        payload.name.as_deref()
    } else {
        None
    };

    let has_any_change = effective_rename.is_some()
        || payload.private_key_content.is_some()
        || payload.public_key_content.is_some()
        || payload.cert_content.is_some()
        || payload.remove_cert
        || payload.passphrase.is_some()
        || payload.clear_passphrase;

    if !has_any_change {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Keine Änderungen übermittelt. Senden Sie mindestens eines der Felder: \"name\", \"cert\", \"private_key\", \"public_key\", \"passphrase\", \"clear_passphrase\" oder \"remove_cert\".",
        ));
    }

    let (effective_priv, next_priv_enc, next_priv_nonce) = match payload.private_key_content.as_deref() {
        Some(new_priv) => {
            let (enc, nonce) = state
                .vault
                .encrypt(new_priv.as_bytes())
                .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
            (new_priv.to_string(), enc, nonce)
        }
        None => {
            let plain_bytes = state
                .vault
                .decrypt(&existing.private_key_enc, &existing.private_key_nonce)
                .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
            let plain = std::str::from_utf8(&plain_bytes)
                .map(str::to_string)
                .map_err(|_| err_resp(StatusCode::INTERNAL_SERVER_ERROR, "Gespeicherter Schlüssel ungültig."))?;
            (
                plain,
                existing.private_key_enc.clone(),
                existing.private_key_nonce.clone(),
            )
        }
    };

    let effective_pub = payload
        .public_key_content
        .as_deref()
        .unwrap_or(&existing.public_key)
        .trim()
        .to_string();

    let effective_cert = if payload.remove_cert {
        String::new()
    } else if let Some(new_cert) = payload.cert_content.as_deref() {
        new_cert.trim().to_string()
    } else {
        existing.certificate.trim().to_string()
    };

    let inspection = ssh::inspect_certificate_bundle(
        &effective_priv,
        &effective_pub,
        if effective_cert.is_empty() {
            None
        } else {
            Some(effective_cert.as_str())
        },
    )
    .await
    .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;

    let (next_pass_enc, next_pass_nonce) = if payload.clear_passphrase {
        (None, None)
    } else if let Some(ref new_pass) = payload.passphrase {
        let (pe, pn) = state
            .vault
            .encrypt(new_pass.as_bytes())
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        (Some(pe), Some(pn))
    } else if payload.private_key_content.is_some() && !inspection.private_key_encrypted {
        (None, None)
    } else {
        (
            existing.passphrase_enc.clone(),
            existing.passphrase_nonce.clone(),
        )
    };

    let next_name = effective_rename.unwrap_or(&existing.name);
    let next_priv_file = payload
        .private_key_file_name
        .as_deref()
        .unwrap_or(&existing.private_key_file_name);
    let next_pub_file = payload
        .public_key_file_name
        .as_deref()
        .unwrap_or(&existing.public_key_file_name);
    let next_cert_file = if effective_cert.is_empty() {
        ""
    } else if let Some(f) = payload.cert_file_name.as_deref() {
        f
    } else if !existing.cert_file_name.trim().is_empty() {
        existing.cert_file_name.as_str()
    } else {
        "zertifikat-cert.pub"
    };

    state
        .db
        .update_certificate_bundle(
            &existing.id,
            &user.id,
            &user.username,
            next_name,
            next_priv_file,
            next_pub_file,
            next_cert_file,
            &next_priv_enc,
            &next_priv_nonce,
            next_pass_enc.as_deref(),
            next_pass_nonce.as_deref(),
            &effective_pub,
            &effective_cert,
            &inspection,
            existing.shared_with_all,
            &existing.shared_with_user_ids,
        )
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))
}

async fn api_update_cert(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    req: AxumRequest,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
    let owner = state
        .db
        .get_certificate_owner(&id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    match owner {
        None => return Err(err_resp(StatusCode::NOT_FOUND, "Zertifikatspaket nicht gefunden.")),
        Some(owner_id) if owner_id != user.id => {
            return Err(err_resp(
                StatusCode::FORBIDDEN,
                "Sie können nur selbst angelegte Zertifikatspakete bearbeiten.",
            ));
        }
        _ => {}
    }

    let existing = state
        .db
        .get_owned_certificate_by_id_or_name(&user.id, &id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "Zertifikatspaket nicht gefunden."))?;

    let payload = parse_cert_payload(&headers, req, &state).await?;
    let updated = apply_partial_cert_update(&state, &user, &existing, &payload, true).await?;
    Ok(Json(json!({ "ok": true, "certificate": updated })))
}

fn require_api_key_user(state: &SharedState, headers: &HeaderMap) -> Result<UserPublic, ApiError> {
    let api_key = extract_api_key(headers).ok_or_else(|| {
        err_resp(
            StatusCode::UNAUTHORIZED,
            "Ungültiger oder fehlender API-Schlüssel. Senden Sie ihn als Header \"X-API-Key: sshc_...\" oder \"Authorization: Bearer sshc_...\".",
        )
    })?;
    if !api_key.starts_with("sshc_") || api_key.len() < 20 {
        return Err(err_resp(StatusCode::UNAUTHORIZED, "Ungültiger API-Schlüssel."));
    }
    let key_hash = hash_api_key(&api_key);
    state
        .db
        .user_by_api_key_hash(&key_hash)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::UNAUTHORIZED, "Ungültiger oder widerrufener API-Schlüssel."))
}

async fn api_v1_list_certs(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = require_api_key_user(&state, &headers)?;
    let certs: Vec<UserCertificatePublic> = state
        .db
        .list_accessible_certificates(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .into_iter()
        .filter(|c| c.user_id == user.id)
        .collect();
    Ok(Json(json!({ "ok": true, "certificates": certs })))
}

async fn api_v1_upload_cert(
    State(state): State<SharedState>,
    headers: HeaderMap,
    req: AxumRequest,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let user = require_api_key_user(&state, &headers)?;
    let payload = parse_cert_payload(&headers, req, &state).await?;

    let priv_content = payload.private_key_content.clone().unwrap_or_default();
    let pub_content = payload.public_key_content.clone().unwrap_or_default();
    let priv_file = payload
        .private_key_file_name
        .clone()
        .unwrap_or_else(|| "zertifikat".to_string());
    let pub_file = payload
        .public_key_file_name
        .clone()
        .unwrap_or_else(|| "zertifikat.pub".to_string());
    let cert_file = payload
        .cert_file_name
        .clone()
        .unwrap_or_else(|| "zertifikat-cert.pub".to_string());
    let cert_content = payload.cert_content.clone().unwrap_or_default();

    // Smart partial update: if private_key or public_key is omitted, update matching existing bundle by id or name
    if priv_content.trim().is_empty() || pub_content.trim().is_empty() {
        let lookup = payload.id.as_deref().or(payload.name.as_deref()).unwrap_or("");
        if !lookup.is_empty() {
            if let Some(existing) = state
                .db
                .get_owned_certificate_by_id_or_name(&user.id, lookup)
                .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
            {
                let updated = apply_partial_cert_update(&state, &user, &existing, &payload, false).await?;
                return Ok((
                    StatusCode::OK,
                    Json(json!({ "ok": true, "replaced": true, "updated": true, "certificate": updated })),
                ));
            }
        }
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Für ein neues Paket sind \"private_key\" (zertifikat) und \"public_key\" (zertifikat.pub) erforderlich. Um nur zertifikat-cert.pub eines bestehenden Pakets zu tauschen, geben Sie dessen \"name\" an oder nutzen Sie PATCH /api/v1/certificates/<name-oder-id>.",
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

    let (pass_enc, pass_nonce) = match payload.passphrase.as_deref().filter(|p| !p.is_empty()) {
        Some(pass) => {
            let (pe, pn) = state
                .vault
                .encrypt(pass.as_bytes())
                .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
            (Some(pe), Some(pn))
        }
        None => (None, None),
    };

    let effective_name = if let Some(n) = payload.name.filter(|s| !s.is_empty()) {
        n
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
            pass_enc.as_deref(),
            pass_nonce.as_deref(),
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

async fn api_v1_update_cert(
    State(state): State<SharedState>,
    headers: HeaderMap,
    AxumPath(id_or_name): AxumPath<String>,
    req: AxumRequest,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = require_api_key_user(&state, &headers)?;
    let existing = state
        .db
        .get_owned_certificate_by_id_or_name(&user.id, &id_or_name)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| {
            err_resp(
                StatusCode::NOT_FOUND,
                format!("Zertifikatspaket „{id_or_name}“ nicht gefunden (nur eigene Pakete können bearbeitet werden)."),
            )
        })?;

    let payload = parse_cert_payload(&headers, req, &state).await?;
    let updated = apply_partial_cert_update(&state, &user, &existing, &payload, true).await?;
    Ok(Json(json!({ "ok": true, "updated": true, "certificate": updated })))
}

#[derive(Debug, Deserialize, Default)]
struct ShellWsQuery {
    ticket: Option<String>,
}

fn is_ws_origin_allowed(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let expected = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim().to_ascii_lowercase())
        .unwrap_or_default();
    if expected.is_empty() {
        return true;
    }
    let origin_host = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .unwrap_or(origin)
        .split('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    origin_host == expected
}

async fn api_shell_ticket(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<shell::ShellTicketRequest>,
) -> Result<Json<shell::ShellTicketResponse>, ApiError> {
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
    let cert = state
        .db
        .get_accessible_certificate_secret(&req.certificate_id, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| {
            err_resp(
                StatusCode::BAD_REQUEST,
                "Zertifikatspaket nicht gefunden oder keine Berechtigung.",
            )
        })?;

    let policy = state.db.get_auth_policy();
    let (target_ip, target_port, ssh_user, server_label, ignore_host_key) =
        if let Some(server_id) = req
            .server_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let srv = state
                .db
                .get_accessible_server(server_id, &user.id)
                .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
                .ok_or_else(|| {
                    err_resp(
                        StatusCode::BAD_REQUEST,
                        "Ausgewählter Server nicht gefunden oder keine Berechtigung.",
                    )
                })?;
            let user_override = req
                .ssh_user
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let effective_user = match user_override {
                Some(u) => {
                    ssh::validate_ssh_user(u).map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?
                }
                None => srv.ssh_user.clone(),
            };
            let effective_ignore = policy.allow_insecure_host_key && srv.ignore_host_key;
            (
                srv.ip_address,
                srv.port,
                effective_user,
                srv.label,
                effective_ignore,
            )
        } else {
            let raw_ip = req.ip_address.as_deref().unwrap_or("");
            let ip = ssh::validate_ip(raw_ip).map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
            let port = req.port.unwrap_or(22).clamp(1, 65535);
            let raw_user = req
                .ssh_user
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(&user.default_ssh_user);
            let valid_user = ssh::validate_ssh_user(raw_user)
                .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
            if req.ignore_host_key == Some(true) && !policy.allow_insecure_host_key {
                return Err(err_resp(
                    StatusCode::FORBIDDEN,
                    "Das Deaktivieren der Host-Key-Prüfung (StrictHostKeyChecking=no) ist global vom Administrator verboten.",
                ));
            }
            let effective_ignore =
                policy.allow_insecure_host_key && req.ignore_host_key.unwrap_or(false);
            (ip.clone(), port, valid_user, ip, effective_ignore)
        };

    let token = state
        .shell_tickets
        .issue(shell::ShellTicket {
            user_id: user.id,
            username: user.username,
            server_label: server_label.clone(),
            ip_address: target_ip.clone(),
            port: target_port,
            ssh_user: ssh_user.clone(),
            certificate_id: cert.id,
            passphrase: req
                .passphrase
                .filter(|p| !p.is_empty())
                .map(zeroize::Zeroizing::new),
            ignore_host_key,
            cols: req.cols.unwrap_or(100),
            rows: req.rows.unwrap_or(30),
            expires_at: std::time::Instant::now(),
        })
        .await;

    Ok(Json(shell::ShellTicketResponse {
        ticket: token,
        target_ip,
        target_port,
        ssh_user,
        server_label,
        certificate_name: cert.name,
        openssh_available: Path::new("/usr/bin/ssh").exists(),
    }))
}

fn resolve_cert_passphrase(
    state: &SharedState,
    cert: &UserCertificateSecret,
    provided: Option<&str>,
) -> Result<Option<zeroize::Zeroizing<String>>, ApiError> {
    if let Some(pass) = provided.filter(|p| !p.is_empty()) {
        return Ok(Some(zeroize::Zeroizing::new(pass.to_string())));
    }
    if let (Some(enc), Some(nonce)) = (&cert.passphrase_enc, &cert.passphrase_nonce) {
        let plain_bytes = state
            .vault
            .decrypt(enc, nonce)
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let plain = std::str::from_utf8(&plain_bytes)
            .map_err(|_| err_resp(StatusCode::INTERNAL_SERVER_ERROR, "Gespeichertes Schlüssel-Passwort ungültig."))?;
        if !plain.is_empty() {
            return Ok(Some(zeroize::Zeroizing::new(plain.to_string())));
        }
    }
    Ok(None)
}

async fn api_ws_shell(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(query): Query<ShellWsQuery>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, ApiError> {
    if !is_ws_origin_allowed(&headers) {
        return Err(err_resp(StatusCode::FORBIDDEN, "Ungültiger WebSocket-Origin."));
    }
    let token = query.ticket.unwrap_or_default();
    let ticket = state
        .shell_tickets
        .consume(&token)
        .await
        .ok_or_else(|| err_resp(StatusCode::UNAUTHORIZED, "Ungültiges oder abgelaufenes Shell-Ticket."))?;

    let cert = state
        .db
        .get_accessible_certificate_secret(&ticket.certificate_id, &ticket.user_id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| {
            err_resp(
                StatusCode::FORBIDDEN,
                "Zertifikatspaket nicht gefunden oder keine Berechtigung.",
            )
        })?;

    let private_key_plain = state
        .vault
        .decrypt(&cert.private_key_enc, &cert.private_key_nonce)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let passphrase_plain = resolve_cert_passphrase(
        &state,
        &cert,
        ticket.passphrase.as_deref().map(|s| s.as_str()),
    )?;

    Ok(ws.on_upgrade(move |socket| {
        shell::handle_ssh_websocket(socket, state, ticket, cert, private_key_plain, passphrase_plain)
    }))
}

async fn api_execute(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<ExecuteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
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

    let resolved_passphrase = resolve_cert_passphrase(&state, &cert, req.passphrase.as_deref())?;
    if cert.private_key_encrypted && resolved_passphrase.is_none() {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Der private Schlüssel dieses Zertifikats ist passwortgeschützt. Bitte geben Sie das Schlüssel-Passwort ein oder hinterlegen Sie es beim Zertifikat.",
        ));
    }

    let policy = state.db.get_auth_policy();
    let known_hosts_path = ssh::user_known_hosts_path(&state.data_dir, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let mut logs = Vec::new();
    for target in req.targets {
        let (ip, port, ssh_user, label, ignore_host_key) = if let Some(srv_id) = target.server_id {
            let srv = state
                .db
                .get_accessible_server(&srv_id, &user.id)
                .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
                .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "Server nicht gefunden."))?;
            (
                srv.ip_address,
                srv.port,
                srv.ssh_user,
                srv.label,
                policy.allow_insecure_host_key && srv.ignore_host_key,
            )
        } else {
            let ip = ssh::validate_ip(target.ip_address.as_deref().unwrap_or(""))
                .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
            let ssh_u = ssh::validate_ssh_user(
                target.ssh_user.as_deref().unwrap_or(&user.default_ssh_user),
            )
            .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
            let lbl = ip.clone();
            let ignore =
                policy.allow_insecure_host_key && target.ignore_host_key.unwrap_or(false);
            (ip, target.port.unwrap_or(22), ssh_u, lbl, ignore)
        };

        let plain_key = state
            .vault
            .decrypt(&cert.private_key_enc, &cert.private_key_nonce)
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;

        let result = ssh::run_ssh_command(
            &ip,
            port,
            &ssh_user,
            &cmd,
            &cert,
            plain_key,
            resolved_passphrase.as_deref().map(|s| s.as_str()),
            ignore_host_key,
            &known_hosts_path,
        )
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

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ListLogsQuery {
    user_id: Option<String>,
}

async fn api_list_logs(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(query): Query<ListLogsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
    let logs = state
        .db
        .list_logs(&user, query.user_id.as_deref())
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(json!({ "logs": logs })))
}

async fn known_last_online_at(state: &SharedState, srv: &UserServer) -> Option<String> {
    let guard = state.ping.read().await;
    guard
        .statuses
        .get(&srv.id)
        .and_then(|s| s.last_online_at.clone())
        .or_else(|| srv.last_online_at.clone())
}

fn compute_offline_backoff(
    consecutive_failures: u32,
    base_interval_sec: u64,
    threshold: u32,
    multiplier: u64,
) -> (bool, u64) {
    if threshold > 0 && consecutive_failures >= threshold && multiplier > 1 {
        let extended = base_interval_sec.saturating_mul(multiplier).min(86_400);
        (true, extended)
    } else {
        (false, base_interval_sec)
    }
}

fn is_status_due_for_cycle(
    status: Option<&ServerPingStatus>,
    cycle_start_epoch_ms: i64,
    base_interval_sec: u64,
    threshold: u32,
    multiplier: u64,
) -> bool {
    let Some(st) = status else {
        return true;
    };
    if st.online {
        return true;
    }
    let (backoff_active, effective_interval_sec) =
        compute_offline_backoff(st.consecutive_failures, base_interval_sec, threshold, multiplier);
    if !backoff_active {
        return true;
    }
    let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(&st.checked_at) else {
        return true;
    };
    let last_checked_ms = parsed.timestamp_millis();
    let base_interval_ms = (base_interval_sec.saturating_mul(1000)) as i64;
    let effective_interval_ms = (effective_interval_sec.saturating_mul(1000)) as i64;
    let guard_margin_ms = (base_interval_ms / 10).min(2000);
    last_checked_ms.saturating_add(effective_interval_ms)
        <= cycle_start_epoch_ms
            .saturating_add(base_interval_ms)
            .saturating_sub(guard_margin_ms)
}

async fn record_ping_result(state: &SharedState, srv: &UserServer, mut status: ServerPingStatus) {
    if status.online {
        let _ = state.db.record_server_last_online(&srv.id, &status.checked_at);
    }
    let base_interval_sec = state.db.get_ping_interval_sec();
    let threshold = state.db.get_ping_offline_threshold();
    let multiplier = state.db.get_ping_offline_multiplier();
    let mut guard = state.ping.write().await;
    let prev_failures = guard
        .statuses
        .get(&srv.id)
        .map(|s| s.consecutive_failures)
        .unwrap_or(0);
    if status.online {
        status.consecutive_failures = 0;
        status.backoff_active = false;
        status.effective_interval_sec = base_interval_sec;
    } else {
        let failures = prev_failures.saturating_add(1);
        let (backoff_active, effective_interval_sec) =
            compute_offline_backoff(failures, base_interval_sec, threshold, multiplier);
        status.consecutive_failures = failures;
        status.backoff_active = backoff_active;
        status.effective_interval_sec = effective_interval_sec;
    }
    guard.statuses.insert(srv.id.clone(), status);
}

async fn ping_servers_bounded(
    state: &SharedState,
    targets: Vec<UserServer>,
    max_concurrency: usize,
    stagger_ms: u64,
    require_auto_ping: bool,
) {
    if targets.is_empty() {
        return;
    }
    let semaphore = Arc::new(Semaphore::new(max_concurrency.max(1)));
    let mut handles = Vec::with_capacity(targets.len());

    for (idx, srv) in targets.into_iter().enumerate() {
        if stagger_ms > 0 && idx > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(stagger_ms)).await;
        }
        if require_auto_ping && !state.db.get_ping_allowed() {
            break;
        }
        let permit = match Arc::clone(&semaphore).acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let task_state = Arc::clone(state);
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let prev_ok = known_last_online_at(&task_state, &srv).await;
            let status = ping::check_server_reachability(&srv, prev_ok).await;
            if !require_auto_ping || (task_state.db.get_ping_allowed() && srv.ping_enabled) {
                record_ping_result(&task_state, &srv, status).await;
            }
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }
}

async fn build_dashboard_status_json(
    state: &SharedState,
    user: &UserPublic,
) -> Result<serde_json::Value, ApiError> {
    let global_ping_allowed = state.db.get_ping_allowed();
    let interval_sec = state.db.get_ping_interval_sec();
    let offline_threshold = state.db.get_ping_offline_threshold();
    let offline_multiplier = state.db.get_ping_offline_multiplier();
    let user_ping_enabled = user.ping_enabled;
    let effective_auto_ping = global_ping_allowed && user_ping_enabled;

    let servers = state
        .db
        .list_accessible_servers(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let guard = state.ping.read().await;
    let mut user_statuses = serde_json::Map::new();
    let mut backoff_count: usize = 0;

    for srv in servers {
        if let Some(st) = guard.statuses.get(&srv.id) {
            let mut merged = st.clone();
            if merged.last_online_at.is_none() {
                merged.last_online_at = srv.last_online_at.clone();
            }
            if merged.online {
                merged.consecutive_failures = 0;
                merged.backoff_active = false;
                merged.effective_interval_sec = interval_sec;
            } else {
                let (backoff_active, effective_interval_sec) = compute_offline_backoff(
                    merged.consecutive_failures,
                    interval_sec,
                    offline_threshold,
                    offline_multiplier,
                );
                merged.backoff_active = backoff_active;
                merged.effective_interval_sec = effective_interval_sec;
                if effective_auto_ping && srv.ping_enabled && backoff_active {
                    backoff_count += 1;
                }
            }
            user_statuses.insert(
                srv.id,
                serde_json::to_value(merged).unwrap_or(serde_json::Value::Null),
            );
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
        "offlineThreshold": offline_threshold,
        "offlineMultiplier": offline_multiplier,
        "backoffCount": backoff_count,
        "lastCycleAt": if effective_auto_ping { guard.last_cycle_at.clone() } else { None },
        "nextCycleAt": if effective_auto_ping { guard.next_cycle_at.clone() } else { None },
        "pacingMs": if effective_auto_ping { guard.pacing_ms } else { None },
        "activeTargetCount": if effective_auto_ping { guard.active_target_count } else { 0 },
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
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
    Ok(Json(build_dashboard_status_json(&state, &user).await?))
}

async fn api_dashboard_ping(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<ManualPingRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
    let servers = state
        .db
        .list_accessible_servers(&user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if let Some(ref id) = req.server_id {
        if !servers.iter().any(|s| s.id == *id) {
            return Err(err_resp(StatusCode::NOT_FOUND, "Server nicht gefunden."));
        }
    }
    // Manuelles Prüfen funktioniert immer, auch wenn regelmäßiger Auto-Ping deaktiviert ist
    let targets: Vec<UserServer> = match req.server_id {
        Some(ref id) => servers.into_iter().filter(|s| s.id == *id).collect(),
        None => servers,
    };

    let stagger_ms = if targets.len() > 20 {
        MANUAL_PING_STAGGER_MS
    } else {
        0
    };
    ping_servers_bounded(&state, targets, MAX_CONCURRENT_MANUAL_PINGS, stagger_ms, false).await;

    Ok(Json(build_dashboard_status_json(&state, &user).await?))
}

async fn api_user_ping_settings(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<UserPingSettingsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
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
                let targets: Vec<UserServer> =
                    servers.into_iter().filter(|s| s.ping_enabled).collect();
                let stagger_ms = if targets.len() > 20 {
                    MANUAL_PING_STAGGER_MS
                } else {
                    0
                };
                ping_servers_bounded(
                    &bg_state,
                    targets,
                    MAX_CONCURRENT_MANUAL_PINGS,
                    stagger_ms,
                    true,
                )
                .await;
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
        .set_global_ping_settings(
            req.ping_allowed,
            req.ping_interval_sec,
            req.ping_offline_threshold,
            req.ping_offline_multiplier,
        )
        .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;

    {
        let mut guard = state.ping.write().await;
        if !ping_allowed {
            guard.next_cycle_at = None;
            guard.pacing_ms = None;
            guard.active_target_count = 0;
        } else {
            guard.next_cycle_at =
                Some((Utc::now() + chrono::Duration::seconds(ping_interval_sec as i64)).to_rfc3339());
        }
    }
    state.ping_notify.notify_one();

    let dashboard_status = build_dashboard_status_json(&state, &admin).await?;
    Ok(Json(json!({
        "settings": serialize_public_settings(&state),
        "dashboardStatus": dashboard_status
    })))
}

async fn api_execute_batch(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<BatchExecuteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
    let cert = state
        .db
        .get_accessible_certificate_secret(&req.certificate_id, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "Zertifikatspaket nicht gefunden."))?;

    if req.jobs.is_empty() || req.jobs.len() > 50 {
        return Err(err_resp(StatusCode::BAD_REQUEST, "1 bis 50 Aufträge zulässig."));
    }

    let resolved_passphrase = resolve_cert_passphrase(&state, &cert, req.passphrase.as_deref())?;
    if cert.private_key_encrypted && resolved_passphrase.is_none() {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Der private Schlüssel dieses Zertifikats ist passwortgeschützt. Bitte geben Sie das Schlüssel-Passwort ein oder hinterlegen Sie es beim Zertifikat.",
        ));
    }

    let policy = state.db.get_auth_policy();
    let known_hosts_path = ssh::user_known_hosts_path(&state.data_dir, &user.id)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?;
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

        let ignore_host_key = policy.allow_insecure_host_key && srv.ignore_host_key;
        let result = ssh::run_ssh_command(
            &srv.ip_address,
            srv.port,
            &srv.ssh_user,
            &cmd,
            &cert,
            plain_key,
            resolved_passphrase.as_deref().map(|s| s.as_str()),
            ignore_host_key,
            &known_hosts_path,
        )
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

async fn api_reset_user_host_key(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    body: Option<Json<ResetHostKeyRequest>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (user, _) = current_compliant_user(&state, &jar, &headers)?;
    let req = body.map(|Json(b)| b).unwrap_or_default();

    let (target_ip, target_port) = if let Some(srv_id) = req
        .server_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let srv = state
            .db
            .get_accessible_server(srv_id, &user.id)
            .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e))?
            .ok_or_else(|| err_resp(StatusCode::NOT_FOUND, "Server nicht gefunden."))?;
        (srv.ip_address, srv.port)
    } else if let Some(raw_ip) = req
        .ip_address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let ip = ssh::validate_ip(raw_ip).map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
        let port = req.port.unwrap_or(22);
        if port == 0 {
            return Err(err_resp(StatusCode::BAD_REQUEST, "Ungültiger SSH-Port."));
        }
        (ip, port)
    } else {
        return Err(err_resp(
            StatusCode::BAD_REQUEST,
            "Server-ID oder IP-Adresse erforderlich.",
        ));
    };

    let (removed_count, remaining_count) =
        ssh::remove_user_host_key(&state.data_dir, &user.id, &target_ip, Some(target_port))
            .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;

    Ok(Json(json!({
        "ok": true,
        "ipAddress": target_ip,
        "port": target_port,
        "removedCount": removed_count,
        "remainingCount": remaining_count
    })))
}

async fn api_admin_host_key_stats(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _ = require_admin(&state, &jar, &headers)?;
    let (total_entries, user_files) = ssh::global_known_hosts_stats(&state.data_dir);
    Ok(Json(json!({
        "totalEntries": total_entries,
        "userFiles": user_files
    })))
}

async fn api_admin_clear_host_keys(
    State(state): State<SharedState>,
    jar: CookieJar,
    headers: HeaderMap,
    body: Option<Json<AdminDeleteHostKeysRequest>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _ = require_admin(&state, &jar, &headers)?;
    let req = body.map(|Json(b)| b).unwrap_or_default();

    let ip_filter = match req
        .ip_address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw_ip) => {
            let valid =
                ssh::validate_ip(raw_ip).map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;
            Some(valid)
        }
        None => None,
    };

    let port_filter = match req.port {
        Some(0) => return Err(err_resp(StatusCode::BAD_REQUEST, "Ungültiger SSH-Port.")),
        other => other,
    };

    let (removed_count, total_entries, affected_files) =
        ssh::clear_global_host_keys(&state.data_dir, ip_filter.as_deref(), port_filter)
            .map_err(|e| err_resp(StatusCode::BAD_REQUEST, e))?;

    Ok(Json(json!({
        "ok": true,
        "removedCount": removed_count,
        "totalEntries": total_entries,
        "affectedFiles": affected_files
    })))
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
    let _ = current_compliant_user(&state, &jar, &headers)?;
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
        pacing_ms: None,
        active_target_count: 0,
    }));
    let ping_notify = Arc::new(Notify::new());
    let state = Arc::new(AppState {
        data_dir,
        db,
        vault,
        ping: ping_state,
        ping_notify,
        shell_tickets: shell::ShellTicketStore::default(),
        auth_challenges: auth_extra::AuthChallengeStore::default(),
    });

    // Hintergrund-Task: Gleichmäßig über pingIntervalSec verteilter Auto-Ping
    // (pro IP exakt im eingestellten Intervall, aber ohne Netzwerk-Spitzen bei vielen IPs)
    let bg_state = Arc::clone(&state);
    tokio::spawn(async move {
        let auto_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_AUTO_PINGS));
        let in_flight_ids = Arc::new(AsyncMutex::new(HashSet::<String>::new()));

        loop {
            let allowed = bg_state.db.get_ping_allowed();
            let interval_sec = bg_state.db.get_ping_interval_sec().clamp(10, 3600);
            let offline_threshold = bg_state.db.get_ping_offline_threshold();
            let offline_multiplier = bg_state.db.get_ping_offline_multiplier();

            if !allowed {
                {
                    let mut guard = bg_state.ping.write().await;
                    guard.next_cycle_at = None;
                    guard.pacing_ms = None;
                    guard.active_target_count = 0;
                }
                bg_state.ping_notify.notified().await;
                continue;
            }

            let interval_ms: u64 = interval_sec.saturating_mul(1000);
            let cycle_start = tokio::time::Instant::now();
            let cycle_end = cycle_start + std::time::Duration::from_millis(interval_ms);
            let mut interrupted = false;

            if let Ok(servers) = bg_state.db.list_all_servers() {
                let now = Utc::now();
                let now_epoch_ms = now.timestamp_millis();
                let next = now + chrono::Duration::seconds(interval_sec as i64);
                let existing_ids: HashSet<String> = servers.iter().map(|s| s.id.clone()).collect();
                let mut targets: Vec<UserServer> = {
                    let mut guard = bg_state.ping.write().await;
                    // Nur gelöschte Server entfernen; manuelle Ping-Ergebnisse bleiben erhalten
                    guard.statuses.retain(|k, _| existing_ids.contains(k));
                    let due: Vec<UserServer> = servers
                        .into_iter()
                        .filter(|s| {
                            bg_state.db.should_ping_server(s)
                                && is_status_due_for_cycle(
                                    guard.statuses.get(&s.id),
                                    now_epoch_ms,
                                    interval_sec,
                                    offline_threshold,
                                    offline_multiplier,
                                )
                        })
                        .collect();
                    let total_due = due.len();
                    let pacing_ms = if total_due > 0 {
                        Some(((interval_ms as f64) / (total_due as f64)).round().max(1.0) as u64)
                    } else {
                        None
                    };
                    guard.last_cycle_at = Some(now.to_rfc3339());
                    guard.next_cycle_at = Some(next.to_rfc3339());
                    guard.pacing_ms = pacing_ms;
                    guard.active_target_count = total_due;
                    due
                };
                targets.sort_by(|a, b| a.id.cmp(&b.id));

                let total = targets.len();

                for (idx, srv) in targets.into_iter().enumerate() {
                    if !bg_state.db.get_ping_allowed() {
                        interrupted = true;
                        break;
                    }

                    let offset_ms = ((idx as u128 * interval_ms as u128) / (total as u128)) as u64;
                    let target_instant = cycle_start + std::time::Duration::from_millis(offset_ms);
                    if target_instant > tokio::time::Instant::now() {
                        tokio::select! {
                            _ = tokio::time::sleep_until(target_instant) => {}
                            _ = bg_state.ping_notify.notified() => {
                                interrupted = true;
                                break;
                            }
                        }
                    }

                    if !bg_state.db.get_ping_allowed() {
                        interrupted = true;
                        break;
                    }
                    if !bg_state.db.should_ping_server(&srv) {
                        continue;
                    }
                    {
                        let guard = in_flight_ids.lock().await;
                        if guard.contains(&srv.id) {
                            continue;
                        }
                    }

                    let permit = tokio::select! {
                        res = Arc::clone(&auto_semaphore).acquire_owned() => match res {
                            Ok(p) => p,
                            Err(_) => {
                                interrupted = true;
                                break;
                            }
                        },
                        _ = bg_state.ping_notify.notified() => {
                            interrupted = true;
                            break;
                        }
                    };

                    if !bg_state.db.get_ping_allowed() || !bg_state.db.should_ping_server(&srv) {
                        drop(permit);
                        continue;
                    }
                    {
                        let mut guard = in_flight_ids.lock().await;
                        if !guard.insert(srv.id.clone()) {
                            drop(permit);
                            continue;
                        }
                    }

                    let task_state = Arc::clone(&bg_state);
                    let task_in_flight = Arc::clone(&in_flight_ids);
                    tokio::spawn(async move {
                        let _permit = permit;
                        let prev_ok = known_last_online_at(&task_state, &srv).await;
                        let st = ping::check_server_reachability(&srv, prev_ok).await;
                        if task_state.db.get_ping_allowed() && task_state.db.should_ping_server(&srv)
                        {
                            record_ping_result(&task_state, &srv, st).await;
                        }
                        let mut guard = task_in_flight.lock().await;
                        guard.remove(&srv.id);
                    });
                }
            }

            if !interrupted {
                if cycle_end > tokio::time::Instant::now() {
                    tokio::select! {
                        _ = tokio::time::sleep_until(cycle_end) => {}
                        _ = bg_state.ping_notify.notified() => {}
                    }
                } else {
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
                        _ = bg_state.ping_notify.notified() => {}
                    }
                }
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
        .route("/api/auth/login/2fa", post(api_login_2fa))
        .route("/api/auth/passkey/login/options", post(api_passkey_login_options))
        .route("/api/auth/passkey/login/verify", post(api_passkey_login_verify))
        .route("/api/auth/sso/url", get(api_sso_url))
        .route("/api/auth/sso/callback", get(api_sso_callback))
        .route("/api/auth/sso/callback/", get(api_sso_callback))
        .route("/api/auth/logout", post(api_logout))
        .route("/api/auth/security", get(api_user_security))
        .route("/api/auth/2fa/totp/setup", post(api_totp_setup))
        .route("/api/auth/2fa/totp/verify", post(api_totp_verify))
        .route("/api/auth/2fa/totp", delete(api_totp_disable))
        .route("/api/auth/webauthn/register/options", post(api_webauthn_register_options))
        .route("/api/auth/webauthn/register/verify", post(api_webauthn_register_verify))
        .route("/api/auth/webauthn/:id", delete(api_webauthn_delete))
        .route("/api/auth/change-password", post(api_change_password))
        .route("/api/auth/api-keys", get(api_list_api_keys).post(api_create_api_key))
        .route("/api/auth/api-keys/:id", delete(api_delete_api_key))
        .route("/api/admin/users", get(api_admin_list_users).post(api_admin_create_user))
        .route(
            "/api/admin/users/:id",
            patch(api_admin_update_user).delete(api_admin_delete_user),
        )
        .route("/api/admin/users/:id/reset-auth", post(api_admin_reset_user_auth))
        .route(
            "/api/admin/auth/settings",
            get(api_admin_get_auth_settings).patch(api_admin_patch_auth_settings),
        )
        .route("/api/admin/auth/sso/discover", post(api_admin_sso_discover))
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
        .route(
            "/api/server-categories",
            get(api_list_server_categories).post(api_create_server_category),
        )
        .route("/api/server-categories/:id", delete(api_delete_server_category))
        .route("/api/host-keys/reset", post(api_reset_user_host_key))
        .route("/api/host-keys", delete(api_reset_user_host_key))
        .route(
            "/api/admin/host-keys",
            get(api_admin_host_key_stats).delete(api_admin_clear_host_keys),
        )
        .route("/api/certificates", get(api_list_certs).post(api_upload_cert))
        .route("/api/certificates/generate-test", post(api_generate_test_cert))
        .route(
            "/api/certificates/:id",
            patch(api_update_cert).delete(api_delete_cert),
        )
        .route("/api/certificates/:id/share", patch(api_share_cert))
        .route("/api/v1/certificates", get(api_v1_list_certs))
        .route("/api/v1/certificates/upload", post(api_v1_upload_cert))
        .route(
            "/api/v1/certificates/:id_or_name",
            patch(api_v1_update_cert).put(api_v1_update_cert),
        )
        .route("/api/execute", post(api_execute))
        .route("/api/execute/batch", post(api_execute_batch))
        .route("/api/shell/ticket", post(api_shell_ticket))
        .route("/api/ws/shell", get(api_ws_shell))
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
