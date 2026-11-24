use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

// ── Pure-Rust RFC 3174 SHA-1 + HMAC-SHA1 + Base32 + RFC 6238 TOTP ───────────

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let digest = sha1(key);
        key_block[..20].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut o_key_pad = [0x5cu8; 64];
    let mut i_key_pad = [0x36u8; 64];
    for i in 0..64 {
        o_key_pad[i] ^= key_block[i];
        i_key_pad[i] ^= key_block[i];
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend_from_slice(&i_key_pad);
    inner.extend_from_slice(msg);
    let inner_hash = sha1(&inner);

    let mut outer = Vec::with_capacity(64 + 20);
    outer.extend_from_slice(&o_key_pad);
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut bits: u32 = 0;
    let mut value: u32 = 0;
    for &b in data {
        value = (value << 8) | (b as u32);
        bits += 8;
        while bits >= 5 {
            out.push(BASE32_ALPHABET[((value >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(BASE32_ALPHABET[((value << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut bits: u32 = 0;
    let mut value: u32 = 0;
    for ch in input.chars() {
        if ch.is_whitespace() || ch == '=' || ch == '-' {
            continue;
        }
        let up = ch.to_ascii_uppercase() as u8;
        let idx = BASE32_ALPHABET
            .iter()
            .position(|&c| c == up)
            .ok_or_else(|| "Ungültiges Base32-Zeichen im TOTP-Schlüssel.".to_string())?;
        value = (value << 5) | (idx as u32);
        bits += 5;
        if bits >= 8 {
            out.push(((value >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    Ok(out)
}

pub fn generate_totp_secret() -> String {
    let mut bytes = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base32_encode(&bytes)
}

pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

pub fn build_otpauth_uri(issuer: &str, account: &str, secret: &str) -> String {
    let label = format!("{}:{}", url_encode(issuer), url_encode(account));
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        label,
        url_encode(secret),
        url_encode(issuer)
    )
}

fn totp_at_counter(secret_bytes: &[u8], counter: u64) -> String {
    let hmac = hmac_sha1(secret_bytes, &counter.to_be_bytes());
    let offset = (hmac[19] & 0x0f) as usize;
    let code = (((hmac[offset] & 0x7f) as u32) << 24)
        | ((hmac[offset + 1] as u32) << 16)
        | ((hmac[offset + 2] as u32) << 8)
        | (hmac[offset + 3] as u32);
    format!("{:06}", code % 1_000_000)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn verify_totp_code(secret_b32: &str, raw_code: &str) -> bool {
    let digits: String = raw_code.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 6 {
        return false;
    }
    let Ok(secret_bytes) = base32_decode(secret_b32) else {
        return false;
    };
    let now_step = (Utc::now().timestamp().max(0) as u64) / 30;
    for delta in -1i64..=1i64 {
        let step = (now_step as i64 + delta).max(0) as u64;
        let expected = totp_at_counter(&secret_bytes, step);
        if ct_eq(expected.as_bytes(), digits.as_bytes()) {
            return true;
        }
    }
    false
}

pub fn hash_recovery_code(raw: &str) -> String {
    let normalized: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

pub fn generate_recovery_codes(count: usize) -> (Vec<String>, Vec<String>) {
    let mut plain = Vec::with_capacity(count);
    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        let mut bytes = [0u8; 4];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let h = hex::encode(bytes).to_uppercase();
        let formatted = format!("{}-{}", &h[0..4], &h[4..8]);
        hashes.push(hash_recovery_code(&formatted));
        plain.push(formatted);
    }
    (plain, hashes)
}

// ── Ephemeral In-Memory Challenge Stores ────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SsoStateEntry {
    pub mode: String, // "login" | "test"
    pub code_verifier: String,
    pub redirect_uri: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct TwoFactorTicketEntry {
    pub user_id: String,
    pub webauthn_challenge: Option<String>,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct PendingTotpEntry {
    pub secret: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct WebAuthnChallengeEntry {
    pub challenge: String,
    pub user_id: Option<String>,
    pub kind: String, // "security-key" | "passkey" | "passkey-login"
    pub name: String,
    pub rp_id: String,
    pub origin: String,
    pub expires_at: i64,
}

#[derive(Default)]
pub struct AuthChallengeStore {
    sso_states: Mutex<HashMap<String, SsoStateEntry>>,
    two_factor_tickets: Mutex<HashMap<String, TwoFactorTicketEntry>>,
    pending_totp: Mutex<HashMap<String, PendingTotpEntry>>,
    webauthn: Mutex<HashMap<String, WebAuthnChallengeEntry>>,
}

fn random_b64url(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn random_hex(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

impl AuthChallengeStore {
    pub fn create_sso_state(&self, mode: &str, redirect_uri: &str) -> (String, String) {
        let now = Utc::now().timestamp();
        let state = random_b64url(24);
        let code_verifier = random_b64url(32);
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let mut guard = self.sso_states.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, v| v.expires_at > now);
        guard.insert(
            state.clone(),
            SsoStateEntry {
                mode: mode.to_string(),
                code_verifier,
                redirect_uri: redirect_uri.to_string(),
                expires_at: (Utc::now() + Duration::minutes(10)).timestamp(),
            },
        );
        (state, code_challenge)
    }

    pub fn consume_sso_state(&self, state: &str) -> Option<SsoStateEntry> {
        let now = Utc::now().timestamp();
        let mut guard = self.sso_states.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, v| v.expires_at > now);
        guard.remove(state).filter(|v| v.expires_at > now)
    }

    pub fn create_2fa_ticket(&self, user_id: &str, webauthn_challenge: Option<String>) -> String {
        let now = Utc::now().timestamp();
        let ticket = random_hex(24);
        let mut guard = self
            .two_factor_tickets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, v| v.expires_at > now);
        guard.insert(
            ticket.clone(),
            TwoFactorTicketEntry {
                user_id: user_id.to_string(),
                webauthn_challenge,
                expires_at: (Utc::now() + Duration::minutes(5)).timestamp(),
            },
        );
        ticket
    }

    pub fn peek_2fa_ticket(&self, ticket: &str) -> Option<TwoFactorTicketEntry> {
        let now = Utc::now().timestamp();
        let mut guard = self
            .two_factor_tickets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, v| v.expires_at > now);
        guard.get(ticket).cloned()
    }

    pub fn consume_2fa_ticket(&self, ticket: &str) -> Option<TwoFactorTicketEntry> {
        let now = Utc::now().timestamp();
        let mut guard = self
            .two_factor_tickets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, v| v.expires_at > now);
        guard.remove(ticket)
    }

    pub fn store_pending_totp(&self, user_id: &str, secret: &str) {
        let now = Utc::now().timestamp();
        let mut guard = self.pending_totp.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, v| v.expires_at > now);
        guard.insert(
            user_id.to_string(),
            PendingTotpEntry {
                secret: secret.to_string(),
                expires_at: (Utc::now() + Duration::minutes(15)).timestamp(),
            },
        );
    }

    pub fn consume_pending_totp(&self, user_id: &str) -> Option<String> {
        let now = Utc::now().timestamp();
        let mut guard = self.pending_totp.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, v| v.expires_at > now);
        guard.remove(user_id).map(|e| e.secret)
    }

    pub fn store_webauthn_challenge(
        &self,
        user_id: Option<String>,
        kind: &str,
        name: &str,
        rp_id: &str,
        origin: &str,
    ) -> (String, String) {
        let now = Utc::now().timestamp();
        let challenge_id = random_hex(20);
        let challenge = random_b64url(32);
        let mut guard = self.webauthn.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, v| v.expires_at > now);
        guard.insert(
            challenge_id.clone(),
            WebAuthnChallengeEntry {
                challenge: challenge.clone(),
                user_id,
                kind: kind.to_string(),
                name: name.to_string(),
                rp_id: rp_id.to_string(),
                origin: origin.to_string(),
                expires_at: (Utc::now() + Duration::minutes(5)).timestamp(),
            },
        );
        (challenge_id, challenge)
    }

    pub fn consume_webauthn_challenge(&self, challenge_id: &str) -> Option<WebAuthnChallengeEntry> {
        let now = Utc::now().timestamp();
        let mut guard = self.webauthn.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, v| v.expires_at > now);
        guard.remove(challenge_id)
    }
}

// ── OIDC Discovery & Token/UserInfo Exchange via /usr/bin/curl ──────────────

pub fn validate_external_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("URL enthält ungültige Zeichen.".into());
    }
    let rest = if let Some(r) = trimmed.strip_prefix("https://") {
        r
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        r
    } else {
        return Err("SSO-Endpunkte müssen mit https:// oder http:// beginnen.".into());
    };
    let host_port = rest.split('/').next().unwrap_or("");
    let host = host_port
        .split('@')
        .last()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_lowercase();
    if host.is_empty() {
        return Err("Ungültige URL: Hostname fehlt.".into());
    }
    if host == "169.254.169.254" || host == "metadata.google.internal" || host == "[fd00" {
        return Err("Metadaten-Adressen sind als SSO-Endpunkt nicht zulässig.".into());
    }
    Ok(trimmed.to_string())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcDiscoveryResult {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
}

#[derive(Debug, Clone)]
pub struct SsoProfile {
    pub sub: String,
    pub username: String,
    pub display_name: String,
    pub email: String,
}

async fn curl_get_json(url: &str, bearer_token: Option<&str>) -> Result<Value, String> {
    let mut cmd = Command::new("/usr/bin/curl");
    cmd.args([
        "-sS",
        "--fail-with-body",
        "--max-time",
        "12",
        "-H",
        "Accept: application/json",
    ]);
    if bearer_token.is_some() {
        cmd.args(["-K", "-"]);
    }
    cmd.arg(url);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("curl konnte nicht gestartet werden: {e}"))?;
    if let Some(tok) = bearer_token {
        if let Some(mut stdin) = child.stdin.take() {
            let safe_tok = tok.replace(['\r', '\n', '"'], "");
            let cfg = format!("header = \"Authorization: Bearer {safe_tok}\"\n");
            let _ = stdin.write_all(cfg.as_bytes()).await;
        }
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("curl-Fehler: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "HTTP-Anfrage fehlgeschlagen: {} {}",
            stderr.trim(),
            stdout.trim()
        ));
    }
    serde_json::from_slice::<Value>(&output.stdout)
        .map_err(|e| format!("Ungültige JSON-Antwort vom SSO-Anbieter: {e}"))
}

async fn curl_post_form_json(url: &str, form_body: &str) -> Result<Value, String> {
    let mut cmd = Command::new("/usr/bin/curl");
    cmd.args([
        "-sS",
        "--max-time",
        "12",
        "-X",
        "POST",
        "-H",
        "Content-Type: application/x-www-form-urlencoded",
        "-H",
        "Accept: application/json",
        "--data-binary",
        "@-",
        url,
    ]);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("curl konnte nicht gestartet werden: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(form_body.as_bytes()).await;
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("curl-Fehler: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("SSO Token-Anfrage fehlgeschlagen: {}", stderr.trim()));
    }
    serde_json::from_slice::<Value>(&output.stdout)
        .map_err(|e| format!("Ungültige Token-JSON-Antwort: {e}"))
}

pub async fn discover_oidc(issuer_url: &str) -> Result<OidcDiscoveryResult, String> {
    let clean = validate_external_url(issuer_url)?;
    if clean.is_empty() {
        return Err("Issuer-URL ist erforderlich.".into());
    }
    let trimmed = clean.trim_end_matches('/');
    let discovery_url = if trimmed.ends_with("/.well-known/openid-configuration") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/.well-known/openid-configuration")
    };
    let doc = curl_get_json(&discovery_url, None).await?;
    let auth_ep = doc
        .get("authorization_endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Discovery-Antwort enthält keinen authorization_endpoint.".to_string())?;
    let token_ep = doc
        .get("token_endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Discovery-Antwort enthält keinen token_endpoint.".to_string())?;
    let userinfo_ep = doc
        .get("userinfo_endpoint")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let issuer = doc
        .get("issuer")
        .and_then(|v| v.as_str())
        .unwrap_or(trimmed);

    Ok(OidcDiscoveryResult {
        issuer: issuer.to_string(),
        authorization_endpoint: validate_external_url(auth_ep)?,
        token_endpoint: validate_external_url(token_ep)?,
        userinfo_endpoint: validate_external_url(userinfo_ep)?,
    })
}

fn decode_jwt_claims(jwt: &str) -> Option<serde_json::Map<String, Value>> {
    let part = jwt.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(part).ok()?;
    serde_json::from_slice::<Value>(&bytes)
        .ok()?
        .as_object()
        .cloned()
}

pub async fn exchange_sso_code_for_profile(
    token_url: &str,
    userinfo_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> Result<SsoProfile, String> {
    let token_ep = validate_external_url(token_url)?;
    let mut form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        url_encode(code),
        url_encode(redirect_uri),
        url_encode(client_id),
        url_encode(code_verifier)
    );
    if !client_secret.is_empty() {
        form.push_str(&format!("&client_secret={}", url_encode(client_secret)));
    }

    let token_json = curl_post_form_json(&token_ep, &form).await?;
    if let Some(err) = token_json.get("error").and_then(|v| v.as_str()) {
        let desc = token_json
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or(err);
        return Err(format!("SSO-Fehler beim Token-Austausch: {desc}"));
    }

    let mut claims = serde_json::Map::new();
    if let Some(id_tok) = token_json.get("id_token").and_then(|v| v.as_str()) {
        if let Some(map) = decode_jwt_claims(id_tok) {
            for (k, v) in map {
                claims.insert(k, v);
            }
        }
    }

    if !userinfo_url.trim().is_empty() {
        if let Some(access_tok) = token_json.get("access_token").and_then(|v| v.as_str()) {
            let ui_ep = validate_external_url(userinfo_url)?;
            if let Ok(ui_json) = curl_get_json(&ui_ep, Some(access_tok)).await {
                if let Some(obj) = ui_json.as_object() {
                    for (k, v) in obj {
                        claims.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }

    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .or_else(|| claims.get("id").and_then(|v| v.as_str()))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "SSO-Anbieter hat keine eindeutige Benutzer-ID (sub) geliefert.".to_string())?;

    let email = claims
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let preferred = claims
        .get("preferred_username")
        .and_then(|v| v.as_str())
        .or_else(|| claims.get("login").and_then(|v| v.as_str()))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if !email.is_empty() {
                email.split('@').next().unwrap_or("sso_user").to_string()
            } else {
                let short: String = sub.chars().take(10).collect();
                format!("sso_{short}")
            }
        });

    let mut username: String = preferred
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    username = username.trim_start_matches(|c: char| !c.is_ascii_alphanumeric()).to_string();
    if username.len() < 2 {
        let h = hex::encode(Sha256::digest(sub.as_bytes()));
        username = format!("sso_{}", &h[0..8]);
    }
    username.truncate(32);

    let display_name = claims
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| claims.get("given_name").and_then(|v| v.as_str()))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| username.clone());

    Ok(SsoProfile {
        sub,
        username,
        display_name: display_name.chars().take(64).collect(),
        email,
    })
}

// ── Minimal CBOR Decoder + COSE (ES256/RS256) -> SPKI DER + WebAuthn Verify ─

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum CborVal {
    Uint(u64),
    Neg(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborVal>),
    Map(Vec<(CborVal, CborVal)>),
    Other,
}

impl CborVal {
    fn as_i64(&self) -> Option<i64> {
        match self {
            CborVal::Uint(u) => i64::try_from(*u).ok(),
            CborVal::Neg(n) => Some(*n),
            _ => None,
        }
    }

    fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            CborVal::Bytes(b) => Some(b),
            _ => None,
        }
    }

    fn map_get_str(&self, key: &str) -> Option<&CborVal> {
        if let CborVal::Map(entries) = self {
            for (k, v) in entries {
                if let CborVal::Text(s) = k {
                    if s == key {
                        return Some(v);
                    }
                }
            }
        }
        None
    }

    fn map_get_int(&self, key: i64) -> Option<&CborVal> {
        if let CborVal::Map(entries) = self {
            for (k, v) in entries {
                if k.as_i64() == Some(key) {
                    return Some(v);
                }
            }
        }
        None
    }
}

fn cbor_read_len(data: &[u8], pos: &mut usize, ai: u8) -> Result<u64, String> {
    match ai {
        0..=23 => Ok(ai as u64),
        24 => {
            if *pos + 1 > data.len() {
                return Err("CBOR unerwartetes Ende".into());
            }
            let v = data[*pos] as u64;
            *pos += 1;
            Ok(v)
        }
        25 => {
            if *pos + 2 > data.len() {
                return Err("CBOR unerwartetes Ende".into());
            }
            let v = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as u64;
            *pos += 2;
            Ok(v)
        }
        26 => {
            if *pos + 4 > data.len() {
                return Err("CBOR unerwartetes Ende".into());
            }
            let v = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]])
                as u64;
            *pos += 4;
            Ok(v)
        }
        27 => {
            if *pos + 8 > data.len() {
                return Err("CBOR unerwartetes Ende".into());
            }
            let v = u64::from_be_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
                data[*pos + 4],
                data[*pos + 5],
                data[*pos + 6],
                data[*pos + 7],
            ]);
            *pos += 8;
            Ok(v)
        }
        _ => Err("Nicht unterstützte CBOR-Längencodierung".into()),
    }
}

fn cbor_decode_item(data: &[u8], pos: &mut usize, depth: usize) -> Result<CborVal, String> {
    if depth > 16 || *pos >= data.len() {
        return Err("Ungültige CBOR-Struktur".into());
    }
    let head = data[*pos];
    *pos += 1;
    let major = head >> 5;
    let ai = head & 0x1f;

    match major {
        0 => Ok(CborVal::Uint(cbor_read_len(data, pos, ai)?)),
        1 => {
            let n = cbor_read_len(data, pos, ai)?;
            Ok(CborVal::Neg(-1i64 - (n as i64)))
        }
        2 => {
            let len = cbor_read_len(data, pos, ai)? as usize;
            if *pos + len > data.len() {
                return Err("CBOR Byte-String abgeschnitten".into());
            }
            let slice = data[*pos..*pos + len].to_vec();
            *pos += len;
            Ok(CborVal::Bytes(slice))
        }
        3 => {
            let len = cbor_read_len(data, pos, ai)? as usize;
            if *pos + len > data.len() {
                return Err("CBOR Text-String abgeschnitten".into());
            }
            let s = String::from_utf8(data[*pos..*pos + len].to_vec())
                .map_err(|_| "Ungültiges UTF-8 in CBOR".to_string())?;
            *pos += len;
            Ok(CborVal::Text(s))
        }
        4 => {
            let len = cbor_read_len(data, pos, ai)? as usize;
            let mut arr = Vec::with_capacity(len.min(64));
            for _ in 0..len {
                arr.push(cbor_decode_item(data, pos, depth + 1)?);
            }
            Ok(CborVal::Array(arr))
        }
        5 => {
            let len = cbor_read_len(data, pos, ai)? as usize;
            let mut entries = Vec::with_capacity(len.min(64));
            for _ in 0..len {
                let k = cbor_decode_item(data, pos, depth + 1)?;
                let v = cbor_decode_item(data, pos, depth + 1)?;
                entries.push((k, v));
            }
            Ok(CborVal::Map(entries))
        }
        6 => {
            let _tag = cbor_read_len(data, pos, ai)?;
            cbor_decode_item(data, pos, depth + 1)
        }
        _ => Ok(CborVal::Other),
    }
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_unsigned_int(bytes: &[u8]) -> Vec<u8> {
    let mut trimmed = bytes;
    while trimmed.len() > 1 && trimmed[0] == 0 {
        trimmed = &trimmed[1..];
    }
    let mut v = Vec::new();
    if trimmed.first().copied().unwrap_or(0) & 0x80 != 0 {
        v.push(0x00);
    }
    v.extend_from_slice(trimmed);
    der_tlv(0x02, &v)
}

fn cose_to_spki_pem(cose_bytes: &[u8]) -> Result<String, String> {
    let mut pos = 0usize;
    let val = cbor_decode_item(cose_bytes, &mut pos, 0)?;
    let kty = val
        .map_get_int(1)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "COSE-Schlüssel: kty fehlt".to_string())?;

    let spki_der = match kty {
        // EC2 P-256 (ES256, alg=-7, crv=1)
        2 => {
            let crv = val.map_get_int(-1).and_then(|v| v.as_i64()).unwrap_or(0);
            if crv != 1 {
                return Err(format!("Nicht unterstützte EC-Kurve (crv={crv})."));
            }
            let x = val
                .map_get_int(-2)
                .and_then(|v| v.as_bytes())
                .ok_or_else(|| "COSE EC-Schlüssel: x fehlt".to_string())?;
            let y = val
                .map_get_int(-3)
                .and_then(|v| v.as_bytes())
                .ok_or_else(|| "COSE EC-Schlüssel: y fehlt".to_string())?;
            if x.len() != 32 || y.len() != 32 {
                return Err("Ungültige P-256 Koordinatenlänge.".into());
            }
            // AlgorithmIdentifier for id-ecPublicKey (1.2.840.10045.2.1) + prime256v1 (1.2.840.10045.3.1.7)
            let alg_id: &[u8] = &[
                0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
                0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            ];
            let mut bit_str = Vec::with_capacity(66);
            bit_str.push(0x00); // unused bits
            bit_str.push(0x04); // uncompressed point
            bit_str.extend_from_slice(x);
            bit_str.extend_from_slice(y);
            let mut seq = Vec::new();
            seq.extend_from_slice(alg_id);
            seq.extend_from_slice(&der_tlv(0x03, &bit_str));
            der_tlv(0x30, &seq)
        }
        // RSA (RS256, alg=-257)
        3 => {
            let n = val
                .map_get_int(-1)
                .and_then(|v| v.as_bytes())
                .ok_or_else(|| "COSE RSA-Schlüssel: n fehlt".to_string())?;
            let e = val
                .map_get_int(-2)
                .and_then(|v| v.as_bytes())
                .ok_or_else(|| "COSE RSA-Schlüssel: e fehlt".to_string())?;
            let mut rsa_inner = Vec::new();
            rsa_inner.extend_from_slice(&der_unsigned_int(n));
            rsa_inner.extend_from_slice(&der_unsigned_int(e));
            let rsa_pub_der = der_tlv(0x30, &rsa_inner);

            // rsaEncryption OID (1.2.840.113549.1.1.1) + NULL
            let alg_id: &[u8] = &[
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
                0x05, 0x00,
            ];
            let mut bit_str = Vec::with_capacity(1 + rsa_pub_der.len());
            bit_str.push(0x00);
            bit_str.extend_from_slice(&rsa_pub_der);
            let mut seq = Vec::new();
            seq.extend_from_slice(alg_id);
            seq.extend_from_slice(&der_tlv(0x03, &bit_str));
            der_tlv(0x30, &seq)
        }
        _ => return Err(format!("Nicht unterstützter WebAuthn-Schlüsseltyp (kty={kty}).")),
    };

    let b64 = STANDARD.encode(&spki_der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    Ok(pem)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
}

pub fn build_webauthn_register_options(
    rp_name: &str,
    rp_id: &str,
    user_id: &str,
    username: &str,
    display_name: &str,
    challenge: &str,
    kind: &str,
    exclude_cred_ids: &[String],
) -> Value {
    let is_passkey = kind == "passkey";
    let exclude: Vec<Value> = exclude_cred_ids
        .iter()
        .map(|id| json!({ "id": id, "type": "public-key" }))
        .collect();
    json!({
        "challenge": challenge,
        "rp": { "name": rp_name, "id": rp_id },
        "user": {
            "id": URL_SAFE_NO_PAD.encode(user_id.as_bytes()),
            "name": username,
            "displayName": display_name
        },
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 },
            { "type": "public-key", "alg": -257 }
        ],
        "timeout": 60000,
        "attestation": "none",
        "excludeCredentials": exclude,
        "authenticatorSelection": if is_passkey {
            json!({
                "residentKey": "required",
                "requireResidentKey": true,
                "userVerification": "required"
            })
        } else {
            json!({
                "residentKey": "discouraged",
                "userVerification": "preferred"
            })
        }
    })
}

pub fn build_webauthn_auth_options(
    rp_id: &str,
    challenge: &str,
    allow_cred_ids: Option<&[String]>,
    require_uv: bool,
) -> Value {
    let mut obj = json!({
        "challenge": challenge,
        "timeout": 60000,
        "rpId": rp_id,
        "userVerification": if require_uv { "required" } else { "preferred" }
    });
    if let Some(ids) = allow_cred_ids {
        let allow: Vec<Value> = ids
            .iter()
            .map(|id| json!({ "id": id, "type": "public-key" }))
            .collect();
        if let Some(map) = obj.as_object_mut() {
            map.insert("allowCredentials".into(), Value::Array(allow));
        }
    }
    obj
}

pub struct VerifiedWebAuthnRegistration {
    pub credential_id: String,
    pub public_key_b64: String,
    pub counter: u32,
    pub transports: Vec<String>,
}

pub fn verify_webauthn_registration(
    response: &Value,
    expected_challenge: &str,
    expected_origin: &str,
    expected_rp_id: &str,
    is_passkey: bool,
) -> Result<VerifiedWebAuthnRegistration, String> {
    let resp = response
        .get("response")
        .ok_or_else(|| "WebAuthn response-Objekt fehlt.".to_string())?;
    let client_data_b64 = resp
        .get("clientDataJSON")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "clientDataJSON fehlt.".to_string())?;
    let att_obj_b64 = resp
        .get("attestationObject")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "attestationObject fehlt.".to_string())?;

    let client_data_bytes = URL_SAFE_NO_PAD
        .decode(client_data_b64)
        .map_err(|_| "Ungültige clientDataJSON-Kodierung.".to_string())?;
    let client_data: ClientData = serde_json::from_slice(&client_data_bytes)
        .map_err(|_| "Ungültiges clientDataJSON.".to_string())?;

    if client_data.kind != "webauthn.create" {
        return Err("Ungültiger WebAuthn-Typ bei Registrierung.".into());
    }
    if client_data.challenge != expected_challenge {
        return Err("WebAuthn-Challenge stimmt nicht überein.".into());
    }
    if client_data.origin != expected_origin {
        return Err(format!(
            "WebAuthn-Origin stimmt nicht überein ({} != {}).",
            client_data.origin, expected_origin
        ));
    }

    let att_bytes = URL_SAFE_NO_PAD
        .decode(att_obj_b64)
        .map_err(|_| "Ungültige attestationObject-Kodierung.".to_string())?;
    let mut pos = 0usize;
    let att_cbor = cbor_decode_item(&att_bytes, &mut pos, 0)?;
    let auth_data = att_cbor
        .map_get_str("authData")
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| "authData fehlt in attestationObject.".to_string())?;

    if auth_data.len() < 55 {
        return Err("authData zu kurz.".into());
    }
    let expected_rp_hash = Sha256::digest(expected_rp_id.as_bytes());
    if auth_data[0..32] != expected_rp_hash[..] {
        return Err("RP-ID-Hash stimmt nicht überein.".into());
    }
    let flags = auth_data[32];
    if (flags & 0x01) == 0 {
        return Err("Benutzerpräsenz (UP) nicht bestätigt.".into());
    }
    if is_passkey && (flags & 0x04) == 0 {
        return Err("Benutzerverifizierung (UV) für Passkey erforderlich.".into());
    }
    if (flags & 0x40) == 0 {
        return Err("Attested Credential Data fehlt.".into());
    }

    let counter = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let cred_end = 55 + cred_id_len;
    if cred_end >= auth_data.len() {
        return Err("Credential-ID in authData ungültig.".into());
    }
    let cred_id_bytes = &auth_data[55..cred_end];
    let cose_key_bytes = &auth_data[cred_end..];

    // Validate COSE key can be parsed into SPKI PEM right away
    let _ = cose_to_spki_pem(cose_key_bytes)?;

    let transports = resp
        .get("transports")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    Ok(VerifiedWebAuthnRegistration {
        credential_id: URL_SAFE_NO_PAD.encode(cred_id_bytes),
        public_key_b64: URL_SAFE_NO_PAD.encode(cose_key_bytes),
        counter,
        transports,
    })
}

pub async fn verify_webauthn_authentication(
    response: &Value,
    expected_challenge: &str,
    expected_origin: &str,
    expected_rp_id: &str,
    stored_cose_b64: &str,
    stored_counter: u32,
    require_uv: bool,
) -> Result<u32, String> {
    let resp = response
        .get("response")
        .ok_or_else(|| "WebAuthn response-Objekt fehlt.".to_string())?;
    let client_data_b64 = resp
        .get("clientDataJSON")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "clientDataJSON fehlt.".to_string())?;
    let auth_data_b64 = resp
        .get("authenticatorData")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "authenticatorData fehlt.".to_string())?;
    let sig_b64 = resp
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "signature fehlt.".to_string())?;

    let client_data_bytes = URL_SAFE_NO_PAD
        .decode(client_data_b64)
        .map_err(|_| "Ungültige clientDataJSON-Kodierung.".to_string())?;
    let client_data: ClientData = serde_json::from_slice(&client_data_bytes)
        .map_err(|_| "Ungültiges clientDataJSON.".to_string())?;

    if client_data.kind != "webauthn.get" {
        return Err("Ungültiger WebAuthn-Typ bei Anmeldung.".into());
    }
    if client_data.challenge != expected_challenge {
        return Err("WebAuthn-Challenge stimmt nicht überein.".into());
    }
    if client_data.origin != expected_origin {
        return Err("WebAuthn-Origin stimmt nicht überein.".into());
    }

    let auth_data = URL_SAFE_NO_PAD
        .decode(auth_data_b64)
        .map_err(|_| "Ungültige authenticatorData-Kodierung.".to_string())?;
    if auth_data.len() < 37 {
        return Err("authenticatorData zu kurz.".into());
    }
    let expected_rp_hash = Sha256::digest(expected_rp_id.as_bytes());
    if auth_data[0..32] != expected_rp_hash[..] {
        return Err("RP-ID-Hash stimmt nicht überein.".into());
    }
    let flags = auth_data[32];
    if (flags & 0x01) == 0 {
        return Err("Benutzerpräsenz (UP) nicht bestätigt.".into());
    }
    if require_uv && (flags & 0x04) == 0 {
        return Err("Benutzerverifizierung (UV) erforderlich.".into());
    }

    let new_counter = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    if stored_counter > 0 && new_counter > 0 && new_counter <= stored_counter {
        return Err("Signaturzähler ungültig (möglicher geklonter Schlüssel).".into());
    }

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| "Ungültige Signatur-Kodierung.".to_string())?;
    let cose_bytes = URL_SAFE_NO_PAD
        .decode(stored_cose_b64)
        .map_err(|_| "Gespeicherter WebAuthn-Schlüssel ist beschädigt.".to_string())?;
    let spki_pem = cose_to_spki_pem(&cose_bytes)?;

    let mut signed_payload = Vec::with_capacity(auth_data.len() + 32);
    signed_payload.extend_from_slice(&auth_data);
    signed_payload.extend_from_slice(&Sha256::digest(&client_data_bytes));

    let tmp_dir = tempfile::tempdir().map_err(|e| format!("Tempdir-Fehler: {e}"))?;
    let pub_path = tmp_dir.path().join("pub.pem");
    let sig_path = tmp_dir.path().join("sig.bin");
    let msg_path = tmp_dir.path().join("msg.bin");
    std::fs::write(&pub_path, spki_pem.as_bytes())
        .map_err(|e| format!("Schreibfehler pub.pem: {e}"))?;
    std::fs::write(&sig_path, &sig_bytes)
        .map_err(|e| format!("Schreibfehler sig.bin: {e}"))?;
    std::fs::write(&msg_path, &signed_payload)
        .map_err(|e| format!("Schreibfehler msg.bin: {e}"))?;

    let output = Command::new("/usr/bin/openssl")
        .arg("dgst")
        .arg("-sha256")
        .arg("-verify")
        .arg(&pub_path)
        .arg("-signature")
        .arg(&sig_path)
        .arg(&msg_path)
        .output()
        .await
        .map_err(|e| format!("openssl-Verifikation fehlgeschlagen: {e}"))?;

    if !output.status.success() {
        return Err("WebAuthn-Signatur konnte nicht verifiziert werden.".into());
    }

    Ok(new_counter)
}
