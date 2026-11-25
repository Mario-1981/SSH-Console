use crate::models::{CertInspection, CommandStep, SshCommand, UserCertificateSecret};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::process::Command;
use tokio::time::timeout;
use zeroize::Zeroizing;

/// Kompiliert eine Befehlskette mit konfigurierbaren `sleep`-Pausen dazwischen
/// in einen einzigen POSIX-kompatiblen SSH-Befehl.
pub fn compile_command_chain(
    steps: &[CommandStep],
    stop_on_error: bool,
) -> Result<(String, Vec<CommandStep>, u64), String> {
    let cleaned: Vec<CommandStep> = steps
        .iter()
        .map(|s| CommandStep {
            command: s.command.trim().to_string(),
            sleep_after_sec: s.sleep_after_sec.min(600),
        })
        .filter(|s| !s.command.is_empty())
        .collect();

    if cleaned.is_empty() {
        return Err("Eine Befehlskette benötigt mindestens einen SSH-Befehl.".into());
    }

    let sep = if stop_on_error { " && " } else { "; " };
    let mut parts: Vec<String> = Vec::new();
    let mut total_sleep: u64 = 0;

    for (idx, step) in cleaned.iter().enumerate() {
        parts.push(format!("{{ {}; }}", step.command));
        let is_last = idx + 1 == cleaned.len();
        if !is_last && step.sleep_after_sec > 0 {
            total_sleep = total_sleep.saturating_add(step.sleep_after_sec);
            parts.push(format!("sleep {}", step.sleep_after_sec));
        }
    }

    Ok((parts.join(sep), cleaned, total_sleep))
}

pub fn validate_ip(ip: &str) -> Result<String, String> {
    let trimmed = ip.trim();
    trimmed
        .parse::<IpAddr>()
        .map(|addr| addr.to_string())
        .map_err(|_| format!("Ungültige IPv4- oder IPv6-Adresse: '{trimmed}'"))
}

pub fn validate_ssh_user(user: &str) -> Result<String, String> {
    let trimmed = user.trim();
    if trimmed.is_empty() || trimmed.len() > 32 {
        return Err("SSH-Benutzername muss 1–32 Zeichen lang sein.".into());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(format!("Ungültiger SSH-Benutzername: '{trimmed}'"));
    }
    Ok(trimmed.to_string())
}

fn ensure_known_hosts_dir(data_dir: &Path) -> Result<PathBuf, String> {
    let dir = data_dir.join("known_hosts");
    fs::create_dir_all(&dir)
        .map_err(|e| format!("known_hosts-Verzeichnis konnte nicht erstellt werden: {e}"))?;
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    Ok(dir)
}

fn sanitize_user_id_for_filename(user_id: &str) -> Result<String, String> {
    let clean: String = user_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if clean.is_empty() {
        return Err("Ungültige Benutzer-ID für known_hosts.".into());
    }
    Ok(clean)
}

pub fn user_known_hosts_path(data_dir: &Path, user_id: &str) -> Result<PathBuf, String> {
    let dir = ensure_known_hosts_dir(data_dir)?;
    let file_name = format!("{}.known_hosts", sanitize_user_id_for_filename(user_id)?);
    let file_path = dir.join(file_name);
    if !file_path.exists() {
        fs::write(&file_path, "")
            .map_err(|e| format!("known_hosts-Datei konnte nicht erstellt werden: {e}"))?;
        let _ = fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600));
    }
    Ok(file_path)
}

fn count_known_hosts_file(path: &Path) -> usize {
    let Ok(content) = fs::read_to_string(path) else {
        return 0;
    };
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .count()
}

fn matches_host_token(token: &str, ip_lower: &str, port: Option<u16>) -> bool {
    let clean = token.trim().to_ascii_lowercase();
    if clean.is_empty() {
        return false;
    }
    match port {
        None => clean == ip_lower || clean.starts_with(&format!("[{ip_lower}]:")),
        Some(22) => clean == ip_lower || clean == format!("[{ip_lower}]:22"),
        Some(p) => clean == format!("[{ip_lower}]:{p}"),
    }
}

fn remove_matching_entries_from_file(
    file_path: &Path,
    ip: &str,
    port: Option<u16>,
) -> Result<(usize, usize), String> {
    let clean_ip = validate_ip(ip)?;
    if !file_path.exists() {
        return Ok((0, 0));
    }

    let before_count = count_known_hosts_file(file_path);

    // 1. Zuerst OpenSSH ssh-keygen -R nutzen (entfernt auch evtl. gehashte |1|-Einträge)
    if Path::new("/usr/bin/ssh-keygen").exists() {
        let targets: Vec<String> = match port {
            None | Some(22) => vec![clean_ip.clone(), format!("[{clean_ip}]:22")],
            Some(p) => vec![format!("[{clean_ip}]:{p}")],
        };
        for target in targets {
            let _ = StdCommand::new("/usr/bin/ssh-keygen")
                .arg("-R")
                .arg(&target)
                .arg("-f")
                .arg(file_path)
                .output();
        }
        let backup = PathBuf::from(format!("{}.old", file_path.display()));
        if backup.exists() {
            let _ = fs::remove_file(backup);
        }
    }

    // 2. Deterministische Klartext-Filterung (IPv4, IPv6, [ip]:port, kommagetrennte Host-Listen)
    let ip_lower = clean_ip.to_ascii_lowercase();
    let content = fs::read_to_string(file_path)
        .map_err(|e| format!("known_hosts konnte nicht gelesen werden: {e}"))?;
    let mut next_lines: Vec<String> = Vec::new();

    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            next_lines.push(raw_line.to_string());
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let host_idx = if parts.first().is_some_and(|p| p.starts_with('@')) && parts.len() >= 4 {
            1
        } else {
            0
        };
        if parts.len() < host_idx + 3 {
            next_lines.push(raw_line.to_string());
            continue;
        }

        let host_tokens: Vec<&str> = parts[host_idx].split(',').collect();
        let remaining_tokens: Vec<&str> = host_tokens
            .iter()
            .copied()
            .filter(|tok| !matches_host_token(tok, &ip_lower, port))
            .collect();

        if remaining_tokens.is_empty() {
            continue;
        }
        if remaining_tokens.len() != host_tokens.len() {
            let mut rebuilt: Vec<String> = parts.iter().map(|s| (*s).to_string()).collect();
            rebuilt[host_idx] = remaining_tokens.join(",");
            next_lines.push(rebuilt.join(" "));
        } else {
            next_lines.push(raw_line.to_string());
        }
    }

    let next_content = if next_lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", next_lines.join("\n"))
    };
    fs::write(file_path, next_content)
        .map_err(|e| format!("known_hosts konnte nicht geschrieben werden: {e}"))?;
    let _ = fs::set_permissions(file_path, fs::Permissions::from_mode(0o600));

    let remaining_count = count_known_hosts_file(file_path);
    let removed_count = before_count.saturating_sub(remaining_count);
    Ok((removed_count, remaining_count))
}

pub fn remove_user_host_key(
    data_dir: &Path,
    user_id: &str,
    ip: &str,
    port: Option<u16>,
) -> Result<(usize, usize), String> {
    let file_path = user_known_hosts_path(data_dir, user_id)?;
    remove_matching_entries_from_file(&file_path, ip, port)
}

fn list_known_hosts_files(data_dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(dir) = ensure_known_hosts_dir(data_dir) {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.ends_with(".known_hosts"))
                {
                    files.push(path);
                }
            }
        }
    }
    let legacy = data_dir.join("known_hosts.txt");
    if legacy.is_file() {
        files.push(legacy);
    }
    files
}

pub fn global_known_hosts_stats(data_dir: &Path) -> (usize, usize) {
    let mut total_entries = 0usize;
    let mut user_files = 0usize;
    for path in list_known_hosts_files(data_dir) {
        let count = count_known_hosts_file(&path);
        if count > 0 {
            total_entries += count;
            user_files += 1;
        }
    }
    (total_entries, user_files)
}

pub fn clear_global_host_keys(
    data_dir: &Path,
    ip: Option<&str>,
    port: Option<u16>,
) -> Result<(usize, usize, usize), String> {
    let files = list_known_hosts_files(data_dir);
    let mut removed_count = 0usize;
    let mut affected_files = 0usize;

    if let Some(target_ip) = ip {
        for path in &files {
            let (removed, _) = remove_matching_entries_from_file(path, target_ip, port)?;
            if removed > 0 {
                removed_count += removed;
                affected_files += 1;
            }
        }
        let (total_entries, _) = global_known_hosts_stats(data_dir);
        return Ok((removed_count, total_entries, affected_files));
    }

    for path in &files {
        let count = count_known_hosts_file(path);
        if count > 0 {
            removed_count += count;
            affected_files += 1;
        }
        let _ = fs::write(path, "");
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }

    Ok((removed_count, 0, affected_files))
}

fn detect_private_key_format(private_key: &str) -> String {
    if private_key.contains("BEGIN OPENSSH PRIVATE KEY") {
        "openssh-v1".into()
    } else if private_key.contains("BEGIN RSA PRIVATE KEY") {
        "pem-rsa".into()
    } else if private_key.contains("BEGIN EC PRIVATE KEY") {
        "pem-ec".into()
    } else if private_key.contains("BEGIN PRIVATE KEY")
        || private_key.contains("BEGIN ENCRYPTED PRIVATE KEY")
    {
        "pem-pkcs8".into()
    } else {
        "unknown".into()
    }
}

fn read_ssh_wire_str<'a>(buf: &'a [u8], offset: &mut usize) -> Option<&'a str> {
    if *offset + 4 > buf.len() {
        return None;
    }
    let len = u32::from_be_bytes([
        buf[*offset],
        buf[*offset + 1],
        buf[*offset + 2],
        buf[*offset + 3],
    ]) as usize;
    *offset += 4;
    if *offset + len > buf.len() {
        return None;
    }
    let s = std::str::from_utf8(&buf[*offset..*offset + len]).ok()?;
    *offset += len;
    Some(s)
}

fn detect_private_key_encrypted(private_key: &str) -> bool {
    if private_key.contains("ENCRYPTED") || private_key.contains("Proc-Type: 4,ENCRYPTED") {
        return true;
    }
    if private_key.contains("BEGIN OPENSSH PRIVATE KEY") {
        let mut inside = false;
        let mut b64 = String::new();
        for line in private_key.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
                inside = true;
                continue;
            }
            if trimmed.starts_with("-----END OPENSSH PRIVATE KEY-----") {
                break;
            }
            if inside && !trimmed.is_empty() {
                b64.push_str(trimmed);
            }
        }
        if let Ok(raw) = STANDARD.decode(&b64) {
            const MAGIC: &[u8] = b"openssh-key-v1\0";
            if raw.starts_with(MAGIC) {
                let mut offset = MAGIC.len();
                if let (Some(cipher), Some(kdf)) = (
                    read_ssh_wire_str(&raw, &mut offset),
                    read_ssh_wire_str(&raw, &mut offset),
                ) {
                    return cipher != "none" || kdf != "none";
                }
            }
        }
    }
    false
}

fn first_non_empty_line(text: &str) -> &str {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .unwrap_or("")
}

/// Validiert die hochgeladenen SSH-Dateien (`zertifikat`, `zertifikat.pub` sowie optional
/// `zertifikat-cert.pub`) mithilfe von `/usr/bin/ssh-keygen` unter Debian Trixie.
pub async fn inspect_certificate_bundle(
    private_key: &str,
    public_key: &str,
    cert_content: Option<&str>,
) -> Result<CertInspection, String> {
    if !private_key.contains("BEGIN OPENSSH PRIVATE KEY") && !private_key.contains("PRIVATE KEY") {
        return Err("Privater Schlüssel (zertifikat) besitzt keinen gültigen OpenSSH/PEM-Header.".into());
    }
    let clean_cert = cert_content.map(str::trim).filter(|c| !c.is_empty());
    if let Some(c) = clean_cert {
        if !c.contains("-cert-v01@openssh.com") {
            return Err("zertifikat-cert.pub ist kein gültiges OpenSSH-Zertifikat (*-cert-v01@openssh.com).".into());
        }
    }

    let tmp_dir = TempDir::new().map_err(|e| format!("Temp-Verzeichnis fehlgeschlagen: {e}"))?;
    fs::set_permissions(tmp_dir.path(), fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod 0700 fehlgeschlagen: {e}"))?;

    let priv_path = tmp_dir.path().join("zertifikat");
    let pub_path = tmp_dir.path().join("zertifikat.pub");
    let cert_path = tmp_dir.path().join("zertifikat-cert.pub");

    fs::write(&priv_path, private_key).map_err(|e| e.to_string())?;
    fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    fs::write(&pub_path, public_key).map_err(|e| e.to_string())?;

    // 1. Prüfe öffentlichen Schlüssel mit ssh-keygen -lf
    let pub_check = Command::new("/usr/bin/ssh-keygen")
        .arg("-lf")
        .arg(&pub_path)
        .output()
        .await
        .map_err(|e| format!("ssh-keygen konnte nicht gestartet werden (openssh-client installiert?): {e}"))?;
    if !pub_check.status.success() {
        return Err(format!(
            "zertifikat.pub ist ungültig: {}",
            String::from_utf8_lossy(&pub_check.stderr)
        ));
    }
    let pub_summary = String::from_utf8_lossy(&pub_check.stdout).trim().to_string();
    let pub_fingerprint = pub_summary
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_string();
    let pub_line = first_non_empty_line(public_key);
    let pub_parts: Vec<&str> = pub_line.split_whitespace().collect();
    let pub_key_algorithm = pub_parts.first().copied().unwrap_or("unknown").to_string();
    let comment = if pub_parts.len() >= 3 {
        pub_parts[2..].join(" ")
    } else {
        String::new()
    };

    let private_key_format = detect_private_key_format(private_key);
    let private_key_encrypted = detect_private_key_encrypted(private_key);

    let mut warnings = Vec::new();
    if private_key_encrypted {
        warnings.push(
            "Der private Schlüssel ist passwortgeschützt. Sie können das Passwort optional verschlüsselt beim Zertifikat hinterlegen oder bei jeder Nutzung eingeben."
                .into(),
        );
    }

    // Prüfe optional, ob Privatschlüssel zum Public Key passt
    let mut private_key_matches_pub: Option<bool> = None;
    if !private_key_encrypted {
        if let Ok(derived) = Command::new("/usr/bin/ssh-keygen")
            .args(["-y", "-P", "", "-f"])
            .arg(&priv_path)
            .output()
            .await
        {
            if derived.status.success() {
                let derived_str = String::from_utf8_lossy(&derived.stdout);
                let derived_parts: Vec<&str> = derived_str.trim().split_whitespace().collect();
                if derived_parts.len() >= 2 && pub_parts.len() >= 2 {
                    let matches = derived_parts[1] == pub_parts[1];
                    private_key_matches_pub = Some(matches);
                    if !matches {
                        warnings.push(
                            "Der private Schlüssel (zertifikat) passt nicht zum öffentlichen Schlüssel (zertifikat.pub)."
                                .into(),
                        );
                    }
                }
            }
        }
    }

    // Ohne zertifikat-cert.pub: Klassisches 2-Dateien-SSH-Schlüsselpaar
    let Some(cert_text) = clean_cert else {
        return Ok(CertInspection {
            has_certificate: false,
            cert_algorithm: "ohne Zertifikat (SSH-Schlüsselpaar)".into(),
            pub_key_algorithm,
            serial: "—".into(),
            cert_type: "keypair".into(),
            key_id: comment,
            principals: vec![],
            valid_after: "Unbegrenzt".into(),
            valid_before: "Unbegrenzt".into(),
            valid_after_unix: 0,
            valid_before_unix: 0,
            is_expired: false,
            is_not_yet_valid: false,
            critical_options: vec![],
            extensions: vec![],
            pub_key_fingerprint: pub_fingerprint,
            ca_fingerprint: String::new(),
            private_key_format,
            private_key_encrypted,
            pub_key_matches_cert: true,
            private_key_matches_pub,
            warnings,
        });
    };

    fs::write(&cert_path, cert_text).map_err(|e| e.to_string())?;
    let cert_line = first_non_empty_line(cert_text);
    let cert_algorithm = cert_line
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .to_string();

    // 2. Prüfe OpenSSH-Zertifikat mit ssh-keygen -L -f
    let cert_check = Command::new("/usr/bin/ssh-keygen")
        .arg("-L")
        .arg("-f")
        .arg(&cert_path)
        .output()
        .await
        .map_err(|e| format!("ssh-keygen -L fehlgeschlagen: {e}"))?;
    if !cert_check.status.success() {
        return Err(format!(
            "zertifikat-cert.pub ist ungültig: {}",
            String::from_utf8_lossy(&cert_check.stderr)
        ));
    }

    let summary = String::from_utf8_lossy(&cert_check.stdout).to_string();
    let mut key_id = String::new();
    let mut serial = String::from("0");
    let mut raw_type = String::from("unknown");
    let mut valid_after = String::from("unbegrenzt");
    let mut valid_before = String::from("unbegrenzt");
    let mut ca_fingerprint = String::new();
    let mut principals = Vec::new();
    let mut critical_options = Vec::new();
    let mut extensions = Vec::new();
    let mut section = "";

    for line in summary.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Type:") {
            section = "";
            raw_type = trimmed.trim_start_matches("Type:").trim().to_string();
        } else if trimmed.starts_with("Key ID:") {
            section = "";
            key_id = trimmed
                .trim_start_matches("Key ID:")
                .trim()
                .trim_matches('"')
                .to_string();
        } else if trimmed.starts_with("Serial:") {
            section = "";
            serial = trimmed.trim_start_matches("Serial:").trim().to_string();
        } else if trimmed.starts_with("Valid:") {
            section = "";
            let valid_str = trimmed.trim_start_matches("Valid:").trim();
            if let Some((from_part, to_part)) = valid_str.split_once(" to ") {
                valid_after = from_part.trim_start_matches("from ").trim().to_string();
                valid_before = to_part.trim().to_string();
            } else {
                valid_after = valid_str.to_string();
                valid_before = valid_str.to_string();
            }
        } else if trimmed.starts_with("Signing CA:") {
            section = "";
            ca_fingerprint = trimmed.trim_start_matches("Signing CA:").trim().to_string();
        } else if trimmed.starts_with("Principals:") {
            section = "principals";
        } else if trimmed.starts_with("Critical Options:") {
            section = "critical";
        } else if trimmed.starts_with("Extensions:") {
            section = "extensions";
        } else if trimmed.ends_with(':') {
            section = "";
        } else if !trimmed.is_empty() && trimmed != "(none)" {
            match section {
                "principals" => principals.push(trimmed.to_string()),
                "critical" => critical_options.push(trimmed.to_string()),
                "extensions" => extensions.push(trimmed.to_string()),
                _ => {}
            }
        }
    }

    if !raw_type.contains("user certificate") {
        return Err(format!(
            "zertifikat-cert.pub ist kein Benutzerzertifikat (erkannt: '{raw_type}')."
        ));
    }

    Ok(CertInspection {
        has_certificate: true,
        cert_algorithm,
        pub_key_algorithm,
        serial,
        cert_type: "user".into(),
        key_id,
        principals,
        valid_after,
        valid_before,
        valid_after_unix: 0,
        valid_before_unix: 0,
        is_expired: false,
        is_not_yet_valid: false,
        critical_options,
        extensions,
        pub_key_fingerprint: pub_fingerprint,
        ca_fingerprint,
        private_key_format,
        private_key_encrypted,
        pub_key_matches_cert: true,
        private_key_matches_pub,
        warnings,
    })
}

pub struct GeneratedTestBundle {
    pub private_key: String,
    pub public_key: String,
}

pub fn is_valid_principal_token(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 64
        && !trimmed.starts_with('-')
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '@' | '.' | '-'))
}

pub fn parse_and_validate_principals(raw: &serde_json::Value) -> Result<Vec<String>, String> {
    let mut items: Vec<String> = Vec::new();
    match raw {
        serde_json::Value::Array(arr) => {
            for v in arr {
                if let Some(s) = v.as_str() {
                    items.push(s.to_string());
                }
            }
        }
        serde_json::Value::String(s) => {
            for part in s.split(|c| matches!(c, ',' | ';' | '\n' | '\r')) {
                items.push(part.to_string());
            }
        }
        _ => {
            return Err(
                "Bitte mindestens einen Principal (-n) angeben (z. B. root oder admin).".into(),
            );
        }
    }

    let mut out: Vec<String> = Vec::new();
    for raw_item in items {
        let trimmed = raw_item.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !is_valid_principal_token(trimmed) {
            return Err(format!(
                "Ungültiger Principal (-n): „{trimmed}“. Erlaubt sind Buchstaben, Ziffern, Punkt, Unterstrich, Bindestrich (nicht am Anfang) und @ (max. 64 Zeichen)."
            ));
        }
        if !out.iter().any(|x| x == trimmed) {
            out.push(trimmed.to_string());
        }
    }

    if out.is_empty() {
        return Err("Bitte mindestens einen Principal (-n) angeben (z. B. root oder admin).".into());
    }
    if out.len() > 32 {
        return Err("Maximal 32 Principals (-n) pro Zertifikat sind zulässig.".into());
    }
    Ok(out)
}

fn parse_duration_part(part: &str, prefix: char) -> Result<(u64, char), String> {
    let mut chars = part.chars();
    if chars.next() != Some(prefix) {
        return Err("Ungültiges Zeitformat".into());
    }
    let rest: String = chars.collect();
    if rest.len() < 2 {
        return Err("Ungültiges Zeitformat".into());
    }
    let unit = rest
        .chars()
        .last()
        .unwrap()
        .to_ascii_lowercase();
    if !matches!(unit, 's' | 'm' | 'h' | 'd' | 'w') {
        return Err("Ungültige Zeiteinheit".into());
    }
    let num_str = &rest[..rest.len() - 1];
    if !num_str.chars().all(|c| c.is_ascii_digit()) {
        return Err("Ungültige Zahl".into());
    }
    let amount = num_str.parse::<u64>().map_err(|_| "Ungültige Zahl".to_string())?;
    let unit_sec: u64 = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        'w' => 604800,
        _ => return Err("Ungültige Zeiteinheit".into()),
    };
    let total = amount.checked_mul(unit_sec).ok_or_else(|| "Gültigkeitsdauer zu groß".to_string())?;
    let max_sec = 100u64 * 365 * 86400;
    if total > max_sec {
        return Err("Gültigkeitsdauer überschreitet das Maximum von 100 Jahren.".into());
    }
    Ok((amount, unit))
}

pub fn validate_validity_spec(raw_opt: Option<&str>) -> Result<String, String> {
    let raw = raw_opt.map(str::trim).filter(|s| !s.is_empty()).unwrap_or("+30d");
    let lower = raw.to_ascii_lowercase();
    if lower == "forever" || lower == "always" || lower == "always:forever" {
        return Ok("always:forever".into());
    }
    if raw.starts_with('+') {
        let (amount, unit) = parse_duration_part(raw, '+').map_err(|_| {
            format!(
                "Ungültige Gültigkeitsdauer (-V): „{raw}“. Erlaubt sind z. B. +8h, +24h, +7d, +30d, +52w oder forever."
            )
        })?;
        let unit_sec: u64 = match unit {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            _ => 604800,
        };
        if amount.saturating_mul(unit_sec) < 60 {
            return Err("Ungültige Gültigkeitsdauer (-V): Mindestens +60s erforderlich.".into());
        }
        return Ok(format!("+{amount}{unit}"));
    }
    if let Some((left, right)) = raw.split_once(':') {
        let (back_amt, back_unit) = parse_duration_part(left, '-').map_err(|_| {
            format!("Ungültige Gültigkeitsdauer (-V): „{raw}“.")
        })?;
        let (fwd_amt, fwd_unit) = parse_duration_part(right, '+').map_err(|_| {
            format!("Ungültige Gültigkeitsdauer (-V): „{raw}“.")
        })?;
        let fwd_unit_sec: u64 = match fwd_unit {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            _ => 604800,
        };
        if fwd_amt.saturating_mul(fwd_unit_sec) < 60 {
            return Err("Ungültige Gültigkeitsdauer (-V): Mindestens +60s erforderlich.".into());
        }
        return Ok(format!("-{back_amt}{back_unit}:+{fwd_amt}{fwd_unit}"));
    }
    Err(format!(
        "Ungültige Gültigkeitsdauer (-V): „{raw}“. Erlaubt sind z. B. +8h, +24h, +7d, +30d, +52w oder forever."
    ))
}

pub fn validity_forward_seconds(raw_opt: Option<&str>) -> Result<Option<u64>, String> {
    let normalized = validate_validity_spec(raw_opt)?;
    if normalized == "always:forever" {
        return Ok(None);
    }
    let fwd_part = if let Some((_, right)) = normalized.split_once(':') {
        right
    } else {
        normalized.as_str()
    };
    let (amount, unit) = parse_duration_part(fwd_part, '+')?;
    let unit_sec: u64 = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => 604800,
    };
    Ok(Some(amount.saturating_mul(unit_sec)))
}

pub fn sanitize_key_id(raw: &str, fallback: &str) -> String {
    let mapped: String = raw
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '@' | '.' | ':' | '/' | ' ' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = mapped.trim_start_matches('-').trim();
    let limited: String = trimmed.chars().take(128).collect();
    if limited.is_empty() {
        fallback.to_string()
    } else {
        limited
    }
}

pub fn derive_cert_file_name(existing: &str, pub_file: &str, priv_file: &str) -> String {
    if !existing.trim().is_empty() {
        return existing.trim().to_string();
    }
    let pub_clean = pub_file.trim();
    if pub_clean.to_ascii_lowercase().ends_with(".pub") && pub_clean.len() > 4 {
        return format!("{}-cert.pub", &pub_clean[..pub_clean.len() - 4]);
    }
    let priv_clean = priv_file.trim();
    if priv_clean.is_empty() {
        "zertifikat-cert.pub".into()
    } else {
        format!("{priv_clean}-cert.pub")
    }
}

pub fn extract_fingerprint_token(raw: &str) -> String {
    for tok in raw.split_whitespace() {
        let clean = tok.trim_matches(|c| matches!(c, '(' | ')' | ',' | ';'));
        if clean.len() > 7 && clean[..7].eq_ignore_ascii_case("SHA256:") {
            let body = clean[7..].trim_end_matches('=');
            return format!("SHA256:{body}");
        }
        if clean.len() > 4 && clean[..4].eq_ignore_ascii_case("MD5:") {
            return clean.to_ascii_lowercase();
        }
    }
    raw.trim().to_string()
}

pub fn is_signed_by_same_ca(existing_ca_fp: &str, selected_ca_fp: &str) -> bool {
    let a = extract_fingerprint_token(existing_ca_fp);
    let b = extract_fingerprint_token(selected_ca_fp);
    !a.is_empty() && !b.is_empty() && a == b
}

/// Signiert einen öffentlichen Benutzerschlüssel (`zertifikat.pub`) mithilfe einer
/// passwortgeschützten CA über `/usr/bin/ssh-keygen -s` und `SSH_ASKPASS`.
#[allow(clippy::too_many_arguments)]
pub async fn sign_user_public_key_with_ca(
    ca_private_key: &[u8],
    ca_public_key: &str,
    ca_passphrase: &str,
    user_public_key: &str,
    key_id: &str,
    principals: &[String],
    validity_spec: &str,
    serial: u64,
) -> Result<String, String> {
    let tmp_dir = TempDir::new().map_err(|e| format!("Temp-Verzeichnis fehlgeschlagen: {e}"))?;
    fs::set_permissions(tmp_dir.path(), fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod 0700 fehlgeschlagen: {e}"))?;

    let ca_path = tmp_dir.path().join("ca");
    let ca_pub_path = tmp_dir.path().join("ca.pub");
    let target_pub_path = tmp_dir.path().join("target.pub");
    let target_cert_path = tmp_dir.path().join("target-cert.pub");
    let pass_path = tmp_dir.path().join("passphrase");
    let askpass_path = tmp_dir.path().join("askpass.sh");

    if ca_private_key.ends_with(b"\n") {
        fs::write(&ca_path, ca_private_key).map_err(|e| e.to_string())?;
    } else {
        let mut key_nl = Zeroizing::new(Vec::with_capacity(ca_private_key.len() + 1));
        key_nl.extend_from_slice(ca_private_key);
        key_nl.push(b'\n');
        fs::write(&ca_path, key_nl.as_slice()).map_err(|e| e.to_string())?;
    }
    fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod 0600 fehlgeschlagen: {e}"))?;
    fs::write(&ca_pub_path, format!("{}\n", ca_public_key.trim())).map_err(|e| e.to_string())?;
    fs::write(&target_pub_path, format!("{}\n", user_public_key.trim()))
        .map_err(|e| e.to_string())?;

    let pass_line = Zeroizing::new(format!("{ca_passphrase}\n"));
    fs::write(&pass_path, pass_line.as_bytes()).map_err(|e| e.to_string())?;
    fs::set_permissions(&pass_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod 0600 fehlgeschlagen: {e}"))?;
    fs::write(&askpass_path, "#!/bin/sh\ncat \"$TRIXIESSH_PASS_FILE\"\n")
        .map_err(|e| e.to_string())?;
    fs::set_permissions(&askpass_path, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod 0700 fehlgeschlagen: {e}"))?;

    let mut cmd = Command::new("/usr/bin/ssh-keygen");
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", tmp_dir.path())
        .env("SSH_ASKPASS", &askpass_path)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", "none:0")
        .env("TRIXIESSH_PASS_FILE", &pass_path)
        .stdin(Stdio::null())
        .arg("-s")
        .arg(&ca_path)
        .arg("-I")
        .arg(key_id)
        .arg("-n")
        .arg(principals.join(","))
        .arg("-V")
        .arg(validity_spec)
        .arg("-z")
        .arg(serial.to_string())
        .arg(&target_pub_path);

    let out_res = timeout(Duration::from_secs(15), cmd.output()).await;

    // Sensible Dateien vor Verlassen sofort mit Nullen überschreiben
    let _ = fs::write(&ca_path, vec![0u8; ca_private_key.len().max(16)]);
    let _ = fs::write(&pass_path, vec![0u8; ca_passphrase.len().max(16)]);
    let _ = fs::remove_file(&pass_path);
    let _ = fs::remove_file(&askpass_path);

    let out = match out_res {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            return Err(format!(
                "ssh-keygen konnte nicht gestartet werden (openssh-client installiert?): {e}"
            ))
        }
        Err(_) => return Err("CA-Signierung wegen Zeitüberschreitung abgebrochen.".into()),
    };

    if !out.status.success() {
        let stderr_text = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let lower = stderr_text.to_ascii_lowercase();
        if lower.contains("incorrect passphrase")
            || lower.contains("load key")
            || lower.contains("bad passphrase")
            || lower.contains("cannot decode")
        {
            return Err("CA-Schlüssel konnte nicht entsperrt werden (falsches CA-Passwort?).".into());
        }
        return Err(format!("CA-Signierung fehlgeschlagen: {stderr_text}"));
    }

    let signed_cert = fs::read_to_string(&target_cert_path)
        .map_err(|e| format!("Signiertes Zertifikat konnte nicht gelesen werden: {e}"))?;
    Ok(format!("{}\n", signed_cert.trim()))
}

/// Erzeugt ein OpenSSH-Ed25519-Schlüsselpaar (zertifikat + zertifikat.pub)
/// über `/usr/bin/ssh-keygen` ohne CA-Zertifikat, optional mit Passwort verschlüsselt.
pub async fn generate_test_cert_bundle(
    key_id: &str,
    passphrase: &str,
) -> Result<GeneratedTestBundle, String> {
    let tmp_dir = TempDir::new().map_err(|e| format!("Temp-Verzeichnis fehlgeschlagen: {e}"))?;
    fs::set_permissions(tmp_dir.path(), fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod 0700 fehlgeschlagen: {e}"))?;

    let user_path = tmp_dir.path().join("zertifikat");
    let pub_path = tmp_dir.path().join("zertifikat.pub");

    let user_out = Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N"])
        .arg(passphrase)
        .args(["-C", key_id, "-f"])
        .arg(&user_path)
        .output()
        .await
        .map_err(|e| format!("ssh-keygen fehlgeschlagen: {e}"))?;
    if !user_out.status.success() {
        return Err(format!(
            "Zertifikat konnte nicht erzeugt werden: {}",
            String::from_utf8_lossy(&user_out.stderr)
        ));
    }

    let private_key = fs::read_to_string(&user_path).map_err(|e| e.to_string())?;
    let public_key = fs::read_to_string(&pub_path).map_err(|e| e.to_string())?;

    Ok(GeneratedTestBundle {
        private_key,
        public_key,
    })
}

pub struct SshRunOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub ssh_invocation: String,
}

fn is_benign_known_hosts_added_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("Warning: Permanently added '")
        && trimmed.ends_with(" to the list of known hosts.")
}

fn filter_benign_ssh_stderr(stderr: &str) -> String {
    let kept: Vec<&str> = stderr
        .lines()
        .filter(|line| !is_benign_known_hosts_added_line(line))
        .collect();
    let joined = kept.join("\n");
    if joined.trim().is_empty() {
        String::new()
    } else {
        joined.trim_end().to_string()
    }
}

/// Führt den freigegebenen SSH-Befehl über OpenSSH aus.
/// Legt `zertifikat` (0600), `zertifikat.pub` (0644) und optional `zertifikat-cert.pub` (0644)
/// sowie bei Bedarf ein einmaliges `SSH_ASKPASS`-Skript in einem isolierten 0700-Temp-Verzeichnis an
/// und überschreibt/löscht sensible Dateien sofort nach Ausführung.
#[allow(clippy::too_many_arguments)]
pub async fn run_ssh_command(
    ip: &str,
    port: u16,
    ssh_user: &str,
    server_label: &str,
    command: &SshCommand,
    cert: &UserCertificateSecret,
    private_key_plain: Zeroizing<Vec<u8>>,
    passphrase: Option<&str>,
    workflow_vars: Option<&HashMap<String, String>>,
    ignore_host_key: bool,
    known_hosts_path: &Path,
) -> Result<SshRunOutput, String> {
    let started = Instant::now();
    let tmp_dir = TempDir::new().map_err(|e| format!("TempDir-Fehler: {e}"))?;
    fs::set_permissions(tmp_dir.path(), fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod 0700 fehlgeschlagen: {e}"))?;

    let key_path = tmp_dir.path().join("zertifikat");
    let pub_path = tmp_dir.path().join("zertifikat.pub");
    let cert_path = tmp_dir.path().join("zertifikat-cert.pub");
    let pass_path = tmp_dir.path().join("passphrase");
    let askpass_path = tmp_dir.path().join("askpass.sh");
    let has_cert = !cert.certificate.trim().is_empty();
    let effective_pass = passphrase.filter(|p| !p.is_empty());
    let is_workflow = command.kind == "workflow";

    if private_key_plain.ends_with(b"\n") {
        fs::write(&key_path, private_key_plain.as_slice())
            .map_err(|e| format!("Schreiben von zertifikat fehlgeschlagen: {e}"))?;
    } else {
        let mut key_with_nl = Zeroizing::new(Vec::with_capacity(private_key_plain.len() + 1));
        key_with_nl.extend_from_slice(private_key_plain.as_slice());
        key_with_nl.push(b'\n');
        fs::write(&key_path, key_with_nl.as_slice())
            .map_err(|e| format!("Schreiben von zertifikat fehlgeschlagen: {e}"))?;
    }
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod 0600 fehlgeschlagen: {e}"))?;
    fs::write(&pub_path, cert.public_key.as_bytes())
        .map_err(|e| format!("Schreiben von zertifikat.pub fehlgeschlagen: {e}"))?;
    if has_cert {
        fs::write(&cert_path, cert.certificate.as_bytes())
            .map_err(|e| format!("Schreiben von zertifikat-cert.pub fehlgeschlagen: {e}"))?;
    }

    if let Some(pass) = effective_pass {
        let pass_line = Zeroizing::new(format!("{pass}\n"));
        fs::write(&pass_path, pass_line.as_bytes())
            .map_err(|e| format!("Schreiben der Passwortdatei fehlgeschlagen: {e}"))?;
        fs::set_permissions(&pass_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 für Passwortdatei fehlgeschlagen: {e}"))?;
        // Passwortdatei wird nach Befehlsende zuverlässig mit Nullen überschrieben und gelöscht
        let askpass_script = "#!/bin/sh\ncat \"$TRIXIESSH_PASS_FILE\"\n";
        fs::write(&askpass_path, askpass_script.as_bytes())
            .map_err(|e| format!("Schreiben von askpass.sh fehlgeschlagen: {e}"))?;
        fs::set_permissions(&askpass_path, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod 0700 für askpass.sh fehlgeschlagen: {e}"))?;
    }

    let host_key_display = if ignore_host_key {
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    } else {
        "-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=<known_hosts>"
    };
    let mode_display = if effective_pass.is_some() {
        "-o NumberOfPasswordPrompts=1"
    } else {
        "-o BatchMode=yes"
    };

    let ssh_invocation = if has_cert {
        format!(
            "ssh -i zertifikat -o CertificateFile=zertifikat-cert.pub -o IdentitiesOnly=yes {mode_display} {host_key_display} -p {port} {ssh_user}@{ip} -- {}",
            command.command
        )
    } else {
        format!(
            "ssh -i zertifikat -o IdentitiesOnly=yes {mode_display} {host_key_display} -p {port} {ssh_user}@{ip} -- {}",
            command.command
        )
    };

    let mut base_args: Vec<String> = vec!["-i".into(), key_path.display().to_string()];
    if has_cert {
        base_args.push("-o".into());
        base_args.push(format!("CertificateFile={}", cert_path.display()));
    }
    base_args.push("-o".into());
    base_args.push("IdentitiesOnly=yes".into());
    if effective_pass.is_some() {
        // NumberOfPasswordPrompts muss >= 1 sein, damit OpenSSH SSH_ASKPASS zum Entsperren
        // passwortgeschützter privater Schlüssel aufruft (PasswordAuthentication bleibt deaktiviert).
        base_args.push("-o".into());
        base_args.push("NumberOfPasswordPrompts=1".into());
    } else {
        base_args.push("-o".into());
        base_args.push("BatchMode=yes".into());
    }
    base_args.extend([
        "-o".into(),
        "PasswordAuthentication=no".into(),
        "-o".into(),
        "KbdInteractiveAuthentication=no".into(),
    ]);
    if ignore_host_key {
        base_args.extend([
            "-o".into(),
            "StrictHostKeyChecking=no".into(),
            "-o".into(),
            "UserKnownHostsFile=/dev/null".into(),
        ]);
    } else {
        base_args.extend([
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            format!("UserKnownHostsFile={}", known_hosts_path.display()),
            "-o".into(),
            "HashKnownHosts=no".into(),
        ]);
    }
    base_args.extend([
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-p".into(),
        port.to_string(),
        format!("{ssh_user}@{ip}"),
        "--".into(),
    ]);

    let tmp_home = tmp_dir.path().to_path_buf();
    let use_askpass = effective_pass.is_some();

    let run_result: Result<SshRunOutput, String> = if is_workflow {
        match crate::workflow::parse_and_validate_workflow(&command.workflow_json) {
            Err(err_msg) => Ok(SshRunOutput {
                exit_code: 2,
                stdout: String::new(),
                stderr: format!("Ungültiger JSON-Workflow: {err_msg}"),
                duration_ms: started.elapsed().as_millis() as u64,
                ssh_invocation,
            }),
            Ok(validated) => {
                let target_info = crate::workflow::WorkflowTargetInfo {
                    ip: ip.to_string(),
                    port,
                    user: ssh_user.to_string(),
                    label: if server_label.trim().is_empty() {
                        ip.to_string()
                    } else {
                        server_label.to_string()
                    },
                };
                let args_shared = base_args.clone();
                let home_shared = tmp_home.clone();
                let askpass_shared = askpass_path.clone();
                let pass_shared = pass_path.clone();

                let wf_out = crate::workflow::execute_workflow(
                    &validated,
                    target_info,
                    command.timeout_sec,
                    workflow_vars,
                    move |remote_cmd: String, step_timeout: Duration| {
                        let args_clone = args_shared.clone();
                        let home_clone = home_shared.clone();
                        let askpass_clone = askpass_shared.clone();
                        let pass_clone = pass_shared.clone();
                        async move {
                            let mut cmd = Command::new("/usr/bin/ssh");
                            cmd.env_clear()
                                .env("PATH", "/usr/bin:/bin")
                                .env("HOME", &home_clone);
                            if use_askpass {
                                cmd.env("SSH_ASKPASS", &askpass_clone)
                                    .env("SSH_ASKPASS_REQUIRE", "force")
                                    .env("DISPLAY", "none:0")
                                    .env("TRIXIESSH_PASS_FILE", &pass_clone);
                            }
                            for a in &args_clone {
                                cmd.arg(a);
                            }
                            cmd.arg(&remote_cmd);
                            match timeout(step_timeout.max(Duration::from_secs(1)), cmd.output()).await {
                                Ok(Ok(out)) => Ok(crate::workflow::StepExecOutput {
                                    exit_code: out.status.code().unwrap_or(255),
                                    stdout: String::from_utf8_lossy(&out.stdout).to_string(),
                                    stderr: filter_benign_ssh_stderr(&String::from_utf8_lossy(&out.stderr)),
                                }),
                                Ok(Err(e)) => Err(format!("OpenSSH-Ausführung fehlgeschlagen: {e}")),
                                Err(_) => Ok(crate::workflow::StepExecOutput {
                                    exit_code: 124,
                                    stdout: String::new(),
                                    stderr: "Schritt wegen Zeitüberschreitung abgebrochen (Timeout).".into(),
                                }),
                            }
                        }
                    },
                )
                .await;

                match wf_out {
                    Ok(res) => {
                        let wf_invocation = if res.commands_run.is_empty() {
                            ssh_invocation
                        } else {
                            let lines: Vec<String> = res
                                .commands_run
                                .iter()
                                .enumerate()
                                .map(|(i, c)| format!("  {}. ssh ... {ssh_user}@{ip} -- {c}", i + 1))
                                .collect();
                            format!(
                                "[JSON-Workflow · {} Schritte · {} SSH-Befehle]\n{}",
                                res.executed_steps,
                                res.commands_run.len(),
                                lines.join("\n")
                            )
                        };
                        Ok(SshRunOutput {
                            exit_code: res.exit_code,
                            stdout: res.stdout,
                            stderr: res.stderr,
                            duration_ms: started.elapsed().as_millis() as u64,
                            ssh_invocation: wf_invocation,
                        })
                    }
                    Err(e) => Err(e),
                }
            }
        }
    } else {
        let mut cmd = Command::new("/usr/bin/ssh");
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &tmp_home);
        if use_askpass {
            cmd.env("SSH_ASKPASS", &askpass_path)
                .env("SSH_ASKPASS_REQUIRE", "force")
                .env("DISPLAY", "none:0")
                .env("TRIXIESSH_PASS_FILE", &pass_path);
        }
        for a in &base_args {
            cmd.arg(a);
        }
        cmd.arg(&command.command);

        let max_duration = Duration::from_secs(command.timeout_sec.clamp(5, 3600));
        match timeout(max_duration, cmd.output()).await {
            Ok(Ok(out)) => Ok(SshRunOutput {
                exit_code: out.status.code().unwrap_or(255),
                stdout: String::from_utf8_lossy(&out.stdout).to_string(),
                stderr: filter_benign_ssh_stderr(&String::from_utf8_lossy(&out.stderr)),
                duration_ms: started.elapsed().as_millis() as u64,
                ssh_invocation,
            }),
            Ok(Err(e)) => Err(format!("OpenSSH-Ausführung fehlgeschlagen: {e}")),
            Err(_) => Ok(SshRunOutput {
                exit_code: 124,
                stdout: String::new(),
                stderr: format!("Befehl nach {} Sekunden abgebrochen (Timeout).", command.timeout_sec),
                duration_ms: started.elapsed().as_millis() as u64,
                ssh_invocation,
            }),
        }
    };

    // Privatschlüssel und ggf. Passwortdatei vor dem Entfernen des TempDir mit Nullen überschreiben
    let _ = fs::write(&key_path, vec![0u8; private_key_plain.len()]);
    if let Some(pass) = effective_pass {
        if pass_path.exists() {
            let _ = fs::write(&pass_path, vec![0u8; pass.len().max(16)]);
            let _ = fs::remove_file(&pass_path);
        }
        let _ = fs::remove_file(&askpass_path);
    }

    run_result
}
