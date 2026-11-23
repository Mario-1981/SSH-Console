use crate::models::{CertInspection, CommandStep, SshCommand, UserCertificateSecret};
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
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
    let private_key_encrypted =
        private_key.contains("ENCRYPTED") || private_key.contains("Proc-Type: 4,ENCRYPTED");

    let mut warnings = Vec::new();
    if private_key_encrypted {
        warnings.push(
            "Der private Schlüssel scheint passwortgeschützt zu sein. Für automatisierte BatchMode-SSH-Ausführungen wird ein entschlüsselter Schlüssel benötigt."
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
    pub certificate: String,
    pub ca_public_key: String,
}

/// Erzeugt ein echtes OpenSSH-Ed25519-Testzertifikat (CA + Benutzerschlüssel + Signatur)
/// über `/usr/bin/ssh-keygen` für schnelle Tests auf Debian Trixie.
pub async fn generate_test_cert_bundle(
    key_id: &str,
    principals: &[String],
) -> Result<GeneratedTestBundle, String> {
    let tmp_dir = TempDir::new().map_err(|e| format!("Temp-Verzeichnis fehlgeschlagen: {e}"))?;
    fs::set_permissions(tmp_dir.path(), fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod 0700 fehlgeschlagen: {e}"))?;

    let ca_path = tmp_dir.path().join("ca");
    let user_path = tmp_dir.path().join("zertifikat");

    let ca_out = Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "ssh-console-test-ca", "-f"])
        .arg(&ca_path)
        .output()
        .await
        .map_err(|e| format!("ssh-keygen fehlgeschlagen: {e}"))?;
    if !ca_out.status.success() {
        return Err(format!(
            "Test-CA konnte nicht erzeugt werden: {}",
            String::from_utf8_lossy(&ca_out.stderr)
        ));
    }

    let user_out = Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", key_id, "-f"])
        .arg(&user_path)
        .output()
        .await
        .map_err(|e| format!("ssh-keygen fehlgeschlagen: {e}"))?;
    if !user_out.status.success() {
        return Err(format!(
            "Testschlüssel konnte nicht erzeugt werden: {}",
            String::from_utf8_lossy(&user_out.stderr)
        ));
    }

    let principals_csv = if principals.is_empty() {
        "root".to_string()
    } else {
        principals.join(",")
    };
    let pub_path = tmp_dir.path().join("zertifikat.pub");
    let sign_out = Command::new("/usr/bin/ssh-keygen")
        .arg("-q")
        .arg("-s")
        .arg(&ca_path)
        .arg("-I")
        .arg(key_id)
        .arg("-n")
        .arg(&principals_csv)
        .arg("-V")
        .arg("+90d")
        .arg(&pub_path)
        .output()
        .await
        .map_err(|e| format!("ssh-keygen Signatur fehlgeschlagen: {e}"))?;
    if !sign_out.status.success() {
        return Err(format!(
            "Testzertifikat konnte nicht signiert werden: {}",
            String::from_utf8_lossy(&sign_out.stderr)
        ));
    }

    let private_key = fs::read_to_string(&user_path).map_err(|e| e.to_string())?;
    let public_key = fs::read_to_string(&pub_path).map_err(|e| e.to_string())?;
    let certificate =
        fs::read_to_string(tmp_dir.path().join("zertifikat-cert.pub")).map_err(|e| e.to_string())?;
    let ca_public_key =
        fs::read_to_string(tmp_dir.path().join("ca.pub")).map_err(|e| e.to_string())?;

    Ok(GeneratedTestBundle {
        private_key,
        public_key,
        certificate,
        ca_public_key,
    })
}

pub struct SshRunOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub ssh_invocation: String,
}

/// Führt den freigegebenen SSH-Befehl passwortlos über OpenSSH aus.
/// Legt `zertifikat` (0600), `zertifikat.pub` (0644) und optional `zertifikat-cert.pub` (0644)
/// in einem isolierten 0700-Temp-Verzeichnis an und löscht diese nach Ausführung sofort.
pub async fn run_ssh_command(
    ip: &str,
    port: u16,
    ssh_user: &str,
    command: &SshCommand,
    cert: &UserCertificateSecret,
    private_key_plain: Zeroizing<Vec<u8>>,
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
    let has_cert = !cert.certificate.trim().is_empty();

    fs::write(&key_path, private_key_plain.as_slice())
        .map_err(|e| format!("Schreiben von zertifikat fehlgeschlagen: {e}"))?;
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod 0600 fehlgeschlagen: {e}"))?;
    fs::write(&pub_path, cert.public_key.as_bytes())
        .map_err(|e| format!("Schreiben von zertifikat.pub fehlgeschlagen: {e}"))?;
    if has_cert {
        fs::write(&cert_path, cert.certificate.as_bytes())
            .map_err(|e| format!("Schreiben von zertifikat-cert.pub fehlgeschlagen: {e}"))?;
    }

    let host_key_display = if ignore_host_key {
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    } else {
        "-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=<known_hosts>"
    };

    let ssh_invocation = if has_cert {
        format!(
            "ssh -i zertifikat -o CertificateFile=zertifikat-cert.pub -o IdentitiesOnly=yes -o BatchMode=yes {host_key_display} -p {port} {ssh_user}@{ip} -- {}",
            command.command
        )
    } else {
        format!(
            "ssh -i zertifikat -o IdentitiesOnly=yes -o BatchMode=yes {host_key_display} -p {port} {ssh_user}@{ip} -- {}",
            command.command
        )
    };

    let mut cmd = Command::new("/usr/bin/ssh");
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", tmp_dir.path())
        .arg("-i")
        .arg(&key_path);

    if has_cert {
        cmd.arg("-o")
            .arg(format!("CertificateFile={}", cert_path.display()));
    }

    cmd.arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("PasswordAuthentication=no")
        .arg("-o")
        .arg("KbdInteractiveAuthentication=no");

    if ignore_host_key {
        cmd.arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null");
    } else {
        cmd.arg("-o")
            .arg("StrictHostKeyChecking=accept-new")
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", known_hosts_path.display()))
            .arg("-o")
            .arg("HashKnownHosts=no");
    }

    cmd.arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-p")
        .arg(port.to_string())
        .arg(format!("{ssh_user}@{ip}"))
        .arg("--")
        .arg(&command.command);

    let max_duration = Duration::from_secs(command.timeout_sec.clamp(5, 3600));
    let output_res = timeout(max_duration, cmd.output()).await;

    // Privatschlüssel vor dem Entfernen des TempDir überschreiben
    let _ = fs::write(&key_path, vec![0u8; private_key_plain.len()]);

    match output_res {
        Ok(Ok(out)) => Ok(SshRunOutput {
            exit_code: out.status.code().unwrap_or(255),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
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
}
