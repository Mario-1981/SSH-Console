use crate::models::{CertInspection, CommandStep, SshCommand, UserCertificateSecret};
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::process::Command;
use tokio::time::timeout;
use zeroize::Zeroizing;

/// Kompiliert eine Befehlskette mit konfigurierbaren `sleep`-Pausen dazwischen
/// in einen einzigen POSIX-kompatiblen SSH-Befehl.
pub fn compile_command_chain(steps: &[CommandStep], stop_on_error: bool) -> Result<(String, Vec<CommandStep>, u64), String> {
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

/// Validiert die 3 hochgeladenen Dateien (zertifikat, zertifikat.pub, zertifikat-cert.pub)
/// mithilfe von `/usr/bin/ssh-keygen -L -f` unter Debian Trixie und liest Key-ID, Serial,
/// Principals, Gültigkeitszeitraum und CA-Fingerabdruck aus.
pub async fn inspect_certificate_bundle(
    private_key: &str,
    public_key: &str,
    cert_content: &str,
) -> Result<CertInspection, String> {
    if !private_key.contains("BEGIN OPENSSH PRIVATE KEY") && !private_key.contains("PRIVATE KEY") {
        return Err("Privater Schlüssel (zertifikat) besitzt keinen gültigen OpenSSH/PEM-Header.".into());
    }
    if !cert_content.contains("-cert-v01@openssh.com") {
        return Err("zertifikat-cert.pub ist kein gültiges OpenSSH-Zertifikat (*-cert-v01@openssh.com).".into());
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
    fs::write(&cert_path, cert_content).map_err(|e| e.to_string())?;

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
    let mut cert_type = String::from("unknown");
    let mut valid_range = String::new();
    let mut ca_fingerprint = String::new();
    let mut principals = Vec::new();
    let mut in_principals = false;

    for line in summary.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Type:") {
            in_principals = false;
            cert_type = trimmed.trim_start_matches("Type:").trim().to_string();
        } else if trimmed.starts_with("Key ID:") {
            in_principals = false;
            key_id = trimmed
                .trim_start_matches("Key ID:")
                .trim()
                .trim_matches('"')
                .to_string();
        } else if trimmed.starts_with("Serial:") {
            in_principals = false;
            serial = trimmed.trim_start_matches("Serial:").trim().to_string();
        } else if trimmed.starts_with("Valid:") {
            in_principals = false;
            valid_range = trimmed.trim_start_matches("Valid:").trim().to_string();
        } else if trimmed.starts_with("Signing CA:") {
            in_principals = false;
            ca_fingerprint = trimmed.trim_start_matches("Signing CA:").trim().to_string();
        } else if trimmed.starts_with("Principals:") {
            in_principals = true;
        } else if trimmed.ends_with(':') {
            in_principals = false;
        } else if in_principals && !trimmed.is_empty() && trimmed != "(none)" {
            principals.push(trimmed.to_string());
        }
    }

    if !cert_type.contains("user certificate") {
        return Err(format!(
            "zertifikat-cert.pub ist kein Benutzerzertifikat (erkannt: '{cert_type}')."
        ));
    }

    Ok(CertInspection {
        key_id,
        serial,
        cert_type,
        principals,
        valid_range,
        ca_fingerprint,
        raw_summary: summary,
    })
}

pub struct SshRunOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

/// Führt den vom Admin freigegebenen SSH-Befehl passwortlos über OpenSSH aus.
/// Legt `zertifikat` (0600), `zertifikat.pub` (0644) und `zertifikat-cert.pub` (0644)
/// in einem isolierten 0700-Temp-Verzeichnis an und löscht diese nach Ausführung sofort.
pub async fn run_ssh_command(
    ip: &str,
    port: u16,
    ssh_user: &str,
    command: &SshCommand,
    cert: &UserCertificateSecret,
    private_key_plain: Zeroizing<Vec<u8>>,
) -> Result<SshRunOutput, String> {
    let started = Instant::now();
    let tmp_dir = TempDir::new().map_err(|e| format!("TempDir-Fehler: {e}"))?;
    fs::set_permissions(tmp_dir.path(), fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod 0700 fehlgeschlagen: {e}"))?;

    let key_path = tmp_dir.path().join("zertifikat");
    let pub_path = tmp_dir.path().join("zertifikat.pub");
    let cert_path = tmp_dir.path().join("zertifikat-cert.pub");

    fs::write(&key_path, private_key_plain.as_slice())
        .map_err(|e| format!("Schreiben von zertifikat fehlgeschlagen: {e}"))?;
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod 0600 fehlgeschlagen: {e}"))?;
    fs::write(&pub_path, cert.public_key.as_bytes())
        .map_err(|e| format!("Schreiben von zertifikat.pub fehlgeschlagen: {e}"))?;
    fs::write(&cert_path, cert.certificate.as_bytes())
        .map_err(|e| format!("Schreiben von zertifikat-cert.pub fehlgeschlagen: {e}"))?;

    let mut cmd = Command::new("/usr/bin/ssh");
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", tmp_dir.path())
        .arg("-i")
        .arg(&key_path)
        .arg("-o")
        .arg(format!("CertificateFile={}", cert_path.display()))
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("PasswordAuthentication=no")
        .arg("-o")
        .arg("KbdInteractiveAuthentication=no")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("-o")
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
        }),
        Ok(Err(e)) => Err(format!("OpenSSH-Ausführung fehlgeschlagen: {e}")),
        Err(_) => Ok(SshRunOutput {
            exit_code: 124,
            stdout: String::new(),
            stderr: format!("Befehl nach {} Sekunden abgebrochen (Timeout).", command.timeout_sec),
            duration_ms: started.elapsed().as_millis() as u64,
        }),
    }
}
