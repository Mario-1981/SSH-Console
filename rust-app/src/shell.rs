use crate::models::{ExecutionLog, UserCertificateSecret};
use crate::AppState;
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Command as StdCommand, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::{mpsc, RwLock};
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub struct ShellTicket {
    pub user_id: String,
    pub username: String,
    pub server_label: String,
    pub ip_address: String,
    pub port: u16,
    pub ssh_user: String,
    pub certificate_id: String,
    pub ignore_host_key: bool,
    pub cols: u16,
    pub rows: u16,
    pub expires_at: Instant,
}

#[derive(Default)]
pub struct ShellTicketStore {
    inner: RwLock<HashMap<String, ShellTicket>>,
}

impl ShellTicketStore {
    pub async fn issue(&self, mut ticket: ShellTicket) -> String {
        let mut bytes = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        let token = hex::encode(bytes);

        ticket.cols = ticket.cols.clamp(20, 400);
        ticket.rows = ticket.rows.clamp(8, 200);
        ticket.expires_at = Instant::now() + Duration::from_secs(30);

        let mut guard = self.inner.write().await;
        let now = Instant::now();
        guard.retain(|_, v| v.expires_at > now);
        guard.insert(token.clone(), ticket);
        token
    }

    pub async fn consume(&self, token: &str) -> Option<ShellTicket> {
        if token.is_empty() {
            return None;
        }
        let mut guard = self.inner.write().await;
        let now = Instant::now();
        guard.retain(|_, v| v.expires_at > now);
        guard.remove(token).filter(|t| t.expires_at > now)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellTicketRequest {
    pub server_id: Option<String>,
    pub ip_address: Option<String>,
    pub port: Option<u16>,
    pub ssh_user: Option<String>,
    #[serde(alias = "ignore_host_key")]
    pub ignore_host_key: Option<bool>,
    pub certificate_id: String,
    pub cols: Option<u16>,
    pub rows: Option<u16>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellTicketResponse {
    pub ticket: String,
    pub target_ip: String,
    pub target_port: u16,
    pub ssh_user: String,
    pub server_label: String,
    pub certificate_name: String,
    pub openssh_available: bool,
}

#[derive(Deserialize)]
struct ClientWsMsg {
    #[serde(rename = "type")]
    kind: String,
    data: Option<String>,
    cols: Option<u16>,
    rows: Option<u16>,
}

fn open_posix_pty(cols: u16, rows: u16) -> Result<(OwnedFd, String), String> {
    unsafe {
        let raw_master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if raw_master < 0 {
            return Err("posix_openpt fehlgeschlagen.".into());
        }
        let master = OwnedFd::from_raw_fd(raw_master);
        if libc::grantpt(master.as_raw_fd()) != 0 {
            return Err("grantpt fehlgeschlagen.".into());
        }
        if libc::unlockpt(master.as_raw_fd()) != 0 {
            return Err("unlockpt fehlgeschlagen.".into());
        }
        let name_ptr = libc::ptsname(master.as_raw_fd());
        if name_ptr.is_null() {
            return Err("ptsname fehlgeschlagen.".into());
        }
        let slave_path = CStr::from_ptr(name_ptr)
            .to_string_lossy()
            .into_owned();

        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let _ = libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ as _, &ws);

        Ok((master, slave_path))
    }
}

fn set_pty_size(master_fd: i32, child_pid: i32, cols: u16, rows: u16) {
    let ws = libc::winsize {
        ws_row: rows.clamp(8, 200),
        ws_col: cols.clamp(20, 400),
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        let _ = libc::ioctl(master_fd, libc::TIOCSWINSZ as _, &ws);
        if child_pid > 0 {
            let _ = libc::kill(-child_pid, libc::SIGWINCH);
        }
    }
}

pub async fn handle_ssh_websocket(
    socket: WebSocket,
    state: Arc<AppState>,
    ticket: ShellTicket,
    cert: UserCertificateSecret,
    private_key_plain: Zeroizing<Vec<u8>>,
) {
    let started = Instant::now();
    let (mut ws_tx, mut ws_rx) = socket.split();

    let tmp_dir = match TempDir::new() {
        Ok(d) => d,
        Err(e) => {
            let _ = ws_tx
                .send(Message::Text(
                    json!({ "type": "error", "message": format!("Temp-Verzeichnis fehlgeschlagen: {e}") })
                        .to_string(),
                ))
                .await;
            return;
        }
    };

    if let Err(e) = fs::set_permissions(tmp_dir.path(), fs::Permissions::from_mode(0o700)) {
        let _ = ws_tx
            .send(Message::Text(
                json!({ "type": "error", "message": format!("chmod 0700 fehlgeschlagen: {e}") })
                    .to_string(),
            ))
            .await;
        return;
    }

    let key_path = tmp_dir.path().join("zertifikat");
    let pub_path = tmp_dir.path().join("zertifikat.pub");
    let cert_path = tmp_dir.path().join("zertifikat-cert.pub");
    let has_cert = !cert.certificate.trim().is_empty();

    if let Err(e) = fs::write(&key_path, private_key_plain.as_slice())
        .and_then(|_| fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)))
        .and_then(|_| fs::write(&pub_path, cert.public_key.as_bytes()))
        .and_then(|_| {
            if has_cert {
                fs::write(&cert_path, cert.certificate.as_bytes())
            } else {
                Ok(())
            }
        })
    {
        let _ = fs::write(&key_path, vec![0u8; private_key_plain.len()]);
        let _ = ws_tx
            .send(Message::Text(
                json!({ "type": "error", "message": format!("Schlüsseldateien konnten nicht vorbereitet werden: {e}") })
                    .to_string(),
            ))
            .await;
        return;
    }

    let (master_fd, slave_path) = match open_posix_pty(ticket.cols, ticket.rows) {
        Ok(pair) => pair,
        Err(e) => {
            let _ = fs::write(&key_path, vec![0u8; private_key_plain.len()]);
            let _ = ws_tx
                .send(Message::Text(
                    json!({ "type": "error", "message": format!("PTY konnte nicht geöffnet werden: {e}") })
                        .to_string(),
                ))
                .await;
            return;
        }
    };

    let slave_file = match fs::OpenOptions::new().read(true).write(true).open(&slave_path) {
        Ok(f) => f,
        Err(e) => {
            let _ = fs::write(&key_path, vec![0u8; private_key_plain.len()]);
            let _ = ws_tx
                .send(Message::Text(
                    json!({ "type": "error", "message": format!("PTY-Slave konnte nicht geöffnet werden: {e}") })
                        .to_string(),
                ))
                .await;
            return;
        }
    };

    let stdin_fd = match slave_file.try_clone() {
        Ok(f) => f,
        Err(e) => {
            let _ = fs::write(&key_path, vec![0u8; private_key_plain.len()]);
            let _ = ws_tx
                .send(Message::Text(
                    json!({ "type": "error", "message": format!("PTY clone fehlgeschlagen: {e}") })
                        .to_string(),
                ))
                .await;
            return;
        }
    };
    let stdout_fd = match slave_file.try_clone() {
        Ok(f) => f,
        Err(e) => {
            let _ = fs::write(&key_path, vec![0u8; private_key_plain.len()]);
            let _ = ws_tx
                .send(Message::Text(
                    json!({ "type": "error", "message": format!("PTY clone fehlgeschlagen: {e}") })
                        .to_string(),
                ))
                .await;
            return;
        }
    };

    let host_key_display = if ticket.ignore_host_key {
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    } else {
        "-o StrictHostKeyChecking=accept-new"
    };

    let ssh_invocation = if has_cert {
        format!(
            "ssh -tt -i zertifikat -o CertificateFile=zertifikat-cert.pub -o IdentitiesOnly=yes {host_key_display} -p {} {}@{}",
            ticket.port, ticket.ssh_user, ticket.ip_address
        )
    } else {
        format!(
            "ssh -tt -i zertifikat -o IdentitiesOnly=yes {host_key_display} -p {} {}@{}",
            ticket.port, ticket.ssh_user, ticket.ip_address
        )
    };

    let mut cmd = StdCommand::new("/usr/bin/ssh");
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", tmp_dir.path())
        .env("TERM", "xterm-256color")
        .env("LANG", "C.UTF-8")
        .arg("-tt")
        .arg("-i")
        .arg(&key_path);

    if has_cert {
        cmd.arg("-o")
            .arg(format!("CertificateFile={}", cert_path.display()));
    }

    cmd.arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("PasswordAuthentication=no")
        .arg("-o")
        .arg("KbdInteractiveAuthentication=no");

    if ticket.ignore_host_key {
        cmd.arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null");
    } else {
        cmd.arg("-o")
            .arg("StrictHostKeyChecking=accept-new");
    }

    cmd.arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("ServerAliveInterval=30")
        .arg("-o")
        .arg("ServerAliveCountMax=3")
        .arg("-p")
        .arg(ticket.port.to_string())
        .arg(format!("{}@{}", ticket.ssh_user, ticket.ip_address))
        .stdin(Stdio::from(stdin_fd))
        .stdout(Stdio::from(stdout_fd))
        .stderr(Stdio::from(slave_file));

    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let _ = libc::ioctl(0, libc::TIOCSCTTY as _, 0);
            Ok(())
        });
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = fs::write(&key_path, vec![0u8; private_key_plain.len()]);
            let _ = ws_tx
                .send(Message::Text(
                    json!({ "type": "error", "message": format!("OpenSSH konnte nicht gestartet werden: {e}") })
                        .to_string(),
                ))
                .await;
            return;
        }
    };

    let child_pid = child.id() as i32;
    let master_raw = master_fd.as_raw_fd();

    let master_writer_fd = unsafe { libc::dup(master_raw) };
    if master_writer_fd < 0 {
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::write(&key_path, vec![0u8; private_key_plain.len()]);
        return;
    }

    let mut reader_file = fs::File::from(master_fd);
    let mut writer_file = unsafe { fs::File::from_raw_fd(master_writer_fd) };

    let _ = ws_tx
        .send(Message::Text(
            json!({
                "type": "ready",
                "mode": "openssh-live",
                "target": format!("{}@{}:{}", ticket.ssh_user, ticket.ip_address, ticket.port),
                "certificateName": cert.name,
            })
            .to_string(),
        ))
        .await;

    enum PtyCommand {
        Input(Vec<u8>),
        Resize(u16, u16),
    }

    let (out_tx, mut out_rx) = mpsc::channel::<String>(256);
    let (in_tx, mut in_rx) = mpsc::channel::<PtyCommand>(256);

    let reader_task = tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader_file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                    if out_tx.blocking_send(text).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let writer_task = tokio::task::spawn_blocking(move || {
        while let Some(cmd_msg) = in_rx.blocking_recv() {
            match cmd_msg {
                PtyCommand::Input(bytes) => {
                    if writer_file.write_all(&bytes).is_err() {
                        break;
                    }
                    let _ = writer_file.flush();
                }
                PtyCommand::Resize(cols, rows) => {
                    set_pty_size(writer_file.as_raw_fd(), child_pid, cols, rows);
                }
            }
        }
    });

    let mut exit_reason = String::from("Interaktive SSH-Sitzung beendet");

    loop {
        tokio::select! {
            maybe_out = out_rx.recv() => {
                match maybe_out {
                    Some(text) => {
                        if ws_tx.send(Message::Text(json!({ "type": "output", "data": text }).to_string())).await.is_err() {
                            exit_reason = "Verbindung vom Browser getrennt".into();
                            break;
                        }
                    }
                    None => {
                        break;
                    }
                }
            }
            maybe_ws = ws_rx.next() => {
                match maybe_ws {
                    Some(Ok(Message::Text(txt))) => {
                        if let Ok(parsed) = serde_json::from_str::<ClientWsMsg>(&txt) {
                            match parsed.kind.as_str() {
                                "input" => {
                                    if let Some(data) = parsed.data {
                                        if in_tx.send(PtyCommand::Input(data.into_bytes())).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                                "resize" => {
                                    let cols = parsed.cols.unwrap_or(100);
                                    let rows = parsed.rows.unwrap_or(30);
                                    let _ = in_tx.send(PtyCommand::Resize(cols, rows)).await;
                                }
                                "ping" => {
                                    let _ = ws_tx.send(Message::Text(json!({ "type": "pong" }).to_string())).await;
                                }
                                _ => {}
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        exit_reason = "Verbindung vom Browser getrennt".into();
                        break;
                    }
                    Some(Err(_)) => {
                        exit_reason = "WebSocket-Verbindungsfehler".into();
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    drop(in_tx);

    let exit_code = match child.try_wait() {
        Ok(Some(status)) => status.code().unwrap_or(0),
        _ => {
            unsafe {
                let _ = libc::kill(-child_pid, libc::SIGHUP);
                let _ = libc::kill(-child_pid, libc::SIGTERM);
            }
            let _ = child.kill();
            child
                .wait()
                .ok()
                .and_then(|s| s.code())
                .unwrap_or(0)
        }
    };

    let _ = ws_tx
        .send(Message::Text(
            json!({
                "type": "exit",
                "code": exit_code,
                "reason": format!("{exit_reason} (Exit-Code {exit_code})"),
            })
            .to_string(),
        ))
        .await;
    let _ = ws_tx.close().await;

    let _ = reader_task.await;
    let _ = writer_task.await;

    // Privatschlüssel vor dem Entfernen des TempDir mit Nullen überschreiben
    let _ = fs::write(&key_path, vec![0u8; private_key_plain.len()]);

    let log = ExecutionLog {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: ticket.user_id,
        username: ticket.username,
        command_id: "interactive-shell".into(),
        command_name: "SSH-Shell (Interaktiv)".into(),
        command_text: "interactive-shell".into(),
        target_ip: ticket.ip_address,
        target_port: ticket.port,
        ssh_user: ticket.ssh_user,
        server_label: ticket.server_label,
        certificate_id: cert.id,
        certificate_key_id: if cert.key_id.is_empty() {
            cert.name
        } else {
            cert.key_id
        },
        mode: "openssh-live".into(),
        ssh_invocation,
        exit_code,
        stdout: exit_reason,
        stderr: String::new(),
        duration_ms: started.elapsed().as_millis() as u64,
        executed_at: chrono::Utc::now().to_rfc3339(),
    };
    let _ = state.db.insert_log(&log);
}
