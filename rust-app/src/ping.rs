use crate::models::{BmcCheckResult, ServerPingStatus, UserServer};
use chrono::Utc;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio::time::timeout;

#[derive(Default)]
pub struct PingState {
    pub statuses: HashMap<String, ServerPingStatus>,
    pub last_cycle_at: Option<String>,
    pub next_cycle_at: Option<String>,
    pub pacing_ms: Option<u64>,
    pub active_target_count: usize,
}

pub type SharedPingState = Arc<RwLock<PingState>>;

/// Prüft eine Ziel-IP per `/bin/ping -c 1 -W 2` (iputils-ping unter Debian Trixie)
/// mit automatischem Fallback auf einen TCP-Connect zum SSH-Port.
pub async fn check_server_reachability(
    server: &UserServer,
    previous_last_online_at: Option<String>,
) -> ServerPingStatus {
    let checked_at = Utc::now().to_rfc3339();
    let is_ipv6 = server
        .ip_address
        .parse::<IpAddr>()
        .map(|addr| addr.is_ipv6())
        .unwrap_or(false);

    let ping_bin = if std::path::Path::new("/bin/ping").exists() {
        Some("/bin/ping")
    } else if std::path::Path::new("/usr/bin/ping").exists() {
        Some("/usr/bin/ping")
    } else {
        None
    };

    if let Some(bin) = ping_bin {
        let started = Instant::now();
        let mut cmd = Command::new(bin);
        if is_ipv6 {
            cmd.arg("-6");
        }
        cmd.args(["-c", "1", "-W", "2", &server.ip_address]);

        if let Ok(Ok(out)) = timeout(Duration::from_secs(3), cmd.output()).await {
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            if !combined.contains("Operation not permitted") && !combined.contains("Permission denied") {
                if out.status.success() {
                    let ms = parse_ping_ms(&combined)
                        .unwrap_or_else(|| started.elapsed().as_millis().max(1) as u64);
                    return ServerPingStatus {
                        server_id: server.id.clone(),
                        ip_address: server.ip_address.clone(),
                        port: server.port,
                        online: true,
                        latency_ms: Some(ms),
                        method: "icmp-ping".into(),
                        last_online_at: Some(checked_at.clone()),
                        checked_at,
                        consecutive_failures: 0,
                        backoff_active: false,
                        effective_interval_sec: 0,
                        error: None,
                    };
                }
                return ServerPingStatus {
                    server_id: server.id.clone(),
                    ip_address: server.ip_address.clone(),
                    port: server.port,
                    online: false,
                    latency_ms: None,
                    method: "icmp-ping".into(),
                    last_online_at: previous_last_online_at,
                    checked_at,
                    consecutive_failures: 0,
                    backoff_active: false,
                    effective_interval_sec: 0,
                    error: Some("Keine ICMP-Antwort".into()),
                };
            }
        }
    }

    // Fallback: TCP-Ping auf SSH-Port
    let started = Instant::now();
    let target = if is_ipv6 {
        format!("[{}]:{}", server.ip_address, server.port)
    } else {
        format!("{}:{}", server.ip_address, server.port)
    };
    match timeout(Duration::from_secs(2), TcpStream::connect(&target)).await {
        Ok(Ok(_)) => ServerPingStatus {
            server_id: server.id.clone(),
            ip_address: server.ip_address.clone(),
            port: server.port,
            online: true,
            latency_ms: Some(started.elapsed().as_millis().max(1) as u64),
            method: "tcp-ping".into(),
            last_online_at: Some(checked_at.clone()),
            checked_at,
            consecutive_failures: 0,
            backoff_active: false,
            effective_interval_sec: 0,
            error: None,
        },
        Ok(Err(e)) => ServerPingStatus {
            server_id: server.id.clone(),
            ip_address: server.ip_address.clone(),
            port: server.port,
            online: false,
            latency_ms: None,
            method: "tcp-ping".into(),
            last_online_at: previous_last_online_at,
            checked_at,
            consecutive_failures: 0,
            backoff_active: false,
            effective_interval_sec: 0,
            error: Some(e.to_string()),
        },
        Err(_) => ServerPingStatus {
            server_id: server.id.clone(),
            ip_address: server.ip_address.clone(),
            port: server.port,
            online: false,
            latency_ms: None,
            method: "tcp-ping".into(),
            last_online_at: previous_last_online_at,
            checked_at,
            consecutive_failures: 0,
            backoff_active: false,
            effective_interval_sec: 0,
            error: Some("Zeitüberschreitung".into()),
        },
    }
}

fn parse_ping_ms(output: &str) -> Option<u64> {
    let idx = output.find("time=")?;
    let rest = &output[idx + 5..];
    let num_str: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let parsed: f64 = num_str.parse().ok()?;
    Some(parsed.round().max(1.0) as u64)
}

/// Prüft die HTTPS-Erreichbarkeit einer BMC-IP auf Port 443 (inkl. selbstsignierter Zertifikate).
pub async fn check_bmc_https(server_id: &str, slot: u8, bmc_ip: &str) -> BmcCheckResult {
    let clean_ip = bmc_ip.trim();
    let checked_at = Utc::now().to_rfc3339();
    let is_ipv6 = clean_ip
        .parse::<IpAddr>()
        .map(|addr| addr.is_ipv6())
        .unwrap_or(false);
    let url = if is_ipv6 {
        format!("https://[{clean_ip}]")
    } else {
        format!("https://{clean_ip}")
    };

    if std::path::Path::new("/usr/bin/curl").exists() {
        let started = Instant::now();
        let mut cmd = Command::new("/usr/bin/curl");
        cmd.args([
            "-k",
            "-I",
            "-sS",
            "--max-time",
            "4",
            "--connect-timeout",
            "3",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            &format!("{url}:443/"),
        ]);
        if let Ok(Ok(out)) = timeout(Duration::from_secs(5), cmd.output()).await {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let code = stdout.parse::<u16>().ok().filter(|c| *c > 0);
            if out.status.success() || code.is_some() {
                return BmcCheckResult {
                    server_id: server_id.to_string(),
                    slot,
                    bmc_ip_address: clean_ip.to_string(),
                    url,
                    port: 443,
                    reachable: true,
                    http_status: code,
                    tls_protocol: Some("TLS".into()),
                    latency_ms: Some(started.elapsed().as_millis().max(1) as u64),
                    checked_at,
                    error: None,
                };
            }
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return BmcCheckResult {
                server_id: server_id.to_string(),
                slot,
                bmc_ip_address: clean_ip.to_string(),
                url,
                port: 443,
                reachable: false,
                http_status: None,
                tls_protocol: None,
                latency_ms: None,
                checked_at,
                error: Some(if stderr.is_empty() {
                    "HTTPS-Port 443 nicht erreichbar".into()
                } else {
                    stderr
                }),
            };
        }
    }

    // Fallback: TCP-Connect auf Port 443
    let started = Instant::now();
    let target = if is_ipv6 {
        format!("[{clean_ip}]:443")
    } else {
        format!("{clean_ip}:443")
    };
    match timeout(Duration::from_secs(4), TcpStream::connect(&target)).await {
        Ok(Ok(_)) => BmcCheckResult {
            server_id: server_id.to_string(),
            slot,
            bmc_ip_address: clean_ip.to_string(),
            url,
            port: 443,
            reachable: true,
            http_status: None,
            tls_protocol: None,
            latency_ms: Some(started.elapsed().as_millis().max(1) as u64),
            checked_at,
            error: None,
        },
        Ok(Err(e)) => BmcCheckResult {
            server_id: server_id.to_string(),
            slot,
            bmc_ip_address: clean_ip.to_string(),
            url,
            port: 443,
            reachable: false,
            http_status: None,
            tls_protocol: None,
            latency_ms: None,
            checked_at,
            error: Some(e.to_string()),
        },
        Err(_) => BmcCheckResult {
            server_id: server_id.to_string(),
            slot,
            bmc_ip_address: clean_ip.to_string(),
            url,
            port: 443,
            reachable: false,
            http_status: None,
            tls_protocol: None,
            latency_ms: None,
            checked_at,
            error: Some("Zeitüberschreitung auf Port 443".into()),
        },
    }
}
