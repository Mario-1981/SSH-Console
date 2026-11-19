use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPublic {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub role: String, // "admin" | "user"
    pub default_ssh_user: String,
    pub active: bool,
    pub created_at: String,
    pub last_login_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandStep {
    pub command: String,
    #[serde(default)]
    pub sleep_after_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshCommand {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub category: String,
    pub kind: String, // "single" | "chain"
    pub command: String,
    pub steps: Vec<CommandStep>,
    pub stop_on_error: bool,
    pub description: String,
    pub timeout_sec: u64,
    pub enabled: bool,
    pub created_by: String,
    pub shared_with_all: bool,
    pub shared_with_user_ids: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserServer {
    pub id: String,
    pub user_id: String,
    pub owner_username: String,
    pub label: String,
    pub ip_address: String,
    pub bmc_ip_address: String,
    pub port: u16,
    pub ssh_user: String,
    pub notes: String,
    pub shared_with_all: bool,
    pub shared_with_user_ids: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BmcCheckResult {
    pub server_id: String,
    pub bmc_ip_address: String,
    pub url: String,
    pub port: u16,
    pub reachable: bool,
    pub http_status: Option<u16>,
    pub tls_protocol: Option<String>,
    pub latency_ms: Option<u64>,
    pub checked_at: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInspection {
    #[serde(default)]
    pub has_certificate: bool,
    pub key_id: String,
    pub serial: String,
    pub cert_type: String,
    pub principals: Vec<String>,
    pub valid_range: String,
    pub ca_fingerprint: String,
    pub raw_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCertificatePublic {
    pub id: String,
    pub user_id: String,
    pub owner_username: String,
    pub name: String,
    pub private_key_file: String,
    pub public_key_file: String,
    pub cert_file: String,
    pub inspection: CertInspection,
    pub shared_with_all: bool,
    pub shared_with_user_ids: Vec<String>,
    pub uploaded_at: String,
}

#[derive(Debug, Clone)]
pub struct UserCertificateSecret {
    pub id: String,
    pub name: String,
    pub private_key_enc: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
    pub public_key: String,
    pub certificate: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionLog {
    pub id: String,
    pub user_id: String,
    pub username: String,
    pub command_name: String,
    pub command_text: String,
    pub target_ip: String,
    pub target_port: u16,
    pub ssh_user: String,
    pub certificate_key_id: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub executed_at: String,
}

#[derive(Debug, Deserialize)]
pub struct SetupRequest {
    pub username: String,
    pub display_name: Option<String>,
    pub password: String,
    pub instance_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub display_name: Option<String>,
    pub password: String,
    pub role: String,
    pub default_ssh_user: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct ShareUpdateRequest {
    #[serde(default)]
    pub shared_with_all: bool,
    #[serde(default)]
    pub shared_with_user_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCommandRequest {
    pub name: String,
    pub category: Option<String>,
    pub kind: Option<String>,
    pub command: Option<String>,
    pub steps: Option<Vec<CommandStep>>,
    pub stop_on_error: Option<bool>,
    pub description: Option<String>,
    pub timeout_sec: Option<u64>,
    pub shared_with_all: Option<bool>,
    pub shared_with_user_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateServerRequest {
    pub label: Option<String>,
    pub ip_address: String,
    pub bmc_ip_address: Option<String>,
    pub port: Option<u16>,
    pub ssh_user: Option<String>,
    pub notes: Option<String>,
    pub shared_with_all: Option<bool>,
    pub shared_with_user_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateServerRequest {
    pub label: Option<String>,
    pub ip_address: Option<String>,
    pub bmc_ip_address: Option<String>,
    pub port: Option<u16>,
    pub ssh_user: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UploadCertBundleRequest {
    pub name: Option<String>,
    pub private_key_file: Option<String>,
    pub public_key_file: Option<String>,
    pub cert_file: Option<String>,
    pub private_key_content: String,
    pub public_key_content: String,
    #[serde(default)]
    pub cert_content: Option<String>,
    pub shared_with_all: Option<bool>,
    pub shared_with_user_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct ExecuteTarget {
    pub server_id: Option<String>,
    pub ip_address: Option<String>,
    pub port: Option<u16>,
    pub ssh_user: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExecuteRequest {
    pub command_id: String,
    pub certificate_id: String,
    pub targets: Vec<ExecuteTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPingStatus {
    pub server_id: String,
    pub ip_address: String,
    pub port: u16,
    pub online: bool,
    pub latency_ms: Option<u64>,
    pub method: String,
    pub checked_at: String,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ManualPingRequest {
    pub server_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BatchJobItem {
    pub server_id: String,
    pub command_id: String,
}

#[derive(Debug, Deserialize)]
pub struct BatchExecuteRequest {
    pub certificate_id: String,
    pub jobs: Vec<BatchJobItem>,
}
