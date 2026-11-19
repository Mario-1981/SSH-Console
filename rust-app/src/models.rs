use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct CommandStep {
    pub command: String,
    #[serde(default, alias = "sleep_after_sec")]
    pub sleep_after_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct CertInspection {
    #[serde(default)]
    pub has_certificate: bool,
    #[serde(default)]
    pub cert_algorithm: String,
    #[serde(default)]
    pub pub_key_algorithm: String,
    #[serde(default)]
    pub serial: String,
    #[serde(default)]
    pub cert_type: String,
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub principals: Vec<String>,
    #[serde(default)]
    pub valid_after: String,
    #[serde(default)]
    pub valid_before: String,
    #[serde(default)]
    pub valid_after_unix: i64,
    #[serde(default)]
    pub valid_before_unix: i64,
    #[serde(default)]
    pub is_expired: bool,
    #[serde(default)]
    pub is_not_yet_valid: bool,
    #[serde(default)]
    pub critical_options: Vec<String>,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub pub_key_fingerprint: String,
    #[serde(default)]
    pub ca_fingerprint: String,
    #[serde(default)]
    pub private_key_format: String,
    #[serde(default)]
    pub private_key_encrypted: bool,
    #[serde(default)]
    pub pub_key_matches_cert: bool,
    #[serde(default)]
    pub private_key_matches_pub: Option<bool>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl Default for CertInspection {
    fn default() -> Self {
        Self {
            has_certificate: false,
            cert_algorithm: "ohne Zertifikat (SSH-Schlüsselpaar)".into(),
            pub_key_algorithm: "unknown".into(),
            serial: "—".into(),
            cert_type: "keypair".into(),
            key_id: String::new(),
            principals: Vec::new(),
            valid_after: "Unbegrenzt".into(),
            valid_before: "Unbegrenzt".into(),
            valid_after_unix: 0,
            valid_before_unix: 0,
            is_expired: false,
            is_not_yet_valid: false,
            critical_options: Vec::new(),
            extensions: Vec::new(),
            pub_key_fingerprint: String::new(),
            ca_fingerprint: String::new(),
            private_key_format: "openssh-v1".into(),
            private_key_encrypted: false,
            pub_key_matches_cert: true,
            private_key_matches_pub: None,
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserCertificatePublic {
    pub id: String,
    pub user_id: String,
    pub owner_username: String,
    pub name: String,
    pub private_key_file_name: String,
    pub public_key_file_name: String,
    pub cert_file_name: String,
    pub metadata: CertInspection,
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
#[serde(rename_all = "camelCase")]
pub struct ExecutionLog {
    pub id: String,
    pub user_id: String,
    pub username: String,
    pub command_id: String,
    pub command_name: String,
    pub command_text: String,
    pub target_ip: String,
    pub target_port: u16,
    pub ssh_user: String,
    pub server_label: String,
    pub certificate_id: String,
    pub certificate_key_id: String,
    pub mode: String,
    pub ssh_invocation: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub executed_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupRequest {
    pub username: String,
    #[serde(alias = "display_name")]
    pub display_name: Option<String>,
    pub password: String,
    #[serde(alias = "instance_name")]
    pub instance_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserRequest {
    pub username: String,
    #[serde(alias = "display_name")]
    pub display_name: Option<String>,
    pub password: String,
    pub role: String,
    #[serde(alias = "default_ssh_user")]
    pub default_ssh_user: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserRequest {
    #[serde(alias = "display_name")]
    pub display_name: Option<String>,
    pub role: Option<String>,
    #[serde(alias = "default_ssh_user")]
    pub default_ssh_user: Option<String>,
    pub active: Option<bool>,
    #[serde(alias = "new_password")]
    pub new_password: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    #[serde(alias = "current_password")]
    pub current_password: String,
    #[serde(alias = "new_password")]
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareUpdateRequest {
    #[serde(default, alias = "shared_with_all")]
    pub shared_with_all: bool,
    #[serde(default, alias = "shared_with_user_ids")]
    pub shared_with_user_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCommandRequest {
    pub name: String,
    pub category: Option<String>,
    pub kind: Option<String>,
    pub command: Option<String>,
    pub steps: Option<Vec<CommandStep>>,
    #[serde(alias = "stop_on_error")]
    pub stop_on_error: Option<bool>,
    pub description: Option<String>,
    #[serde(alias = "timeout_sec")]
    pub timeout_sec: Option<u64>,
    pub enabled: Option<bool>,
    #[serde(alias = "shared_with_all")]
    pub shared_with_all: Option<bool>,
    #[serde(alias = "shared_with_user_ids")]
    pub shared_with_user_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCommandRequest {
    pub name: Option<String>,
    pub category: Option<String>,
    pub kind: Option<String>,
    pub command: Option<String>,
    pub steps: Option<Vec<CommandStep>>,
    #[serde(alias = "stop_on_error")]
    pub stop_on_error: Option<bool>,
    pub description: Option<String>,
    #[serde(alias = "timeout_sec")]
    pub timeout_sec: Option<u64>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateServerRequest {
    pub label: Option<String>,
    #[serde(alias = "ip_address")]
    pub ip_address: String,
    #[serde(alias = "bmc_ip_address")]
    pub bmc_ip_address: Option<String>,
    pub port: Option<u16>,
    #[serde(alias = "ssh_user")]
    pub ssh_user: Option<String>,
    pub notes: Option<String>,
    #[serde(alias = "shared_with_all")]
    pub shared_with_all: Option<bool>,
    #[serde(alias = "shared_with_user_ids")]
    pub shared_with_user_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateServerRequest {
    pub label: Option<String>,
    #[serde(alias = "ip_address")]
    pub ip_address: Option<String>,
    #[serde(alias = "bmc_ip_address")]
    pub bmc_ip_address: Option<String>,
    pub port: Option<u16>,
    #[serde(alias = "ssh_user")]
    pub ssh_user: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadCertBundleRequest {
    pub name: Option<String>,
    #[serde(alias = "private_key_file")]
    pub private_key_file_name: Option<String>,
    #[serde(alias = "public_key_file")]
    pub public_key_file_name: Option<String>,
    #[serde(alias = "cert_file")]
    pub cert_file_name: Option<String>,
    #[serde(alias = "private_key_content")]
    pub private_key_content: String,
    #[serde(alias = "public_key_content")]
    pub public_key_content: String,
    #[serde(default, alias = "cert_content")]
    pub cert_content: Option<String>,
    #[serde(alias = "shared_with_all")]
    pub shared_with_all: Option<bool>,
    #[serde(alias = "shared_with_user_ids")]
    pub shared_with_user_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateTestCertRequest {
    #[serde(alias = "key_id")]
    pub key_id: Option<String>,
    pub principals: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteTarget {
    #[serde(alias = "server_id")]
    pub server_id: Option<String>,
    #[serde(alias = "ip_address")]
    pub ip_address: Option<String>,
    pub port: Option<u16>,
    #[serde(alias = "ssh_user")]
    pub ssh_user: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteRequest {
    #[serde(alias = "command_id")]
    pub command_id: String,
    #[serde(alias = "certificate_id")]
    pub certificate_id: String,
    pub targets: Vec<ExecuteTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct ManualPingRequest {
    #[serde(alias = "server_id")]
    pub server_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchJobItem {
    #[serde(alias = "server_id")]
    pub server_id: String,
    #[serde(alias = "command_id")]
    pub command_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchExecuteRequest {
    #[serde(alias = "certificate_id")]
    pub certificate_id: String,
    pub jobs: Vec<BatchJobItem>,
}
