use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn default_true() -> bool {
    true
}

fn default_validity() -> String {
    "+30d".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupCaAssignment {
    pub ca_id: String,
    #[serde(default)]
    pub principals: Vec<String>,
    #[serde(default)]
    pub include_owner_principal: bool,
    #[serde(default = "default_validity")]
    pub validity: String,
    #[serde(default)]
    pub auto_renew_before_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupPermissions {
    #[serde(default = "default_true")]
    pub manage_own_servers: bool,
    #[serde(default = "default_true")]
    pub create_single_commands: bool,
    #[serde(default = "default_true")]
    pub create_chain_commands: bool,
    #[serde(default = "default_true")]
    pub create_workflow_commands: bool,
    #[serde(default = "default_true")]
    pub upload_certificates: bool,
    #[serde(default = "default_true")]
    pub upload_signed_cert: bool,
    #[serde(default = "default_true")]
    pub generate_test_certificates: bool,
    #[serde(default)]
    pub require_certificate_passphrase: bool,
    #[serde(default = "default_true")]
    pub store_certificate_passphrase: bool,
    #[serde(default)]
    pub self_sign_certificates: bool,
    #[serde(default)]
    pub auto_renew_certificates: bool,
    #[serde(default = "default_true")]
    pub use_api: bool,
    #[serde(default)]
    pub share_resources: bool,
    #[serde(default = "default_true")]
    pub use_ssh_shell: bool,
    #[serde(default = "default_true")]
    pub use_ssh_shell_custom_ip: bool,
    #[serde(default = "default_true")]
    pub execute_commands: bool,
    #[serde(default = "default_true")]
    pub view_own_logs: bool,
    #[serde(default)]
    pub ca_signing_assignments: Vec<GroupCaAssignment>,
}

impl GroupPermissions {
    pub fn all() -> Self {
        Self {
            manage_own_servers: true,
            create_single_commands: true,
            create_chain_commands: true,
            create_workflow_commands: true,
            upload_certificates: true,
            upload_signed_cert: true,
            generate_test_certificates: true,
            require_certificate_passphrase: false,
            store_certificate_passphrase: true,
            self_sign_certificates: true,
            auto_renew_certificates: true,
            use_api: true,
            share_resources: true,
            use_ssh_shell: true,
            use_ssh_shell_custom_ip: true,
            execute_commands: true,
            view_own_logs: true,
            ca_signing_assignments: Vec::new(),
        }
    }

    pub fn default_user() -> Self {
        Self {
            manage_own_servers: true,
            create_single_commands: true,
            create_chain_commands: true,
            create_workflow_commands: true,
            upload_certificates: true,
            upload_signed_cert: true,
            generate_test_certificates: true,
            require_certificate_passphrase: false,
            store_certificate_passphrase: true,
            self_sign_certificates: false,
            auto_renew_certificates: false,
            use_api: true,
            share_resources: false,
            use_ssh_shell: true,
            use_ssh_shell_custom_ip: true,
            execute_commands: true,
            view_own_logs: true,
            ca_signing_assignments: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserGroup {
    pub id: String,
    pub name: String,
    pub description: String,
    pub is_system: bool,
    pub is_immutable: bool,
    pub is_admin: bool,
    pub permissions: GroupPermissions,
    pub member_count: usize,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareableUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub role: String,
    pub group_id: String,
    pub group_name: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPublic {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub role: String, // "admin" | "user"
    pub group_id: String,
    pub group_name: String,
    pub permissions: GroupPermissions,
    pub auth_provider: String, // "local" | "sso"
    pub email: String,
    pub default_ssh_user: String,
    pub active: bool,
    pub ping_enabled: bool,
    pub totp_enabled: bool,
    pub security_key_count: usize,
    pub passkey_count: usize,
    pub has_two_factor: bool,
    pub must_setup_two_factor: bool,
    pub must_setup_passkey: bool,
    pub created_at: String,
    pub last_login_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnCredentialPublic {
    pub id: String,
    pub kind: String, // "security-key" | "passkey"
    pub name: String,
    pub transports: Vec<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WebAuthnCredentialStored {
    pub id: String,
    pub user_id: String,
    pub kind: String,
    pub name: String,
    pub credential_id: String,
    pub public_key: String,
    pub counter: u32,
    pub transports: Vec<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthPolicySettings {
    pub sso_enabled: bool,
    pub sso_provider_name: String,
    pub sso_issuer_url: String,
    pub sso_auth_url: String,
    pub sso_token_url: String,
    pub sso_userinfo_url: String,
    pub sso_client_id: String,
    pub sso_client_secret_enc: Option<(Vec<u8>, Vec<u8>)>,
    pub sso_scopes: String,
    pub sso_auto_create_users: bool,
    pub sso_tested_at: Option<String>,
    pub local_login_disabled: bool,
    pub two_factor_enabled: bool,
    pub two_factor_enforced: bool,
    pub passkey_enabled: bool,
    pub passkey_enforced: bool,
    pub allow_insecure_host_key: bool,
    pub public_url: String,
}

impl AuthPolicySettings {
    pub fn is_sso_configured(&self) -> bool {
        !self.sso_auth_url.trim().is_empty()
            && !self.sso_token_url.trim().is_empty()
            && !self.sso_client_id.trim().is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserApiKeyPublic {
    pub id: String,
    pub name: String,
    pub key_prefix: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateApiKeyRequest {
    pub name: Option<String>,
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
    pub kind: String, // "single" | "chain" | "workflow"
    pub command: String,
    pub steps: Vec<CommandStep>,
    #[serde(default)]
    pub workflow_json: String,
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
pub struct ServerCategory {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub created_at: String,
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
    pub bmc_ip_address2: String,
    pub port: u16,
    pub ssh_user: String,
    pub notes: String,
    pub ping_enabled: bool,
    pub ignore_host_key: bool,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub last_online_at: Option<String>,
    pub shared_with_all: bool,
    pub shared_with_user_ids: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BmcCheckResult {
    pub server_id: String,
    pub slot: u8,
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
pub struct CertificateAutoRenewConfig {
    pub enabled: bool,
    pub mode: String, // "admin" | "user"
    pub ca_id: String,
    #[serde(default)]
    pub ca_name: String,
    #[serde(default)]
    pub principals: Vec<String>,
    #[serde(default)]
    pub include_owner_principal: bool,
    #[serde(default = "default_validity")]
    pub validity: String,
    #[serde(default)]
    pub key_id_prefix: String,
    #[serde(default)]
    pub renew_before_seconds: u64,
    #[serde(default)]
    pub enabled_by_user_id: String,
    #[serde(default)]
    pub enabled_by_username: String,
    #[serde(default)]
    pub enabled_at: String,
    #[serde(default)]
    pub last_renewed_at: Option<String>,
    #[serde(default)]
    pub last_checked_at: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
    #[serde(default)]
    pub revoked_reason: Option<String>,
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
    #[serde(default)]
    pub has_stored_passphrase: bool,
    #[serde(default)]
    pub auto_renew: Option<CertificateAutoRenewConfig>,
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
    pub passphrase_enc: Option<Vec<u8>>,
    pub passphrase_nonce: Option<Vec<u8>>,
    pub private_key_encrypted: bool,
    pub public_key: String,
    pub certificate: String,
    pub key_id: String,
}

#[derive(Debug, Clone)]
pub struct StoredCertificateForSigning {
    pub id: String,
    pub user_id: String,
    pub owner_username: String,
    pub name: String,
    pub private_key_file_name: String,
    pub public_key_file_name: String,
    pub cert_file_name: String,
    pub private_key_enc: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
    pub public_key: String,
    pub certificate: String,
    pub has_certificate: bool,
    pub existing_ca_fingerprint: String,
    pub valid_after_unix: i64,
    pub valid_before_unix: i64,
    pub auto_renew: Option<CertificateAutoRenewConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateAuthorityPublic {
    pub id: String,
    pub name: String,
    pub description: String,
    pub private_key_file_name: String,
    pub public_key_file_name: String,
    pub public_key: String,
    pub key_type: String,
    pub fingerprint: String,
    pub private_key_format: String,
    pub private_key_encrypted: bool,
    pub has_stored_passphrase: bool,
    pub created_by: String,
    pub created_by_username: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct StoredCertificateAuthorityForEdit {
    pub id: String,
    pub name: String,
    pub description: String,
    pub private_key_file_name: String,
    pub public_key_file_name: String,
    pub private_key_enc: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
    pub passphrase_enc: Option<Vec<u8>>,
    pub passphrase_nonce: Option<Vec<u8>>,
    pub public_key: String,
    pub key_type: String,
    pub fingerprint: String,
    pub private_key_format: String,
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
    #[serde(default)]
    pub role: Option<String>,
    #[serde(alias = "group_id")]
    pub group_id: Option<String>,
    #[serde(alias = "default_ssh_user")]
    pub default_ssh_user: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserRequest {
    #[serde(alias = "display_name")]
    pub display_name: Option<String>,
    pub role: Option<String>,
    #[serde(alias = "group_id")]
    pub group_id: Option<String>,
    #[serde(alias = "default_ssh_user")]
    pub default_ssh_user: Option<String>,
    pub active: Option<bool>,
    #[serde(alias = "new_password")]
    pub new_password: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Option<GroupPermissions>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateGroupRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub permissions: Option<GroupPermissions>,
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
pub struct BulkUpdateCommandsRequest {
    #[serde(default, alias = "command_ids")]
    pub command_ids: Vec<String>,
    pub category: Option<String>,
    pub enabled: Option<bool>,
    pub sharing: Option<ShareUpdateRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkUpdateServersRequest {
    #[serde(default, alias = "server_ids")]
    pub server_ids: Vec<String>,
    #[serde(alias = "ping_enabled")]
    pub ping_enabled: Option<bool>,
    #[serde(alias = "ignore_host_key")]
    pub ignore_host_key: Option<bool>,
    #[serde(alias = "categories_action")]
    pub categories_action: Option<String>,
    pub categories: Option<Vec<String>>,
    pub sharing: Option<ShareUpdateRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCommandRequest {
    pub name: String,
    pub category: Option<String>,
    pub kind: Option<String>,
    pub command: Option<String>,
    pub steps: Option<Vec<CommandStep>>,
    #[serde(default, alias = "workflow_json")]
    pub workflow_json: Option<String>,
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
    #[serde(default, alias = "workflow_json")]
    pub workflow_json: Option<String>,
    #[serde(alias = "stop_on_error")]
    pub stop_on_error: Option<bool>,
    pub description: Option<String>,
    #[serde(alias = "timeout_sec")]
    pub timeout_sec: Option<u64>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateServerCategoryRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateServerRequest {
    pub label: Option<String>,
    #[serde(alias = "ip_address")]
    pub ip_address: String,
    #[serde(alias = "bmc_ip_address")]
    pub bmc_ip_address: Option<String>,
    #[serde(alias = "bmc_ip_address2", alias = "bmc_ip_address_2")]
    pub bmc_ip_address2: Option<String>,
    pub port: Option<u16>,
    #[serde(alias = "ssh_user")]
    pub ssh_user: Option<String>,
    pub notes: Option<String>,
    #[serde(alias = "ping_enabled")]
    pub ping_enabled: Option<bool>,
    #[serde(alias = "ignore_host_key")]
    pub ignore_host_key: Option<bool>,
    #[serde(default)]
    pub categories: Option<Vec<String>>,
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
    #[serde(alias = "bmc_ip_address2", alias = "bmc_ip_address_2")]
    pub bmc_ip_address2: Option<String>,
    pub port: Option<u16>,
    #[serde(alias = "ssh_user")]
    pub ssh_user: Option<String>,
    pub notes: Option<String>,
    #[serde(alias = "ping_enabled")]
    pub ping_enabled: Option<bool>,
    #[serde(alias = "ignore_host_key")]
    pub ignore_host_key: Option<bool>,
    #[serde(default)]
    pub categories: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CheckBmcRequest {
    #[serde(alias = "bmcSlot", alias = "bmc_slot")]
    pub slot: Option<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadCertBundleRequest {
    #[serde(alias = "label")]
    pub name: Option<String>,
    #[serde(alias = "private_key_file")]
    pub private_key_file_name: Option<String>,
    #[serde(alias = "public_key_file")]
    pub public_key_file_name: Option<String>,
    #[serde(alias = "cert_file")]
    pub cert_file_name: Option<String>,
    #[serde(alias = "private_key_content", alias = "private_key", alias = "privateKey", alias = "zertifikat")]
    pub private_key_content: String,
    #[serde(alias = "public_key_content", alias = "public_key", alias = "publicKey", alias = "zertifikat_pub")]
    pub public_key_content: String,
    #[serde(default, alias = "cert_content", alias = "cert", alias = "certificate", alias = "cert_pub", alias = "zertifikat_cert")]
    pub cert_content: Option<String>,
    #[serde(default, alias = "key_passphrase", alias = "keyPassphrase")]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub overwrite: Option<bool>,
    #[serde(alias = "shared_with_all")]
    pub shared_with_all: Option<bool>,
    #[serde(alias = "shared_with_user_ids")]
    pub shared_with_user_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCertBundleRequest {
    #[serde(default, alias = "certificate_id", alias = "certificateId")]
    pub id: Option<String>,
    #[serde(default, alias = "label")]
    pub name: Option<String>,
    #[serde(default, alias = "private_key_file")]
    pub private_key_file_name: Option<String>,
    #[serde(default, alias = "public_key_file")]
    pub public_key_file_name: Option<String>,
    #[serde(default, alias = "cert_file")]
    pub cert_file_name: Option<String>,
    #[serde(default, alias = "private_key_content", alias = "private_key", alias = "privateKey", alias = "zertifikat", alias = "key")]
    pub private_key_content: Option<String>,
    #[serde(default, alias = "public_key_content", alias = "public_key", alias = "publicKey", alias = "zertifikat_pub", alias = "pub")]
    pub public_key_content: Option<String>,
    #[serde(default, alias = "cert_content", alias = "cert", alias = "certificate", alias = "cert_pub", alias = "zertifikat_cert")]
    pub cert_content: Option<String>,
    #[serde(default, alias = "remove_cert")]
    pub remove_cert: Option<bool>,
    #[serde(default, alias = "key_passphrase", alias = "keyPassphrase")]
    pub passphrase: Option<String>,
    #[serde(default, alias = "clear_passphrase")]
    pub clear_passphrase: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct StoredCertificateForEdit {
    pub id: String,
    pub name: String,
    pub private_key_file_name: String,
    pub public_key_file_name: String,
    pub cert_file_name: String,
    pub private_key_enc: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
    pub passphrase_enc: Option<Vec<u8>>,
    pub passphrase_nonce: Option<Vec<u8>>,
    pub public_key: String,
    pub certificate: String,
    pub shared_with_all: bool,
    pub shared_with_user_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateTestCertRequest {
    #[serde(alias = "key_id")]
    pub key_id: Option<String>,
    pub passphrase: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateCaRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub passphrase: String,
    #[serde(default, alias = "store_passphrase")]
    pub store_passphrase: Option<bool>,
    #[serde(default)]
    pub overwrite: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadCaRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    #[serde(alias = "private_key_file_name")]
    pub private_key_file_name: Option<String>,
    #[serde(alias = "public_key_file_name")]
    pub public_key_file_name: Option<String>,
    #[serde(alias = "private_key_content")]
    pub private_key_content: String,
    #[serde(alias = "public_key_content")]
    pub public_key_content: String,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub overwrite: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCaRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    #[serde(alias = "private_key_file_name")]
    pub private_key_file_name: Option<String>,
    #[serde(alias = "public_key_file_name")]
    pub public_key_file_name: Option<String>,
    #[serde(alias = "private_key_content")]
    pub private_key_content: Option<String>,
    #[serde(alias = "public_key_content")]
    pub public_key_content: Option<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default, alias = "clear_passphrase")]
    pub clear_passphrase: Option<bool>,
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
    #[serde(alias = "ignore_host_key")]
    pub ignore_host_key: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteRequest {
    #[serde(alias = "command_id")]
    pub command_id: String,
    #[serde(alias = "certificate_id")]
    pub certificate_id: String,
    pub targets: Vec<ExecuteTarget>,
    #[serde(default, alias = "key_passphrase", alias = "keyPassphrase")]
    pub passphrase: Option<String>,
    #[serde(default, alias = "workflow_vars")]
    pub workflow_vars: Option<HashMap<String, String>>,
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
    #[serde(default)]
    pub last_online_at: Option<String>,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub backoff_active: bool,
    #[serde(default)]
    pub effective_interval_sec: u64,
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
pub struct UserPingSettingsRequest {
    #[serde(alias = "ping_enabled")]
    pub ping_enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminPingSettingsRequest {
    #[serde(alias = "ping_allowed")]
    pub ping_allowed: Option<bool>,
    #[serde(alias = "ping_interval_sec")]
    pub ping_interval_sec: Option<i64>,
    #[serde(alias = "ping_offline_threshold")]
    pub ping_offline_threshold: Option<i64>,
    #[serde(alias = "ping_offline_multiplier")]
    pub ping_offline_multiplier: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchJobItem {
    #[serde(alias = "server_id")]
    pub server_id: String,
    #[serde(alias = "command_id")]
    pub command_id: String,
    #[serde(default, alias = "workflow_vars")]
    pub workflow_vars: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchExecuteRequest {
    #[serde(alias = "certificate_id")]
    pub certificate_id: String,
    pub jobs: Vec<BatchJobItem>,
    #[serde(default, alias = "key_passphrase", alias = "keyPassphrase")]
    pub passphrase: Option<String>,
    #[serde(default, alias = "workflow_vars")]
    pub workflow_vars: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoFactorLoginRequest {
    pub ticket: String,
    pub method: String, // "totp" | "recovery" | "security-key"
    pub code: Option<String>,
    pub assertion: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpVerifyRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnRegisterOptionsRequest {
    pub kind: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnRegisterVerifyRequest {
    pub challenge_id: String,
    pub response: serde_json::Value,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyLoginVerifyRequest {
    pub challenge_id: String,
    pub response: serde_json::Value,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AdminAuthSettingsPatchRequest {
    pub sso_enabled: Option<bool>,
    pub sso_provider_name: Option<String>,
    pub sso_issuer_url: Option<String>,
    pub sso_auth_url: Option<String>,
    pub sso_token_url: Option<String>,
    pub sso_userinfo_url: Option<String>,
    pub sso_client_id: Option<String>,
    pub sso_client_secret: Option<String>,
    pub clear_sso_client_secret: Option<bool>,
    pub sso_scopes: Option<String>,
    pub sso_auto_create_users: Option<bool>,
    pub local_login_disabled: Option<bool>,
    pub two_factor_enabled: Option<bool>,
    pub two_factor_enforced: Option<bool>,
    pub passkey_enabled: Option<bool>,
    pub passkey_enforced: Option<bool>,
    #[serde(alias = "allow_insecure_host_key")]
    pub allow_insecure_host_key: Option<bool>,
    #[serde(default, alias = "public_url")]
    pub public_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcDiscoverRequest {
    pub issuer_url: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResetHostKeyRequest {
    #[serde(default, alias = "server_id")]
    pub server_id: Option<String>,
    #[serde(default, alias = "ip_address")]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AdminDeleteHostKeysRequest {
    #[serde(default, alias = "ip_address")]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminSignCertificatesRequest {
    pub ca_id: String,
    #[serde(default)]
    pub ca_passphrase: Option<String>,
    #[serde(default)]
    pub certificate_ids: Vec<String>,
    #[serde(default)]
    pub principals: serde_json::Value,
    #[serde(default)]
    pub include_owner_principal: bool,
    #[serde(default)]
    pub validity: Option<String>,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub confirm_overwrite_foreign_ca: bool,
    #[serde(default)]
    pub auto_renew: Option<bool>,
    #[serde(default)]
    pub auto_renew_before_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserSelfSignCertificatesRequest {
    pub ca_id: String,
    #[serde(default)]
    pub certificate_ids: Vec<String>,
    #[serde(default)]
    pub confirm_overwrite_foreign_ca: bool,
    #[serde(default)]
    pub auto_renew: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeAutoRenewBatchRequest {
    #[serde(default)]
    pub certificate_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignedSigningCaPublic {
    pub id: String,
    pub name: String,
    pub description: String,
    pub key_type: String,
    pub fingerprint: String,
    pub has_stored_passphrase: bool,
    pub principals: Vec<String>,
    pub include_owner_principal: bool,
    pub effective_principals: Vec<String>,
    pub validity: String,
    pub auto_renew_before_seconds: u64,
}


