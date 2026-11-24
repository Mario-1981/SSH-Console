export type UserRole = 'admin' | 'user';
export type AuthProvider = 'local' | 'sso';
export type WebAuthnCredentialKind = 'security-key' | 'passkey';

export interface User {
  id: string;
  username: string;
  displayName: string;
  role: UserRole;
  authProvider: AuthProvider;
  email: string;
  defaultSshUser: string;
  active: boolean;
  pingEnabled: boolean;
  totpEnabled: boolean;
  securityKeyCount: number;
  passkeyCount: number;
  hasTwoFactor: boolean;
  mustSetupTwoFactor: boolean;
  mustSetupPasskey: boolean;
  createdAt: string;
  lastLoginAt: string | null;
}

export interface UserApiKey {
  id: string;
  name: string;
  keyPrefix: string;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface WebAuthnCredentialItem {
  id: string;
  kind: WebAuthnCredentialKind;
  name: string;
  transports: string[];
  createdAt: string;
  lastUsedAt: string | null;
}

export interface UserSecurityStatus {
  totpEnabled: boolean;
  recoveryCodesRemaining: number;
  securityKeys: WebAuthnCredentialItem[];
  passkeys: WebAuthnCredentialItem[];
}

export interface AppSettings {
  instanceName: string;
  initializedAt: string | null;
  pingAllowed: boolean;
  pingIntervalSec: number;
  pingOfflineThreshold?: number;
  pingOfflineMultiplier?: number;
  ssoEnabled: boolean;
  ssoProviderName: string;
  ssoAutoCreateUsers: boolean;
  ssoConfigured: boolean;
  ssoTestedAt: string | null;
  localLoginDisabled: boolean;
  twoFactorEnabled: boolean;
  twoFactorEnforced: boolean;
  passkeyEnabled: boolean;
  passkeyEnforced: boolean;
  allowInsecureHostKey: boolean;
  publicUrl?: string;
  maxBackgroundJobs?: number;
}

export interface AdminAuthSettings {
  ssoEnabled: boolean;
  ssoProviderName: string;
  ssoIssuerUrl: string;
  ssoAuthUrl: string;
  ssoTokenUrl: string;
  ssoUserinfoUrl: string;
  ssoClientId: string;
  ssoHasClientSecret: boolean;
  ssoScopes: string;
  ssoAutoCreateUsers: boolean;
  ssoConfigured: boolean;
  ssoTestedAt: string | null;
  localLoginDisabled: boolean;
  twoFactorEnabled: boolean;
  twoFactorEnforced: boolean;
  passkeyEnabled: boolean;
  passkeyEnforced: boolean;
  allowInsecureHostKey: boolean;
  publicUrl: string;
  callbackUrl: string;
}

export type LoginResponse =
  | {
      requiresTwoFactor?: false;
      user: User;
      sessionToken?: string;
    }
  | {
      requiresTwoFactor: true;
      ticket: string;
      methods: {
        totp: boolean;
        securityKey: boolean;
      };
      webauthnOptions: Record<string, unknown> | null;
    };

export interface AppStatus {
  initialized: boolean;
  settings: AppSettings;
  user: User | null;
  opensshAvailable: boolean;
}

export type CommandKind = 'single' | 'chain' | 'workflow';

export interface CommandStep {
  command: string;
  sleepAfterSec: number;
}

export interface SshCommand {
  id: string;
  userId: string;
  name: string;
  category: string;
  kind: CommandKind;
  command: string;
  steps: CommandStep[];
  workflowJson?: string;
  stopOnError: boolean;
  description: string;
  timeoutSec: number;
  enabled: boolean;
  createdBy: string;
  sharedWithAll: boolean;
  sharedWithUserIds: string[];
  createdAt: string;
  updatedAt: string;
}

export interface ServerCategory {
  id: string;
  userId: string;
  name: string;
  createdAt: string;
}

export interface UserServer {
  id: string;
  userId: string;
  ownerUsername: string;
  label: string;
  ipAddress: string;
  bmcIpAddress: string;
  bmcIpAddress2: string;
  port: number;
  sshUser: string;
  notes: string;
  categories?: string[];
  pingEnabled: boolean;
  ignoreHostKey?: boolean;
  lastOnlineAt?: string | null;
  sharedWithAll: boolean;
  sharedWithUserIds: string[];
  createdAt: string;
}

export interface BmcCheckResult {
  serverId: string;
  slot?: 1 | 2;
  bmcIpAddress: string;
  url: string;
  port: number;
  reachable: boolean;
  httpStatus: number | null;
  tlsProtocol: string | null;
  latencyMs: number | null;
  checkedAt: string;
  error?: string;
}

export interface ParsedCertMetadata {
  hasCertificate?: boolean;
  certAlgorithm: string;
  pubKeyAlgorithm: string;
  serial: string;
  certType: 'user' | 'host' | 'keypair' | 'unknown';
  keyId: string;
  principals: string[];
  validAfter: string;
  validBefore: string;
  validAfterUnix: number;
  validBeforeUnix: number;
  isExpired: boolean;
  isNotYetValid: boolean;
  criticalOptions: string[];
  extensions: string[];
  pubKeyFingerprint: string;
  caFingerprint: string;
  privateKeyFormat: 'openssh-v1' | 'pem-rsa' | 'pem-ec' | 'pem-pkcs8' | 'unknown';
  privateKeyEncrypted: boolean;
  pubKeyMatchesCert: boolean;
  privateKeyMatchesPub: boolean | null;
  warnings: string[];
}

export interface UserCertificate {
  id: string;
  userId: string;
  ownerUsername: string;
  name: string;
  privateKeyFileName: string;
  publicKeyFileName: string;
  certFileName: string;
  metadata: ParsedCertMetadata;
  hasStoredPassphrase?: boolean;
  sharedWithAll: boolean;
  sharedWithUserIds: string[];
  uploadedAt: string;
}

export interface ExecutionLog {
  id: string;
  userId: string;
  username: string;
  commandId: string;
  commandName: string;
  commandText: string;
  targetIp: string;
  targetPort: number;
  sshUser: string;
  serverLabel: string;
  certificateId: string;
  certificateKeyId: string;
  mode: 'openssh-live' | 'sandbox-dry-run';
  sshInvocation: string;
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  executedAt: string;
}

export type BackgroundJobStatus = 'running' | 'completed' | 'partial' | 'failed';

export interface BackgroundJob {
  id: string;
  userId: string;
  username: string;
  title: string;
  commandNames: string[];
  targetLabels: string[];
  totalTargets: number;
  completedTargets: number;
  successCount: number;
  failedCount: number;
  status: BackgroundJobStatus;
  startedAt: string;
  finishedAt: string | null;
  durationMs: number | null;
  timeoutSec: number;
  estimatedTimeoutSec: number;
  read: boolean;
  errorMessage?: string | null;
  results: ExecutionLog[];
}

export interface BackgroundJobsResponse {
  jobs: BackgroundJob[];
  activeCount: number;
  totalActiveCount?: number;
  unreadCount: number;
  maxBackgroundJobs: number;
}

export interface AdminBackgroundJobsResponse {
  jobs: BackgroundJob[];
  activeCount: number;
  maxBackgroundJobs: number;
}

export interface RustProjectFile {
  path: string;
  size: number;
  content: string;
}

export interface ServerPingStatus {
  serverId: string;
  ipAddress: string;
  port: number;
  online: boolean;
  latencyMs: number | null;
  method: 'icmp-ping' | 'tcp-ping';
  checkedAt: string;
  lastOnlineAt?: string | null;
  consecutiveFailures?: number;
  backoffActive?: boolean;
  effectiveIntervalSec?: number;
  error?: string;
}

export interface DashboardPingResponse {
  statuses: Record<string, ServerPingStatus>;
  intervalSec: number;
  offlineThreshold?: number;
  offlineMultiplier?: number;
  backoffCount?: number;
  lastCycleAt: string | null;
  nextCycleAt: string | null;
  pacingMs?: number | null;
  activeTargetCount?: number;
  pingMode: 'icmp-ping' | 'tcp-ping';
  globalPingAllowed: boolean;
  userPingEnabled: boolean;
}

export type ActiveTab =
  | 'dashboard'
  | 'shell'
  | 'jobs'
  | 'servers'
  | 'certificates'
  | 'logs'
  | 'account'
  | 'admin-commands'
  | 'admin-users'
  | 'admin-auth';
