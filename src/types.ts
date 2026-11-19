export type UserRole = 'admin' | 'user';

export interface User {
  id: string;
  username: string;
  displayName: string;
  role: UserRole;
  defaultSshUser: string;
  active: boolean;
  createdAt: string;
  lastLoginAt: string | null;
}

export interface AppSettings {
  instanceName: string;
  initializedAt: string | null;
}

export interface AppStatus {
  initialized: boolean;
  settings: AppSettings;
  user: User | null;
  opensshAvailable: boolean;
}

export type CommandKind = 'single' | 'chain';

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

export interface UserServer {
  id: string;
  userId: string;
  ownerUsername: string;
  label: string;
  ipAddress: string;
  bmcIpAddress: string;
  port: number;
  sshUser: string;
  notes: string;
  sharedWithAll: boolean;
  sharedWithUserIds: string[];
  createdAt: string;
}

export interface BmcCheckResult {
  serverId: string;
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
  error?: string;
}

export interface DashboardPingResponse {
  statuses: Record<string, ServerPingStatus>;
  intervalSec: number;
  lastCycleAt: string | null;
  nextCycleAt: string;
  pingMode: 'icmp-ping' | 'tcp-ping';
}

export type ActiveTab =
  | 'dashboard'
  | 'execute'
  | 'servers'
  | 'certificates'
  | 'logs'
  | 'account'
  | 'admin-commands'
  | 'admin-users'
  | 'rust-deploy';
