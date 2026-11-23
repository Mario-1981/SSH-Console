import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { ParsedCertMetadata } from './opensshCert.ts';

export type UserRole = 'admin' | 'user';
export type AuthProvider = 'local' | 'sso';
export type WebAuthnCredentialKind = 'security-key' | 'passkey';

export interface StoredWebAuthnCredential {
  id: string;
  userId: string;
  kind: WebAuthnCredentialKind;
  name: string;
  credentialId: string;
  publicKey: string;
  counter: number;
  transports: string[];
  createdAt: string;
  lastUsedAt: string | null;
}

export interface StoredUser {
  id: string;
  username: string;
  displayName: string;
  role: UserRole;
  authProvider: AuthProvider;
  ssoSubject: string | null;
  email: string;
  defaultSshUser: string;
  active: boolean;
  pingEnabled: boolean;
  passwordSalt: string;
  passwordHash: string;
  totpEnabled: boolean;
  totpSecretEncrypted: EncryptedBlob | null;
  totpRecoveryHashes: string[];
  createdAt: string;
  lastLoginAt: string | null;
}

export interface StoredSession {
  token: string;
  userId: string;
  createdAt: string;
  expiresAt: string;
}

export interface StoredApiKey {
  id: string;
  userId: string;
  name: string;
  keyPrefix: string;
  keyHash: string;
  createdAt: string;
  lastUsedAt: string | null;
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

export function compileCommandChain(steps: CommandStep[], stopOnError: boolean): string {
  const cleaned = steps
    .map((s) => ({
      command: s.command.trim(),
      sleepAfterSec: Math.min(600, Math.max(0, Math.floor(Number(s.sleepAfterSec) || 0))),
    }))
    .filter((s) => s.command.length > 0);

  if (cleaned.length === 0) {
    throw new Error('Eine Befehlskette muss mindestens einen SSH-Befehl enthalten.');
  }

  const sep = stopOnError ? ' && ' : '; ';
  const parts: string[] = [];

  cleaned.forEach((step, idx) => {
    parts.push(`{ ${step.command}; }`);
    const isLast = idx === cleaned.length - 1;
    if (!isLast && step.sleepAfterSec > 0) {
      parts.push(`sleep ${step.sleepAfterSec}`);
    }
  });

  return parts.join(sep);
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
  categories: string[];
  pingEnabled: boolean;
  ignoreHostKey: boolean;
  lastOnlineAt?: string | null;
  sharedWithAll: boolean;
  sharedWithUserIds: string[];
  createdAt: string;
}

export interface EncryptedBlob {
  iv: string;
  tag: string;
  ciphertext: string;
}

export interface UserCertificateBundle {
  id: string;
  userId: string;
  ownerUsername: string;
  name: string;
  privateKeyFileName: string;
  publicKeyFileName: string;
  certFileName: string;
  privateKeyEncrypted: EncryptedBlob;
  passphraseEncrypted?: EncryptedBlob;
  publicKeyContent: string;
  certContent: string;
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

export interface AppSettings {
  instanceName: string;
  initializedAt: string | null;
  pingAllowed: boolean;
  pingIntervalSec: number;
  pingOfflineThreshold: number;
  pingOfflineMultiplier: number;
  // SSO (OIDC / OAuth2)
  ssoEnabled: boolean;
  ssoProviderName: string;
  ssoIssuerUrl: string;
  ssoAuthUrl: string;
  ssoTokenUrl: string;
  ssoUserinfoUrl: string;
  ssoClientId: string;
  ssoClientSecretEncrypted: EncryptedBlob | null;
  ssoScopes: string;
  ssoAutoCreateUsers: boolean;
  ssoTestedAt: string | null;
  localLoginDisabled: boolean;
  // Local 2FA (Authenticator App + Security Key) & Passkeys
  twoFactorEnabled: boolean;
  twoFactorEnforced: boolean;
  passkeyEnabled: boolean;
  passkeyEnforced: boolean;
  // SSH Security
  allowInsecureHostKey: boolean;
  // Public base URL / domain for curl API snippets (e.g. https://ssh.example.net)
  publicUrl: string;
}

interface DatabaseSchema {
  settings: AppSettings;
  users: StoredUser[];
  sessions: StoredSession[];
  apiKeys: StoredApiKey[];
  webauthnCredentials: StoredWebAuthnCredential[];
  commands: SshCommand[];
  servers: UserServer[];
  serverCategories: ServerCategory[];
  certificates: UserCertificateBundle[];
  logs: ExecutionLog[];
}

const DATA_DIR = path.resolve(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'trixiessh.json');
const MASTER_KEY_FILE = path.join(DATA_DIR, 'master.key');

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  }
}

function getMasterKey(): Buffer {
  ensureDataDir();
  if (process.env.TRIXIESSH_MASTER_KEY) {
    return crypto.createHash('sha256').update(process.env.TRIXIESSH_MASTER_KEY).digest();
  }
  if (fs.existsSync(MASTER_KEY_FILE)) {
    return Buffer.from(fs.readFileSync(MASTER_KEY_FILE, 'utf8').trim(), 'hex');
  }
  const key = crypto.randomBytes(32);
  fs.writeFileSync(MASTER_KEY_FILE, key.toString('hex'), { mode: 0o600 });
  return key;
}

const MASTER_KEY = getMasterKey();

export function encryptSecret(plaintext: string): EncryptedBlob {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: encrypted.toString('base64'),
  };
}

export function decryptSecret(blob: EncryptedBlob): string {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    MASTER_KEY,
    Buffer.from(blob.iv, 'base64')
  );
  decipher.setAuthTag(Buffer.from(blob.tag, 'base64'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(blob.ciphertext, 'base64')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

export function hashPassword(password: string): { salt: string; hash: string } {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

export function verifyPassword(password: string, salt: string, expectedHash: string): boolean {
  const derived = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(expectedHash, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

export function hashApiKey(plainKey: string): string {
  return crypto.createHash('sha256').update(plainKey).digest('hex');
}

function emptyDb(): DatabaseSchema {
  return {
    settings: {
      instanceName: 'SSH Console',
      initializedAt: null,
      pingAllowed: true,
      pingIntervalSec: 60,
      pingOfflineThreshold: 5,
      pingOfflineMultiplier: 5,
      ssoEnabled: false,
      ssoProviderName: 'SSO',
      ssoIssuerUrl: '',
      ssoAuthUrl: '',
      ssoTokenUrl: '',
      ssoUserinfoUrl: '',
      ssoClientId: '',
      ssoClientSecretEncrypted: null,
      ssoScopes: 'openid profile email',
      ssoAutoCreateUsers: true,
      ssoTestedAt: null,
      localLoginDisabled: false,
      twoFactorEnabled: false,
      twoFactorEnforced: false,
      passkeyEnabled: false,
      passkeyEnforced: false,
      allowInsecureHostKey: false,
      publicUrl: '',
    },
    users: [],
    sessions: [],
    apiKeys: [],
    webauthnCredentials: [],
    commands: [],
    servers: [],
    serverCategories: [],
    certificates: [],
    logs: [],
  };
}

export function normalizeServerCategories(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  const seen = new Set<string>();
  const result: string[] = [];
  for (const item of input) {
    if (typeof item !== 'string') continue;
    const clean = item.trim().replace(/\s+/g, ' ').slice(0, 48);
    if (!clean) continue;
    const key = clean.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(clean);
    if (result.length >= 20) break;
  }
  return result;
}

class Store {
  private db: DatabaseSchema;

  constructor() {
    this.db = this.load();
  }

  private load(): DatabaseSchema {
    ensureDataDir();
    if (!fs.existsSync(DB_FILE)) {
      return emptyDb();
    }
    try {
      const parsed = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')) as DatabaseSchema;
      const users: StoredUser[] = (parsed.users ?? []).map((u) => ({
        ...u,
        authProvider: u.authProvider === 'sso' ? 'sso' : 'local',
        ssoSubject: typeof u.ssoSubject === 'string' && u.ssoSubject ? u.ssoSubject : null,
        email: typeof u.email === 'string' ? u.email : '',
        pingEnabled: typeof u.pingEnabled === 'boolean' ? u.pingEnabled : true,
        totpEnabled: Boolean(u.totpEnabled),
        totpSecretEncrypted: u.totpSecretEncrypted ?? null,
        totpRecoveryHashes: Array.isArray(u.totpRecoveryHashes) ? u.totpRecoveryHashes : [],
      }));
      const usernameToId = new Map(users.map((u) => [u.username.toLowerCase(), u.id]));
      const idToUsername = new Map(users.map((u) => [u.id, u.username]));
      const fallbackAdminId = users.find((u) => u.role === 'admin')?.id ?? '';

      const migratedCommands: SshCommand[] = (parsed.commands ?? []).map((c) => ({
        ...c,
        userId: c.userId || usernameToId.get((c.createdBy || '').toLowerCase()) || fallbackAdminId,
        kind: (c.kind ?? 'single') as CommandKind,
        steps: Array.isArray(c.steps) ? c.steps : [],
        stopOnError: typeof c.stopOnError === 'boolean' ? c.stopOnError : true,
        sharedWithAll: Boolean(c.sharedWithAll),
        sharedWithUserIds: Array.isArray(c.sharedWithUserIds) ? c.sharedWithUserIds : [],
      }));

      const migratedServers: UserServer[] = (parsed.servers ?? []).map((s) => ({
        ...s,
        ownerUsername: s.ownerUsername || idToUsername.get(s.userId) || '',
        bmcIpAddress: typeof s.bmcIpAddress === 'string' ? s.bmcIpAddress.trim() : '',
        bmcIpAddress2: typeof s.bmcIpAddress2 === 'string' ? s.bmcIpAddress2.trim() : '',
        categories: normalizeServerCategories((s as Partial<UserServer>).categories),
        pingEnabled: typeof s.pingEnabled === 'boolean' ? s.pingEnabled : true,
        ignoreHostKey: Boolean(s.ignoreHostKey),
        lastOnlineAt: typeof s.lastOnlineAt === 'string' ? s.lastOnlineAt : null,
        sharedWithAll: Boolean(s.sharedWithAll),
        sharedWithUserIds: Array.isArray(s.sharedWithUserIds) ? s.sharedWithUserIds : [],
      }));

      const migratedServerCategories: ServerCategory[] = Array.isArray(parsed.serverCategories)
        ? parsed.serverCategories
            .filter((c): c is ServerCategory => Boolean(c && typeof c.name === 'string' && c.name.trim()))
            .map((c) => ({
              id: typeof c.id === 'string' && c.id ? c.id : crypto.randomUUID(),
              userId: typeof c.userId === 'string' ? c.userId : fallbackAdminId,
              name: c.name.trim().replace(/\s+/g, ' ').slice(0, 48),
              createdAt: typeof c.createdAt === 'string' ? c.createdAt : new Date().toISOString(),
            }))
        : [];

      const migratedCertificates: UserCertificateBundle[] = (parsed.certificates ?? []).map((cert) => ({
        ...cert,
        ownerUsername: cert.ownerUsername || idToUsername.get(cert.userId) || '',
        certContent: typeof cert.certContent === 'string' ? cert.certContent : '',
        certFileName: typeof cert.certFileName === 'string' ? cert.certFileName : '',
        metadata: {
          ...cert.metadata,
          hasCertificate:
            typeof cert.metadata?.hasCertificate === 'boolean'
              ? cert.metadata.hasCertificate
              : Boolean(cert.certContent && cert.certContent.trim()),
        },
        sharedWithAll: Boolean(cert.sharedWithAll),
        sharedWithUserIds: Array.isArray(cert.sharedWithUserIds) ? cert.sharedWithUserIds : [],
      }));

      const rawInterval = Number(parsed.settings?.pingIntervalSec);
      const rawOfflineThreshold = Number(parsed.settings?.pingOfflineThreshold);
      const rawOfflineMultiplier = Number(parsed.settings?.pingOfflineMultiplier);
      const baseSettings = emptyDb().settings;
      const ssoEnabled = Boolean(parsed.settings?.ssoEnabled);
      const ssoTestedAt =
        typeof parsed.settings?.ssoTestedAt === 'string' && parsed.settings.ssoTestedAt
          ? parsed.settings.ssoTestedAt
          : null;
      const twoFactorEnabled = Boolean(parsed.settings?.twoFactorEnabled);
      const passkeyEnabled = Boolean(parsed.settings?.passkeyEnabled);

      const migratedSettings: AppSettings = {
        ...baseSettings,
        ...(parsed.settings ?? {}),
        instanceName:
          !parsed.settings?.instanceName || parsed.settings.instanceName === 'TrixieSSH'
            ? 'SSH Console'
            : parsed.settings.instanceName,
        pingAllowed:
          typeof parsed.settings?.pingAllowed === 'boolean' ? parsed.settings.pingAllowed : true,
        pingIntervalSec: Number.isFinite(rawInterval)
          ? Math.min(3600, Math.max(10, Math.round(rawInterval)))
          : 60,
        pingOfflineThreshold: Number.isFinite(rawOfflineThreshold)
          ? Math.min(100, Math.max(0, Math.round(rawOfflineThreshold)))
          : 5,
        pingOfflineMultiplier: Number.isFinite(rawOfflineMultiplier)
          ? Math.min(60, Math.max(2, Math.round(rawOfflineMultiplier)))
          : 5,
        ssoEnabled,
        ssoProviderName:
          typeof parsed.settings?.ssoProviderName === 'string' && parsed.settings.ssoProviderName.trim()
            ? parsed.settings.ssoProviderName.trim()
            : 'SSO',
        ssoIssuerUrl: typeof parsed.settings?.ssoIssuerUrl === 'string' ? parsed.settings.ssoIssuerUrl : '',
        ssoAuthUrl: typeof parsed.settings?.ssoAuthUrl === 'string' ? parsed.settings.ssoAuthUrl : '',
        ssoTokenUrl: typeof parsed.settings?.ssoTokenUrl === 'string' ? parsed.settings.ssoTokenUrl : '',
        ssoUserinfoUrl:
          typeof parsed.settings?.ssoUserinfoUrl === 'string' ? parsed.settings.ssoUserinfoUrl : '',
        ssoClientId: typeof parsed.settings?.ssoClientId === 'string' ? parsed.settings.ssoClientId : '',
        ssoClientSecretEncrypted: parsed.settings?.ssoClientSecretEncrypted ?? null,
        ssoScopes:
          typeof parsed.settings?.ssoScopes === 'string' && parsed.settings.ssoScopes.trim()
            ? parsed.settings.ssoScopes.trim()
            : 'openid profile email',
        ssoAutoCreateUsers:
          typeof parsed.settings?.ssoAutoCreateUsers === 'boolean'
            ? parsed.settings.ssoAutoCreateUsers
            : true,
        ssoTestedAt,
        localLoginDisabled: Boolean(parsed.settings?.localLoginDisabled && ssoEnabled && ssoTestedAt),
        twoFactorEnabled,
        twoFactorEnforced: Boolean(parsed.settings?.twoFactorEnforced && twoFactorEnabled),
        passkeyEnabled,
        passkeyEnforced: Boolean(parsed.settings?.passkeyEnforced && passkeyEnabled),
        allowInsecureHostKey: Boolean(parsed.settings?.allowInsecureHostKey),
        publicUrl: typeof parsed.settings?.publicUrl === 'string' ? parsed.settings.publicUrl : '',
      };

      const migratedWebauthn: StoredWebAuthnCredential[] = Array.isArray(parsed.webauthnCredentials)
        ? parsed.webauthnCredentials.map((c) => ({
            ...c,
            kind: c.kind === 'passkey' ? 'passkey' : 'security-key',
            transports: Array.isArray(c.transports) ? c.transports : [],
            counter: Number.isFinite(Number(c.counter)) ? Number(c.counter) : 0,
            lastUsedAt: typeof c.lastUsedAt === 'string' ? c.lastUsedAt : null,
          }))
        : [];

      return {
        ...emptyDb(),
        ...parsed,
        users,
        settings: migratedSettings,
        apiKeys: Array.isArray(parsed.apiKeys) ? parsed.apiKeys : [],
        webauthnCredentials: migratedWebauthn,
        commands: migratedCommands,
        servers: migratedServers,
        serverCategories: migratedServerCategories,
        certificates: migratedCertificates,
      };
    } catch {
      return emptyDb();
    }
  }

  private save() {
    ensureDataDir();
    const tmp = `${DB_FILE}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.db, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, DB_FILE);
  }

  isInitialized(): boolean {
    return this.db.users.some((u) => u.role === 'admin');
  }

  getSettings(): AppSettings {
    return this.db.settings;
  }

  updateGlobalPingSettings(patch: {
    pingAllowed?: boolean;
    pingIntervalSec?: number;
    pingOfflineThreshold?: number;
    pingOfflineMultiplier?: number;
  }): AppSettings {
    if (patch.pingAllowed !== undefined) {
      this.db.settings.pingAllowed = Boolean(patch.pingAllowed);
    }
    if (patch.pingIntervalSec !== undefined) {
      const n = Math.round(Number(patch.pingIntervalSec));
      if (!Number.isFinite(n) || n < 10 || n > 3600) {
        throw new Error('Ping-Intervall muss zwischen 10 und 3600 Sekunden liegen.');
      }
      this.db.settings.pingIntervalSec = n;
    }
    if (patch.pingOfflineThreshold !== undefined) {
      const t = Math.round(Number(patch.pingOfflineThreshold));
      if (!Number.isFinite(t) || t < 0 || t > 100) {
        throw new Error('Offline-Schwellwert muss zwischen 0 und 100 Fehlversuchen liegen.');
      }
      this.db.settings.pingOfflineThreshold = t;
    }
    if (patch.pingOfflineMultiplier !== undefined) {
      const m = Math.round(Number(patch.pingOfflineMultiplier));
      if (!Number.isFinite(m) || m < 2 || m > 60) {
        throw new Error('Offline-Intervall-Faktor muss zwischen 2 und 60 liegen.');
      }
      this.db.settings.pingOfflineMultiplier = m;
    }
    this.save();
    return this.db.settings;
  }

  setUserPingEnabled(userId: string, pingEnabled: boolean): StoredUser {
    const user = this.db.users.find((u) => u.id === userId);
    if (!user) throw new Error('Benutzer nicht gefunden.');
    user.pingEnabled = Boolean(pingEnabled);
    this.save();
    return user;
  }

  shouldPingServer(server: UserServer): boolean {
    if (!this.db.settings.pingAllowed) return false;
    if (server.pingEnabled === false) return false;
    const owner = this.db.users.find((u) => u.id === server.userId && u.active);
    if (owner && owner.pingEnabled !== false) return true;
    if (server.sharedWithAll) {
      return this.db.users.some((u) => u.active && u.pingEnabled !== false);
    }
    if (server.sharedWithUserIds.length > 0) {
      const sharedSet = new Set(server.sharedWithUserIds);
      return this.db.users.some((u) => u.active && sharedSet.has(u.id) && u.pingEnabled !== false);
    }
    return false;
  }

  setupInitialAdmin(params: {
    username: string;
    displayName: string;
    password: string;
    instanceName: string;
  }): StoredUser {
    if (this.isInitialized()) {
      throw new Error('Die Ersteinrichtung wurde bereits abgeschlossen.');
    }
    const { salt, hash } = hashPassword(params.password);
    const now = new Date().toISOString();
    const admin: StoredUser = {
      id: crypto.randomUUID(),
      username: params.username.trim().toLowerCase(),
      displayName: params.displayName.trim() || params.username.trim(),
      role: 'admin',
      authProvider: 'local',
      ssoSubject: null,
      email: '',
      defaultSshUser: 'root',
      active: true,
      pingEnabled: true,
      passwordSalt: salt,
      passwordHash: hash,
      totpEnabled: false,
      totpSecretEncrypted: null,
      totpRecoveryHashes: [],
      createdAt: now,
      lastLoginAt: now,
    };
    this.db.settings = {
      ...emptyDb().settings,
      instanceName: params.instanceName.trim() || 'SSH Console',
      initializedAt: now,
      pingAllowed: true,
      pingIntervalSec: 60,
    };
    this.db.users.push(admin);
    this.save();
    return admin;
  }

  isSsoConfigured(): boolean {
    const s = this.db.settings;
    return Boolean(s.ssoAuthUrl.trim() && s.ssoTokenUrl.trim() && s.ssoClientId.trim());
  }

  getSsoClientSecretPlain(): string {
    const enc = this.db.settings.ssoClientSecretEncrypted;
    if (!enc) return '';
    try {
      return decryptSecret(enc);
    } catch {
      return '';
    }
  }

  updateAuthSettings(patch: {
    ssoEnabled?: boolean;
    ssoProviderName?: string;
    ssoIssuerUrl?: string;
    ssoAuthUrl?: string;
    ssoTokenUrl?: string;
    ssoUserinfoUrl?: string;
    ssoClientId?: string;
    ssoClientSecret?: string;
    clearSsoClientSecret?: boolean;
    ssoScopes?: string;
    ssoAutoCreateUsers?: boolean;
    localLoginDisabled?: boolean;
    twoFactorEnabled?: boolean;
    twoFactorEnforced?: boolean;
    passkeyEnabled?: boolean;
    passkeyEnforced?: boolean;
    allowInsecureHostKey?: boolean;
    publicUrl?: string;
  }): AppSettings {
    const s = this.db.settings;
    let ssoConfigChanged = false;

    if (patch.ssoProviderName !== undefined) {
      s.ssoProviderName = patch.ssoProviderName.trim().slice(0, 64) || 'SSO';
    }
    if (patch.ssoIssuerUrl !== undefined) {
      const next = patch.ssoIssuerUrl.trim();
      if (next !== s.ssoIssuerUrl) ssoConfigChanged = true;
      s.ssoIssuerUrl = next;
    }
    if (patch.ssoAuthUrl !== undefined) {
      const next = patch.ssoAuthUrl.trim();
      if (next !== s.ssoAuthUrl) ssoConfigChanged = true;
      s.ssoAuthUrl = next;
    }
    if (patch.ssoTokenUrl !== undefined) {
      const next = patch.ssoTokenUrl.trim();
      if (next !== s.ssoTokenUrl) ssoConfigChanged = true;
      s.ssoTokenUrl = next;
    }
    if (patch.ssoUserinfoUrl !== undefined) {
      const next = patch.ssoUserinfoUrl.trim();
      if (next !== s.ssoUserinfoUrl) ssoConfigChanged = true;
      s.ssoUserinfoUrl = next;
    }
    if (patch.ssoClientId !== undefined) {
      const next = patch.ssoClientId.trim();
      if (next !== s.ssoClientId) ssoConfigChanged = true;
      s.ssoClientId = next;
    }
    if (patch.clearSsoClientSecret) {
      if (s.ssoClientSecretEncrypted !== null) ssoConfigChanged = true;
      s.ssoClientSecretEncrypted = null;
    } else if (typeof patch.ssoClientSecret === 'string' && patch.ssoClientSecret.trim()) {
      s.ssoClientSecretEncrypted = encryptSecret(patch.ssoClientSecret.trim());
      ssoConfigChanged = true;
    }
    if (patch.ssoScopes !== undefined) {
      const next = patch.ssoScopes.trim() || 'openid profile email';
      if (next !== s.ssoScopes) ssoConfigChanged = true;
      s.ssoScopes = next;
    }
    if (patch.ssoAutoCreateUsers !== undefined) {
      s.ssoAutoCreateUsers = Boolean(patch.ssoAutoCreateUsers);
    }
    if (patch.ssoEnabled !== undefined) {
      s.ssoEnabled = Boolean(patch.ssoEnabled);
    }

    if (ssoConfigChanged) {
      s.ssoTestedAt = null;
      s.localLoginDisabled = false;
    }

    if (!s.ssoEnabled || !this.isSsoConfigured() || !s.ssoTestedAt) {
      if (patch.localLoginDisabled === true) {
        throw new Error(
          'Die lokale Anmeldung kann erst abgeschaltet werden, wenn SSO aktiviert, vollständig konfiguriert und erfolgreich getestet wurde.'
        );
      }
      s.localLoginDisabled = false;
    } else if (patch.localLoginDisabled !== undefined) {
      s.localLoginDisabled = Boolean(patch.localLoginDisabled);
    }

    if (patch.twoFactorEnabled !== undefined) {
      s.twoFactorEnabled = Boolean(patch.twoFactorEnabled);
      if (!s.twoFactorEnabled) s.twoFactorEnforced = false;
    }
    if (patch.twoFactorEnforced !== undefined) {
      if (patch.twoFactorEnforced && !s.twoFactorEnabled) {
        throw new Error('2FA muss zuerst eingeschaltet werden, bevor sie erzwungen werden kann.');
      }
      s.twoFactorEnforced = Boolean(patch.twoFactorEnforced);
    }

    if (patch.passkeyEnabled !== undefined) {
      s.passkeyEnabled = Boolean(patch.passkeyEnabled);
      if (!s.passkeyEnabled) s.passkeyEnforced = false;
    }
    if (patch.passkeyEnforced !== undefined) {
      if (patch.passkeyEnforced && !s.passkeyEnabled) {
        throw new Error('Passkeys müssen zuerst eingeschaltet werden, bevor sie erzwungen werden können.');
      }
      s.passkeyEnforced = Boolean(patch.passkeyEnforced);
    }

    if (patch.allowInsecureHostKey !== undefined) {
      s.allowInsecureHostKey = Boolean(patch.allowInsecureHostKey);
    }

    if (patch.publicUrl !== undefined) {
      const raw = patch.publicUrl.trim();
      if (!raw) {
        s.publicUrl = '';
      } else {
        if (/[\s"'`$\\<>;&|]/.test(raw)) {
          throw new Error('Ungültige Zeichen in der öffentlichen Domain / URL.');
        }
        const candidate = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
        let parsedUrl: URL;
        try {
          parsedUrl = new URL(candidate);
        } catch {
          throw new Error('Ungültige öffentliche Domain / Basis-URL (z. B. https://ssh.example.net).');
        }
        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
          throw new Error('Die öffentliche URL muss mit http:// oder https:// beginnen.');
        }
        if (!parsedUrl.hostname) {
          throw new Error('Bitte geben Sie einen gültigen Hostnamen bzw. eine Domain an.');
        }
        if (parsedUrl.search || parsedUrl.hash || parsedUrl.username || parsedUrl.password) {
          throw new Error('Die Basis-URL darf keine Zugangsdaten, Query-Parameter oder Fragmente enthalten.');
        }
        const cleanPath = parsedUrl.pathname.replace(/\/+$/, '');
        s.publicUrl = `${parsedUrl.origin}${cleanPath === '/' ? '' : cleanPath}`;
      }
    }

    this.save();
    return s;
  }

  markSsoTested(): AppSettings {
    this.db.settings.ssoTestedAt = new Date().toISOString();
    this.save();
    return this.db.settings;
  }

  findUserByUsername(username: string): StoredUser | undefined {
    const normalized = username.trim().toLowerCase();
    return this.db.users.find((u) => u.username === normalized);
  }

  findUserById(id: string): StoredUser | undefined {
    return this.db.users.find((u) => u.id === id);
  }

  findOrCreateSsoUser(profile: {
    sub: string;
    username: string;
    displayName: string;
    email: string;
  }): { user: StoredUser; created: boolean } {
    const ssoKey = `${this.db.settings.ssoIssuerUrl || this.db.settings.ssoAuthUrl}::${profile.sub}`;
    let user = this.db.users.find((u) => u.ssoSubject === ssoKey);
    if (!user && profile.email) {
      const emailLower = profile.email.toLowerCase();
      user = this.db.users.find((u) => u.email && u.email.toLowerCase() === emailLower);
    }
    if (!user) {
      user = this.findUserByUsername(profile.username);
    }

    if (user) {
      if (!user.active) {
        throw new Error('Dieses Benutzerkonto ist gesperrt. Bitte wenden Sie sich an den Administrator.');
      }
      if (!user.ssoSubject) user.ssoSubject = ssoKey;
      if (profile.email && !user.email) user.email = profile.email;
      if (profile.displayName && user.displayName === user.username) {
        user.displayName = profile.displayName;
      }
      this.save();
      return { user, created: false };
    }

    if (!this.db.settings.ssoAutoCreateUsers) {
      throw new Error(
        'Für diesen SSO-Zugang existiert kein Benutzerkonto und die automatische Benutzeranlage ist deaktiviert.'
      );
    }

    // Ensure unique username
    let baseUsername = profile.username.toLowerCase().replace(/[^a-z0-9._-]/g, '_');
    if (baseUsername.length < 2) baseUsername = `sso_${crypto.randomBytes(3).toString('hex')}`;
    let candidate = baseUsername.slice(0, 32);
    let suffix = 1;
    while (this.db.users.some((u) => u.username === candidate)) {
      const tag = `_${suffix++}`;
      candidate = `${baseUsername.slice(0, 32 - tag.length)}${tag}`;
    }

    const randomSecret = crypto.randomBytes(32).toString('hex');
    const { salt, hash } = hashPassword(randomSecret);
    const createdUser: StoredUser = {
      id: crypto.randomUUID(),
      username: candidate,
      displayName: profile.displayName || candidate,
      role: 'user',
      authProvider: 'sso',
      ssoSubject: ssoKey,
      email: profile.email || '',
      defaultSshUser: 'root',
      active: true,
      pingEnabled: true,
      passwordSalt: salt,
      passwordHash: hash,
      totpEnabled: false,
      totpSecretEncrypted: null,
      totpRecoveryHashes: [],
      createdAt: new Date().toISOString(),
      lastLoginAt: null,
    };
    this.db.users.push(createdUser);
    this.save();
    return { user: createdUser, created: true };
  }

  listUsers(): StoredUser[] {
    return [...this.db.users].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  createUser(params: {
    username: string;
    displayName: string;
    password: string;
    role: UserRole;
    defaultSshUser: string;
  }): StoredUser {
    const normalized = params.username.trim().toLowerCase();
    if (!/^[a-z0-9._-]{2,32}$/.test(normalized)) {
      throw new Error('Benutzername muss 2–32 Zeichen lang sein (a-z, 0-9, ., _, -).');
    }
    if (this.db.users.some((u) => u.username === normalized)) {
      throw new Error(`Benutzer "${normalized}" existiert bereits.`);
    }
    const { salt, hash } = hashPassword(params.password);
    const user: StoredUser = {
      id: crypto.randomUUID(),
      username: normalized,
      displayName: params.displayName.trim() || normalized,
      role: params.role,
      authProvider: 'local',
      ssoSubject: null,
      email: '',
      defaultSshUser: params.defaultSshUser.trim() || 'root',
      active: true,
      pingEnabled: true,
      passwordSalt: salt,
      passwordHash: hash,
      totpEnabled: false,
      totpSecretEncrypted: null,
      totpRecoveryHashes: [],
      createdAt: new Date().toISOString(),
      lastLoginAt: null,
    };
    this.db.users.push(user);
    this.save();
    return user;
  }

  // ── 2FA (TOTP) & WebAuthn (Security Keys + Passkeys) ──────────────────────

  setUserTotp(userId: string, secretBase32: string, recoveryHashes: string[]): StoredUser {
    const user = this.db.users.find((u) => u.id === userId);
    if (!user) throw new Error('Benutzer nicht gefunden.');
    user.totpEnabled = true;
    user.totpSecretEncrypted = encryptSecret(secretBase32);
    user.totpRecoveryHashes = recoveryHashes;
    this.save();
    return user;
  }

  getUserTotpSecretPlain(userId: string): string | null {
    const user = this.db.users.find((u) => u.id === userId);
    if (!user || !user.totpEnabled || !user.totpSecretEncrypted) return null;
    try {
      return decryptSecret(user.totpSecretEncrypted);
    } catch {
      return null;
    }
  }

  consumeRecoveryCode(userId: string, codeHash: string): boolean {
    const user = this.db.users.find((u) => u.id === userId);
    if (!user || !user.totpEnabled) return false;
    const idx = user.totpRecoveryHashes.indexOf(codeHash);
    if (idx === -1) return false;
    user.totpRecoveryHashes.splice(idx, 1);
    this.save();
    return true;
  }

  disableUserTotp(userId: string): StoredUser {
    const user = this.db.users.find((u) => u.id === userId);
    if (!user) throw new Error('Benutzer nicht gefunden.');
    user.totpEnabled = false;
    user.totpSecretEncrypted = null;
    user.totpRecoveryHashes = [];
    this.save();
    return user;
  }

  listUserWebAuthnCredentials(
    userId: string,
    kind?: WebAuthnCredentialKind
  ): StoredWebAuthnCredential[] {
    return this.db.webauthnCredentials
      .filter((c) => c.userId === userId && (!kind || c.kind === kind))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  findWebAuthnCredentialByCredId(credentialId: string): StoredWebAuthnCredential | undefined {
    return this.db.webauthnCredentials.find((c) => c.credentialId === credentialId);
  }

  addWebAuthnCredential(params: {
    userId: string;
    kind: WebAuthnCredentialKind;
    name: string;
    credentialId: string;
    publicKey: string;
    counter: number;
    transports: string[];
  }): StoredWebAuthnCredential {
    if (this.db.webauthnCredentials.some((c) => c.credentialId === params.credentialId)) {
      throw new Error('Dieser Schlüssel bzw. Passkey ist bereits registriert.');
    }
    const cred: StoredWebAuthnCredential = {
      id: crypto.randomUUID(),
      userId: params.userId,
      kind: params.kind,
      name: params.name.trim().slice(0, 64) || (params.kind === 'passkey' ? 'Passkey' : 'Security Key'),
      credentialId: params.credentialId,
      publicKey: params.publicKey,
      counter: params.counter,
      transports: params.transports,
      createdAt: new Date().toISOString(),
      lastUsedAt: null,
    };
    this.db.webauthnCredentials.push(cred);
    this.save();
    return cred;
  }

  updateWebAuthnCredentialUsage(id: string, newCounter: number) {
    const cred = this.db.webauthnCredentials.find((c) => c.id === id);
    if (!cred) return;
    cred.counter = newCounter;
    cred.lastUsedAt = new Date().toISOString();
    this.save();
  }

  deleteWebAuthnCredential(id: string, userId: string): boolean {
    const before = this.db.webauthnCredentials.length;
    this.db.webauthnCredentials = this.db.webauthnCredentials.filter(
      (c) => !(c.id === id && c.userId === userId)
    );
    if (this.db.webauthnCredentials.length !== before) {
      this.save();
      return true;
    }
    return false;
  }

  resetUserSecondFactors(userId: string): StoredUser {
    const user = this.db.users.find((u) => u.id === userId);
    if (!user) throw new Error('Benutzer nicht gefunden.');
    user.totpEnabled = false;
    user.totpSecretEncrypted = null;
    user.totpRecoveryHashes = [];
    this.db.webauthnCredentials = this.db.webauthnCredentials.filter((c) => c.userId !== userId);
    this.save();
    return user;
  }

  updateUser(
    id: string,
    patch: {
      displayName?: string;
      role?: UserRole;
      defaultSshUser?: string;
      active?: boolean;
      newPassword?: string;
    }
  ): StoredUser {
    const user = this.db.users.find((u) => u.id === id);
    if (!user) throw new Error('Benutzer nicht gefunden.');

    // Protect against removing/disabling the last active admin
    const activeAdmins = this.db.users.filter((u) => u.role === 'admin' && u.active);
    if (
      user.role === 'admin' &&
      user.active &&
      activeAdmins.length <= 1 &&
      (patch.active === false || patch.role === 'user')
    ) {
      throw new Error('Der letzte aktive Administrator kann nicht deaktiviert oder herabgestuft werden.');
    }

    if (patch.displayName !== undefined) user.displayName = patch.displayName.trim() || user.username;
    if (patch.role !== undefined) user.role = patch.role;
    if (patch.defaultSshUser !== undefined) user.defaultSshUser = patch.defaultSshUser.trim() || 'root';
    if (patch.active !== undefined) user.active = patch.active;
    if (patch.newPassword && patch.newPassword.length >= 8) {
      const { salt, hash } = hashPassword(patch.newPassword);
      user.passwordSalt = salt;
      user.passwordHash = hash;
    }

    if (!user.active) {
      this.db.sessions = this.db.sessions.filter((s) => s.userId !== user.id);
    }

    this.save();
    return user;
  }

  deleteUser(id: string): void {
    const user = this.db.users.find((u) => u.id === id);
    if (!user) throw new Error('Benutzer nicht gefunden.');
    const activeAdmins = this.db.users.filter((u) => u.role === 'admin' && u.active);
    if (user.role === 'admin' && activeAdmins.length <= 1) {
      throw new Error('Der letzte Administrator kann nicht gelöscht werden.');
    }
    this.db.users = this.db.users.filter((u) => u.id !== id);
    this.db.sessions = this.db.sessions.filter((s) => s.userId !== id);
    this.db.apiKeys = this.db.apiKeys.filter((k) => k.userId !== id);
    this.db.webauthnCredentials = this.db.webauthnCredentials.filter((c) => c.userId !== id);
    this.db.commands = this.db.commands
      .filter((c) => c.userId !== id)
      .map((c) => ({ ...c, sharedWithUserIds: c.sharedWithUserIds.filter((uid) => uid !== id) }));
    this.db.servers = this.db.servers
      .filter((s) => s.userId !== id)
      .map((s) => ({ ...s, sharedWithUserIds: s.sharedWithUserIds.filter((uid) => uid !== id) }));
    this.db.certificates = this.db.certificates
      .filter((c) => c.userId !== id)
      .map((c) => ({ ...c, sharedWithUserIds: c.sharedWithUserIds.filter((uid) => uid !== id) }));
    this.save();
  }

  changeUserPassword(userId: string, newPassword: string, keepSessionToken?: string): void {
    const user = this.db.users.find((u) => u.id === userId);
    if (!user) throw new Error('Benutzer nicht gefunden.');
    const { salt, hash } = hashPassword(newPassword);
    user.passwordSalt = salt;
    user.passwordHash = hash;
    this.db.sessions = this.db.sessions.filter(
      (s) => s.userId !== userId || (keepSessionToken !== undefined && s.token === keepSessionToken)
    );
    this.save();
  }

  createSession(userId: string): StoredSession {
    const now = Date.now();
    const session: StoredSession = {
      token: crypto.randomBytes(32).toString('hex'),
      userId,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 24 * 60 * 60 * 1000).toISOString(),
    };
    const user = this.db.users.find((u) => u.id === userId);
    if (user) {
      user.lastLoginAt = session.createdAt;
    }
    // Prune expired sessions
    this.db.sessions = this.db.sessions.filter((s) => Date.parse(s.expiresAt) > now);
    this.db.sessions.push(session);
    this.save();
    return session;
  }

  getUserBySessionToken(token: string | undefined): StoredUser | null {
    if (!token) return null;
    const now = Date.now();
    const session = this.db.sessions.find((s) => s.token === token && Date.parse(s.expiresAt) > now);
    if (!session) return null;
    const user = this.db.users.find((u) => u.id === session.userId && u.active);
    return user ?? null;
  }

  deleteSession(token: string | undefined): void {
    if (!token) return;
    this.db.sessions = this.db.sessions.filter((s) => s.token !== token);
    this.save();
  }

  // Personal API Keys (for automated curl certificate uploads)
  listApiKeys(userId: string): StoredApiKey[] {
    return this.db.apiKeys
      .filter((k) => k.userId === userId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  createApiKey(userId: string, name: string): { apiKey: StoredApiKey; plainKey: string } {
    const cleanName = name.trim().slice(0, 64) || 'API-Schlüssel';
    const plainKey = `sshc_${crypto.randomBytes(32).toString('hex')}`;
    const apiKey: StoredApiKey = {
      id: crypto.randomUUID(),
      userId,
      name: cleanName,
      keyPrefix: `${plainKey.slice(0, 12)}…`,
      keyHash: hashApiKey(plainKey),
      createdAt: new Date().toISOString(),
      lastUsedAt: null,
    };
    this.db.apiKeys.push(apiKey);
    this.save();
    return { apiKey, plainKey };
  }

  deleteApiKey(id: string, userId: string): void {
    this.db.apiKeys = this.db.apiKeys.filter((k) => !(k.id === id && k.userId === userId));
    this.save();
  }

  getUserByApiKey(plainKey: string | undefined): StoredUser | null {
    if (!plainKey || !plainKey.startsWith('sshc_') || plainKey.length < 20) {
      return null;
    }
    const candidateHash = Buffer.from(hashApiKey(plainKey), 'hex');
    const match = this.db.apiKeys.find((k) => {
      const stored = Buffer.from(k.keyHash, 'hex');
      if (stored.length !== candidateHash.length) return false;
      return crypto.timingSafeEqual(stored, candidateHash);
    });
    if (!match) return null;
    const user = this.db.users.find((u) => u.id === match.userId && u.active);
    if (!user) return null;
    match.lastUsedAt = new Date().toISOString();
    this.save();
    return user;
  }

  private normalizeSharedUserIds(ownerUserId: string, userIds: string[]): string[] {
    const validIds = new Set(this.db.users.map((u) => u.id));
    const unique = new Set<string>();
    for (const uid of userIds) {
      if (typeof uid === 'string' && uid !== ownerUserId && validIds.has(uid)) {
        unique.add(uid);
      }
    }
    return Array.from(unique);
  }

  // SSH Commands (creator-private by default; admin may share with all or specific users)
  listAccessibleCommands(userId: string, includeDisabledOwn: boolean): SshCommand[] {
    const items = this.db.commands.filter((c) => {
      if (c.userId === userId) {
        return includeDisabledOwn ? true : c.enabled;
      }
      return c.enabled && (c.sharedWithAll || c.sharedWithUserIds.includes(userId));
    });
    return [...items].sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
  }

  listOwnCommands(userId: string): SshCommand[] {
    return this.db.commands.filter((c) => c.userId === userId);
  }

  getCommand(id: string): SshCommand | undefined {
    return this.db.commands.find((c) => c.id === id);
  }

  getAccessibleCommand(id: string, userId: string): SshCommand | undefined {
    const cmd = this.db.commands.find((c) => c.id === id);
    if (!cmd || !cmd.enabled) return undefined;
    if (cmd.userId === userId || cmd.sharedWithAll || cmd.sharedWithUserIds.includes(userId)) {
      return cmd;
    }
    return undefined;
  }

  createCommand(params: {
    userId: string;
    name: string;
    category: string;
    kind?: CommandKind;
    command: string;
    steps?: CommandStep[];
    stopOnError?: boolean;
    description: string;
    timeoutSec: number;
    enabled?: boolean;
    createdBy: string;
    sharedWithAll?: boolean;
    sharedWithUserIds?: string[];
  }): SshCommand {
    const now = new Date().toISOString();
    const kind: CommandKind = params.kind === 'chain' ? 'chain' : 'single';
    const stopOnError = params.stopOnError ?? true;
    const normalizedSteps: CommandStep[] =
      kind === 'chain' && Array.isArray(params.steps)
        ? params.steps
            .map((s) => ({
              command: String(s.command ?? '').trim(),
              sleepAfterSec: Math.min(600, Math.max(0, Math.floor(Number(s.sleepAfterSec) || 0))),
            }))
            .filter((s) => s.command.length > 0)
        : [];

    const compiledCommand =
      kind === 'chain'
        ? compileCommandChain(normalizedSteps, stopOnError)
        : params.command.trim();

    const totalSleepSec =
      kind === 'chain'
        ? normalizedSteps.slice(0, -1).reduce((acc, s) => acc + s.sleepAfterSec, 0)
        : 0;
    const requestedTimeout = Number(params.timeoutSec) || 30;
    const minTimeout = Math.max(5, totalSleepSec + 10);

    const sharedWithAll = Boolean(params.sharedWithAll);
    const sharedWithUserIds = sharedWithAll
      ? []
      : this.normalizeSharedUserIds(params.userId, params.sharedWithUserIds ?? []);

    const cmd: SshCommand = {
      id: crypto.randomUUID(),
      userId: params.userId,
      name: params.name.trim(),
      category: params.category.trim() || 'Allgemein',
      kind,
      command: compiledCommand,
      steps: normalizedSteps,
      stopOnError,
      description: params.description.trim(),
      timeoutSec: Math.min(3600, Math.max(minTimeout, requestedTimeout)),
      enabled: params.enabled ?? true,
      createdBy: params.createdBy,
      sharedWithAll,
      sharedWithUserIds,
      createdAt: now,
      updatedAt: now,
    };
    this.db.commands.push(cmd);
    this.save();
    return cmd;
  }

  updateCommand(
    id: string,
    patch: Partial<
      Pick<
        SshCommand,
        | 'name'
        | 'category'
        | 'kind'
        | 'command'
        | 'steps'
        | 'stopOnError'
        | 'description'
        | 'timeoutSec'
        | 'enabled'
        | 'sharedWithAll'
        | 'sharedWithUserIds'
      >
    >
  ): SshCommand {
    const cmd = this.db.commands.find((c) => c.id === id);
    if (!cmd) throw new Error('SSH-Befehl nicht gefunden.');
    if (patch.name !== undefined) cmd.name = patch.name.trim();
    if (patch.category !== undefined) cmd.category = patch.category.trim() || 'Allgemein';
    if (patch.kind !== undefined) cmd.kind = patch.kind === 'chain' ? 'chain' : 'single';
    if (patch.stopOnError !== undefined) cmd.stopOnError = Boolean(patch.stopOnError);

    if (cmd.kind === 'chain') {
      if (patch.steps !== undefined) {
        cmd.steps = patch.steps
          .map((s) => ({
            command: String(s.command ?? '').trim(),
            sleepAfterSec: Math.min(600, Math.max(0, Math.floor(Number(s.sleepAfterSec) || 0))),
          }))
          .filter((s) => s.command.length > 0);
      }
      cmd.command = compileCommandChain(cmd.steps, cmd.stopOnError);
    } else {
      cmd.steps = [];
      if (patch.command !== undefined) cmd.command = patch.command.trim();
    }

    if (patch.description !== undefined) cmd.description = patch.description.trim();
    if (patch.timeoutSec !== undefined || patch.steps !== undefined) {
      const totalSleepSec =
        cmd.kind === 'chain'
          ? cmd.steps.slice(0, -1).reduce((acc, s) => acc + s.sleepAfterSec, 0)
          : 0;
      const minTimeout = Math.max(5, totalSleepSec + 10);
      const nextTimeout = patch.timeoutSec !== undefined ? Number(patch.timeoutSec) || 30 : cmd.timeoutSec;
      cmd.timeoutSec = Math.min(3600, Math.max(minTimeout, nextTimeout));
    }
    if (patch.enabled !== undefined) cmd.enabled = patch.enabled;
    if (patch.sharedWithAll !== undefined || patch.sharedWithUserIds !== undefined) {
      const nextAll = patch.sharedWithAll !== undefined ? Boolean(patch.sharedWithAll) : cmd.sharedWithAll;
      cmd.sharedWithAll = nextAll;
      cmd.sharedWithUserIds = nextAll
        ? []
        : this.normalizeSharedUserIds(cmd.userId, patch.sharedWithUserIds ?? cmd.sharedWithUserIds);
    }
    cmd.updatedAt = new Date().toISOString();
    this.save();
    return cmd;
  }

  updateCommandSharing(
    id: string,
    ownerUserId: string,
    sharedWithAll: boolean,
    sharedWithUserIds: string[]
  ): SshCommand {
    const cmd = this.db.commands.find((c) => c.id === id);
    if (!cmd) throw new Error('SSH-Befehl nicht gefunden.');
    if (cmd.userId !== ownerUserId) {
      throw new Error('Sie können nur eigene SSH-Befehle teilen.');
    }
    cmd.sharedWithAll = Boolean(sharedWithAll);
    cmd.sharedWithUserIds = cmd.sharedWithAll
      ? []
      : this.normalizeSharedUserIds(ownerUserId, sharedWithUserIds);
    cmd.updatedAt = new Date().toISOString();
    this.save();
    return cmd;
  }

  deleteCommand(id: string): void {
    this.db.commands = this.db.commands.filter((c) => c.id !== id);
    this.save();
  }

  // User Target Servers (IPs) — creator-private by default; admin may share
  listAllServers(): UserServer[] {
    return [...this.db.servers];
  }

  listAccessibleServers(userId: string): UserServer[] {
    return this.db.servers
      .filter((s) => s.userId === userId || s.sharedWithAll || s.sharedWithUserIds.includes(userId))
      .sort((a, b) => a.label.localeCompare(b.label) || a.ipAddress.localeCompare(b.ipAddress));
  }

  getServerById(id: string): UserServer | undefined {
    return this.db.servers.find((s) => s.id === id);
  }

  getAccessibleServer(id: string, userId: string): UserServer | undefined {
    return this.db.servers.find(
      (s) =>
        s.id === id &&
        (s.userId === userId || s.sharedWithAll || s.sharedWithUserIds.includes(userId))
    );
  }

  // Server Categories (per-user reusable category catalog)
  listServerCategories(userId: string): ServerCategory[] {
    return this.db.serverCategories
      .filter((c) => c.userId === userId)
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  private ensureUserCategoriesExist(userId: string, names: string[]): void {
    for (const rawName of names) {
      const clean = rawName.trim().replace(/\s+/g, ' ').slice(0, 48);
      if (!clean) continue;
      const lower = clean.toLowerCase();
      const exists = this.db.serverCategories.some(
        (c) => c.userId === userId && c.name.toLowerCase() === lower
      );
      if (!exists) {
        this.db.serverCategories.push({
          id: crypto.randomUUID(),
          userId,
          name: clean,
          createdAt: new Date().toISOString(),
        });
      }
    }
  }

  createServerCategory(userId: string, name: string): ServerCategory {
    const clean = name.trim().replace(/\s+/g, ' ').slice(0, 48);
    if (!clean) {
      throw new Error('Bitte geben Sie einen Kategorienamen an.');
    }
    const lower = clean.toLowerCase();
    const existing = this.db.serverCategories.find(
      (c) => c.userId === userId && c.name.toLowerCase() === lower
    );
    if (existing) {
      return existing;
    }
    const category: ServerCategory = {
      id: crypto.randomUUID(),
      userId,
      name: clean,
      createdAt: new Date().toISOString(),
    };
    this.db.serverCategories.push(category);
    this.save();
    return category;
  }

  deleteServerCategory(id: string, userId: string): boolean {
    const target = this.db.serverCategories.find((c) => c.id === id && c.userId === userId);
    if (!target) return false;
    const targetLower = target.name.toLowerCase();
    this.db.serverCategories = this.db.serverCategories.filter(
      (c) => !(c.id === id && c.userId === userId)
    );
    // Remove deleted category from the owner's own servers
    for (const srv of this.db.servers) {
      if (srv.userId === userId && srv.categories.length > 0) {
        srv.categories = srv.categories.filter((cat) => cat.toLowerCase() !== targetLower);
      }
    }
    this.save();
    return true;
  }

  createServer(params: {
    userId: string;
    ownerUsername: string;
    label: string;
    ipAddress: string;
    bmcIpAddress?: string;
    bmcIpAddress2?: string;
    port: number;
    sshUser: string;
    notes: string;
    categories?: string[];
    pingEnabled?: boolean;
    ignoreHostKey?: boolean;
    sharedWithAll?: boolean;
    sharedWithUserIds?: string[];
  }): UserServer {
    const sharedWithAll = Boolean(params.sharedWithAll);
    const sharedWithUserIds = sharedWithAll
      ? []
      : this.normalizeSharedUserIds(params.userId, params.sharedWithUserIds ?? []);
    const categories = normalizeServerCategories(params.categories);
    this.ensureUserCategoriesExist(params.userId, categories);
    const server: UserServer = {
      id: crypto.randomUUID(),
      userId: params.userId,
      ownerUsername: params.ownerUsername,
      label: params.label.trim() || params.ipAddress.trim(),
      ipAddress: params.ipAddress.trim(),
      bmcIpAddress: (params.bmcIpAddress ?? '').trim(),
      bmcIpAddress2: (params.bmcIpAddress2 ?? '').trim(),
      port: Math.min(65535, Math.max(1, Number(params.port) || 22)),
      sshUser: params.sshUser.trim() || 'root',
      notes: params.notes.trim(),
      categories,
      pingEnabled: params.pingEnabled !== undefined ? Boolean(params.pingEnabled) : true,
      ignoreHostKey: Boolean(params.ignoreHostKey),
      lastOnlineAt: null,
      sharedWithAll,
      sharedWithUserIds,
      createdAt: new Date().toISOString(),
    };
    this.db.servers.push(server);
    this.save();
    return server;
  }

  updateServer(
    id: string,
    ownerUserId: string,
    patch: {
      label?: string;
      ipAddress?: string;
      bmcIpAddress?: string;
      bmcIpAddress2?: string;
      port?: number;
      sshUser?: string;
      notes?: string;
      categories?: string[];
      pingEnabled?: boolean;
      ignoreHostKey?: boolean;
    }
  ): UserServer {
    const srv = this.db.servers.find((s) => s.id === id);
    if (!srv) throw new Error('Server nicht gefunden.');
    if (srv.userId !== ownerUserId) {
      throw new Error('Sie können nur selbst angelegte Server (IPs) bearbeiten.');
    }
    if (patch.ipAddress !== undefined) {
      const nextIp = patch.ipAddress.trim();
      if (nextIp !== srv.ipAddress) {
        srv.lastOnlineAt = null;
      }
      srv.ipAddress = nextIp;
    }
    if (patch.label !== undefined) srv.label = patch.label.trim() || srv.ipAddress;
    if (patch.bmcIpAddress !== undefined) srv.bmcIpAddress = patch.bmcIpAddress.trim();
    if (patch.bmcIpAddress2 !== undefined) srv.bmcIpAddress2 = patch.bmcIpAddress2.trim();
    if (patch.port !== undefined) {
      srv.port = Math.min(65535, Math.max(1, Number(patch.port) || 22));
    }
    if (patch.sshUser !== undefined) srv.sshUser = patch.sshUser.trim() || 'root';
    if (patch.notes !== undefined) srv.notes = patch.notes.trim();
    if (patch.categories !== undefined) {
      srv.categories = normalizeServerCategories(patch.categories);
      this.ensureUserCategoriesExist(ownerUserId, srv.categories);
    }
    if (patch.pingEnabled !== undefined) srv.pingEnabled = Boolean(patch.pingEnabled);
    if (patch.ignoreHostKey !== undefined) srv.ignoreHostKey = Boolean(patch.ignoreHostKey);
    this.save();
    return srv;
  }

  recordServerLastOnline(serverId: string, isoTimestamp: string): void {
    const srv = this.db.servers.find((s) => s.id === serverId);
    if (!srv) return;
    srv.lastOnlineAt = isoTimestamp;
    this.save();
  }

  updateServerSharing(
    id: string,
    ownerUserId: string,
    sharedWithAll: boolean,
    sharedWithUserIds: string[]
  ): UserServer {
    const srv = this.db.servers.find((s) => s.id === id);
    if (!srv) throw new Error('Server nicht gefunden.');
    if (srv.userId !== ownerUserId) {
      throw new Error('Sie können nur eigene Server (IPs) teilen.');
    }
    srv.sharedWithAll = Boolean(sharedWithAll);
    srv.sharedWithUserIds = srv.sharedWithAll
      ? []
      : this.normalizeSharedUserIds(ownerUserId, sharedWithUserIds);
    this.save();
    return srv;
  }

  deleteServer(id: string, userId: string): void {
    this.db.servers = this.db.servers.filter((s) => !(s.id === id && s.userId === userId));
    this.save();
  }

  // User Certificate Bundles (zertifikat, zertifikat.pub, zertifikat-cert.pub) — creator-private; admin may share
  listAccessibleCertificates(userId: string): UserCertificateBundle[] {
    return this.db.certificates
      .filter((c) => c.userId === userId || c.sharedWithAll || c.sharedWithUserIds.includes(userId))
      .sort((a, b) => b.uploadedAt.localeCompare(a.uploadedAt));
  }

  getCertificateById(id: string): UserCertificateBundle | undefined {
    return this.db.certificates.find((c) => c.id === id);
  }

  getAccessibleCertificate(id: string, userId: string): UserCertificateBundle | undefined {
    return this.db.certificates.find(
      (c) =>
        c.id === id &&
        (c.userId === userId || c.sharedWithAll || c.sharedWithUserIds.includes(userId))
    );
  }

  createCertificate(params: {
    userId: string;
    ownerUsername: string;
    name: string;
    privateKeyFileName: string;
    publicKeyFileName: string;
    certFileName?: string;
    privateKeyContent: string;
    publicKeyContent: string;
    certContent?: string;
    passphrase?: string;
    metadata: ParsedCertMetadata;
    sharedWithAll?: boolean;
    sharedWithUserIds?: string[];
  }): { certificate: UserCertificateBundle; replaced: boolean } {
    const cleanName = params.name.trim() || params.metadata.keyId || 'SSH-Zertifikat';
    const normalizedKey = cleanName.toLowerCase();
    const now = new Date().toISOString();
    const trimmedCert = (params.certContent ?? '').trim();
    const formattedCertContent = trimmedCert ? trimmedCert + '\n' : '';
    const effectiveCertFileName = trimmedCert ? params.certFileName || 'zertifikat-cert.pub' : '';
    const nextPassphraseEncrypted =
      typeof params.passphrase === 'string' && params.passphrase.length > 0
        ? encryptSecret(params.passphrase)
        : undefined;

    const matchingIndices: number[] = [];
    this.db.certificates.forEach((c, idx) => {
      if (c.userId === params.userId && c.name.trim().toLowerCase() === normalizedKey) {
        matchingIndices.push(idx);
      }
    });

    const explicitShareAll = Boolean(params.sharedWithAll);
    const explicitShareIds = this.normalizeSharedUserIds(
      params.userId,
      params.sharedWithUserIds ?? []
    );

    if (matchingIndices.length > 0) {
      const existing = this.db.certificates[matchingIndices[0]];
      const keepExistingSharing = !explicitShareAll && explicitShareIds.length === 0;
      const nextSharedWithAll = keepExistingSharing ? existing.sharedWithAll : explicitShareAll;
      const nextSharedWithUserIds = nextSharedWithAll
        ? []
        : keepExistingSharing
          ? existing.sharedWithUserIds
          : explicitShareIds;

      const updated: UserCertificateBundle = {
        ...existing,
        ownerUsername: params.ownerUsername,
        name: cleanName,
        privateKeyFileName: params.privateKeyFileName || 'zertifikat',
        publicKeyFileName: params.publicKeyFileName || 'zertifikat.pub',
        certFileName: effectiveCertFileName,
        privateKeyEncrypted: encryptSecret(params.privateKeyContent),
        passphraseEncrypted: nextPassphraseEncrypted,
        publicKeyContent: params.publicKeyContent.trim() + '\n',
        certContent: formattedCertContent,
        metadata: params.metadata,
        sharedWithAll: nextSharedWithAll,
        sharedWithUserIds: nextSharedWithUserIds,
        uploadedAt: now,
      };

      // Replace the primary match and remove any legacy duplicates with the same label
      this.db.certificates[matchingIndices[0]] = updated;
      if (matchingIndices.length > 1) {
        const duplicateSet = new Set(matchingIndices.slice(1));
        this.db.certificates = this.db.certificates.filter((_, idx) => !duplicateSet.has(idx));
      }
      this.save();
      return { certificate: updated, replaced: true };
    }

    const sharedWithAll = explicitShareAll;
    const sharedWithUserIds = sharedWithAll ? [] : explicitShareIds;
    const bundle: UserCertificateBundle = {
      id: crypto.randomUUID(),
      userId: params.userId,
      ownerUsername: params.ownerUsername,
      name: cleanName,
      privateKeyFileName: params.privateKeyFileName || 'zertifikat',
      publicKeyFileName: params.publicKeyFileName || 'zertifikat.pub',
      certFileName: effectiveCertFileName,
      privateKeyEncrypted: encryptSecret(params.privateKeyContent),
      passphraseEncrypted: nextPassphraseEncrypted,
      publicKeyContent: params.publicKeyContent.trim() + '\n',
      certContent: formattedCertContent,
      metadata: params.metadata,
      sharedWithAll,
      sharedWithUserIds,
      uploadedAt: now,
    };
    this.db.certificates.push(bundle);
    this.save();
    return { certificate: bundle, replaced: false };
  }

  findUserCertificateByIdOrName(userId: string, idOrName: string): UserCertificateBundle | undefined {
    const clean = idOrName.trim();
    if (!clean) return undefined;
    const byId = this.db.certificates.find((c) => c.userId === userId && c.id === clean);
    if (byId) return byId;
    const lower = clean.toLowerCase();
    return this.db.certificates.find(
      (c) => c.userId === userId && c.name.trim().toLowerCase() === lower
    );
  }

  updateCertificate(
    id: string,
    ownerUserId: string,
    patch: {
      name?: string;
      privateKeyFileName?: string;
      publicKeyFileName?: string;
      certFileName?: string;
      privateKeyContent?: string;
      publicKeyContent?: string;
      certContent?: string;
      passphrase?: string;
      clearPassphrase?: boolean;
      metadata: ParsedCertMetadata;
    }
  ): UserCertificateBundle {
    const cert = this.db.certificates.find((c) => c.id === id);
    if (!cert) throw new Error('Zertifikatspaket nicht gefunden.');
    if (cert.userId !== ownerUserId) {
      throw new Error('Sie können nur selbst angelegte Zertifikatspakete bearbeiten.');
    }

    if (patch.name !== undefined) {
      const nextName = patch.name.trim();
      if (!nextName) {
        throw new Error('Die Bezeichnung darf nicht leer sein.');
      }
      const conflict = this.db.certificates.find(
        (c) =>
          c.id !== id &&
          c.userId === ownerUserId &&
          c.name.trim().toLowerCase() === nextName.toLowerCase()
      );
      if (conflict) {
        throw new Error(`Ein anderes Zertifikatspaket mit der Bezeichnung „${nextName}“ existiert bereits.`);
      }
      cert.name = nextName;
    }

    if (patch.privateKeyContent !== undefined) {
      cert.privateKeyEncrypted = encryptSecret(patch.privateKeyContent);
    }
    if (patch.clearPassphrase) {
      delete cert.passphraseEncrypted;
    } else if (typeof patch.passphrase === 'string' && patch.passphrase.length > 0) {
      cert.passphraseEncrypted = encryptSecret(patch.passphrase);
    } else if (patch.privateKeyContent !== undefined && !patch.metadata.privateKeyEncrypted) {
      delete cert.passphraseEncrypted;
    }
    if (patch.privateKeyFileName !== undefined) {
      cert.privateKeyFileName = patch.privateKeyFileName || 'zertifikat';
    }
    if (patch.publicKeyContent !== undefined) {
      cert.publicKeyContent = patch.publicKeyContent.trim() + '\n';
    }
    if (patch.publicKeyFileName !== undefined) {
      cert.publicKeyFileName = patch.publicKeyFileName || 'zertifikat.pub';
    }
    if (patch.certContent !== undefined) {
      const trimmedCert = patch.certContent.trim();
      cert.certContent = trimmedCert ? trimmedCert + '\n' : '';
      cert.certFileName = trimmedCert ? patch.certFileName || cert.certFileName || 'zertifikat-cert.pub' : '';
    } else if (patch.certFileName !== undefined && cert.certContent.trim()) {
      cert.certFileName = patch.certFileName || 'zertifikat-cert.pub';
    }

    cert.metadata = patch.metadata;
    cert.uploadedAt = new Date().toISOString();
    this.save();
    return cert;
  }

  updateCertificateSharing(
    id: string,
    ownerUserId: string,
    sharedWithAll: boolean,
    sharedWithUserIds: string[]
  ): UserCertificateBundle {
    const cert = this.db.certificates.find((c) => c.id === id);
    if (!cert) throw new Error('Zertifikatspaket nicht gefunden.');
    if (cert.userId !== ownerUserId) {
      throw new Error('Sie können nur eigene Zertifikatspakete teilen.');
    }
    cert.sharedWithAll = Boolean(sharedWithAll);
    cert.sharedWithUserIds = cert.sharedWithAll
      ? []
      : this.normalizeSharedUserIds(ownerUserId, sharedWithUserIds);
    this.save();
    return cert;
  }

  deleteCertificate(id: string, userId: string): void {
    this.db.certificates = this.db.certificates.filter((c) => !(c.id === id && c.userId === userId));
    this.save();
  }

  // Audit Execution Logs
  addLog(log: Omit<ExecutionLog, 'id' | 'executedAt'>): ExecutionLog {
    const full: ExecutionLog = {
      ...log,
      id: crypto.randomUUID(),
      executedAt: new Date().toISOString(),
    };
    this.db.logs.unshift(full);
    if (this.db.logs.length > 500) {
      this.db.logs = this.db.logs.slice(0, 500);
    }
    this.save();
    return full;
  }

  listLogs(user: StoredUser, filterUserId?: string): ExecutionLog[] {
    if (user.role === 'admin') {
      const targetUserId = filterUserId?.trim();
      return targetUserId ? this.db.logs.filter((l) => l.userId === targetUserId) : this.db.logs;
    }
    return this.db.logs.filter((l) => l.userId === user.id);
  }
}

export const store = new Store();
