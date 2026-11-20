import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { ParsedCertMetadata } from './opensshCert.ts';

export type UserRole = 'admin' | 'user';

export interface StoredUser {
  id: string;
  username: string;
  displayName: string;
  role: UserRole;
  defaultSshUser: string;
  active: boolean;
  pingEnabled: boolean;
  passwordSalt: string;
  passwordHash: string;
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
  pingEnabled: boolean;
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
}

interface DatabaseSchema {
  settings: AppSettings;
  users: StoredUser[];
  sessions: StoredSession[];
  apiKeys: StoredApiKey[];
  commands: SshCommand[];
  servers: UserServer[];
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
    },
    users: [],
    sessions: [],
    apiKeys: [],
    commands: [],
    servers: [],
    certificates: [],
    logs: [],
  };
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
        pingEnabled: typeof u.pingEnabled === 'boolean' ? u.pingEnabled : true,
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
        pingEnabled: typeof s.pingEnabled === 'boolean' ? s.pingEnabled : true,
        sharedWithAll: Boolean(s.sharedWithAll),
        sharedWithUserIds: Array.isArray(s.sharedWithUserIds) ? s.sharedWithUserIds : [],
      }));

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
      const migratedSettings: AppSettings = {
        ...emptyDb().settings,
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
      };

      return {
        ...emptyDb(),
        ...parsed,
        users,
        settings: migratedSettings,
        apiKeys: Array.isArray(parsed.apiKeys) ? parsed.apiKeys : [],
        commands: migratedCommands,
        servers: migratedServers,
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
      defaultSshUser: 'root',
      active: true,
      pingEnabled: true,
      passwordSalt: salt,
      passwordHash: hash,
      createdAt: now,
      lastLoginAt: now,
    };
    this.db.settings = {
      instanceName: params.instanceName.trim() || 'SSH Console',
      initializedAt: now,
      pingAllowed: true,
      pingIntervalSec: 60,
    };
    this.db.users.push(admin);
    this.save();
    return admin;
  }

  findUserByUsername(username: string): StoredUser | undefined {
    const normalized = username.trim().toLowerCase();
    return this.db.users.find((u) => u.username === normalized);
  }

  findUserById(id: string): StoredUser | undefined {
    return this.db.users.find((u) => u.id === id);
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
      defaultSshUser: params.defaultSshUser.trim() || 'root',
      active: true,
      pingEnabled: true,
      passwordSalt: salt,
      passwordHash: hash,
      createdAt: new Date().toISOString(),
      lastLoginAt: null,
    };
    this.db.users.push(user);
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

  createServer(params: {
    userId: string;
    ownerUsername: string;
    label: string;
    ipAddress: string;
    bmcIpAddress?: string;
    port: number;
    sshUser: string;
    notes: string;
    pingEnabled?: boolean;
    sharedWithAll?: boolean;
    sharedWithUserIds?: string[];
  }): UserServer {
    const sharedWithAll = Boolean(params.sharedWithAll);
    const sharedWithUserIds = sharedWithAll
      ? []
      : this.normalizeSharedUserIds(params.userId, params.sharedWithUserIds ?? []);
    const server: UserServer = {
      id: crypto.randomUUID(),
      userId: params.userId,
      ownerUsername: params.ownerUsername,
      label: params.label.trim() || params.ipAddress.trim(),
      ipAddress: params.ipAddress.trim(),
      bmcIpAddress: (params.bmcIpAddress ?? '').trim(),
      port: Math.min(65535, Math.max(1, Number(params.port) || 22)),
      sshUser: params.sshUser.trim() || 'root',
      notes: params.notes.trim(),
      pingEnabled: params.pingEnabled !== undefined ? Boolean(params.pingEnabled) : true,
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
      port?: number;
      sshUser?: string;
      notes?: string;
      pingEnabled?: boolean;
    }
  ): UserServer {
    const srv = this.db.servers.find((s) => s.id === id);
    if (!srv) throw new Error('Server nicht gefunden.');
    if (srv.userId !== ownerUserId) {
      throw new Error('Sie können nur selbst angelegte Server (IPs) bearbeiten.');
    }
    if (patch.ipAddress !== undefined) srv.ipAddress = patch.ipAddress.trim();
    if (patch.label !== undefined) srv.label = patch.label.trim() || srv.ipAddress;
    if (patch.bmcIpAddress !== undefined) srv.bmcIpAddress = patch.bmcIpAddress.trim();
    if (patch.port !== undefined) {
      srv.port = Math.min(65535, Math.max(1, Number(patch.port) || 22));
    }
    if (patch.sshUser !== undefined) srv.sshUser = patch.sshUser.trim() || 'root';
    if (patch.notes !== undefined) srv.notes = patch.notes.trim();
    if (patch.pingEnabled !== undefined) srv.pingEnabled = Boolean(patch.pingEnabled);
    this.save();
    return srv;
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

  listLogs(user: StoredUser): ExecutionLog[] {
    if (user.role === 'admin') {
      return this.db.logs;
    }
    return this.db.logs.filter((l) => l.userId === user.id);
  }
}

export const store = new Store();
