import fs from 'node:fs';
import path from 'node:path';
import mysql, { type Pool, type PoolConnection, type PoolOptions, type RowDataPacket } from 'mysql2/promise';
import type {
  AppSettings,
  DatabaseSchema,
  EncryptedBlob,
  ExecutionLog,
  ServerCategory,
  SshCommand,
  StoredApiKey,
  StoredCertificateAuthority,
  StoredSession,
  StoredUser,
  StoredWebAuthnCredential,
  UserCertificateBundle,
  UserGroup,
  UserServer,
} from './store.ts';

export type DatabaseEngine = 'sqlite' | 'mariadb';
export type MigrationDirection = 'sqlite-to-mariadb' | 'mariadb-to-sqlite';

export interface StoredMariaDbConfig {
  host: string;
  port: number;
  database: string;
  username: string;
  passwordEncrypted: EncryptedBlob | null;
  ssl: boolean;
  sslRejectUnauthorized: boolean;
}

export interface DatabaseConfigFile {
  engine: DatabaseEngine;
  mariadb: StoredMariaDbConfig | null;
  lastMigratedAt: string | null;
  lastMigrationDirection: MigrationDirection | null;
}

export interface MariaDbConfigInput {
  host: string;
  port?: number;
  database: string;
  username: string;
  password?: string;
  ssl?: boolean;
  sslRejectUnauthorized?: boolean;
}

export interface ResolvedMariaDbConfig {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  ssl: boolean;
  sslRejectUnauthorized: boolean;
}

export interface DatabaseTableCount {
  table: string;
  label: string;
  rows: number;
}

export interface MariaDbTestResult {
  ok: boolean;
  version: string;
  database: string;
  latencyMs: number;
  existingTables: DatabaseTableCount[];
  existingRowCount: number;
}

export const ALL_MARIADB_TABLES: Array<{ name: string; label: string }> = [
  { name: 'settings', label: 'Einstellungen' },
  { name: 'user_groups', label: 'Benutzergruppen' },
  { name: 'users', label: 'Benutzer' },
  { name: 'sessions', label: 'Sitzungen' },
  { name: 'user_api_keys', label: 'API-Schlüssel' },
  { name: 'ssh_commands', label: 'SSH-Befehle & Workflows' },
  { name: 'user_servers', label: 'Server (IPs & BMC)' },
  { name: 'user_server_categories', label: 'Server-Kategorien' },
  { name: 'user_certificates', label: 'SSH-Zertifikate' },
  { name: 'certificate_authorities', label: 'CA-Zertifikate' },
  { name: 'execution_logs', label: 'Ausführungsprotokolle' },
  { name: 'user_webauthn_credentials', label: 'Passkeys & Security Keys' },
];

const DB_NAME_RE = /^[a-zA-Z0-9_$-]{1,64}$/;
const HOST_RE = /^[a-zA-Z0-9._:\-\[\]]{1,253}$/;

export function validateMariaDbInput(
  input: Partial<MariaDbConfigInput>,
  existingPasswordEncrypted?: EncryptedBlob | null,
  requirePassword = true
): {
  host: string;
  port: number;
  database: string;
  username: string;
  passwordInput: string | null;
  ssl: boolean;
  sslRejectUnauthorized: boolean;
} {
  const host = typeof input.host === 'string' ? input.host.trim() : '';
  if (!host || !HOST_RE.test(host)) {
    throw new Error('Bitte einen gültigen MariaDB-Hostnamen oder eine IP-Adresse angeben.');
  }

  const rawPort = input.port === undefined || input.port === null ? 3306 : Number(input.port);
  if (!Number.isInteger(rawPort) || rawPort < 1 || rawPort > 65535) {
    throw new Error('Der MariaDB-Port muss zwischen 1 und 65535 liegen.');
  }

  const database = typeof input.database === 'string' ? input.database.trim() : '';
  if (!database || !DB_NAME_RE.test(database)) {
    throw new Error(
      'Ungültiger Datenbankname (erlaubt sind Buchstaben, Ziffern, Unterstrich, Bindestrich und $, max. 64 Zeichen).'
    );
  }

  const username = typeof input.username === 'string' ? input.username.trim() : '';
  if (!username || username.length > 128 || /[\r\n\0]/.test(username)) {
    throw new Error('Bitte einen gültigen MariaDB-Benutzernamen angeben.');
  }

  const passwordInput =
    typeof input.password === 'string' && input.password.length > 0 ? input.password : null;

  if (requirePassword && !passwordInput && !existingPasswordEncrypted) {
    throw new Error('Bitte das Passwort für den MariaDB-Benutzer angeben.');
  }

  return {
    host,
    port: rawPort,
    database,
    username,
    passwordInput,
    ssl: Boolean(input.ssl),
    sslRejectUnauthorized:
      typeof input.sslRejectUnauthorized === 'boolean' ? input.sslRejectUnauthorized : true,
  };
}

export function getDbConfigPath(dataDir: string): string {
  return path.join(dataDir, 'db-config.json');
}

export function loadDatabaseConfigFile(dataDir: string): DatabaseConfigFile {
  const cfgPath = getDbConfigPath(dataDir);
  if (!fs.existsSync(cfgPath)) {
    return {
      engine: 'sqlite',
      mariadb: null,
      lastMigratedAt: null,
      lastMigrationDirection: null,
    };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(cfgPath, 'utf8')) as Partial<DatabaseConfigFile>;
    const engine: DatabaseEngine = parsed.engine === 'mariadb' && parsed.mariadb ? 'mariadb' : 'sqlite';
    const mariadb: StoredMariaDbConfig | null =
      parsed.mariadb && typeof parsed.mariadb === 'object'
        ? {
            host: typeof parsed.mariadb.host === 'string' ? parsed.mariadb.host : '',
            port: Number.isInteger(parsed.mariadb.port) ? parsed.mariadb.port : 3306,
            database: typeof parsed.mariadb.database === 'string' ? parsed.mariadb.database : '',
            username: typeof parsed.mariadb.username === 'string' ? parsed.mariadb.username : '',
            passwordEncrypted: parsed.mariadb.passwordEncrypted ?? null,
            ssl: Boolean(parsed.mariadb.ssl),
            sslRejectUnauthorized:
              typeof parsed.mariadb.sslRejectUnauthorized === 'boolean'
                ? parsed.mariadb.sslRejectUnauthorized
                : true,
          }
        : null;
    return {
      engine: engine === 'mariadb' && mariadb && mariadb.host && mariadb.database ? 'mariadb' : 'sqlite',
      mariadb,
      lastMigratedAt: typeof parsed.lastMigratedAt === 'string' ? parsed.lastMigratedAt : null,
      lastMigrationDirection:
        parsed.lastMigrationDirection === 'sqlite-to-mariadb' ||
        parsed.lastMigrationDirection === 'mariadb-to-sqlite'
          ? parsed.lastMigrationDirection
          : null,
    };
  } catch {
    return {
      engine: 'sqlite',
      mariadb: null,
      lastMigratedAt: null,
      lastMigrationDirection: null,
    };
  }
}

export function saveDatabaseConfigFile(dataDir: string, cfg: DatabaseConfigFile): void {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  }
  const cfgPath = getDbConfigPath(dataDir);
  const tmp = `${cfgPath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, cfgPath);
}

export function createMariaDbPool(cfg: ResolvedMariaDbConfig): Pool {
  const opts: PoolOptions = {
    host: cfg.host,
    port: cfg.port,
    user: cfg.username,
    password: cfg.password,
    database: cfg.database,
    charset: 'utf8mb4',
    connectionLimit: 5,
    waitForConnections: true,
    connectTimeout: 8000,
    enableKeepAlive: true,
  };
  if (cfg.ssl) {
    opts.ssl = {
      rejectUnauthorized: cfg.sslRejectUnauthorized,
    };
  }
  return mysql.createPool(opts);
}

const MARIADB_SCHEMA_STATEMENTS: string[] = [
  `CREATE TABLE IF NOT EXISTS \`settings\` (
    \`key\` VARCHAR(191) NOT NULL PRIMARY KEY,
    \`value\` LONGTEXT NOT NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`user_groups\` (
    \`id\` VARCHAR(191) NOT NULL PRIMARY KEY,
    \`name\` VARCHAR(191) NOT NULL,
    \`description\` TEXT NOT NULL,
    \`is_system\` TINYINT(1) NOT NULL DEFAULT 0,
    \`is_immutable\` TINYINT(1) NOT NULL DEFAULT 0,
    \`is_admin\` TINYINT(1) NOT NULL DEFAULT 0,
    \`permissions_json\` LONGTEXT NOT NULL,
    \`created_at\` VARCHAR(64) NOT NULL,
    \`updated_at\` VARCHAR(64) NOT NULL,
    UNIQUE KEY \`uq_user_groups_name\` (\`name\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`users\` (
    \`id\` VARCHAR(191) NOT NULL PRIMARY KEY,
    \`username\` VARCHAR(191) NOT NULL,
    \`display_name\` VARCHAR(255) NOT NULL,
    \`role\` VARCHAR(32) NOT NULL,
    \`group_id\` VARCHAR(191) NOT NULL DEFAULT 'user',
    \`default_ssh_user\` VARCHAR(128) NOT NULL DEFAULT 'root',
    \`active\` TINYINT(1) NOT NULL DEFAULT 1,
    \`ping_enabled\` TINYINT(1) NOT NULL DEFAULT 1,
    \`password_hash\` TEXT NOT NULL,
    \`created_at\` VARCHAR(64) NOT NULL,
    \`last_login_at\` VARCHAR(64) NULL,
    \`auth_provider\` VARCHAR(32) NOT NULL DEFAULT 'local',
    \`sso_subject\` VARCHAR(255) NULL,
    \`email\` VARCHAR(255) NOT NULL DEFAULT '',
    \`totp_enabled\` TINYINT(1) NOT NULL DEFAULT 0,
    \`totp_secret_enc\` LONGBLOB NULL,
    \`totp_secret_nonce\` VARBINARY(64) NULL,
    \`totp_recovery_hashes_json\` LONGTEXT NOT NULL,
    UNIQUE KEY \`uq_users_username\` (\`username\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`sessions\` (
    \`token\` VARCHAR(191) NOT NULL PRIMARY KEY,
    \`user_id\` VARCHAR(191) NOT NULL,
    \`created_at\` VARCHAR(64) NOT NULL,
    \`expires_at\` VARCHAR(64) NOT NULL,
    KEY \`idx_sessions_user_id\` (\`user_id\`),
    KEY \`idx_sessions_expires_at\` (\`expires_at\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`user_api_keys\` (
    \`id\` VARCHAR(191) NOT NULL PRIMARY KEY,
    \`user_id\` VARCHAR(191) NOT NULL,
    \`name\` VARCHAR(255) NOT NULL,
    \`key_prefix\` VARCHAR(64) NOT NULL,
    \`key_hash\` VARCHAR(191) NOT NULL,
    \`created_at\` VARCHAR(64) NOT NULL,
    \`last_used_at\` VARCHAR(64) NULL,
    UNIQUE KEY \`uq_user_api_keys_hash\` (\`key_hash\`),
    KEY \`idx_api_keys_user_id\` (\`user_id\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`ssh_commands\` (
    \`id\` VARCHAR(191) NOT NULL PRIMARY KEY,
    \`user_id\` VARCHAR(191) NOT NULL DEFAULT '',
    \`name\` VARCHAR(255) NOT NULL,
    \`category\` VARCHAR(191) NOT NULL,
    \`kind\` VARCHAR(32) NOT NULL DEFAULT 'single',
    \`command\` LONGTEXT NOT NULL,
    \`steps_json\` LONGTEXT NOT NULL,
    \`workflow_json\` LONGTEXT NOT NULL,
    \`stop_on_error\` TINYINT(1) NOT NULL DEFAULT 1,
    \`description\` TEXT NOT NULL,
    \`timeout_sec\` INT NOT NULL DEFAULT 30,
    \`enabled\` TINYINT(1) NOT NULL DEFAULT 1,
    \`created_by\` VARCHAR(191) NOT NULL,
    \`shared_with_all\` TINYINT(1) NOT NULL DEFAULT 0,
    \`shared_with_user_ids\` LONGTEXT NOT NULL,
    \`created_at\` VARCHAR(64) NOT NULL,
    \`updated_at\` VARCHAR(64) NOT NULL DEFAULT '',
    KEY \`idx_commands_user_id\` (\`user_id\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`user_servers\` (
    \`id\` VARCHAR(191) NOT NULL PRIMARY KEY,
    \`user_id\` VARCHAR(191) NOT NULL,
    \`owner_username\` VARCHAR(191) NOT NULL DEFAULT '',
    \`label\` VARCHAR(255) NOT NULL,
    \`ip_address\` VARCHAR(255) NOT NULL,
    \`bmc_ip_address\` VARCHAR(255) NOT NULL DEFAULT '',
    \`bmc_ip_address2\` VARCHAR(255) NOT NULL DEFAULT '',
    \`port\` INT NOT NULL DEFAULT 22,
    \`ssh_user\` VARCHAR(128) NOT NULL DEFAULT 'root',
    \`notes\` LONGTEXT NOT NULL,
    \`ping_enabled\` TINYINT(1) NOT NULL DEFAULT 1,
    \`ignore_host_key\` TINYINT(1) NOT NULL DEFAULT 0,
    \`categories_json\` LONGTEXT NOT NULL,
    \`last_online_at\` VARCHAR(64) NULL,
    \`shared_with_all\` TINYINT(1) NOT NULL DEFAULT 0,
    \`shared_with_user_ids\` LONGTEXT NOT NULL,
    \`created_at\` VARCHAR(64) NOT NULL,
    KEY \`idx_servers_user_id\` (\`user_id\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`user_server_categories\` (
    \`id\` VARCHAR(191) NOT NULL PRIMARY KEY,
    \`user_id\` VARCHAR(191) NOT NULL,
    \`name\` VARCHAR(191) NOT NULL,
    \`created_at\` VARCHAR(64) NOT NULL,
    KEY \`idx_server_categories_user_id\` (\`user_id\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`user_certificates\` (
    \`id\` VARCHAR(191) NOT NULL PRIMARY KEY,
    \`user_id\` VARCHAR(191) NOT NULL,
    \`owner_username\` VARCHAR(191) NOT NULL DEFAULT '',
    \`name\` VARCHAR(255) NOT NULL,
    \`private_key_file\` VARCHAR(255) NOT NULL,
    \`public_key_file\` VARCHAR(255) NOT NULL,
    \`cert_file\` VARCHAR(255) NOT NULL,
    \`private_key_enc\` LONGBLOB NOT NULL,
    \`private_key_nonce\` VARBINARY(64) NOT NULL,
    \`passphrase_enc\` LONGBLOB NULL,
    \`passphrase_nonce\` VARBINARY(64) NULL,
    \`public_key\` LONGTEXT NOT NULL,
    \`certificate\` LONGTEXT NOT NULL,
    \`inspection_json\` LONGTEXT NOT NULL,
    \`auto_renew_json\` LONGTEXT NULL,
    \`shared_with_all\` TINYINT(1) NOT NULL DEFAULT 0,
    \`shared_with_user_ids\` LONGTEXT NOT NULL,
    \`uploaded_at\` VARCHAR(64) NOT NULL,
    KEY \`idx_certs_user_id\` (\`user_id\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`certificate_authorities\` (
    \`id\` VARCHAR(191) NOT NULL PRIMARY KEY,
    \`name\` VARCHAR(255) NOT NULL,
    \`description\` TEXT NOT NULL,
    \`private_key_file\` VARCHAR(255) NOT NULL DEFAULT 'ca',
    \`public_key_file\` VARCHAR(255) NOT NULL DEFAULT 'ca.pub',
    \`private_key_enc\` LONGBLOB NOT NULL,
    \`private_key_nonce\` VARBINARY(64) NOT NULL,
    \`passphrase_enc\` LONGBLOB NULL,
    \`passphrase_nonce\` VARBINARY(64) NULL,
    \`public_key\` LONGTEXT NOT NULL,
    \`key_type\` VARCHAR(64) NOT NULL DEFAULT 'ssh-ed25519',
    \`fingerprint\` VARCHAR(255) NOT NULL DEFAULT '',
    \`private_key_format\` VARCHAR(64) NOT NULL DEFAULT 'openssh-v1',
    \`private_key_encrypted\` TINYINT(1) NOT NULL DEFAULT 1,
    \`created_by\` VARCHAR(191) NOT NULL DEFAULT '',
    \`created_by_username\` VARCHAR(191) NOT NULL DEFAULT '',
    \`created_at\` VARCHAR(64) NOT NULL,
    \`updated_at\` VARCHAR(64) NOT NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`execution_logs\` (
    \`id\` VARCHAR(191) NOT NULL PRIMARY KEY,
    \`user_id\` VARCHAR(191) NOT NULL,
    \`username\` VARCHAR(191) NOT NULL,
    \`command_id\` VARCHAR(191) NOT NULL DEFAULT '',
    \`command_name\` VARCHAR(255) NOT NULL,
    \`command_text\` LONGTEXT NOT NULL,
    \`target_ip\` VARCHAR(255) NOT NULL,
    \`target_port\` INT NOT NULL,
    \`ssh_user\` VARCHAR(128) NOT NULL,
    \`server_label\` VARCHAR(255) NOT NULL DEFAULT '',
    \`certificate_id\` VARCHAR(191) NOT NULL DEFAULT '',
    \`certificate_key_id\` VARCHAR(255) NOT NULL,
    \`mode\` VARCHAR(64) NOT NULL DEFAULT 'openssh-live',
    \`ssh_invocation\` LONGTEXT NOT NULL,
    \`exit_code\` INT NOT NULL,
    \`stdout\` LONGTEXT NOT NULL,
    \`stderr\` LONGTEXT NOT NULL,
    \`duration_ms\` BIGINT NOT NULL,
    \`executed_at\` VARCHAR(64) NOT NULL,
    KEY \`idx_logs_user_executed\` (\`user_id\`, \`executed_at\`),
    KEY \`idx_logs_executed_at\` (\`executed_at\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

  `CREATE TABLE IF NOT EXISTS \`user_webauthn_credentials\` (
    \`id\` VARCHAR(191) NOT NULL PRIMARY KEY,
    \`user_id\` VARCHAR(191) NOT NULL,
    \`kind\` VARCHAR(32) NOT NULL,
    \`name\` VARCHAR(255) NOT NULL,
    \`credential_id\` VARCHAR(512) NOT NULL,
    \`public_key\` LONGTEXT NOT NULL,
    \`counter\` BIGINT NOT NULL DEFAULT 0,
    \`transports_json\` TEXT NOT NULL,
    \`created_at\` VARCHAR(64) NOT NULL,
    \`last_used_at\` VARCHAR(64) NULL,
    KEY \`idx_webauthn_user_id\` (\`user_id\`)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
];

export async function ensureMariaDbSchema(conn: PoolConnection): Promise<void> {
  for (const ddl of MARIADB_SCHEMA_STATEMENTS) {
    await conn.query(ddl);
  }
}

export async function inspectMariaDbExistingTables(conn: PoolConnection): Promise<{
  existingTables: DatabaseTableCount[];
  existingRowCount: number;
}> {
  const [tableRows] = await conn.query<RowDataPacket[]>(
    `SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()`
  );
  const existingSet = new Set(
    tableRows.map((r) => String(r.TABLE_NAME ?? r.table_name ?? '').toLowerCase())
  );

  const existingTables: DatabaseTableCount[] = [];
  let existingRowCount = 0;

  for (const t of ALL_MARIADB_TABLES) {
    if (!existingSet.has(t.name)) continue;
    const [cntRows] = await conn.query<RowDataPacket[]>(
      `SELECT COUNT(*) AS cnt FROM \`${t.name}\``
    );
    const rows = Number(cntRows[0]?.cnt ?? 0);
    existingTables.push({ table: t.name, label: t.label, rows });
    existingRowCount += rows;
  }

  return { existingTables, existingRowCount };
}

export async function testMariaDbConnection(cfg: ResolvedMariaDbConfig): Promise<MariaDbTestResult> {
  const started = Date.now();
  const pool = createMariaDbPool(cfg);
  try {
    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.query<RowDataPacket[]>(
        `SELECT VERSION() AS version, DATABASE() AS db_name`
      );
      const version = String(rows[0]?.version ?? 'MariaDB');
      const database = String(rows[0]?.db_name ?? cfg.database);
      const { existingTables, existingRowCount } = await inspectMariaDbExistingTables(conn);
      return {
        ok: true,
        version,
        database,
        latencyMs: Math.max(1, Date.now() - started),
        existingTables,
        existingRowCount,
      };
    } finally {
      conn.release();
    }
  } finally {
    await pool.end().catch(() => {});
  }
}

function encodeNodeBlob(blob: EncryptedBlob | null | undefined): { enc: Buffer | null; nonce: Buffer | null } {
  if (!blob) return { enc: null, nonce: null };
  return {
    enc: Buffer.from(JSON.stringify(blob), 'utf8'),
    nonce: Buffer.from('node-aes-256-gcm', 'utf8'),
  };
}

function decodeNodeBlob(enc: unknown): EncryptedBlob | null {
  if (!enc) return null;
  const str = Buffer.isBuffer(enc) ? enc.toString('utf8') : String(enc);
  if (!str) return null;
  try {
    const parsed = JSON.parse(str) as Partial<EncryptedBlob>;
    if (
      typeof parsed.iv === 'string' &&
      typeof parsed.tag === 'string' &&
      typeof parsed.ciphertext === 'string'
    ) {
      return { iv: parsed.iv, tag: parsed.tag, ciphertext: parsed.ciphertext };
    }
  } catch {
    // ignore non-node blob
  }
  return null;
}

function serializeSettingsRows(settings: AppSettings): Array<[string, string]> {
  const rows: Array<[string, string]> = [
    ['instance_name', settings.instanceName],
    ['initialized_at', settings.initializedAt ?? ''],
    ['ping_allowed', settings.pingAllowed ? '1' : '0'],
    ['ping_interval_sec', String(settings.pingIntervalSec)],
    ['ping_offline_threshold', String(settings.pingOfflineThreshold)],
    ['ping_offline_multiplier', String(settings.pingOfflineMultiplier)],
    ['sso_enabled', settings.ssoEnabled ? '1' : '0'],
    ['sso_provider_name', settings.ssoProviderName],
    ['sso_issuer_url', settings.ssoIssuerUrl],
    ['sso_auth_url', settings.ssoAuthUrl],
    ['sso_token_url', settings.ssoTokenUrl],
    ['sso_userinfo_url', settings.ssoUserinfoUrl],
    ['sso_client_id', settings.ssoClientId],
    ['sso_scopes', settings.ssoScopes],
    ['sso_auto_create_users', settings.ssoAutoCreateUsers ? '1' : '0'],
    ['sso_tested_at', settings.ssoTestedAt ?? ''],
    ['local_login_disabled', settings.localLoginDisabled ? '1' : '0'],
    ['two_factor_enabled', settings.twoFactorEnabled ? '1' : '0'],
    ['two_factor_enforced', settings.twoFactorEnforced ? '1' : '0'],
    ['passkey_enabled', settings.passkeyEnabled ? '1' : '0'],
    ['passkey_enforced', settings.passkeyEnforced ? '1' : '0'],
    ['allow_insecure_host_key', settings.allowInsecureHostKey ? '1' : '0'],
    ['public_url', settings.publicUrl],
    ['max_background_jobs', String(settings.maxBackgroundJobs)],
  ];
  if (settings.ssoClientSecretEncrypted) {
    rows.push(['node_sso_client_secret_json', JSON.stringify(settings.ssoClientSecretEncrypted)]);
  }
  return rows;
}

function deserializeSettingsRows(rows: RowDataPacket[], defaults: AppSettings): AppSettings {
  const map = new Map<string, string>();
  for (const r of rows) {
    map.set(String(r.key), String(r.value ?? ''));
  }
  const boolVal = (k: string, def: boolean) => {
    const v = map.get(k);
    if (v === undefined) return def;
    return v === '1' || v.toLowerCase() === 'true';
  };
  const intVal = (k: string, def: number) => {
    const v = Number(map.get(k));
    return Number.isFinite(v) ? v : def;
  };

  let ssoClientSecretEncrypted: EncryptedBlob | null = null;
  const rawSecret = map.get('node_sso_client_secret_json');
  if (rawSecret) {
    ssoClientSecretEncrypted = decodeNodeBlob(rawSecret);
  }

  return {
    instanceName: map.get('instance_name') || defaults.instanceName,
    initializedAt: map.get('initialized_at') || null,
    pingAllowed: boolVal('ping_allowed', defaults.pingAllowed),
    pingIntervalSec: intVal('ping_interval_sec', defaults.pingIntervalSec),
    pingOfflineThreshold: intVal('ping_offline_threshold', defaults.pingOfflineThreshold),
    pingOfflineMultiplier: intVal('ping_offline_multiplier', defaults.pingOfflineMultiplier),
    ssoEnabled: boolVal('sso_enabled', defaults.ssoEnabled),
    ssoProviderName: map.get('sso_provider_name') || defaults.ssoProviderName,
    ssoIssuerUrl: map.get('sso_issuer_url') || '',
    ssoAuthUrl: map.get('sso_auth_url') || '',
    ssoTokenUrl: map.get('sso_token_url') || '',
    ssoUserinfoUrl: map.get('sso_userinfo_url') || '',
    ssoClientId: map.get('sso_client_id') || '',
    ssoClientSecretEncrypted,
    ssoScopes: map.get('sso_scopes') || defaults.ssoScopes,
    ssoAutoCreateUsers: boolVal('sso_auto_create_users', defaults.ssoAutoCreateUsers),
    ssoTestedAt: map.get('sso_tested_at') || null,
    localLoginDisabled: boolVal('local_login_disabled', defaults.localLoginDisabled),
    twoFactorEnabled: boolVal('two_factor_enabled', defaults.twoFactorEnabled),
    twoFactorEnforced: boolVal('two_factor_enforced', defaults.twoFactorEnforced),
    passkeyEnabled: boolVal('passkey_enabled', defaults.passkeyEnabled),
    passkeyEnforced: boolVal('passkey_enforced', defaults.passkeyEnforced),
    allowInsecureHostKey: boolVal('allow_insecure_host_key', defaults.allowInsecureHostKey),
    publicUrl: map.get('public_url') || '',
    maxBackgroundJobs: intVal('max_background_jobs', defaults.maxBackgroundJobs),
  };
}

type SqlValue = string | number | boolean | Buffer | null;

async function batchInsertRows(
  conn: PoolConnection,
  table: string,
  columns: string[],
  rows: SqlValue[][]
): Promise<void> {
  if (rows.length === 0) return;
  const colList = columns.map((c) => `\`${c}\``).join(', ');
  const singleRowPlaceholder = `(${columns.map(() => '?').join(', ')})`;
  const chunkSize = 25;

  for (let i = 0; i < rows.length; i += chunkSize) {
    const chunk = rows.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => singleRowPlaceholder).join(', ');
    const flatParams: SqlValue[] = [];
    for (const r of chunk) {
      flatParams.push(...r);
    }
    await conn.execute(`INSERT INTO \`${table}\` (${colList}) VALUES ${placeholders}`, flatParams);
  }
}

export function countSchemaTables(schema: DatabaseSchema): DatabaseTableCount[] {
  const settingsRows = serializeSettingsRows(schema.settings);
  const counts: Record<string, number> = {
    settings: settingsRows.length,
    user_groups: schema.groups.length,
    users: schema.users.length,
    sessions: schema.sessions.length,
    user_api_keys: schema.apiKeys.length,
    ssh_commands: schema.commands.length,
    user_servers: schema.servers.length,
    user_server_categories: schema.serverCategories.length,
    user_certificates: schema.certificates.length,
    certificate_authorities: schema.certificateAuthorities.length,
    execution_logs: schema.logs.length,
    user_webauthn_credentials: schema.webauthnCredentials.length,
  };
  return ALL_MARIADB_TABLES.map((t) => ({
    table: t.name,
    label: t.label,
    rows: counts[t.name] ?? 0,
  }));
}

export async function writeSchemaToMariaDb(
  pool: Pool,
  schema: DatabaseSchema
): Promise<DatabaseTableCount[]> {
  const conn = await pool.getConnection();
  try {
    await ensureMariaDbSchema(conn);
    await conn.beginTransaction();
    try {
      await conn.query('SET FOREIGN_KEY_CHECKS = 0');
      for (const t of ALL_MARIADB_TABLES) {
        await conn.query(`DELETE FROM \`${t.name}\``);
      }

      const settingsRows = serializeSettingsRows(schema.settings);
      await batchInsertRows(conn, 'settings', ['key', 'value'], settingsRows);

      await batchInsertRows(
        conn,
        'user_groups',
        [
          'id',
          'name',
          'description',
          'is_system',
          'is_immutable',
          'is_admin',
          'permissions_json',
          'created_at',
          'updated_at',
        ],
        schema.groups.map((g) => [
          g.id,
          g.name,
          g.description,
          g.isSystem ? 1 : 0,
          g.isImmutable ? 1 : 0,
          g.isAdmin ? 1 : 0,
          JSON.stringify(g.permissions),
          g.createdAt,
          g.updatedAt,
        ])
      );

      await batchInsertRows(
        conn,
        'users',
        [
          'id',
          'username',
          'display_name',
          'role',
          'group_id',
          'default_ssh_user',
          'active',
          'ping_enabled',
          'password_hash',
          'created_at',
          'last_login_at',
          'auth_provider',
          'sso_subject',
          'email',
          'totp_enabled',
          'totp_secret_enc',
          'totp_secret_nonce',
          'totp_recovery_hashes_json',
        ],
        schema.users.map((u) => {
          const totp = encodeNodeBlob(u.totpSecretEncrypted);
          return [
            u.id,
            u.username,
            u.displayName,
            u.role,
            u.groupId,
            u.defaultSshUser,
            u.active ? 1 : 0,
            u.pingEnabled ? 1 : 0,
            `scrypt:${u.passwordSalt}:${u.passwordHash}`,
            u.createdAt,
            u.lastLoginAt,
            u.authProvider,
            u.ssoSubject,
            u.email,
            u.totpEnabled ? 1 : 0,
            totp.enc,
            totp.nonce,
            JSON.stringify(u.totpRecoveryHashes ?? []),
          ];
        })
      );

      await batchInsertRows(
        conn,
        'sessions',
        ['token', 'user_id', 'created_at', 'expires_at'],
        schema.sessions.map((s) => [s.token, s.userId, s.createdAt, s.expiresAt])
      );

      await batchInsertRows(
        conn,
        'user_api_keys',
        ['id', 'user_id', 'name', 'key_prefix', 'key_hash', 'created_at', 'last_used_at'],
        schema.apiKeys.map((k) => [
          k.id,
          k.userId,
          k.name,
          k.keyPrefix,
          k.keyHash,
          k.createdAt,
          k.lastUsedAt,
        ])
      );

      await batchInsertRows(
        conn,
        'ssh_commands',
        [
          'id',
          'user_id',
          'name',
          'category',
          'kind',
          'command',
          'steps_json',
          'workflow_json',
          'stop_on_error',
          'description',
          'timeout_sec',
          'enabled',
          'created_by',
          'shared_with_all',
          'shared_with_user_ids',
          'created_at',
          'updated_at',
        ],
        schema.commands.map((c) => [
          c.id,
          c.userId,
          c.name,
          c.category,
          c.kind,
          c.command,
          JSON.stringify(c.steps ?? []),
          c.workflowJson ?? '',
          c.stopOnError ? 1 : 0,
          c.description,
          c.timeoutSec,
          c.enabled ? 1 : 0,
          c.createdBy,
          c.sharedWithAll ? 1 : 0,
          JSON.stringify(c.sharedWithUserIds ?? []),
          c.createdAt,
          c.updatedAt,
        ])
      );

      await batchInsertRows(
        conn,
        'user_servers',
        [
          'id',
          'user_id',
          'owner_username',
          'label',
          'ip_address',
          'bmc_ip_address',
          'bmc_ip_address2',
          'port',
          'ssh_user',
          'notes',
          'ping_enabled',
          'ignore_host_key',
          'categories_json',
          'last_online_at',
          'shared_with_all',
          'shared_with_user_ids',
          'created_at',
        ],
        schema.servers.map((s) => [
          s.id,
          s.userId,
          s.ownerUsername,
          s.label,
          s.ipAddress,
          s.bmcIpAddress,
          s.bmcIpAddress2,
          s.port,
          s.sshUser,
          s.notes,
          s.pingEnabled ? 1 : 0,
          s.ignoreHostKey ? 1 : 0,
          JSON.stringify(s.categories ?? []),
          s.lastOnlineAt ?? null,
          s.sharedWithAll ? 1 : 0,
          JSON.stringify(s.sharedWithUserIds ?? []),
          s.createdAt,
        ])
      );

      await batchInsertRows(
        conn,
        'user_server_categories',
        ['id', 'user_id', 'name', 'created_at'],
        schema.serverCategories.map((c) => [c.id, c.userId, c.name, c.createdAt])
      );

      await batchInsertRows(
        conn,
        'user_certificates',
        [
          'id',
          'user_id',
          'owner_username',
          'name',
          'private_key_file',
          'public_key_file',
          'cert_file',
          'private_key_enc',
          'private_key_nonce',
          'passphrase_enc',
          'passphrase_nonce',
          'public_key',
          'certificate',
          'inspection_json',
          'auto_renew_json',
          'shared_with_all',
          'shared_with_user_ids',
          'uploaded_at',
        ],
        schema.certificates.map((cert) => {
          const priv = encodeNodeBlob(cert.privateKeyEncrypted);
          const pass = encodeNodeBlob(cert.passphraseEncrypted ?? null);
          return [
            cert.id,
            cert.userId,
            cert.ownerUsername,
            cert.name,
            cert.privateKeyFileName,
            cert.publicKeyFileName,
            cert.certFileName,
            priv.enc ?? Buffer.alloc(0),
            priv.nonce ?? Buffer.from('node-aes-256-gcm', 'utf8'),
            pass.enc,
            pass.nonce,
            cert.publicKeyContent,
            cert.certContent,
            JSON.stringify(cert.metadata),
            cert.autoRenew ? JSON.stringify(cert.autoRenew) : null,
            cert.sharedWithAll ? 1 : 0,
            JSON.stringify(cert.sharedWithUserIds ?? []),
            cert.uploadedAt,
          ];
        })
      );

      await batchInsertRows(
        conn,
        'certificate_authorities',
        [
          'id',
          'name',
          'description',
          'private_key_file',
          'public_key_file',
          'private_key_enc',
          'private_key_nonce',
          'passphrase_enc',
          'passphrase_nonce',
          'public_key',
          'key_type',
          'fingerprint',
          'private_key_format',
          'private_key_encrypted',
          'created_by',
          'created_by_username',
          'created_at',
          'updated_at',
        ],
        schema.certificateAuthorities.map((ca) => {
          const priv = encodeNodeBlob(ca.privateKeyEncrypted);
          const pass = encodeNodeBlob(ca.passphraseEncrypted ?? null);
          return [
            ca.id,
            ca.name,
            ca.description,
            ca.privateKeyFileName,
            ca.publicKeyFileName,
            priv.enc ?? Buffer.alloc(0),
            priv.nonce ?? Buffer.from('node-aes-256-gcm', 'utf8'),
            pass.enc,
            pass.nonce,
            ca.publicKey,
            ca.keyType,
            ca.fingerprint,
            ca.privateKeyFormat,
            ca.privateKeyIsEncrypted ? 1 : 0,
            ca.createdBy,
            ca.createdByUsername,
            ca.createdAt,
            ca.updatedAt,
          ];
        })
      );

      await batchInsertRows(
        conn,
        'execution_logs',
        [
          'id',
          'user_id',
          'username',
          'command_id',
          'command_name',
          'command_text',
          'target_ip',
          'target_port',
          'ssh_user',
          'server_label',
          'certificate_id',
          'certificate_key_id',
          'mode',
          'ssh_invocation',
          'exit_code',
          'stdout',
          'stderr',
          'duration_ms',
          'executed_at',
        ],
        schema.logs.map((l) => [
          l.id,
          l.userId,
          l.username,
          l.commandId,
          l.commandName,
          l.commandText,
          l.targetIp,
          l.targetPort,
          l.sshUser,
          l.serverLabel,
          l.certificateId,
          l.certificateKeyId,
          l.mode,
          l.sshInvocation,
          l.exitCode,
          l.stdout,
          l.stderr,
          l.durationMs,
          l.executedAt,
        ])
      );

      await batchInsertRows(
        conn,
        'user_webauthn_credentials',
        [
          'id',
          'user_id',
          'kind',
          'name',
          'credential_id',
          'public_key',
          'counter',
          'transports_json',
          'created_at',
          'last_used_at',
        ],
        schema.webauthnCredentials.map((w) => [
          w.id,
          w.userId,
          w.kind,
          w.name,
          w.credentialId,
          w.publicKey,
          w.counter,
          JSON.stringify(w.transports ?? []),
          w.createdAt,
          w.lastUsedAt,
        ])
      );

      await conn.query('SET FOREIGN_KEY_CHECKS = 1');
      await conn.commit();
    } catch (err) {
      await conn.rollback().catch(() => {});
      throw err;
    }

    const { existingTables } = await inspectMariaDbExistingTables(conn);
    return existingTables;
  } finally {
    conn.release();
  }
}

function safeJsonParse<T>(raw: unknown, fallback: T): T {
  if (typeof raw !== 'string' || !raw.trim()) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export async function readSchemaFromMariaDb(
  pool: Pool,
  defaultSettings: AppSettings
): Promise<{ schema: DatabaseSchema; counts: DatabaseTableCount[] }> {
  const conn = await pool.getConnection();
  try {
    await ensureMariaDbSchema(conn);

    const [settingsRows] = await conn.query<RowDataPacket[]>('SELECT `key`, `value` FROM `settings`');
    const [groupRows] = await conn.query<RowDataPacket[]>('SELECT * FROM `user_groups`');
    const [userRows] = await conn.query<RowDataPacket[]>('SELECT * FROM `users`');
    const [sessionRows] = await conn.query<RowDataPacket[]>('SELECT * FROM `sessions`');
    const [apiKeyRows] = await conn.query<RowDataPacket[]>('SELECT * FROM `user_api_keys`');
    const [cmdRows] = await conn.query<RowDataPacket[]>('SELECT * FROM `ssh_commands`');
    const [srvRows] = await conn.query<RowDataPacket[]>('SELECT * FROM `user_servers`');
    const [catRows] = await conn.query<RowDataPacket[]>('SELECT * FROM `user_server_categories`');
    const [certRows] = await conn.query<RowDataPacket[]>('SELECT * FROM `user_certificates`');
    const [caRows] = await conn.query<RowDataPacket[]>('SELECT * FROM `certificate_authorities`');
    const [logRows] = await conn.query<RowDataPacket[]>(
      'SELECT * FROM `execution_logs` ORDER BY `executed_at` DESC'
    );
    const [webauthnRows] = await conn.query<RowDataPacket[]>(
      'SELECT * FROM `user_webauthn_credentials`'
    );

    const settings = deserializeSettingsRows(settingsRows, defaultSettings);

    const groups: UserGroup[] = groupRows.map((r) => ({
      id: String(r.id),
      name: String(r.name),
      description: String(r.description ?? ''),
      isSystem: Boolean(r.is_system),
      isImmutable: Boolean(r.is_immutable),
      isAdmin: Boolean(r.is_admin),
      permissions: safeJsonParse(r.permissions_json, {} as UserGroup['permissions']),
      createdAt: String(r.created_at),
      updatedAt: String(r.updated_at),
    }));

    const users: StoredUser[] = userRows.map((r) => {
      const rawHash = String(r.password_hash ?? '');
      let passwordSalt = '';
      let passwordHash = rawHash;
      if (rawHash.startsWith('scrypt:')) {
        const parts = rawHash.split(':');
        passwordSalt = parts[1] ?? '';
        passwordHash = parts[2] ?? '';
      }
      return {
        id: String(r.id),
        username: String(r.username),
        displayName: String(r.display_name),
        role: r.role === 'admin' ? 'admin' : 'user',
        groupId: String(r.group_id || (r.role === 'admin' ? 'admin' : 'user')),
        authProvider: r.auth_provider === 'sso' ? 'sso' : 'local',
        ssoSubject: r.sso_subject ? String(r.sso_subject) : null,
        email: String(r.email ?? ''),
        defaultSshUser: String(r.default_ssh_user || 'root'),
        active: Boolean(r.active),
        pingEnabled: Boolean(r.ping_enabled),
        passwordSalt,
        passwordHash,
        totpEnabled: Boolean(r.totp_enabled),
        totpSecretEncrypted: decodeNodeBlob(r.totp_secret_enc),
        totpRecoveryHashes: safeJsonParse<string[]>(r.totp_recovery_hashes_json, []),
        createdAt: String(r.created_at),
        lastLoginAt: r.last_login_at ? String(r.last_login_at) : null,
      };
    });

    const sessions: StoredSession[] = sessionRows.map((r) => ({
      token: String(r.token),
      userId: String(r.user_id),
      createdAt: String(r.created_at),
      expiresAt: String(r.expires_at),
    }));

    const apiKeys: StoredApiKey[] = apiKeyRows.map((r) => ({
      id: String(r.id),
      userId: String(r.user_id),
      name: String(r.name),
      keyPrefix: String(r.key_prefix),
      keyHash: String(r.key_hash),
      createdAt: String(r.created_at),
      lastUsedAt: r.last_used_at ? String(r.last_used_at) : null,
    }));

    const commands: SshCommand[] = cmdRows.map((r) => ({
      id: String(r.id),
      userId: String(r.user_id ?? ''),
      name: String(r.name),
      category: String(r.category),
      kind: r.kind === 'chain' || r.kind === 'workflow' ? r.kind : 'single',
      command: String(r.command ?? ''),
      steps: safeJsonParse(r.steps_json, []),
      workflowJson: String(r.workflow_json ?? ''),
      stopOnError: Boolean(r.stop_on_error),
      description: String(r.description ?? ''),
      timeoutSec: Number(r.timeout_sec) || 30,
      enabled: Boolean(r.enabled),
      createdBy: String(r.created_by ?? ''),
      sharedWithAll: Boolean(r.shared_with_all),
      sharedWithUserIds: safeJsonParse<string[]>(r.shared_with_user_ids, []),
      createdAt: String(r.created_at),
      updatedAt: String(r.updated_at ?? ''),
    }));

    const servers: UserServer[] = srvRows.map((r) => ({
      id: String(r.id),
      userId: String(r.user_id),
      ownerUsername: String(r.owner_username ?? ''),
      label: String(r.label),
      ipAddress: String(r.ip_address),
      bmcIpAddress: String(r.bmc_ip_address ?? ''),
      bmcIpAddress2: String(r.bmc_ip_address2 ?? ''),
      port: Number(r.port) || 22,
      sshUser: String(r.ssh_user || 'root'),
      notes: String(r.notes ?? ''),
      categories: safeJsonParse<string[]>(r.categories_json, []),
      pingEnabled: Boolean(r.ping_enabled),
      ignoreHostKey: Boolean(r.ignore_host_key),
      lastOnlineAt: r.last_online_at ? String(r.last_online_at) : null,
      sharedWithAll: Boolean(r.shared_with_all),
      sharedWithUserIds: safeJsonParse<string[]>(r.shared_with_user_ids, []),
      createdAt: String(r.created_at),
    }));

    const serverCategories: ServerCategory[] = catRows.map((r) => ({
      id: String(r.id),
      userId: String(r.user_id),
      name: String(r.name),
      createdAt: String(r.created_at),
    }));

    const certificates: UserCertificateBundle[] = certRows.map((r) => ({
      id: String(r.id),
      userId: String(r.user_id),
      ownerUsername: String(r.owner_username ?? ''),
      name: String(r.name),
      privateKeyFileName: String(r.private_key_file),
      publicKeyFileName: String(r.public_key_file),
      certFileName: String(r.cert_file ?? ''),
      privateKeyEncrypted: decodeNodeBlob(r.private_key_enc) ?? { iv: '', tag: '', ciphertext: '' },
      passphraseEncrypted: decodeNodeBlob(r.passphrase_enc) ?? undefined,
      publicKeyContent: String(r.public_key),
      certContent: String(r.certificate ?? ''),
      metadata: safeJsonParse(r.inspection_json, {} as UserCertificateBundle['metadata']),
      autoRenew: r.auto_renew_json ? safeJsonParse(r.auto_renew_json, null) : null,
      sharedWithAll: Boolean(r.shared_with_all),
      sharedWithUserIds: safeJsonParse<string[]>(r.shared_with_user_ids, []),
      uploadedAt: String(r.uploaded_at),
    }));

    const certificateAuthorities: StoredCertificateAuthority[] = caRows.map((r) => ({
      id: String(r.id),
      name: String(r.name),
      description: String(r.description ?? ''),
      privateKeyFileName: String(r.private_key_file || 'ca'),
      publicKeyFileName: String(r.public_key_file || 'ca.pub'),
      privateKeyEncrypted: decodeNodeBlob(r.private_key_enc) ?? { iv: '', tag: '', ciphertext: '' },
      passphraseEncrypted: decodeNodeBlob(r.passphrase_enc) ?? undefined,
      publicKey: String(r.public_key),
      keyType: String(r.key_type || 'ssh-ed25519'),
      fingerprint: String(r.fingerprint ?? ''),
      privateKeyFormat: (r.private_key_format || 'openssh-v1') as StoredCertificateAuthority['privateKeyFormat'],
      privateKeyIsEncrypted: Boolean(r.private_key_encrypted),
      createdBy: String(r.created_by ?? ''),
      createdByUsername: String(r.created_by_username ?? ''),
      createdAt: String(r.created_at),
      updatedAt: String(r.updated_at),
    }));

    const logs: ExecutionLog[] = logRows.map((r) => ({
      id: String(r.id),
      userId: String(r.user_id),
      username: String(r.username),
      commandId: String(r.command_id ?? ''),
      commandName: String(r.command_name),
      commandText: String(r.command_text),
      targetIp: String(r.target_ip),
      targetPort: Number(r.target_port) || 22,
      sshUser: String(r.ssh_user),
      serverLabel: String(r.server_label ?? ''),
      certificateId: String(r.certificate_id ?? ''),
      certificateKeyId: String(r.certificate_key_id ?? ''),
      mode: r.mode === 'sandbox-dry-run' ? 'sandbox-dry-run' : 'openssh-live',
      sshInvocation: String(r.ssh_invocation ?? ''),
      exitCode: Number(r.exit_code) || 0,
      stdout: String(r.stdout ?? ''),
      stderr: String(r.stderr ?? ''),
      durationMs: Number(r.duration_ms) || 0,
      executedAt: String(r.executed_at),
    }));

    const webauthnCredentials: StoredWebAuthnCredential[] = webauthnRows.map((r) => ({
      id: String(r.id),
      userId: String(r.user_id),
      kind: r.kind === 'passkey' ? 'passkey' : 'security-key',
      name: String(r.name),
      credentialId: String(r.credential_id),
      publicKey: String(r.public_key),
      counter: Number(r.counter) || 0,
      transports: safeJsonParse<string[]>(r.transports_json, []),
      createdAt: String(r.created_at),
      lastUsedAt: r.last_used_at ? String(r.last_used_at) : null,
    }));

    const schema: DatabaseSchema = {
      settings,
      groups,
      users,
      sessions,
      apiKeys,
      webauthnCredentials,
      commands,
      servers,
      serverCategories,
      certificates,
      certificateAuthorities,
      logs,
    };

    const counts = countSchemaTables(schema);
    return { schema, counts };
  } finally {
    conn.release();
  }
}
