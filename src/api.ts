import type {
  AdminAuthSettings,
  AppSettings,
  AppStatus,
  BmcCheckResult,
  CommandKind,
  DashboardPingResponse,
  ExecutionLog,
  LoginResponse,
  RustProjectFile,
  ServerCategory,
  SshCommand,
  User,
  UserApiKey,
  UserCertificate,
  UserRole,
  UserSecurityStatus,
  UserServer,
  WebAuthnCredentialItem,
  WebAuthnCredentialKind,
} from './types';

const TOKEN_STORAGE_KEY = 'trixiessh_session_token';
let memoryToken: string | null = null;

function getStoredToken(): string | null {
  if (memoryToken) return memoryToken;
  try {
    const t = window.sessionStorage.getItem(TOKEN_STORAGE_KEY) || window.localStorage.getItem(TOKEN_STORAGE_KEY);
    if (t) memoryToken = t;
    return t;
  } catch {
    return memoryToken;
  }
}

export function setSessionToken(token: string | null) {
  setStoredToken(token);
}

function setStoredToken(token: string | null) {
  memoryToken = token;
  try {
    if (token) {
      window.sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
      window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
    } else {
      window.sessionStorage.removeItem(TOKEN_STORAGE_KEY);
      window.localStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch {
    // storage may be restricted in sandboxed iframes; memoryToken remains active
  }
}

function authHeaders(extra?: HeadersInit): Record<string, string> {
  const headers: Record<string, string> = {};
  if (extra) {
    if (extra instanceof Headers) {
      extra.forEach((v, k) => {
        headers[k] = v;
      });
    } else if (Array.isArray(extra)) {
      for (const [k, v] of extra) headers[k] = v;
    } else {
      Object.assign(headers, extra);
    }
  }
  const token = getStoredToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

let unauthorizedHandler: (() => void) | null = null;

export function setUnauthorizedHandler(handler: (() => void) | null) {
  unauthorizedHandler = handler;
}

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    credentials: 'include',
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(options?.headers),
    },
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (
      res.status === 401 &&
      !url.startsWith('/api/auth/login') &&
      !url.startsWith('/api/auth/passkey/login') &&
      !url.startsWith('/api/setup')
    ) {
      setStoredToken(null);
      unauthorizedHandler?.();
    }
    throw new Error((data as { error?: string }).error || `Anfrage fehlgeschlagen (${res.status})`);
  }
  return data as T;
}

export const api = {
  getStatus: () => request<AppStatus>('/api/status'),

  setupAdmin: async (payload: {
    username: string;
    displayName: string;
    password: string;
    instanceName: string;
  }) => {
    const res = await request<{ user: User; settings: AppSettings; sessionToken?: string }>('/api/setup', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    if (res.sessionToken) setStoredToken(res.sessionToken);
    return res;
  },

  login: async (username: string, password: string): Promise<LoginResponse> => {
    const res = await request<LoginResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    if (!res.requiresTwoFactor && res.sessionToken) {
      setStoredToken(res.sessionToken);
    }
    return res;
  },

  verifyTwoFactorLogin: async (payload: {
    ticket: string;
    method: 'totp' | 'recovery' | 'security-key';
    code?: string;
    assertion?: unknown;
  }) => {
    const res = await request<{ user: User; sessionToken?: string }>('/api/auth/login/2fa', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    if (res.sessionToken) setStoredToken(res.sessionToken);
    return res;
  },

  getPasskeyLoginOptions: () =>
    request<{ challengeId: string; options: Record<string, unknown> }>(
      '/api/auth/passkey/login/options',
      { method: 'POST', body: JSON.stringify({}) }
    ),

  verifyPasskeyLogin: async (challengeId: string, response: unknown) => {
    const res = await request<{ user: User; sessionToken?: string }>(
      '/api/auth/passkey/login/verify',
      {
        method: 'POST',
        body: JSON.stringify({ challengeId, response }),
      }
    );
    if (res.sessionToken) setStoredToken(res.sessionToken);
    return res;
  },

  getSsoUrl: (mode: 'login' | 'test' = 'login') =>
    request<{ url: string; callbackUrl: string }>(
      `/api/auth/sso/url?mode=${encodeURIComponent(mode)}`
    ),

  logout: async () => {
    try {
      return await request<{ ok: boolean }>('/api/auth/logout', {
        method: 'POST',
      });
    } finally {
      setStoredToken(null);
    }
  },

  // Self-service 2FA & Passkeys
  getUserSecurity: () => request<UserSecurityStatus>('/api/auth/security'),

  setupTotp: () =>
    request<{ secret: string; otpauthUri: string }>('/api/auth/2fa/totp/setup', {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  verifyTotp: (code: string) =>
    request<{ ok: boolean; recoveryCodes: string[]; user: User }>('/api/auth/2fa/totp/verify', {
      method: 'POST',
      body: JSON.stringify({ code }),
    }),

  disableTotp: () =>
    request<{ ok: boolean; user: User }>('/api/auth/2fa/totp', {
      method: 'DELETE',
    }),

  getWebAuthnRegisterOptions: (kind: WebAuthnCredentialKind, name: string) =>
    request<{ challengeId: string; options: Record<string, unknown> }>(
      '/api/auth/webauthn/register/options',
      {
        method: 'POST',
        body: JSON.stringify({ kind, name }),
      }
    ),

  verifyWebAuthnRegister: (challengeId: string, response: unknown, name: string) =>
    request<{ ok: boolean; credential: WebAuthnCredentialItem; user: User }>(
      '/api/auth/webauthn/register/verify',
      {
        method: 'POST',
        body: JSON.stringify({ challengeId, response, name }),
      }
    ),

  deleteWebAuthnCredential: (id: string) =>
    request<{ ok: boolean; user: User }>(`/api/auth/webauthn/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ ok: boolean }>('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, newPassword }),
    }),

  // Personal API Keys (curl certificate upload)
  listApiKeys: () => request<{ apiKeys: UserApiKey[] }>('/api/auth/api-keys'),

  createApiKey: (name: string) =>
    request<{ apiKey: UserApiKey; plainKey: string }>('/api/auth/api-keys', {
      method: 'POST',
      body: JSON.stringify({ name }),
    }),

  deleteApiKey: (id: string) =>
    request<{ ok: boolean }>(`/api/auth/api-keys/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  // Admin Users
  listUsers: () => request<{ users: User[] }>('/api/admin/users'),

  createUser: (payload: {
    username: string;
    displayName: string;
    password: string;
    role: UserRole;
    defaultSshUser: string;
  }) =>
    request<{ user: User }>('/api/admin/users', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateUser: (
    id: string,
    payload: {
      displayName?: string;
      role?: UserRole;
      defaultSshUser?: string;
      active?: boolean;
      newPassword?: string;
    }
  ) =>
    request<{ user: User }>(`/api/admin/users/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  resetUserAuth: (id: string) =>
    request<{ ok: boolean; user: User }>(`/api/admin/users/${encodeURIComponent(id)}/reset-auth`, {
      method: 'POST',
      body: JSON.stringify({}),
    }),

  deleteUser: (id: string) =>
    request<{ ok: boolean }>(`/api/admin/users/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  // Admin Authentication, SSO, 2FA & Passkey Policies
  getAdminAuthSettings: () =>
    request<{ authSettings: AdminAuthSettings; settings: AppSettings }>('/api/admin/auth/settings'),

  updateAdminAuthSettings: (payload: {
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
  }) =>
    request<{ authSettings: AdminAuthSettings; settings: AppSettings; user: User | null }>(
      '/api/admin/auth/settings',
      {
        method: 'PATCH',
        body: JSON.stringify(payload),
      }
    ),

  discoverOidc: (issuerUrl: string) =>
    request<{
      discovered: {
        issuer: string;
        authorizationEndpoint: string;
        tokenEndpoint: string;
        userinfoEndpoint: string;
      };
    }>('/api/admin/auth/sso/discover', {
      method: 'POST',
      body: JSON.stringify({ issuerUrl }),
    }),

  // Commands
  listCommands: (all = false) =>
    request<{ commands: SshCommand[] }>(`/api/commands${all ? '?all=1' : ''}`),

  createCommand: (payload: {
    name: string;
    category: string;
    kind: CommandKind;
    command: string;
    steps?: Array<{ command: string; sleepAfterSec: number }>;
    workflowJson?: string;
    stopOnError?: boolean;
    description: string;
    timeoutSec: number;
    enabled?: boolean;
    sharedWithAll?: boolean;
    sharedWithUserIds?: string[];
  }) =>
    request<{ command: SshCommand }>('/api/commands', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  loadPresetCommands: () =>
    request<{ added: SshCommand[]; commands: SshCommand[] }>('/api/commands/presets', {
      method: 'POST',
    }),

  updateCommand: (
    id: string,
    payload: Partial<
      Pick<
        SshCommand,
        | 'name'
        | 'category'
        | 'kind'
        | 'command'
        | 'steps'
        | 'workflowJson'
        | 'stopOnError'
        | 'description'
        | 'timeoutSec'
        | 'enabled'
        | 'sharedWithAll'
        | 'sharedWithUserIds'
      >
    >
  ) =>
    request<{ command: SshCommand }>(`/api/commands/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  shareCommand: (id: string, payload: { sharedWithAll: boolean; sharedWithUserIds: string[] }) =>
    request<{ command: SshCommand }>(`/api/commands/${encodeURIComponent(id)}/share`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  bulkUpdateCommands: (payload: {
    commandIds: string[];
    category?: string;
    enabled?: boolean;
    sharing?: { sharedWithAll: boolean; sharedWithUserIds: string[] };
  }) =>
    request<{ updatedCount: number; commands: SshCommand[] }>('/api/commands/bulk', {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  deleteCommand: (id: string) =>
    request<{ ok: boolean }>(`/api/commands/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  // Servers
  listServers: () => request<{ servers: UserServer[] }>('/api/servers'),

  // Server Categories
  listServerCategories: () =>
    request<{ categories: ServerCategory[] }>('/api/server-categories'),

  createServerCategory: (name: string) =>
    request<{ category: ServerCategory }>('/api/server-categories', {
      method: 'POST',
      body: JSON.stringify({ name }),
    }),

  deleteServerCategory: (id: string) =>
    request<{ ok: boolean }>(`/api/server-categories/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  createServer: (payload: {
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
  }) =>
    request<{ server: UserServer }>('/api/servers', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateServer: (
    id: string,
    payload: {
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
  ) =>
    request<{ server: UserServer }>(`/api/servers/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  checkServerBmc: (id: string, slot: 1 | 2 = 1) =>
    request<{ result: BmcCheckResult }>(`/api/servers/${encodeURIComponent(id)}/check-bmc`, {
      method: 'POST',
      body: JSON.stringify({ slot }),
    }),

  shareServer: (id: string, payload: { sharedWithAll: boolean; sharedWithUserIds: string[] }) =>
    request<{ server: UserServer }>(`/api/servers/${encodeURIComponent(id)}/share`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  bulkUpdateServers: (payload: {
    serverIds: string[];
    pingEnabled?: boolean;
    ignoreHostKey?: boolean;
    categoriesAction?: 'add' | 'remove' | 'replace';
    categories?: string[];
    sharing?: { sharedWithAll: boolean; sharedWithUserIds: string[] };
  }) =>
    request<{ updatedCount: number; servers: UserServer[] }>('/api/servers/bulk', {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  deleteServer: (id: string) =>
    request<{ ok: boolean }>(`/api/servers/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  // SSH Host-Keys (known_hosts)
  resetHostKey: (payload: { serverId?: string; ipAddress?: string; port?: number }) =>
    request<{
      ok: boolean;
      ipAddress: string;
      port: number;
      removedCount: number;
      remainingCount: number;
    }>('/api/host-keys/reset', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getAdminHostKeyStats: () =>
    request<{ totalEntries: number; userFiles: number }>('/api/admin/host-keys'),

  clearAllAdminHostKeys: (filter?: { ipAddress?: string; port?: number }) =>
    request<{
      ok: boolean;
      removedCount: number;
      totalEntries: number;
      affectedFiles: number;
    }>('/api/admin/host-keys', {
      method: 'DELETE',
      body: JSON.stringify(filter ?? {}),
    }),

  // Certificates
  listCertificates: () => request<{ certificates: UserCertificate[] }>('/api/certificates'),

  uploadCertificate: (payload: {
    name: string;
    privateKeyFileName: string;
    publicKeyFileName: string;
    certFileName?: string;
    privateKeyContent: string;
    publicKeyContent: string;
    certContent?: string;
    passphrase?: string;
    sharedWithAll?: boolean;
    sharedWithUserIds?: string[];
  }) =>
    request<{ certificate: UserCertificate; replaced?: boolean }>('/api/certificates', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateCertificate: (
    id: string,
    payload: {
      name?: string;
      privateKeyFileName?: string;
      publicKeyFileName?: string;
      certFileName?: string;
      privateKeyContent?: string;
      publicKeyContent?: string;
      certContent?: string;
      removeCert?: boolean;
      passphrase?: string;
      clearPassphrase?: boolean;
    }
  ) =>
    request<{ ok: boolean; certificate: UserCertificate }>(
      `/api/certificates/${encodeURIComponent(id)}`,
      {
        method: 'PATCH',
        body: JSON.stringify(payload),
      }
    ),

  shareCertificate: (id: string, payload: { sharedWithAll: boolean; sharedWithUserIds: string[] }) =>
    request<{ certificate: UserCertificate }>(`/api/certificates/${encodeURIComponent(id)}/share`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  generateTestCertificate: (payload: { keyId: string; principals: string[] }) =>
    request<{
      privateKey: string;
      publicKey: string;
      certificate: string;
      caPublicKey: string;
    }>('/api/certificates/generate-test', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  deleteCertificate: (id: string) =>
    request<{ ok: boolean }>(`/api/certificates/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  // Execution
  execute: (payload: {
    commandId: string;
    certificateId: string;
    targets: Array<
      | { serverId: string }
      | { ipAddress: string; port: number; sshUser: string; ignoreHostKey?: boolean }
    >;
    passphrase?: string;
    dryRun?: boolean;
  }) =>
    request<{ results: ExecutionLog[] }>('/api/execute', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  executeBatch: (payload: {
    certificateId: string;
    jobs: Array<{ serverId: string; commandId: string }>;
    passphrase?: string;
    dryRun?: boolean;
  }) =>
    request<{ results: ExecutionLog[] }>('/api/execute/batch', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // Interactive SSH Shell
  createShellTicket: (payload: {
    serverId?: string;
    ipAddress?: string;
    port?: number;
    sshUser?: string;
    ignoreHostKey?: boolean;
    certificateId: string;
    passphrase?: string;
    cols: number;
    rows: number;
  }) =>
    request<{
      ticket: string;
      targetIp: string;
      targetPort: number;
      sshUser: string;
      serverLabel: string;
      certificateName: string;
      opensshAvailable: boolean;
    }>('/api/shell/ticket', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // Dashboard Ping Monitor
  getDashboardStatus: () => request<DashboardPingResponse>('/api/dashboard/status'),

  triggerPing: (serverId?: string) =>
    request<DashboardPingResponse>('/api/dashboard/ping', {
      method: 'POST',
      body: JSON.stringify(serverId ? { serverId } : {}),
    }),

  updateUserPingSettings: (pingEnabled: boolean) =>
    request<{ user: User; dashboardStatus: DashboardPingResponse }>('/api/dashboard/ping-settings', {
      method: 'PATCH',
      body: JSON.stringify({ pingEnabled }),
    }),

  updateAdminPingSettings: (payload: {
    pingAllowed?: boolean;
    pingIntervalSec?: number;
    pingOfflineThreshold?: number;
    pingOfflineMultiplier?: number;
  }) =>
    request<{ settings: AppSettings; dashboardStatus: DashboardPingResponse }>('/api/admin/ping-settings', {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  listLogs: () => request<{ logs: ExecutionLog[] }>('/api/logs'),

  // Rust Project
  listRustFiles: () => request<{ files: RustProjectFile[] }>('/api/rust-project/files'),

  downloadRustArchive: async () => {
    const res = await fetch('/api/rust-project/download', {
      credentials: 'include',
      headers: authHeaders(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error((err as { error?: string }).error || 'Download fehlgeschlagen.');
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ssh-console-debian-trixie-rust.tar.gz';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },

  downloadDebPackage: async () => {
    const res = await fetch('/api/rust-project/download-deb', {
      credentials: 'include',
      headers: authHeaders(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error((err as { error?: string }).error || 'Debian-Paket-Download fehlgeschlagen.');
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ssh-console_1.0.0_all.deb';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },
};
