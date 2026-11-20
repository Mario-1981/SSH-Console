import type {
  AppSettings,
  AppStatus,
  BmcCheckResult,
  DashboardPingResponse,
  ExecutionLog,
  RustProjectFile,
  SshCommand,
  User,
  UserApiKey,
  UserCertificate,
  UserRole,
  UserServer,
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
    if (res.status === 401 && !url.startsWith('/api/auth/login') && !url.startsWith('/api/setup')) {
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

  login: async (username: string, password: string) => {
    const res = await request<{ user: User; sessionToken?: string }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    if (res.sessionToken) setStoredToken(res.sessionToken);
    return res;
  },

  logout: async () => {
    try {
      return await request<{ ok: boolean }>('/api/auth/logout', {
        method: 'POST',
      });
    } finally {
      setStoredToken(null);
    }
  },

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

  deleteUser: (id: string) =>
    request<{ ok: boolean }>(`/api/admin/users/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  // Commands
  listCommands: (all = false) =>
    request<{ commands: SshCommand[] }>(`/api/commands${all ? '?all=1' : ''}`),

  createCommand: (payload: {
    name: string;
    category: string;
    kind: 'single' | 'chain';
    command: string;
    steps?: Array<{ command: string; sleepAfterSec: number }>;
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

  deleteCommand: (id: string) =>
    request<{ ok: boolean }>(`/api/commands/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  // Servers
  listServers: () => request<{ servers: UserServer[] }>('/api/servers'),

  createServer: (payload: {
    label: string;
    ipAddress: string;
    bmcIpAddress?: string;
    port: number;
    sshUser: string;
    notes: string;
    pingEnabled?: boolean;
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
      port?: number;
      sshUser?: string;
      notes?: string;
      pingEnabled?: boolean;
    }
  ) =>
    request<{ server: UserServer }>(`/api/servers/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  checkServerBmc: (id: string) =>
    request<{ result: BmcCheckResult }>(`/api/servers/${encodeURIComponent(id)}/check-bmc`, {
      method: 'POST',
    }),

  shareServer: (id: string, payload: { sharedWithAll: boolean; sharedWithUserIds: string[] }) =>
    request<{ server: UserServer }>(`/api/servers/${encodeURIComponent(id)}/share`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  deleteServer: (id: string) =>
    request<{ ok: boolean }>(`/api/servers/${encodeURIComponent(id)}`, {
      method: 'DELETE',
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
    sharedWithAll?: boolean;
    sharedWithUserIds?: string[];
  }) =>
    request<{ certificate: UserCertificate; replaced?: boolean }>('/api/certificates', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

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
      | { ipAddress: string; port: number; sshUser: string }
    >;
    dryRun?: boolean;
  }) =>
    request<{ results: ExecutionLog[] }>('/api/execute', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  executeBatch: (payload: {
    certificateId: string;
    jobs: Array<{ serverId: string; commandId: string }>;
    dryRun?: boolean;
  }) =>
    request<{ results: ExecutionLog[] }>('/api/execute/batch', {
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

  updateAdminPingSettings: (payload: { pingAllowed?: boolean; pingIntervalSec?: number }) =>
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
