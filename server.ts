import express, { type Request, type Response, type NextFunction } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import { generateTestOpenSshCertBundle } from './server/certGen.ts';
import { validateAndParseCertificateBundle } from './server/opensshCert.ts';
import {
  executeSshCommand,
  findOpenSshBinary,
  validateSshUsername,
  validateTargetIp,
} from './server/sshRunner.ts';
import {
  store,
  verifyPassword,
  type StoredApiKey,
  type StoredUser,
  type UserRole,
} from './server/store.ts';
import { parseMultipartFormData } from './server/multipart.ts';
import { buildRustProjectTarGz } from './server/tarBuilder.ts';
import { buildDebianPackage } from './server/debBuilder.ts';
import { pingMonitor } from './server/pingMonitor.ts';
import { checkBmcHttps } from './server/bmcCheck.ts';

const COOKIE_NAME = 'trixiessh_session';
const RUST_APP_DIR = path.resolve(process.cwd(), 'rust-app');

interface AuthedRequest extends Request {
  user?: StoredUser;
  sessionToken?: string;
}

function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  if (!cookieHeader) return result;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx > 0) {
      const key = part.slice(0, idx).trim();
      const val = part.slice(idx + 1).trim();
      result[key] = decodeURIComponent(val);
    }
  }
  return result;
}

function isHttpsRequest(req: Request): boolean {
  const proto = String(req.headers['x-forwarded-proto'] ?? '').split(',')[0].trim();
  return req.secure || proto === 'https';
}

function setSessionCookie(req: Request, res: Response, token: string) {
  const https = isHttpsRequest(req);
  const parts = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    https ? 'SameSite=None' : 'SameSite=Lax',
    `Max-Age=${24 * 60 * 60}`,
  ];
  if (https) {
    parts.push('Secure');
    parts.push('Partitioned');
  }
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearSessionCookie(req: Request, res: Response) {
  const https = isHttpsRequest(req);
  const parts = [
    `${COOKIE_NAME}=`,
    'Path=/',
    'HttpOnly',
    https ? 'SameSite=None' : 'SameSite=Lax',
    'Max-Age=0',
  ];
  if (https) {
    parts.push('Secure');
    parts.push('Partitioned');
  }
  res.setHeader('Set-Cookie', parts.join('; '));
}

function extractSessionToken(req: Request): string | undefined {
  const authHeader = req.headers.authorization;
  if (typeof authHeader === 'string' && authHeader.toLowerCase().startsWith('bearer ')) {
    const bearer = authHeader.slice(7).trim();
    if (bearer) return bearer;
  }
  const cookies = parseCookies(req.headers.cookie);
  return cookies[COOKIE_NAME];
}

function extractApiKey(req: Request): string | undefined {
  const headerKey = req.headers['x-api-key'];
  if (typeof headerKey === 'string' && headerKey.trim()) {
    return headerKey.trim();
  }
  const authHeader = req.headers.authorization;
  if (typeof authHeader === 'string' && authHeader.toLowerCase().startsWith('bearer ')) {
    const bearer = authHeader.slice(7).trim();
    if (bearer.startsWith('sshc_')) return bearer;
  }
  return undefined;
}

function sanitizeApiKey(k: StoredApiKey) {
  return {
    id: k.id,
    name: k.name,
    keyPrefix: k.keyPrefix,
    createdAt: k.createdAt,
    lastUsedAt: k.lastUsedAt,
  };
}

function sanitizeUser(u: StoredUser) {
  return {
    id: u.id,
    username: u.username,
    displayName: u.displayName,
    role: u.role,
    defaultSshUser: u.defaultSshUser,
    active: u.active,
    pingEnabled: u.pingEnabled !== false,
    createdAt: u.createdAt,
    lastLoginAt: u.lastLoginAt,
  };
}

function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const token = extractSessionToken(req);
  const user = store.getUserBySessionToken(token);
  if (!user) {
    res.status(401).json({ error: 'Anmeldung erforderlich.' });
    return;
  }
  req.user = user;
  req.sessionToken = token;
  next();
}

function requireAdmin(req: AuthedRequest, res: Response, next: NextFunction) {
  if (!req.user || req.user.role !== 'admin') {
    res.status(403).json({ error: 'Administratorrechte erforderlich.' });
    return;
  }
  next();
}

function listRustProjectFiles(): Array<{ path: string; size: number; content: string }> {
  if (!fs.existsSync(RUST_APP_DIR)) return [];
  const results: Array<{ path: string; size: number; content: string }> = [];
  function walk(dir: string) {
    const items = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
    for (const item of items) {
      const full = path.join(dir, item.name);
      if (item.isDirectory()) {
        if (item.name === 'target') continue;
        walk(full);
      } else if (item.isFile()) {
        const rel = path.relative(RUST_APP_DIR, full).split(path.sep).join('/');
        const content = fs.readFileSync(full, 'utf8');
        results.push({ path: rel, size: Buffer.byteLength(content, 'utf8'), content });
      }
    }
  }
  walk(RUST_APP_DIR);
  return results;
}

const DEBIAN_PRESET_COMMANDS = [
  {
    name: 'Systemstatus & Laufzeit',
    category: 'Diagnose',
    command: 'hostnamectl --static && uptime && free -h',
    description: 'Zeigt Hostname, Systemlaufzeit, Load-Average und Arbeitsspeicherbelegung an.',
    timeoutSec: 15,
  },
  {
    name: 'Festplattenbelegung prüfen',
    category: 'Diagnose',
    command: 'df -h --output=source,fstype,size,used,avail,pcent,target -x tmpfs -x devtmpfs',
    description: 'Listet die Belegung aller lokalen Dateisysteme ohne temporäre Laufwerke auf.',
    timeoutSec: 15,
  },
  {
    name: 'Fehlgeschlagene Systemd-Dienste',
    category: 'Dienste',
    command: 'systemctl --failed --no-pager',
    description: 'Prüft, ob unter Debian Systemd-Units im Fehlerzustand stehen.',
    timeoutSec: 20,
  },
  {
    name: 'Verfügbare APT-Updates prüfen',
    category: 'Wartung',
    command: 'apt list --upgradable 2>/dev/null',
    description: 'Listet ausstehende Paketaktualisierungen auf dem Debian-Zielserver auf.',
    timeoutSec: 30,
  },
  {
    name: 'Offene Netzwerk-Ports (ss)',
    category: 'Netzwerk',
    kind: 'single' as const,
    command: 'ss -tulpen',
    steps: [],
    stopOnError: true,
    description: 'Zeigt alle aktiven TCP- und UDP-Listener-Sockets samt Prozesszuordnung an.',
    timeoutSec: 15,
  },
  {
    name: 'Nginx prüfen, neu laden & verifizieren',
    category: 'Dienste',
    kind: 'chain' as const,
    command: '',
    steps: [
      { command: 'nginx -t', sleepAfterSec: 2 },
      { command: 'systemctl reload nginx', sleepAfterSec: 3 },
      { command: 'systemctl is-active nginx', sleepAfterSec: 0 },
    ],
    stopOnError: true,
    description: 'Befehlskette: Prüft die Nginx-Konfiguration, wartet 2 s, lädt neu, wartet 3 s und verifiziert den Dienststatus.',
    timeoutSec: 30,
  },
  {
    name: 'APT-Paketlisten aktualisieren & Updates prüfen',
    category: 'Wartung',
    kind: 'chain' as const,
    command: '',
    steps: [
      { command: 'apt-get update -qq', sleepAfterSec: 2 },
      { command: 'apt list --upgradable 2>/dev/null', sleepAfterSec: 0 },
    ],
    stopOnError: true,
    description: 'Befehlskette: Aktualisiert den APT-Index, pausiert 2 s und listet verfügbare Debian-Updates auf.',
    timeoutSec: 60,
  },
];

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '2mb' }));

  // System & Auth Status
  app.get('/api/status', (req: AuthedRequest, res: Response) => {
    const initialized = store.isInitialized();
    const token = extractSessionToken(req);
    const user = store.getUserBySessionToken(token);
    res.json({
      initialized,
      settings: store.getSettings(),
      user: user ? sanitizeUser(user) : null,
      opensshAvailable: Boolean(findOpenSshBinary()),
    });
  });

  // First-Run Initial Admin Setup (strictly locked once an admin exists)
  app.post('/api/setup', (req: Request, res: Response) => {
    if (store.isInitialized()) {
      res.status(403).json({
        error: 'Ersteinrichtung bereits abgeschlossen. Eine Selbstregistrierung ist deaktiviert.',
      });
      return;
    }

    const { username, displayName, password, instanceName } = req.body ?? {};
    if (typeof username !== 'string' || !/^[a-z0-9._-]{2,32}$/i.test(username.trim())) {
      res.status(400).json({ error: 'Ungültiger Benutzername (2–32 Zeichen: a-z, 0-9, ., _, -).' });
      return;
    }
    if (typeof password !== 'string' || password.length < 8) {
      res.status(400).json({ error: 'Das Administrator-Passwort muss mindestens 8 Zeichen lang sein.' });
      return;
    }

    try {
      const admin = store.setupInitialAdmin({
        username,
        displayName: typeof displayName === 'string' ? displayName : username,
        password,
        instanceName: typeof instanceName === 'string' ? instanceName : 'SSH Console',
      });
      const session = store.createSession(admin.id);
      setSessionCookie(req, res, session.token);
      res.status(201).json({
        user: sanitizeUser(admin),
        settings: store.getSettings(),
        sessionToken: session.token,
      });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Fehler bei der Ersteinrichtung.' });
    }
  });

  // Login (no public registration)
  app.post('/api/auth/login', (req: Request, res: Response) => {
    if (!store.isInitialized()) {
      res.status(409).json({ error: 'Bitte schließen Sie zuerst die Admin-Ersteinrichtung ab.' });
      return;
    }
    const { username, password } = req.body ?? {};
    if (typeof username !== 'string' || typeof password !== 'string') {
      res.status(400).json({ error: 'Benutzername und Passwort sind erforderlich.' });
      return;
    }

    const user = store.findUserByUsername(username);
    if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
      res.status(401).json({ error: 'Ungültiger Benutzername oder falsches Passwort.' });
      return;
    }
    if (!user.active) {
      res.status(403).json({ error: 'Dieses Benutzerkonto wurde vom Administrator deaktiviert.' });
      return;
    }

    const session = store.createSession(user.id);
    setSessionCookie(req, res, session.token);
    res.json({
      user: sanitizeUser(user),
      sessionToken: session.token,
    });
  });

  app.post('/api/auth/logout', (req: AuthedRequest, res: Response) => {
    const token = extractSessionToken(req);
    store.deleteSession(token);
    clearSessionCookie(req, res);
    res.json({ ok: true });
  });

  // Self-service Password Change for every authenticated user
  app.post('/api/auth/change-password', requireAuth, (req: AuthedRequest, res: Response) => {
    const { currentPassword, newPassword } = req.body ?? {};
    if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
      res.status(400).json({ error: 'Aktuelles und neues Passwort sind erforderlich.' });
      return;
    }
    const user = req.user!;
    if (!verifyPassword(currentPassword, user.passwordSalt, user.passwordHash)) {
      res.status(400).json({ error: 'Das aktuelle Passwort ist nicht korrekt.' });
      return;
    }
    if (newPassword.length < 8) {
      res.status(400).json({ error: 'Das neue Passwort muss mindestens 8 Zeichen lang sein.' });
      return;
    }
    if (newPassword === currentPassword) {
      res.status(400).json({ error: 'Das neue Passwort muss sich vom aktuellen Passwort unterscheiden.' });
      return;
    }
    try {
      store.changeUserPassword(user.id, newPassword, req.sessionToken);
      res.json({ ok: true });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Passwort konnte nicht geändert werden.' });
    }
  });

  // Personal API Keys (for automated curl certificate uploads)
  app.get('/api/auth/api-keys', requireAuth, (req: AuthedRequest, res: Response) => {
    res.json({ apiKeys: store.listApiKeys(req.user!.id).map(sanitizeApiKey) });
  });

  app.post('/api/auth/api-keys', requireAuth, (req: AuthedRequest, res: Response) => {
    const rawName = typeof req.body?.name === 'string' ? req.body.name : '';
    const { apiKey, plainKey } = store.createApiKey(req.user!.id, rawName);
    res.status(201).json({
      apiKey: sanitizeApiKey(apiKey),
      plainKey,
    });
  });

  app.delete('/api/auth/api-keys/:id', requireAuth, (req: AuthedRequest, res: Response) => {
    store.deleteApiKey(req.params.id, req.user!.id);
    res.json({ ok: true });
  });

  // Admin: User Management (no self-registration)
  app.get('/api/admin/users', requireAuth, requireAdmin, (_req, res) => {
    res.json({ users: store.listUsers().map(sanitizeUser) });
  });

  app.post('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
    const { username, displayName, password, role, defaultSshUser } = req.body ?? {};
    if (typeof password !== 'string' || password.length < 8) {
      res.status(400).json({ error: 'Das Passwort muss mindestens 8 Zeichen lang sein.' });
      return;
    }
    const safeRole: UserRole = role === 'admin' ? 'admin' : 'user';
    try {
      const user = store.createUser({
        username: String(username ?? ''),
        displayName: String(displayName ?? ''),
        password,
        role: safeRole,
        defaultSshUser: String(defaultSshUser ?? 'root'),
      });
      res.status(201).json({ user: sanitizeUser(user) });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Benutzer konnte nicht angelegt werden.' });
    }
  });

  app.patch('/api/admin/users/:id', requireAuth, requireAdmin, (req, res) => {
    const { displayName, role, defaultSshUser, active, newPassword } = req.body ?? {};
    if (newPassword !== undefined && (typeof newPassword !== 'string' || newPassword.length < 8)) {
      res.status(400).json({ error: 'Das neue Passwort muss mindestens 8 Zeichen lang sein.' });
      return;
    }
    try {
      const updated = store.updateUser(req.params.id, {
        displayName,
        role: role === 'admin' || role === 'user' ? role : undefined,
        defaultSshUser,
        active: typeof active === 'boolean' ? active : undefined,
        newPassword,
      });
      res.json({ user: sanitizeUser(updated) });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Benutzer konnte nicht aktualisiert werden.' });
    }
  });

  app.delete('/api/admin/users/:id', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    if (req.user?.id === req.params.id) {
      res.status(400).json({ error: 'Das eigene aktive Administratorkonto kann nicht gelöscht werden.' });
      return;
    }
    try {
      store.deleteUser(req.params.id);
      res.json({ ok: true });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Benutzer konnte nicht gelöscht werden.' });
    }
  });

  // SSH Commands (only visible to creator, except items explicitly shared by an admin)
  app.get('/api/commands', requireAuth, (req: AuthedRequest, res) => {
    const includeDisabledOwn = req.query.all === '1';
    const commands = store.listAccessibleCommands(req.user!.id, includeDisabledOwn);
    res.json({ commands });
  });

  const handleCreateCommand = (req: AuthedRequest, res: Response) => {
    const {
      name,
      category,
      kind,
      command,
      steps,
      stopOnError,
      description,
      timeoutSec,
      enabled,
      sharedWithAll,
      sharedWithUserIds,
    } = req.body ?? {};
    if (typeof name !== 'string' || !name.trim()) {
      res.status(400).json({ error: 'Befehlsname ist erforderlich.' });
      return;
    }
    const isChain = kind === 'chain';
    if (!isChain && (typeof command !== 'string' || !command.trim())) {
      res.status(400).json({ error: 'Der auszuführende SSH-Befehl ist erforderlich.' });
      return;
    }
    if (isChain && (!Array.isArray(steps) || steps.length === 0)) {
      res.status(400).json({ error: 'Eine Befehlskette benötigt mindestens einen Schritt.' });
      return;
    }
    const isAdmin = req.user!.role === 'admin';
    try {
      const created = store.createCommand({
        userId: req.user!.id,
        name,
        category: typeof category === 'string' ? category : 'Allgemein',
        kind: isChain ? 'chain' : 'single',
        command: typeof command === 'string' ? command : '',
        steps: Array.isArray(steps) ? steps : [],
        stopOnError: typeof stopOnError === 'boolean' ? stopOnError : true,
        description: typeof description === 'string' ? description : '',
        timeoutSec: Number(timeoutSec) || 30,
        enabled: typeof enabled === 'boolean' ? enabled : true,
        createdBy: req.user!.username,
        sharedWithAll: isAdmin ? Boolean(sharedWithAll) : false,
        sharedWithUserIds: isAdmin && Array.isArray(sharedWithUserIds) ? sharedWithUserIds : [],
      });
      res.status(201).json({ command: created });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Befehl konnte nicht gespeichert werden.' });
    }
  };

  const handleLoadPresets = (req: AuthedRequest, res: Response) => {
    const ownExisting = store.listOwnCommands(req.user!.id);
    const existingNames = new Set(ownExisting.map((c) => c.name.toLowerCase()));
    const added = [];
    for (const preset of DEBIAN_PRESET_COMMANDS) {
      if (!existingNames.has(preset.name.toLowerCase())) {
        added.push(
          store.createCommand({
            ...preset,
            userId: req.user!.id,
            createdBy: req.user!.username,
          })
        );
      }
    }
    res.status(201).json({ added, commands: store.listAccessibleCommands(req.user!.id, true) });
  };

  const handleUpdateCommand = (req: AuthedRequest, res: Response) => {
    const existing = store.getCommand(req.params.id);
    if (!existing) {
      res.status(404).json({ error: 'Befehl nicht gefunden.' });
      return;
    }
    if (existing.userId !== req.user!.id) {
      res.status(403).json({ error: 'Sie können nur selbst angelegte SSH-Befehle bearbeiten.' });
      return;
    }
    const patch = { ...(req.body ?? {}) };
    if (req.user!.role !== 'admin') {
      delete patch.sharedWithAll;
      delete patch.sharedWithUserIds;
    }
    try {
      const updated = store.updateCommand(req.params.id, patch);
      res.json({ command: updated });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Befehl konnte nicht aktualisiert werden.' });
    }
  };

  const handleShareCommand = (req: AuthedRequest, res: Response) => {
    const { sharedWithAll, sharedWithUserIds } = req.body ?? {};
    try {
      const updated = store.updateCommandSharing(
        req.params.id,
        req.user!.id,
        Boolean(sharedWithAll),
        Array.isArray(sharedWithUserIds) ? sharedWithUserIds : []
      );
      res.json({ command: updated });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Freigabe konnte nicht aktualisiert werden.' });
    }
  };

  const handleDeleteCommand = (req: AuthedRequest, res: Response) => {
    const existing = store.getCommand(req.params.id);
    if (!existing) {
      res.json({ ok: true });
      return;
    }
    if (existing.userId !== req.user!.id) {
      res.status(403).json({ error: 'Sie können nur selbst angelegte SSH-Befehle löschen.' });
      return;
    }
    store.deleteCommand(req.params.id);
    res.json({ ok: true });
  };

  app.post('/api/commands', requireAuth, handleCreateCommand);
  app.post('/api/admin/commands', requireAuth, handleCreateCommand);

  app.post('/api/commands/presets', requireAuth, handleLoadPresets);
  app.post('/api/admin/commands/presets', requireAuth, handleLoadPresets);

  app.patch('/api/commands/:id', requireAuth, handleUpdateCommand);
  app.patch('/api/admin/commands/:id', requireAuth, handleUpdateCommand);

  app.patch('/api/commands/:id/share', requireAuth, requireAdmin, handleShareCommand);

  app.delete('/api/commands/:id', requireAuth, handleDeleteCommand);
  app.delete('/api/admin/commands/:id', requireAuth, handleDeleteCommand);

  // User Target Servers (IP addresses — creator-private; admin may share)
  app.get('/api/servers', requireAuth, (req: AuthedRequest, res) => {
    res.json({ servers: store.listAccessibleServers(req.user!.id) });
  });

  app.post('/api/servers', requireAuth, (req: AuthedRequest, res) => {
    const {
      label,
      ipAddress,
      bmcIpAddress,
      port,
      sshUser,
      notes,
      pingEnabled,
      sharedWithAll,
      sharedWithUserIds,
    } = req.body ?? {};
    if (typeof ipAddress !== 'string' || !validateTargetIp(ipAddress)) {
      res.status(400).json({ error: 'Bitte geben Sie eine gültige IPv4- oder IPv6-Adresse an.' });
      return;
    }
    const cleanBmcIp = typeof bmcIpAddress === 'string' ? bmcIpAddress.trim() : '';
    if (cleanBmcIp && !validateTargetIp(cleanBmcIp)) {
      res.status(400).json({ error: 'Bitte geben Sie eine gültige IPv4- oder IPv6-Adresse für die BMC-IP an (oder lassen Sie das Feld leer).' });
      return;
    }
    const cleanSshUser = typeof sshUser === 'string' && sshUser.trim() ? sshUser.trim() : req.user!.defaultSshUser;
    if (!validateSshUsername(cleanSshUser)) {
      res.status(400).json({ error: 'Ungültiger SSH-Benutzername (erlaubt: a-z, 0-9, ., _, -).' });
      return;
    }
    const isAdmin = req.user!.role === 'admin';
    const server = store.createServer({
      userId: req.user!.id,
      ownerUsername: req.user!.username,
      label: typeof label === 'string' ? label : ipAddress,
      ipAddress: ipAddress.trim(),
      bmcIpAddress: cleanBmcIp,
      port: Number(port) || 22,
      sshUser: cleanSshUser,
      notes: typeof notes === 'string' ? notes : '',
      pingEnabled: pingEnabled !== undefined ? Boolean(pingEnabled) : true,
      sharedWithAll: isAdmin ? Boolean(sharedWithAll) : false,
      sharedWithUserIds: isAdmin && Array.isArray(sharedWithUserIds) ? sharedWithUserIds : [],
    });
    // Trigger background initial ping only if allowed globally, for user, and for this server
    if (server.pingEnabled && store.getSettings().pingAllowed && req.user!.pingEnabled !== false) {
      void pingMonitor.pingUserServers(req.user!.id, server.id);
    }
    res.status(201).json({ server });
  });

  app.patch('/api/servers/:id', requireAuth, (req: AuthedRequest, res) => {
    const { label, ipAddress, bmcIpAddress, port, sshUser, notes, pingEnabled } = req.body ?? {};
    if (ipAddress !== undefined && (typeof ipAddress !== 'string' || !validateTargetIp(ipAddress))) {
      res.status(400).json({ error: 'Bitte geben Sie eine gültige IPv4- oder IPv6-Adresse an.' });
      return;
    }
    if (bmcIpAddress !== undefined) {
      if (typeof bmcIpAddress !== 'string') {
        res.status(400).json({ error: 'Ungültige BMC-IP-Adresse.' });
        return;
      }
      const trimmedBmc = bmcIpAddress.trim();
      if (trimmedBmc && !validateTargetIp(trimmedBmc)) {
        res.status(400).json({ error: 'Bitte geben Sie eine gültige IPv4- oder IPv6-Adresse für die BMC-IP an (oder lassen Sie das Feld leer).' });
        return;
      }
    }
    if (sshUser !== undefined && (typeof sshUser !== 'string' || !validateSshUsername(sshUser.trim()))) {
      res.status(400).json({ error: 'Ungültiger SSH-Benutzername (erlaubt: a-z, 0-9, ., _, -).' });
      return;
    }
    try {
      const updated = store.updateServer(req.params.id, req.user!.id, {
        label: typeof label === 'string' ? label : undefined,
        ipAddress: typeof ipAddress === 'string' ? ipAddress : undefined,
        bmcIpAddress: typeof bmcIpAddress === 'string' ? bmcIpAddress : undefined,
        port: port !== undefined ? Number(port) : undefined,
        sshUser: typeof sshUser === 'string' ? sshUser : undefined,
        notes: typeof notes === 'string' ? notes : undefined,
        pingEnabled: typeof pingEnabled === 'boolean' ? pingEnabled : undefined,
      });
      if (!updated.pingEnabled) {
        pingMonitor.clearServerStatus(updated.id);
      } else if (store.getSettings().pingAllowed && req.user!.pingEnabled !== false) {
        void pingMonitor.pingUserServers(req.user!.id, updated.id);
      }
      res.json({ server: updated });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Server konnte nicht aktualisiert werden.';
      const status = msg.includes('selbst angelegte') ? 403 : 400;
      res.status(status).json({ error: msg });
    }
  });

  app.post('/api/servers/:id/check-bmc', requireAuth, async (req: AuthedRequest, res) => {
    const server = store.getAccessibleServer(req.params.id, req.user!.id);
    if (!server) {
      res.status(404).json({ error: 'Server nicht gefunden.' });
      return;
    }
    if (!server.bmcIpAddress) {
      res.status(400).json({ error: 'Für diesen Server ist keine BMC-IP hinterlegt.' });
      return;
    }
    const result = await checkBmcHttps(server.bmcIpAddress);
    res.json({
      result: {
        serverId: server.id,
        ...result,
      },
    });
  });

  app.patch('/api/servers/:id/share', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    const { sharedWithAll, sharedWithUserIds } = req.body ?? {};
    try {
      const updated = store.updateServerSharing(
        req.params.id,
        req.user!.id,
        Boolean(sharedWithAll),
        Array.isArray(sharedWithUserIds) ? sharedWithUserIds : []
      );
      res.json({ server: updated });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Server-Freigabe konnte nicht aktualisiert werden.' });
    }
  });

  app.delete('/api/servers/:id', requireAuth, (req: AuthedRequest, res) => {
    const existing = store.getServerById(req.params.id);
    if (existing && existing.userId !== req.user!.id) {
      res.status(403).json({ error: 'Sie können nur selbst angelegte Server (IPs) entfernen.' });
      return;
    }
    store.deleteServer(req.params.id, req.user!.id);
    res.json({ ok: true });
  });

  // User 3-File SSH Certificates (zertifikat, zertifikat.pub, zertifikat-cert.pub — creator-private; admin may share)
  function serializeCertificate(c: ReturnType<typeof store.listAccessibleCertificates>[number]) {
    return {
      id: c.id,
      userId: c.userId,
      ownerUsername: c.ownerUsername,
      name: c.name,
      privateKeyFileName: c.privateKeyFileName,
      publicKeyFileName: c.publicKeyFileName,
      certFileName: c.certFileName,
      metadata: c.metadata,
      sharedWithAll: c.sharedWithAll,
      sharedWithUserIds: c.sharedWithUserIds,
      uploadedAt: c.uploadedAt,
    };
  }

  app.get('/api/certificates', requireAuth, (req: AuthedRequest, res) => {
    const list = store.listAccessibleCertificates(req.user!.id).map(serializeCertificate);
    res.json({ certificates: list });
  });

  app.post('/api/certificates', requireAuth, (req: AuthedRequest, res) => {
    const {
      name,
      privateKeyFileName,
      publicKeyFileName,
      certFileName,
      privateKeyContent,
      publicKeyContent,
      certContent,
      sharedWithAll,
      sharedWithUserIds,
    } = req.body ?? {};

    if (
      typeof privateKeyContent !== 'string' ||
      !privateKeyContent.trim() ||
      typeof publicKeyContent !== 'string' ||
      !publicKeyContent.trim()
    ) {
      res.status(400).json({
        error:
          'Privater Schlüssel (zertifikat) und öffentlicher Schlüssel (zertifikat.pub) sind erforderlich. Das signierte Zertifikat (zertifikat-cert.pub) ist optional.',
      });
      return;
    }

    const cleanCertContent = typeof certContent === 'string' ? certContent : '';
    const isAdmin = req.user!.role === 'admin';
    try {
      const metadata = validateAndParseCertificateBundle(
        privateKeyContent,
        publicKeyContent,
        cleanCertContent
      );
      const { certificate: saved, replaced } = store.createCertificate({
        userId: req.user!.id,
        ownerUsername: req.user!.username,
        name: typeof name === 'string' ? name : metadata.keyId || 'SSH-Zertifikat',
        privateKeyFileName: String(privateKeyFileName || 'zertifikat'),
        publicKeyFileName: String(publicKeyFileName || 'zertifikat.pub'),
        certFileName: cleanCertContent.trim() ? String(certFileName || 'zertifikat-cert.pub') : '',
        privateKeyContent,
        publicKeyContent,
        certContent: cleanCertContent,
        metadata,
        sharedWithAll: isAdmin ? Boolean(sharedWithAll) : false,
        sharedWithUserIds: isAdmin && Array.isArray(sharedWithUserIds) ? sharedWithUserIds : [],
      });

      res.status(replaced ? 200 : 201).json({
        certificate: serializeCertificate(saved),
        replaced,
      });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Zertifikatsprüfung fehlgeschlagen.',
      });
    }
  });

  app.patch('/api/certificates/:id/share', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    const { sharedWithAll, sharedWithUserIds } = req.body ?? {};
    try {
      const updated = store.updateCertificateSharing(
        req.params.id,
        req.user!.id,
        Boolean(sharedWithAll),
        Array.isArray(sharedWithUserIds) ? sharedWithUserIds : []
      );
      res.json({ certificate: serializeCertificate(updated) });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Zertifikats-Freigabe konnte nicht aktualisiert werden.' });
    }
  });

  app.post('/api/certificates/generate-test', requireAuth, (req: AuthedRequest, res) => {
    const { keyId, principals } = req.body ?? {};
    const cleanKeyId =
      typeof keyId === 'string' && keyId.trim()
        ? keyId.trim().slice(0, 64)
        : `${req.user!.username}-trixie-cert`;
    const cleanPrincipals = Array.isArray(principals)
      ? principals.map((p) => String(p).trim()).filter(Boolean)
      : [req.user!.defaultSshUser || 'root', 'deploy'];

    const generated = generateTestOpenSshCertBundle({
      keyId: cleanKeyId,
      principals: cleanPrincipals.length > 0 ? cleanPrincipals : ['root'],
      validDays: 90,
    });
    res.json(generated);
  });

  app.delete('/api/certificates/:id', requireAuth, (req: AuthedRequest, res) => {
    const existing = store.getCertificateById(req.params.id);
    if (existing && existing.userId !== req.user!.id) {
      res.status(403).json({ error: 'Sie können nur selbst angelegte Zertifikatspakete entfernen.' });
      return;
    }
    store.deleteCertificate(req.params.id, req.user!.id);
    res.json({ ok: true });
  });

  // Simple API-Key Upload Endpoint for curl (supports multipart/form-data and JSON)
  app.post('/api/v1/certificates/upload', async (req: Request, res: Response) => {
    const apiKey = extractApiKey(req);
    const user = store.getUserByApiKey(apiKey);
    if (!user) {
      res.status(401).json({
        error:
          'Ungültiger oder fehlender API-Schlüssel. Senden Sie ihn als Header "X-API-Key: sshc_..." oder "Authorization: Bearer sshc_...".',
      });
      return;
    }

    let bundleName = '';
    let privateKeyFileName = 'zertifikat';
    let publicKeyFileName = 'zertifikat.pub';
    let certFileName = 'zertifikat-cert.pub';
    let privateKeyContent = '';
    let publicKeyContent = '';
    let certContent = '';

    const contentType = String(req.headers['content-type'] ?? '').toLowerCase();
    try {
      if (contentType.includes('multipart/form-data')) {
        const parsed = await parseMultipartFormData(req);
        const pickPart = (
          names: string[]
        ): { content: string; filename?: string } | undefined => {
          for (const n of names) {
            if (parsed.files[n] && parsed.files[n].content.trim()) {
              return { content: parsed.files[n].content, filename: parsed.files[n].filename };
            }
            if (parsed.fields[n] && parsed.fields[n].trim()) {
              return { content: parsed.fields[n] };
            }
          }
          return undefined;
        };

        const priv = pickPart(['private_key', 'privateKey', 'zertifikat', 'key']);
        const pub = pickPart(['public_key', 'publicKey', 'zertifikat_pub', 'pub']);
        const cert = pickPart(['cert', 'certificate', 'cert_pub', 'zertifikat_cert', 'certContent']);

        bundleName = (parsed.fields.name ?? parsed.fields.label ?? '').trim();
        if (priv) {
          privateKeyContent = priv.content;
          if (priv.filename) privateKeyFileName = path.basename(priv.filename);
        }
        if (pub) {
          publicKeyContent = pub.content;
          if (pub.filename) publicKeyFileName = path.basename(pub.filename);
        }
        if (cert) {
          certContent = cert.content;
          if (cert.filename) certFileName = path.basename(cert.filename);
        }
      } else {
        const body = (req.body ?? {}) as Record<string, unknown>;
        const readStr = (...keys: string[]): string => {
          for (const k of keys) {
            if (typeof body[k] === 'string' && (body[k] as string).trim()) {
              return body[k] as string;
            }
          }
          return '';
        };
        bundleName = readStr('name', 'label').trim();
        privateKeyContent = readStr('private_key', 'privateKey', 'privateKeyContent', 'zertifikat');
        publicKeyContent = readStr('public_key', 'publicKey', 'publicKeyContent', 'zertifikat_pub');
        certContent = readStr('cert', 'certificate', 'certContent', 'cert_pub', 'zertifikat_cert');
        privateKeyFileName =
          readStr('privateKeyFileName', 'private_key_file') || privateKeyFileName;
        publicKeyFileName =
          readStr('publicKeyFileName', 'public_key_file') || publicKeyFileName;
        certFileName = readStr('certFileName', 'cert_file') || certFileName;
      }
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Anfrage konnte nicht verarbeitet werden.',
      });
      return;
    }

    if (!privateKeyContent.trim() || !publicKeyContent.trim()) {
      res.status(400).json({
        error:
          'Erforderliche Felder fehlen: "private_key" (zertifikat) und "public_key" (zertifikat.pub). Optional: "cert" (zertifikat-cert.pub) und "name".',
      });
      return;
    }

    const cleanCertContent = certContent.trim();
    try {
      const metadata = validateAndParseCertificateBundle(
        privateKeyContent,
        publicKeyContent,
        cleanCertContent
      );
      const effectiveName =
        bundleName ||
        metadata.keyId ||
        privateKeyFileName.replace(/\.(pem|key)$/i, '') ||
        'SSH-Zertifikat';

      const { certificate: saved, replaced } = store.createCertificate({
        userId: user.id,
        ownerUsername: user.username,
        name: effectiveName,
        privateKeyFileName,
        publicKeyFileName,
        certFileName: cleanCertContent ? certFileName : '',
        privateKeyContent,
        publicKeyContent,
        certContent: cleanCertContent,
        metadata,
      });

      res.status(replaced ? 200 : 201).json({
        ok: true,
        replaced,
        certificate: serializeCertificate(saved),
      });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Zertifikatsprüfung fehlgeschlagen.',
      });
    }
  });

  // Execute SSH Command on One or Multiple Target IPs (own or admin-shared)
  app.post('/api/execute', requireAuth, async (req: AuthedRequest, res) => {
    const { commandId, certificateId, targets, dryRun } = req.body ?? {};

    const command = store.getAccessibleCommand(String(commandId ?? ''), req.user!.id);
    if (!command) {
      res.status(404).json({ error: 'Ausgewählter SSH-Befehl ist nicht verfügbar oder deaktiviert.' });
      return;
    }

    const certificate = store.getAccessibleCertificate(String(certificateId ?? ''), req.user!.id);
    if (!certificate) {
      res.status(404).json({ error: 'Bitte wählen Sie ein gültiges SSH-Zertifikatspaket aus.' });
      return;
    }

    if (!Array.isArray(targets) || targets.length === 0 || targets.length > 20) {
      res.status(400).json({ error: 'Bitte wählen Sie zwischen 1 und 20 Ziel-IPs aus.' });
      return;
    }

    const resolvedTargets: Array<{ ipAddress: string; port: number; sshUser: string; label: string }> = [];
    for (const t of targets) {
      if (typeof t?.serverId === 'string' && t.serverId) {
        const srv = store.getAccessibleServer(t.serverId, req.user!.id);
        if (!srv) {
          res.status(404).json({ error: `Server ${t.serverId} nicht gefunden.` });
          return;
        }
        resolvedTargets.push({
          ipAddress: srv.ipAddress,
          port: srv.port,
          sshUser: srv.sshUser,
          label: srv.label,
        });
      } else {
        const ip = String(t?.ipAddress ?? '').trim();
        const port = Math.min(65535, Math.max(1, Number(t?.port) || 22));
        const sshUser = String(t?.sshUser ?? req.user!.defaultSshUser ?? 'root').trim();
        if (!validateTargetIp(ip)) {
          res.status(400).json({ error: `Ungültige Ziel-IP: "${ip}"` });
          return;
        }
        if (!validateSshUsername(sshUser)) {
          res.status(400).json({ error: `Ungültiger SSH-Benutzer: "${sshUser}"` });
          return;
        }
        resolvedTargets.push({
          ipAddress: ip,
          port,
          sshUser,
          label: ip,
        });
      }
    }

    const logs = await Promise.all(
      resolvedTargets.map(async (target) => {
        const result = await executeSshCommand({
          ipAddress: target.ipAddress,
          port: target.port,
          sshUser: target.sshUser,
          command,
          certificate,
          forceDryRun: Boolean(dryRun),
        });

        return store.addLog({
          userId: req.user!.id,
          username: req.user!.username,
          commandId: command.id,
          commandName: command.name,
          commandText: command.command,
          targetIp: target.ipAddress,
          targetPort: target.port,
          sshUser: target.sshUser,
          serverLabel: target.label,
          certificateId: certificate.id,
          certificateKeyId: certificate.metadata.keyId || certificate.name,
          mode: result.mode,
          sshInvocation: result.sshInvocation,
          exitCode: result.exitCode,
          stdout: result.stdout,
          stderr: result.stderr,
          durationMs: result.durationMs,
        });
      })
    );

    res.json({ results: logs });
  });

  // Dashboard: Ping Status, User & Admin Ping Settings, Manual Ping Trigger
  app.get('/api/dashboard/status', requireAuth, (req: AuthedRequest, res) => {
    res.json(pingMonitor.getUserStatuses(req.user!.id));
  });

  app.post('/api/dashboard/ping', requireAuth, async (req: AuthedRequest, res) => {
    const settings = store.getSettings();
    if (!settings.pingAllowed) {
      res.status(403).json({ error: 'Anpingen wurde vom Administrator global verboten.' });
      return;
    }
    if (req.user!.pingEnabled === false) {
      res.status(400).json({ error: 'Anpingen ist für Ihr Konto deaktiviert.' });
      return;
    }
    const serverId = typeof req.body?.serverId === 'string' ? req.body.serverId : undefined;
    if (serverId) {
      const srv = store.getAccessibleServer(serverId, req.user!.id);
      if (srv && srv.pingEnabled === false) {
        res.status(400).json({ error: 'Anpingen ist für diese IP deaktiviert.' });
        return;
      }
    }
    await pingMonitor.pingUserServers(req.user!.id, serverId);
    res.json(pingMonitor.getUserStatuses(req.user!.id));
  });

  app.patch('/api/dashboard/ping-settings', requireAuth, (req: AuthedRequest, res) => {
    const { pingEnabled } = req.body ?? {};
    if (typeof pingEnabled !== 'boolean') {
      res.status(400).json({ error: 'Ungültiger Wert für pingEnabled.' });
      return;
    }
    const updatedUser = store.setUserPingEnabled(req.user!.id, pingEnabled);
    if (pingEnabled && store.getSettings().pingAllowed) {
      void pingMonitor.pingUserServers(updatedUser.id);
    }
    res.json({
      user: sanitizeUser(updatedUser),
      dashboardStatus: pingMonitor.getUserStatuses(updatedUser.id),
    });
  });

  app.patch('/api/admin/ping-settings', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    const { pingAllowed, pingIntervalSec } = req.body ?? {};
    const prevAllowed = store.getSettings().pingAllowed;
    try {
      const settings = store.updateGlobalPingSettings({
        pingAllowed: typeof pingAllowed === 'boolean' ? pingAllowed : undefined,
        pingIntervalSec: pingIntervalSec !== undefined ? Number(pingIntervalSec) : undefined,
      });
      const becameEnabled = !prevAllowed && settings.pingAllowed;
      pingMonitor.reschedule(becameEnabled);
      res.json({
        settings,
        dashboardStatus: pingMonitor.getUserStatuses(req.user!.id),
      });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Ping-Einstellungen konnten nicht gespeichert werden.',
      });
    }
  });

  // Dashboard Batch Execution: Execute assigned commands across multiple IPs in one go
  app.post('/api/execute/batch', requireAuth, async (req: AuthedRequest, res) => {
    const { certificateId, jobs, dryRun } = req.body ?? {};

    const certificate = store.getAccessibleCertificate(String(certificateId ?? ''), req.user!.id);
    if (!certificate) {
      res.status(404).json({ error: 'Bitte wählen Sie zuerst ein gültiges 3-Dateien-SSH-Zertifikat aus.' });
      return;
    }

    if (!Array.isArray(jobs) || jobs.length === 0 || jobs.length > 50) {
      res.status(400).json({ error: 'Bitte wählen Sie zwischen 1 und 50 Aufträge für die Sammelausführung aus.' });
      return;
    }

    const resolvedJobs: Array<{
      server: { ipAddress: string; port: number; sshUser: string; label: string };
      command: NonNullable<ReturnType<typeof store.getCommand>>;
    }> = [];

    for (const item of jobs) {
      const srv = store.getAccessibleServer(String(item?.serverId ?? ''), req.user!.id);
      if (!srv) {
        res.status(404).json({ error: `Server "${item?.serverId ?? ''}" wurde nicht gefunden.` });
        return;
      }
      const cmd = store.getAccessibleCommand(String(item?.commandId ?? ''), req.user!.id);
      if (!cmd) {
        res.status(404).json({
          error: `Befehl für Server ${srv.label} (${srv.ipAddress}) ist nicht verfügbar oder deaktiviert.`,
        });
        return;
      }
      resolvedJobs.push({
        server: {
          ipAddress: srv.ipAddress,
          port: srv.port,
          sshUser: srv.sshUser,
          label: srv.label,
        },
        command: cmd,
      });
    }

    const logs = await Promise.all(
      resolvedJobs.map(async ({ server, command }) => {
        const result = await executeSshCommand({
          ipAddress: server.ipAddress,
          port: server.port,
          sshUser: server.sshUser,
          command,
          certificate,
          forceDryRun: Boolean(dryRun),
        });

        return store.addLog({
          userId: req.user!.id,
          username: req.user!.username,
          commandId: command.id,
          commandName: command.name,
          commandText: command.command,
          targetIp: server.ipAddress,
          targetPort: server.port,
          sshUser: server.sshUser,
          serverLabel: server.label,
          certificateId: certificate.id,
          certificateKeyId: certificate.metadata.keyId || certificate.name,
          mode: result.mode,
          sshInvocation: result.sshInvocation,
          exitCode: result.exitCode,
          stdout: result.stdout,
          stderr: result.stderr,
          durationMs: result.durationMs,
        });
      })
    );

    res.json({ results: logs });
  });

  // Execution History / Audit Logs
  app.get('/api/logs', requireAuth, (req: AuthedRequest, res) => {
    res.json({ logs: store.listLogs(req.user!) });
  });

  // Rust Debian Trixie Source Inspector & Archive Download
  app.get('/api/rust-project/files', requireAuth, (_req, res) => {
    res.json({ files: listRustProjectFiles() });
  });

  app.get('/api/rust-project/download', requireAuth, (_req, res) => {
    if (!fs.existsSync(RUST_APP_DIR)) {
      res.status(404).json({ error: 'Rust-Projektverzeichnis nicht gefunden.' });
      return;
    }
    const tarGz = buildRustProjectTarGz(RUST_APP_DIR);
    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Disposition', 'attachment; filename="ssh-console-debian-trixie-rust.tar.gz"');
    res.send(tarGz);
  });

  app.get('/api/rust-project/download-deb', requireAuth, (_req, res) => {
    try {
      const pkg = buildDebianPackage(process.cwd(), RUST_APP_DIR);
      res.setHeader('Content-Type', 'application/vnd.debian.binary-package');
      res.setHeader('Content-Disposition', `attachment; filename="${pkg.fileName}"`);
      res.send(pkg.buffer);
    } catch (err) {
      res.status(500).json({
        error:
          err instanceof Error
            ? `Debian-Paket konnte nicht erzeugt werden: ${err.message}`
            : 'Debian-Paket konnte nicht erzeugt werden.',
      });
    }
  });

  // Vite middleware in development, static dist in production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  pingMonitor.start();
  const PORT = 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SSH Console server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
