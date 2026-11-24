import crypto from 'node:crypto';
import express, { type Request, type Response, type NextFunction } from 'express';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import { generateTestOpenSshCertBundle } from './server/certGen.ts';
import { validateAndParseCertificateBundle } from './server/opensshCert.ts';
import {
  parseAndValidateWorkflow,
  resolveWorkflowRuntimeVars,
  sanitizeRuntimeVarsInput,
} from './src/workflowEngine.ts';
import {
  clearGlobalHostKeys,
  getGlobalKnownHostsStats,
  removeUserHostKey,
} from './server/knownHosts.ts';
import {
  executeSshCommand,
  findOpenSshBinary,
  validateSshUsername,
  validateTargetIp,
} from './server/sshRunner.ts';
import {
  decryptSecret,
  store,
  verifyPassword,
  type StoredApiKey,
  type StoredUser,
  type StoredWebAuthnCredential,
  type UserCertificateBundle,
  type UserRole,
  type WebAuthnCredentialKind,
} from './server/store.ts';
import {
  buildOtpAuthUri,
  generateRecoveryCodes,
  generateTotpSecret,
  hashRecoveryCode,
  verifyTotpCode,
} from './server/totp.ts';
import {
  consumePendingTotpSetup,
  consumeSsoState,
  consumeTwoFactorTicket,
  consumeWebAuthnChallenge,
  createSsoState,
  createTwoFactorTicket,
  createWebAuthnAuthenticationOptions,
  createWebAuthnRegistrationOptions,
  discoverOidcConfiguration,
  exchangeSsoCodeForProfile,
  getSsoCallbackUrl,
  getWebAuthnContext,
  peekTwoFactorTicket,
  storePendingTotpSetup,
  storeWebAuthnChallenge,
  validateExternalEndpointUrl,
  verifyWebAuthnAuthentication,
  verifyWebAuthnRegistration,
} from './server/authSecurity.ts';
import { parseMultipartFormData } from './server/multipart.ts';
import { buildRustProjectTarGz } from './server/tarBuilder.ts';
import { buildDebianPackage } from './server/debBuilder.ts';
import { pingMonitor } from './server/pingMonitor.ts';
import { checkBmcHttps } from './server/bmcCheck.ts';
import { attachSshShellWebSocket, issueShellTicket } from './server/sshShell.ts';
import { backgroundJobs } from './server/backgroundJobs.ts';

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
      if (!key) continue;
      try {
        result[key] = decodeURIComponent(val);
      } catch {
        result[key] = val;
      }
    }
  }
  return result;
}

const MAX_CONCURRENT_SSH_JOBS = 8;

async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  worker: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  if (items.length === 0) return [];
  const results = new Array<R>(items.length);
  let nextIndex = 0;
  const workerCount = Math.min(Math.max(1, limit), items.length);
  await Promise.all(
    Array.from({ length: workerCount }, async () => {
      while (true) {
        const current = nextIndex++;
        if (current >= items.length) break;
        results[current] = await worker(items[current], current);
      }
    })
  );
  return results;
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

function sanitizeWebAuthnCredential(c: StoredWebAuthnCredential) {
  return {
    id: c.id,
    kind: c.kind,
    name: c.name,
    transports: c.transports,
    createdAt: c.createdAt,
    lastUsedAt: c.lastUsedAt,
  };
}

function serializePublicSettings() {
  const s = store.getSettings();
  return {
    instanceName: s.instanceName,
    initializedAt: s.initializedAt,
    pingAllowed: s.pingAllowed,
    pingIntervalSec: s.pingIntervalSec,
    pingOfflineThreshold: s.pingOfflineThreshold ?? 5,
    pingOfflineMultiplier: s.pingOfflineMultiplier ?? 5,
    ssoEnabled: s.ssoEnabled,
    ssoProviderName: s.ssoProviderName || 'SSO',
    ssoAutoCreateUsers: s.ssoAutoCreateUsers,
    ssoConfigured: store.isSsoConfigured(),
    ssoTestedAt: s.ssoTestedAt,
    localLoginDisabled: s.localLoginDisabled,
    twoFactorEnabled: s.twoFactorEnabled,
    twoFactorEnforced: s.twoFactorEnforced,
    passkeyEnabled: s.passkeyEnabled,
    passkeyEnforced: s.passkeyEnforced,
    allowInsecureHostKey: s.allowInsecureHostKey,
    publicUrl: s.publicUrl || '',
    maxBackgroundJobs: s.maxBackgroundJobs ?? 5,
  };
}

function serializeAdminAuthSettings(req: Request) {
  const s = store.getSettings();
  return {
    ssoEnabled: s.ssoEnabled,
    ssoProviderName: s.ssoProviderName || 'SSO',
    ssoIssuerUrl: s.ssoIssuerUrl,
    ssoAuthUrl: s.ssoAuthUrl,
    ssoTokenUrl: s.ssoTokenUrl,
    ssoUserinfoUrl: s.ssoUserinfoUrl,
    ssoClientId: s.ssoClientId,
    ssoHasClientSecret: Boolean(s.ssoClientSecretEncrypted),
    ssoScopes: s.ssoScopes || 'openid profile email',
    ssoAutoCreateUsers: s.ssoAutoCreateUsers,
    ssoConfigured: store.isSsoConfigured(),
    ssoTestedAt: s.ssoTestedAt,
    localLoginDisabled: s.localLoginDisabled,
    twoFactorEnabled: s.twoFactorEnabled,
    twoFactorEnforced: s.twoFactorEnforced,
    passkeyEnabled: s.passkeyEnabled,
    passkeyEnforced: s.passkeyEnforced,
    allowInsecureHostKey: s.allowInsecureHostKey,
    publicUrl: s.publicUrl || '',
    callbackUrl: getSsoCallbackUrl(req),
  };
}

function sanitizeUser(u: StoredUser) {
  const settings = store.getSettings();
  const securityKeyCount = store.listUserWebAuthnCredentials(u.id, 'security-key').length;
  const passkeyCount = store.listUserWebAuthnCredentials(u.id, 'passkey').length;
  const hasTwoFactor = Boolean(u.totpEnabled || securityKeyCount > 0);
  const authProvider = u.authProvider || 'local';
  const isLocal = authProvider === 'local';
  const mustSetupTwoFactor =
    isLocal && settings.twoFactorEnabled && settings.twoFactorEnforced && !hasTwoFactor;
  const mustSetupPasskey =
    isLocal && settings.passkeyEnabled && settings.passkeyEnforced && passkeyCount === 0;

  return {
    id: u.id,
    username: u.username,
    displayName: u.displayName,
    role: u.role,
    authProvider,
    email: u.email || '',
    defaultSshUser: u.defaultSshUser,
    active: u.active,
    pingEnabled: u.pingEnabled !== false,
    totpEnabled: Boolean(u.totpEnabled),
    securityKeyCount,
    passkeyCount,
    hasTwoFactor,
    mustSetupTwoFactor,
    mustSetupPasskey,
    createdAt: u.createdAt,
    lastLoginAt: u.lastLoginAt,
  };
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderSsoCallbackPage(payload: Record<string, unknown>, title: string, message: string): string {
  const safeJson = JSON.stringify(payload)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
  const escapedTitle = escapeHtml(title);
  const escapedMsg = escapeHtml(message);
  return `<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapedTitle}</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 24px; }
    .card { max-width: 420px; background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; text-align: center; }
    h1 { font-size: 18px; margin: 0 0 8px; }
    p { font-size: 14px; color: #94a3b8; margin: 0; }
  </style>
</head>
<body>
  <div class="card">
    <h1>${escapedTitle}</h1>
    <p>${escapedMsg}</p>
  </div>
  <script>
    (function () {
      var data = ${safeJson};
      try {
        if (window.opener && !window.opener.closed) {
          window.opener.postMessage(data, window.location.origin);
          window.close();
          return;
        }
      } catch (e) {}
      setTimeout(function () { window.location.replace('/'); }, 900);
    })();
  </script>
</body>
</html>`;
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

function requireSecurityCompliant(req: AuthedRequest, res: Response, next: NextFunction) {
  if (!req.user) {
    res.status(401).json({ error: 'Anmeldung erforderlich.' });
    return;
  }
  const summary = sanitizeUser(req.user);
  if (summary.mustSetupTwoFactor || summary.mustSetupPasskey) {
    res.status(403).json({
      error:
        'Bitte schließen Sie zuerst die vorgeschriebene Einrichtung von 2FA bzw. Passkey unter Konto & Sicherheit ab.',
      code: 'SECURITY_SETUP_REQUIRED',
    });
    return;
  }
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
];

async function startServer() {
  const app = express();
  app.disable('x-powered-by');
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    if (req.path.startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store');
    }
    next();
  });
  app.use(express.json({ limit: '2mb' }));

  // Same-origin / custom-header check for cookie-authenticated API mutations
  app.use('/api', (req: Request, res: Response, next: NextFunction) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
      next();
      return;
    }
    const hasBearerOrApiKey = Boolean(req.headers.authorization || req.headers['x-api-key']);
    const hasCustomHeader = Boolean(req.headers['x-requested-with']);
    const cookies = parseCookies(req.headers.cookie);
    if (!cookies[COOKIE_NAME] || hasBearerOrApiKey || hasCustomHeader) {
      next();
      return;
    }
    const origin = req.headers.origin;
    const expectedHost = String(req.headers['x-forwarded-host'] || req.headers.host || '')
      .split(',')[0]
      .trim()
      .toLowerCase();
    if (origin && expectedHost) {
      try {
        if (new URL(origin).host.toLowerCase() === expectedHost) {
          next();
          return;
        }
      } catch {
        // invalid origin header falls through to 403
      }
      res.status(403).json({ error: 'Ungültiger Anfrage-Ursprung (Origin).' });
      return;
    }
    next();
  });

  // System & Auth Status
  app.get('/api/status', (req: AuthedRequest, res: Response) => {
    const initialized = store.isInitialized();
    const token = extractSessionToken(req);
    const user = store.getUserBySessionToken(token);
    res.json({
      initialized,
      settings: serializePublicSettings(),
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
        settings: serializePublicSettings(),
        sessionToken: session.token,
      });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Fehler bei der Ersteinrichtung.' });
    }
  });

  // Local Login (no public registration; respects localLoginDisabled, Passkey enforcement, and 2FA)
  app.post('/api/auth/login', async (req: Request, res: Response) => {
    if (!store.isInitialized()) {
      res.status(409).json({ error: 'Bitte schließen Sie zuerst die Admin-Ersteinrichtung ab.' });
      return;
    }
    const settings = store.getSettings();
    if (settings.localLoginDisabled) {
      res.status(403).json({
        error: 'Die lokale Anmeldung ist deaktiviert. Bitte melden Sie sich über SSO an.',
      });
      return;
    }
    const { username, password } = req.body ?? {};
    if (typeof username !== 'string' || typeof password !== 'string') {
      res.status(400).json({ error: 'Benutzername und Passwort sind erforderlich.' });
      return;
    }

    const user = store.findUserByUsername(username);
    if (!user) {
      res.status(401).json({ error: 'Ungültiger Benutzername oder falsches Passwort.' });
      return;
    }
    if ((user.authProvider || 'local') === 'sso') {
      res.status(403).json({
        error: 'Dieses Konto nutzt SSO. Bitte melden Sie sich über den SSO-Anbieter an.',
      });
      return;
    }
    if (!verifyPassword(password, user.passwordSalt, user.passwordHash)) {
      res.status(401).json({ error: 'Ungültiger Benutzername oder falsches Passwort.' });
      return;
    }
    if (!user.active) {
      res.status(403).json({ error: 'Dieses Benutzerkonto wurde vom Administrator deaktiviert.' });
      return;
    }

    // If Passkeys are enforced and the user already has a Passkey, require Passkey login
    const passkeyCount = store.listUserWebAuthnCredentials(user.id, 'passkey').length;
    if (settings.passkeyEnabled && settings.passkeyEnforced && passkeyCount > 0) {
      res.status(403).json({
        error:
          'Passkey-Anmeldung ist vorgeschrieben. Bitte nutzen Sie die Schaltfläche „Mit Passkey anmelden“.',
        code: 'PASSKEY_REQUIRED',
      });
      return;
    }

    // If 2FA is enabled and the user has TOTP or a Security Key configured, start step 2
    const securityKeys = store.listUserWebAuthnCredentials(user.id, 'security-key');
    const hasTotp = Boolean(user.totpEnabled);
    const hasSecurityKey = securityKeys.length > 0;
    if (settings.twoFactorEnabled && (hasTotp || hasSecurityKey)) {
      const { rpId } = getWebAuthnContext(req);
      const webauthnOptions = hasSecurityKey
        ? await createWebAuthnAuthenticationOptions({
            rpId,
            allowCredentials: securityKeys,
            requireUserVerification: false,
          })
        : null;
      const ticket = createTwoFactorTicket(user.id, webauthnOptions?.challenge);
      res.json({
        requiresTwoFactor: true,
        ticket,
        methods: {
          totp: hasTotp,
          securityKey: hasSecurityKey,
        },
        webauthnOptions,
      });
      return;
    }

    const session = store.createSession(user.id);
    setSessionCookie(req, res, session.token);
    res.json({
      user: sanitizeUser(user),
      sessionToken: session.token,
    });
  });

  // Local Login Step 2: Verify 2FA (Authenticator App TOTP, Recovery Code, or Hardware Security Key)
  app.post('/api/auth/login/2fa', async (req: Request, res: Response) => {
    const { ticket, method, code, assertion } = req.body ?? {};
    if (typeof ticket !== 'string' || !ticket.trim()) {
      res.status(400).json({ error: '2FA-Anmeldeticket fehlt oder ist abgelaufen.' });
      return;
    }
    const pending = peekTwoFactorTicket(ticket.trim());
    if (!pending) {
      res.status(401).json({ error: 'Die 2FA-Sitzung ist abgelaufen. Bitte melden Sie sich erneut an.' });
      return;
    }
    const user = store.findUserById(pending.userId);
    if (!user || !user.active) {
      consumeTwoFactorTicket(ticket.trim());
      res.status(403).json({ error: 'Benutzerkonto ist nicht verfügbar.' });
      return;
    }

    if (method === 'totp') {
      const secret = store.getUserTotpSecretPlain(user.id);
      if (!secret || typeof code !== 'string' || !verifyTotpCode(secret, code)) {
        res.status(401).json({ error: 'Ungültiger Authenticator-Code. Bitte erneut versuchen.' });
        return;
      }
    } else if (method === 'recovery') {
      if (typeof code !== 'string' || !code.trim()) {
        res.status(400).json({ error: 'Bitte geben Sie einen Wiederherstellungscode ein.' });
        return;
      }
      const ok = store.consumeRecoveryCode(user.id, hashRecoveryCode(code));
      if (!ok) {
        res.status(401).json({ error: 'Ungültiger oder bereits verwendeter Wiederherstellungscode.' });
        return;
      }
    } else if (method === 'security-key') {
      if (!pending.webauthnChallenge || !assertion || typeof assertion.id !== 'string') {
        res.status(400).json({ error: 'Ungültige Sicherheitsschlüssel-Antwort.' });
        return;
      }
      const cred = store.findWebAuthnCredentialByCredId(assertion.id);
      if (!cred || cred.userId !== user.id || cred.kind !== 'security-key') {
        res.status(401).json({ error: 'Sicherheitsschlüssel gehört nicht zu diesem Benutzerkonto.' });
        return;
      }
      const { origin, rpId } = getWebAuthnContext(req);
      try {
        const result = await verifyWebAuthnAuthentication({
          response: assertion,
          expectedChallenge: pending.webauthnChallenge,
          expectedOrigin: origin,
          expectedRPID: rpId,
          credential: cred,
          requireUserVerification: false,
        });
        store.updateWebAuthnCredentialUsage(cred.id, result.newCounter);
      } catch (err) {
        res.status(401).json({
          error:
            err instanceof Error
              ? err.message
              : 'Sicherheitsschlüssel konnte nicht verifiziert werden.',
        });
        return;
      }
    } else {
      res.status(400).json({ error: 'Unbekannte 2FA-Methode.' });
      return;
    }

    consumeTwoFactorTicket(ticket.trim());
    const session = store.createSession(user.id);
    setSessionCookie(req, res, session.token);
    res.json({
      user: sanitizeUser(user),
      sessionToken: session.token,
    });
  });

  // Passkey Passwordless Login
  app.post('/api/auth/passkey/login/options', async (req: Request, res: Response) => {
    if (!store.isInitialized()) {
      res.status(409).json({ error: 'Bitte schließen Sie zuerst die Admin-Ersteinrichtung ab.' });
      return;
    }
    const settings = store.getSettings();
    if (settings.localLoginDisabled) {
      res.status(403).json({ error: 'Die lokale Anmeldung ist deaktiviert. Bitte nutzen Sie SSO.' });
      return;
    }
    if (!settings.passkeyEnabled) {
      res.status(403).json({ error: 'Passkeys sind vom Administrator nicht aktiviert.' });
      return;
    }
    const { origin, rpId } = getWebAuthnContext(req);
    const options = await createWebAuthnAuthenticationOptions({
      rpId,
      requireUserVerification: true,
    });
    const challengeId = storeWebAuthnChallenge({
      challenge: options.challenge,
      kind: 'passkey-login',
      rpId,
      origin,
    });
    res.json({ challengeId, options });
  });

  app.post('/api/auth/passkey/login/verify', async (req: Request, res: Response) => {
    const settings = store.getSettings();
    if (settings.localLoginDisabled || !settings.passkeyEnabled) {
      res.status(403).json({ error: 'Passkey-Anmeldung ist derzeit nicht verfügbar.' });
      return;
    }
    const { challengeId, response } = req.body ?? {};
    if (typeof challengeId !== 'string' || !response || typeof response.id !== 'string') {
      res.status(400).json({ error: 'Ungültige Passkey-Anmeldedaten.' });
      return;
    }
    const challenge = consumeWebAuthnChallenge(challengeId);
    if (!challenge || challenge.kind !== 'passkey-login') {
      res.status(401).json({ error: 'Passkey-Challenge ist abgelaufen. Bitte erneut versuchen.' });
      return;
    }
    const cred = store.findWebAuthnCredentialByCredId(response.id);
    if (!cred || cred.kind !== 'passkey') {
      res.status(401).json({ error: 'Unbekannter Passkey.' });
      return;
    }
    const user = store.findUserById(cred.userId);
    if (!user || !user.active) {
      res.status(403).json({ error: 'Das zugehörige Benutzerkonto ist deaktiviert.' });
      return;
    }

    try {
      const result = await verifyWebAuthnAuthentication({
        response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: challenge.origin,
        expectedRPID: challenge.rpId,
        credential: cred,
        requireUserVerification: true,
      });
      store.updateWebAuthnCredentialUsage(cred.id, result.newCounter);
      const session = store.createSession(user.id);
      setSessionCookie(req, res, session.token);
      res.json({
        user: sanitizeUser(user),
        sessionToken: session.token,
      });
    } catch (err) {
      res.status(401).json({
        error: err instanceof Error ? err.message : 'Passkey konnte nicht verifiziert werden.',
      });
    }
  });

  // OIDC / OAuth 2.0 SSO (Popup Authorization URL + Callback for both login & admin test gate)
  app.get('/api/auth/sso/url', (req: Request, res: Response) => {
    const mode = req.query.mode === 'test' ? 'test' : 'login';
    const settings = store.getSettings();
    let adminUserId: string | undefined;

    if (mode === 'test') {
      const token = extractSessionToken(req);
      const admin = store.getUserBySessionToken(token);
      if (!admin || admin.role !== 'admin') {
        res.status(403).json({ error: 'Nur Administratoren können einen SSO-Test starten.' });
        return;
      }
      adminUserId = admin.id;
    } else if (!settings.ssoEnabled) {
      res.status(403).json({ error: 'SSO ist nicht aktiviert.' });
      return;
    }

    if (!store.isSsoConfigured()) {
      res.status(400).json({
        error: 'SSO ist nicht vollständig konfiguriert (Authorization-URL, Token-URL und Client-ID erforderlich).',
      });
      return;
    }

    let authEndpoint: string;
    try {
      authEndpoint = validateExternalEndpointUrl(settings.ssoAuthUrl);
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Ungültige SSO Authorization-URL.' });
      return;
    }

    const redirectUri = getSsoCallbackUrl(req);
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const { state, codeChallenge } = createSsoState({
      mode,
      adminUserId,
      codeVerifier,
      redirectUri,
    });

    const url = new URL(authEndpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', settings.ssoClientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('scope', settings.ssoScopes || 'openid profile email');
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');

    res.json({
      url: url.toString(),
      callbackUrl: redirectUri,
    });
  });

  const handleSsoCallback = async (req: Request, res: Response) => {
    const errorParam = typeof req.query.error === 'string' ? req.query.error : '';
    const errorDesc =
      typeof req.query.error_description === 'string' ? req.query.error_description : '';
    if (errorParam) {
      const msg = errorDesc || errorParam;
      res
        .status(200)
        .type('html')
        .send(
          renderSsoCallbackPage(
            { type: 'SSO_ERROR', error: `SSO-Anbieter meldete Fehler: ${msg}` },
            'SSO-Anmeldung fehlgeschlagen',
            msg
          )
        );
      return;
    }

    const code = typeof req.query.code === 'string' ? req.query.code : '';
    const state = typeof req.query.state === 'string' ? req.query.state : '';
    if (!code || !state) {
      res
        .status(400)
        .type('html')
        .send(
          renderSsoCallbackPage(
            { type: 'SSO_ERROR', error: 'Ungültige SSO-Callback-Parameter (code/state fehlt).' },
            'SSO-Callback ungültig',
            'Fehlende Parameter.'
          )
        );
      return;
    }

    const stateEntry = consumeSsoState(state);
    if (!stateEntry) {
      res
        .status(400)
        .type('html')
        .send(
          renderSsoCallbackPage(
            { type: 'SSO_ERROR', error: 'SSO-Anfrage ist abgelaufen oder wurde bereits verwendet.' },
            'SSO-Sitzung abgelaufen',
            'Bitte starten Sie die Anmeldung erneut.'
          )
        );
      return;
    }

    const settings = store.getSettings();
    try {
      const profile = await exchangeSsoCodeForProfile({
        tokenUrl: settings.ssoTokenUrl,
        userinfoUrl: settings.ssoUserinfoUrl,
        clientId: settings.ssoClientId,
        clientSecret: store.getSsoClientSecretPlain(),
        code,
        codeVerifier: stateEntry.codeVerifier,
        redirectUri: stateEntry.redirectUri,
      });

      if (stateEntry.mode === 'test') {
        const updated = store.markSsoTested();
        res
          .status(200)
          .type('html')
          .send(
            renderSsoCallbackPage(
              {
                type: 'SSO_TEST_SUCCESS',
                testedAt: updated.ssoTestedAt,
                profile: {
                  username: profile.username,
                  displayName: profile.displayName,
                  email: profile.email,
                },
              },
              'SSO-Test erfolgreich',
              `Verbindung bestätigt für ${profile.displayName} (${profile.email || profile.username}). Dieses Fenster schließt sich automatisch.`
            )
          );
        return;
      }

      const { user, created } = store.findOrCreateSsoUser(profile);
      const session = store.createSession(user.id);
      setSessionCookie(req, res, session.token);
      res
        .status(200)
        .type('html')
        .send(
          renderSsoCallbackPage(
            {
              type: 'SSO_LOGIN_SUCCESS',
              sessionToken: session.token,
              created,
            },
            'SSO-Anmeldung erfolgreich',
            `Angemeldet als ${user.displayName}. Dieses Fenster schließt sich automatisch.`
          )
        );
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'SSO-Authentifizierung fehlgeschlagen.';
      res
        .status(200)
        .type('html')
        .send(
          renderSsoCallbackPage(
            { type: 'SSO_ERROR', error: msg },
            'SSO fehlgeschlagen',
            msg
          )
        );
    }
  };

  app.get('/api/auth/sso/callback', handleSsoCallback);
  app.get('/api/auth/sso/callback/', handleSsoCallback);

  app.post('/api/auth/logout', (req: AuthedRequest, res: Response) => {
    const token = extractSessionToken(req);
    store.deleteSession(token);
    clearSessionCookie(req, res);
    res.json({ ok: true });
  });

  // Self-service 2FA (Authenticator App TOTP + Hardware Security Keys) & Passkeys
  app.get('/api/auth/security', requireAuth, (req: AuthedRequest, res: Response) => {
    const user = req.user!;
    const securityKeys = store
      .listUserWebAuthnCredentials(user.id, 'security-key')
      .map(sanitizeWebAuthnCredential);
    const passkeys = store
      .listUserWebAuthnCredentials(user.id, 'passkey')
      .map(sanitizeWebAuthnCredential);
    res.json({
      totpEnabled: Boolean(user.totpEnabled),
      recoveryCodesRemaining: user.totpRecoveryHashes?.length ?? 0,
      securityKeys,
      passkeys,
    });
  });

  app.post('/api/auth/2fa/totp/setup', requireAuth, (req: AuthedRequest, res: Response) => {
    const settings = store.getSettings();
    if (!settings.twoFactorEnabled) {
      res.status(403).json({ error: '2-Faktor-Authentifizierung ist vom Administrator nicht eingeschaltet.' });
      return;
    }
    const secret = generateTotpSecret();
    storePendingTotpSetup(req.user!.id, secret);
    const otpauthUri = buildOtpAuthUri({
      issuer: settings.instanceName || 'SSH Console',
      accountName: req.user!.username,
      secret,
    });
    res.json({ secret, otpauthUri });
  });

  app.post('/api/auth/2fa/totp/verify', requireAuth, (req: AuthedRequest, res: Response) => {
    const settings = store.getSettings();
    if (!settings.twoFactorEnabled) {
      res.status(403).json({ error: '2-Faktor-Authentifizierung ist vom Administrator nicht eingeschaltet.' });
      return;
    }
    const code = typeof req.body?.code === 'string' ? req.body.code : '';
    const pending = consumePendingTotpSetup(req.user!.id);
    if (!pending) {
      res.status(400).json({ error: 'Keine aktive Authenticator-Einrichtung gefunden. Bitte starten Sie erneut.' });
      return;
    }
    if (!verifyTotpCode(pending.secret, code)) {
      // Keep setup alive if user mistyped the 6-digit code
      storePendingTotpSetup(req.user!.id, pending.secret);
      res.status(400).json({ error: 'Ungültiger 6-stelliger Code. Bitte prüfen Sie die Uhrzeit und versuchen Sie es erneut.' });
      return;
    }
    const { plainCodes, hashedCodes } = generateRecoveryCodes(8);
    const updatedUser = store.setUserTotp(req.user!.id, pending.secret, hashedCodes);
    res.json({
      ok: true,
      recoveryCodes: plainCodes,
      user: sanitizeUser(updatedUser),
    });
  });

  app.delete('/api/auth/2fa/totp', requireAuth, (req: AuthedRequest, res: Response) => {
    const settings = store.getSettings();
    const user = req.user!;
    const securityKeyCount = store.listUserWebAuthnCredentials(user.id, 'security-key').length;
    if (
      (user.authProvider || 'local') === 'local' &&
      settings.twoFactorEnabled &&
      settings.twoFactorEnforced &&
      securityKeyCount === 0
    ) {
      res.status(400).json({
        error:
          '2FA ist vom Administrator erzwungen. Registrieren Sie zuerst einen Hardware-Sicherheitsschlüssel, bevor Sie die Authenticator-App entfernen.',
      });
      return;
    }
    const updatedUser = store.disableUserTotp(user.id);
    res.json({ ok: true, user: sanitizeUser(updatedUser) });
  });

  app.post('/api/auth/webauthn/register/options', requireAuth, async (req: AuthedRequest, res: Response) => {
    const settings = store.getSettings();
    const kind: WebAuthnCredentialKind =
      req.body?.kind === 'passkey' ? 'passkey' : 'security-key';
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';

    if (kind === 'security-key' && !settings.twoFactorEnabled) {
      res.status(403).json({ error: '2-Faktor-Authentifizierung ist vom Administrator nicht eingeschaltet.' });
      return;
    }
    if (kind === 'passkey' && !settings.passkeyEnabled) {
      res.status(403).json({ error: 'Passkeys sind vom Administrator nicht eingeschaltet.' });
      return;
    }

    const { origin, rpId } = getWebAuthnContext(req);
    const existing = store.listUserWebAuthnCredentials(req.user!.id);
    const options = await createWebAuthnRegistrationOptions({
      rpName: settings.instanceName || 'SSH Console',
      rpId,
      userId: req.user!.id,
      username: req.user!.username,
      displayName: req.user!.displayName,
      kind,
      existingCredentials: existing,
    });
    const challengeId = storeWebAuthnChallenge({
      challenge: options.challenge,
      userId: req.user!.id,
      kind,
      name: name || (kind === 'passkey' ? 'Passkey' : 'Security Key'),
      rpId,
      origin,
    });
    res.json({ challengeId, options });
  });

  app.post('/api/auth/webauthn/register/verify', requireAuth, async (req: AuthedRequest, res: Response) => {
    const { challengeId, response, name } = req.body ?? {};
    if (typeof challengeId !== 'string' || !response) {
      res.status(400).json({ error: 'Ungültige Registrierungsdaten.' });
      return;
    }
    const challenge = consumeWebAuthnChallenge(challengeId);
    if (
      !challenge ||
      challenge.userId !== req.user!.id ||
      (challenge.kind !== 'security-key' && challenge.kind !== 'passkey')
    ) {
      res.status(400).json({ error: 'Registrierungs-Challenge ist abgelaufen. Bitte erneut starten.' });
      return;
    }

    try {
      const verified = await verifyWebAuthnRegistration({
        response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: challenge.origin,
        expectedRPID: challenge.rpId,
        kind: challenge.kind,
      });
      const label =
        typeof name === 'string' && name.trim() ? name.trim() : challenge.name || 'WebAuthn';
      const saved = store.addWebAuthnCredential({
        userId: req.user!.id,
        kind: challenge.kind,
        name: label,
        credentialId: verified.credentialId,
        publicKey: verified.publicKey,
        counter: verified.counter,
        transports: verified.transports,
      });
      const freshUser = store.findUserById(req.user!.id) ?? req.user!;
      res.status(201).json({
        ok: true,
        credential: sanitizeWebAuthnCredential(saved),
        user: sanitizeUser(freshUser),
      });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Registrierung konnte nicht verifiziert werden.',
      });
    }
  });

  app.delete('/api/auth/webauthn/:id', requireAuth, (req: AuthedRequest, res: Response) => {
    const user = req.user!;
    const settings = store.getSettings();
    const allCreds = store.listUserWebAuthnCredentials(user.id);
    const target = allCreds.find((c) => c.id === req.params.id);
    if (!target) {
      res.status(404).json({ error: 'Schlüssel nicht gefunden.' });
      return;
    }
    const isLocal = (user.authProvider || 'local') === 'local';
    if (
      isLocal &&
      target.kind === 'security-key' &&
      settings.twoFactorEnabled &&
      settings.twoFactorEnforced &&
      !user.totpEnabled &&
      allCreds.filter((c) => c.kind === 'security-key').length <= 1
    ) {
      res.status(400).json({
        error:
          '2FA ist erzwungen. Der letzte Sicherheitsschlüssel kann nicht entfernt werden, solange keine Authenticator-App aktiv ist.',
      });
      return;
    }
    if (
      isLocal &&
      target.kind === 'passkey' &&
      settings.passkeyEnabled &&
      settings.passkeyEnforced &&
      allCreds.filter((c) => c.kind === 'passkey').length <= 1
    ) {
      res.status(400).json({
        error: 'Passkeys sind erzwungen. Der letzte Passkey kann nicht entfernt werden.',
      });
      return;
    }
    store.deleteWebAuthnCredential(target.id, user.id);
    const freshUser = store.findUserById(user.id) ?? user;
    res.json({ ok: true, user: sanitizeUser(freshUser) });
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

  app.post('/api/admin/users/:id/reset-auth', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    try {
      const updated = store.resetUserSecondFactors(req.params.id);
      res.json({ ok: true, user: sanitizeUser(updated) });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : '2FA/Passkeys konnten nicht zurückgesetzt werden.',
      });
    }
  });

  // Admin: SSO, 2FA & Passkey Security Policy Settings
  app.get('/api/admin/auth/settings', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    res.json({
      authSettings: serializeAdminAuthSettings(req),
      settings: serializePublicSettings(),
    });
  });

  app.patch('/api/admin/auth/settings', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    const body = req.body ?? {};
    try {
      const validateOptUrl = (val: unknown): string | undefined => {
        if (val === undefined) return undefined;
        if (typeof val !== 'string') throw new Error('Ungültige URL-Angabe.');
        const trimmed = val.trim();
        if (!trimmed) return '';
        return validateExternalEndpointUrl(trimmed);
      };

      store.updateAuthSettings({
        ssoEnabled: typeof body.ssoEnabled === 'boolean' ? body.ssoEnabled : undefined,
        ssoProviderName: typeof body.ssoProviderName === 'string' ? body.ssoProviderName : undefined,
        ssoIssuerUrl: validateOptUrl(body.ssoIssuerUrl),
        ssoAuthUrl: validateOptUrl(body.ssoAuthUrl),
        ssoTokenUrl: validateOptUrl(body.ssoTokenUrl),
        ssoUserinfoUrl: validateOptUrl(body.ssoUserinfoUrl),
        ssoClientId: typeof body.ssoClientId === 'string' ? body.ssoClientId : undefined,
        ssoClientSecret: typeof body.ssoClientSecret === 'string' ? body.ssoClientSecret : undefined,
        clearSsoClientSecret: Boolean(body.clearSsoClientSecret),
        ssoScopes: typeof body.ssoScopes === 'string' ? body.ssoScopes : undefined,
        ssoAutoCreateUsers:
          typeof body.ssoAutoCreateUsers === 'boolean' ? body.ssoAutoCreateUsers : undefined,
        localLoginDisabled:
          typeof body.localLoginDisabled === 'boolean' ? body.localLoginDisabled : undefined,
        twoFactorEnabled:
          typeof body.twoFactorEnabled === 'boolean' ? body.twoFactorEnabled : undefined,
        twoFactorEnforced:
          typeof body.twoFactorEnforced === 'boolean' ? body.twoFactorEnforced : undefined,
        passkeyEnabled:
          typeof body.passkeyEnabled === 'boolean' ? body.passkeyEnabled : undefined,
        passkeyEnforced:
          typeof body.passkeyEnforced === 'boolean' ? body.passkeyEnforced : undefined,
        allowInsecureHostKey:
          typeof body.allowInsecureHostKey === 'boolean' ? body.allowInsecureHostKey : undefined,
        publicUrl: typeof body.publicUrl === 'string' ? body.publicUrl : undefined,
      });

      res.json({
        authSettings: serializeAdminAuthSettings(req),
        settings: serializePublicSettings(),
        user: req.user ? sanitizeUser(store.findUserById(req.user.id) ?? req.user) : null,
      });
    } catch (err) {
      res.status(400).json({
        error:
          err instanceof Error
            ? err.message
            : 'Authentifizierungseinstellungen konnten nicht gespeichert werden.',
      });
    }
  });

  app.post('/api/admin/auth/sso/discover', requireAuth, requireAdmin, async (req: AuthedRequest, res) => {
    const issuerUrl = typeof req.body?.issuerUrl === 'string' ? req.body.issuerUrl.trim() : '';
    if (!issuerUrl) {
      res.status(400).json({ error: 'Bitte geben Sie eine OIDC Issuer-URL ein.' });
      return;
    }
    try {
      const discovered = await discoverOidcConfiguration(issuerUrl);
      res.json({ discovered });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'OIDC Auto-Discovery fehlgeschlagen.',
      });
    }
  });

  // SSH Commands (only visible to creator, except items explicitly shared by an admin)
  app.get('/api/commands', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
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
      workflowJson,
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
    const isWorkflow = kind === 'workflow';
    if (!isChain && !isWorkflow && (typeof command !== 'string' || !command.trim())) {
      res.status(400).json({ error: 'Der auszuführende SSH-Befehl ist erforderlich.' });
      return;
    }
    if (isChain && (!Array.isArray(steps) || steps.length === 0)) {
      res.status(400).json({ error: 'Eine Befehlskette benötigt mindestens einen Schritt.' });
      return;
    }
    if (isWorkflow && (typeof workflowJson !== 'string' || !workflowJson.trim())) {
      res.status(400).json({ error: 'Eine komplexe Befehlskette benötigt eine gültige JSON-Definition.' });
      return;
    }
    const isAdmin = req.user!.role === 'admin';
    try {
      const created = store.createCommand({
        userId: req.user!.id,
        name,
        category: typeof category === 'string' ? category : 'Allgemein',
        kind: isWorkflow ? 'workflow' : isChain ? 'chain' : 'single',
        command: typeof command === 'string' ? command : '',
        steps: Array.isArray(steps) ? steps : [],
        workflowJson: typeof workflowJson === 'string' ? workflowJson : '',
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

  const handleBulkUpdateCommands = (req: AuthedRequest, res: Response) => {
    const { commandIds, category, enabled, sharing } = req.body ?? {};
    if (!Array.isArray(commandIds) || commandIds.length === 0) {
      res.status(400).json({ error: 'Bitte wählen Sie mindestens einen SSH-Befehl aus.' });
      return;
    }
    if (commandIds.length > 500) {
      res.status(400).json({ error: 'Maximal 500 Befehle pro Sammeleinstellung erlaubt.' });
      return;
    }
    const isAdmin = req.user!.role === 'admin';
    if (sharing !== undefined && !isAdmin) {
      res.status(403).json({ error: 'Nur Administratoren dürfen Freigaben ändern.' });
      return;
    }
    const hasCategory = typeof category === 'string' && category.trim().length > 0;
    const hasEnabled = typeof enabled === 'boolean';
    const hasSharing = sharing !== undefined && typeof sharing === 'object' && sharing !== null;
    if (!hasCategory && !hasEnabled && !hasSharing) {
      res.status(400).json({ error: 'Bitte wählen Sie mindestens eine zu ändernde Einstellung aus.' });
      return;
    }
    try {
      const updated = store.bulkUpdateCommands({
        commandIds,
        ownerUserId: req.user!.id,
        isAdmin,
        category: hasCategory ? category : undefined,
        enabled: hasEnabled ? enabled : undefined,
        sharing: hasSharing
          ? {
              sharedWithAll: Boolean(sharing.sharedWithAll),
              sharedWithUserIds: Array.isArray(sharing.sharedWithUserIds)
                ? sharing.sharedWithUserIds
                : [],
            }
          : undefined,
      });
      res.json({ updatedCount: updated.length, commands: updated });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Sammeleinstellung konnte nicht gespeichert werden.';
      const status = msg.includes('selbst angelegte') ? 403 : 400;
      res.status(status).json({ error: msg });
    }
  };

  app.post('/api/commands', requireAuth, requireSecurityCompliant, handleCreateCommand);
  app.post('/api/admin/commands', requireAuth, requireSecurityCompliant, handleCreateCommand);

  app.post('/api/commands/presets', requireAuth, requireSecurityCompliant, handleLoadPresets);
  app.post('/api/admin/commands/presets', requireAuth, requireSecurityCompliant, handleLoadPresets);

  app.patch('/api/commands/bulk', requireAuth, requireSecurityCompliant, handleBulkUpdateCommands);
  app.patch('/api/admin/commands/bulk', requireAuth, requireSecurityCompliant, handleBulkUpdateCommands);

  app.patch('/api/commands/:id', requireAuth, requireSecurityCompliant, handleUpdateCommand);
  app.patch('/api/admin/commands/:id', requireAuth, requireSecurityCompliant, handleUpdateCommand);

  app.patch('/api/commands/:id/share', requireAuth, requireAdmin, handleShareCommand);

  app.delete('/api/commands/:id', requireAuth, requireSecurityCompliant, handleDeleteCommand);
  app.delete('/api/admin/commands/:id', requireAuth, requireSecurityCompliant, handleDeleteCommand);

  // Server Categories (reusable per-user category catalog)
  app.get('/api/server-categories', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    res.json({ categories: store.listServerCategories(req.user!.id) });
  });

  app.post('/api/server-categories', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    const name = typeof req.body?.name === 'string' ? req.body.name : '';
    try {
      const category = store.createServerCategory(req.user!.id, name);
      res.status(201).json({ category });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Kategorie konnte nicht angelegt werden.',
      });
    }
  });

  app.delete(
    '/api/server-categories/:id',
    requireAuth,
    requireSecurityCompliant,
    (req: AuthedRequest, res) => {
      const deleted = store.deleteServerCategory(req.params.id, req.user!.id);
      if (!deleted) {
        res.status(404).json({ error: 'Kategorie nicht gefunden.' });
        return;
      }
      res.json({ ok: true });
    }
  );

  // User Target Servers (IP addresses — creator-private; admin may share)
  app.get('/api/servers', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    res.json({ servers: store.listAccessibleServers(req.user!.id) });
  });

  app.post('/api/servers', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    const {
      label,
      ipAddress,
      bmcIpAddress,
      bmcIpAddress2,
      port,
      sshUser,
      notes,
      categories,
      pingEnabled,
      ignoreHostKey,
      sharedWithAll,
      sharedWithUserIds,
    } = req.body ?? {};
    if (typeof ipAddress !== 'string' || !validateTargetIp(ipAddress)) {
      res.status(400).json({ error: 'Bitte geben Sie eine gültige IPv4- oder IPv6-Adresse an.' });
      return;
    }
    const cleanBmcIp = typeof bmcIpAddress === 'string' ? bmcIpAddress.trim() : '';
    if (cleanBmcIp && !validateTargetIp(cleanBmcIp)) {
      res.status(400).json({ error: 'Bitte geben Sie eine gültige IPv4- oder IPv6-Adresse für BMC-IP 1 an (oder lassen Sie das Feld leer).' });
      return;
    }
    const cleanBmcIp2 = typeof bmcIpAddress2 === 'string' ? bmcIpAddress2.trim() : '';
    if (cleanBmcIp2 && !validateTargetIp(cleanBmcIp2)) {
      res.status(400).json({ error: 'Bitte geben Sie eine gültige IPv4- oder IPv6-Adresse für BMC-IP 2 an (oder lassen Sie das Feld leer).' });
      return;
    }
    const cleanSshUser = typeof sshUser === 'string' && sshUser.trim() ? sshUser.trim() : req.user!.defaultSshUser;
    if (!validateSshUsername(cleanSshUser)) {
      res.status(400).json({ error: 'Ungültiger SSH-Benutzername (erlaubt: a-z, 0-9, ., _, -).' });
      return;
    }
    if (Boolean(ignoreHostKey) && !store.getSettings().allowInsecureHostKey) {
      res.status(403).json({
        error:
          'Das Deaktivieren der SSH-Host-Key-Prüfung (StrictHostKeyChecking=no) ist vom Administrator global verboten.',
      });
      return;
    }
    const isAdmin = req.user!.role === 'admin';
    const server = store.createServer({
      userId: req.user!.id,
      ownerUsername: req.user!.username,
      label: typeof label === 'string' ? label : ipAddress,
      ipAddress: ipAddress.trim(),
      bmcIpAddress: cleanBmcIp,
      bmcIpAddress2: cleanBmcIp2,
      port: Number(port) || 22,
      sshUser: cleanSshUser,
      notes: typeof notes === 'string' ? notes : '',
      categories: Array.isArray(categories) ? categories : [],
      pingEnabled: pingEnabled !== undefined ? Boolean(pingEnabled) : true,
      ignoreHostKey: Boolean(ignoreHostKey),
      sharedWithAll: isAdmin ? Boolean(sharedWithAll) : false,
      sharedWithUserIds: isAdmin && Array.isArray(sharedWithUserIds) ? sharedWithUserIds : [],
    });
    // Trigger background initial ping only if allowed globally, for user, and for this server
    if (server.pingEnabled && store.getSettings().pingAllowed && req.user!.pingEnabled !== false) {
      void pingMonitor.pingUserServers(req.user!.id, server.id);
    }
    res.status(201).json({ server });
  });

  app.patch('/api/servers/bulk', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    const {
      serverIds,
      pingEnabled,
      ignoreHostKey,
      categoriesAction,
      categories,
      sharing,
    } = req.body ?? {};

    if (!Array.isArray(serverIds) || serverIds.length === 0) {
      res.status(400).json({ error: 'Bitte wählen Sie mindestens einen Server (IP) aus.' });
      return;
    }
    if (serverIds.length > 500) {
      res.status(400).json({ error: 'Maximal 500 Server pro Sammeleinstellung erlaubt.' });
      return;
    }
    const isAdmin = req.user!.role === 'admin';
    if (sharing !== undefined && !isAdmin) {
      res.status(403).json({ error: 'Nur Administratoren dürfen Freigaben ändern.' });
      return;
    }
    const validCatAction =
      categoriesAction === 'add' || categoriesAction === 'remove' || categoriesAction === 'replace'
        ? categoriesAction
        : undefined;
    if (categoriesAction !== undefined && !validCatAction) {
      res.status(400).json({ error: 'Ungültige Kategorie-Aktion (erlaubt: add, remove, replace).' });
      return;
    }
    if (ignoreHostKey === true && !store.getSettings().allowInsecureHostKey) {
      res.status(403).json({
        error:
          'Das Deaktivieren der SSH-Host-Key-Prüfung (StrictHostKeyChecking=no) ist vom Administrator global verboten.',
      });
      return;
    }
    const hasPing = typeof pingEnabled === 'boolean';
    const hasHostKey = typeof ignoreHostKey === 'boolean';
    const hasCategories = validCatAction !== undefined;
    const hasSharing = sharing !== undefined && typeof sharing === 'object' && sharing !== null;
    if (!hasPing && !hasHostKey && !hasCategories && !hasSharing) {
      res.status(400).json({ error: 'Bitte wählen Sie mindestens eine zu ändernde Einstellung aus.' });
      return;
    }

    try {
      const updated = store.bulkUpdateServers({
        serverIds,
        ownerUserId: req.user!.id,
        isAdmin,
        pingEnabled: hasPing ? pingEnabled : undefined,
        ignoreHostKey: hasHostKey ? ignoreHostKey : undefined,
        categoriesAction: validCatAction,
        categories: hasCategories && Array.isArray(categories) ? categories : [],
        sharing: hasSharing
          ? {
              sharedWithAll: Boolean(sharing.sharedWithAll),
              sharedWithUserIds: Array.isArray(sharing.sharedWithUserIds)
                ? sharing.sharedWithUserIds
                : [],
            }
          : undefined,
      });
      if (pingEnabled === true && store.getSettings().pingAllowed && req.user!.pingEnabled !== false) {
        void pingMonitor.pingUserServers(req.user!.id);
      }
      res.json({ updatedCount: updated.length, servers: updated });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Sammeleinstellung konnte nicht gespeichert werden.';
      const status = msg.includes('selbst angelegte') ? 403 : 400;
      res.status(status).json({ error: msg });
    }
  });

  app.patch('/api/servers/:id', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    const {
      label,
      ipAddress,
      bmcIpAddress,
      bmcIpAddress2,
      port,
      sshUser,
      notes,
      categories,
      pingEnabled,
      ignoreHostKey,
    } = req.body ?? {};
    if (ipAddress !== undefined && (typeof ipAddress !== 'string' || !validateTargetIp(ipAddress))) {
      res.status(400).json({ error: 'Bitte geben Sie eine gültige IPv4- oder IPv6-Adresse an.' });
      return;
    }
    if (bmcIpAddress !== undefined) {
      if (typeof bmcIpAddress !== 'string') {
        res.status(400).json({ error: 'Ungültige BMC-IP-Adresse 1.' });
        return;
      }
      const trimmedBmc = bmcIpAddress.trim();
      if (trimmedBmc && !validateTargetIp(trimmedBmc)) {
        res.status(400).json({ error: 'Bitte geben Sie eine gültige IPv4- oder IPv6-Adresse für BMC-IP 1 an (oder lassen Sie das Feld leer).' });
        return;
      }
    }
    if (bmcIpAddress2 !== undefined) {
      if (typeof bmcIpAddress2 !== 'string') {
        res.status(400).json({ error: 'Ungültige BMC-IP-Adresse 2.' });
        return;
      }
      const trimmedBmc2 = bmcIpAddress2.trim();
      if (trimmedBmc2 && !validateTargetIp(trimmedBmc2)) {
        res.status(400).json({ error: 'Bitte geben Sie eine gültige IPv4- oder IPv6-Adresse für BMC-IP 2 an (oder lassen Sie das Feld leer).' });
        return;
      }
    }
    if (sshUser !== undefined && (typeof sshUser !== 'string' || !validateSshUsername(sshUser.trim()))) {
      res.status(400).json({ error: 'Ungültiger SSH-Benutzername (erlaubt: a-z, 0-9, ., _, -).' });
      return;
    }
    if (ignoreHostKey === true && !store.getSettings().allowInsecureHostKey) {
      const existing = store.getAccessibleServer(req.params.id, req.user!.id);
      if (!existing || !existing.ignoreHostKey) {
        res.status(403).json({
          error:
            'Das Deaktivieren der SSH-Host-Key-Prüfung (StrictHostKeyChecking=no) ist vom Administrator global verboten.',
        });
        return;
      }
    }
    try {
      const updated = store.updateServer(req.params.id, req.user!.id, {
        label: typeof label === 'string' ? label : undefined,
        ipAddress: typeof ipAddress === 'string' ? ipAddress : undefined,
        bmcIpAddress: typeof bmcIpAddress === 'string' ? bmcIpAddress : undefined,
        bmcIpAddress2: typeof bmcIpAddress2 === 'string' ? bmcIpAddress2 : undefined,
        port: port !== undefined ? Number(port) : undefined,
        sshUser: typeof sshUser === 'string' ? sshUser : undefined,
        notes: typeof notes === 'string' ? notes : undefined,
        categories: Array.isArray(categories) ? categories : undefined,
        pingEnabled: typeof pingEnabled === 'boolean' ? pingEnabled : undefined,
        ignoreHostKey: typeof ignoreHostKey === 'boolean' ? ignoreHostKey : undefined,
      });
      if (updated.pingEnabled && store.getSettings().pingAllowed && req.user!.pingEnabled !== false) {
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
    const requestedSlot = Number(req.body?.slot ?? req.body?.bmcSlot);
    let slot: 1 | 2;
    if (requestedSlot === 2) {
      slot = 2;
    } else if (requestedSlot === 1) {
      slot = 1;
    } else {
      slot = server.bmcIpAddress ? 1 : 2;
    }
    const targetBmcIp = slot === 2 ? server.bmcIpAddress2 : server.bmcIpAddress;
    if (!targetBmcIp) {
      res.status(400).json({ error: `Für diesen Server ist keine BMC-IP ${slot} hinterlegt.` });
      return;
    }
    const result = await checkBmcHttps(targetBmcIp);
    res.json({
      result: {
        serverId: server.id,
        slot,
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

  // SSH Host-Key Management (per-IP reset for users, global stats & purge for admin)
  const handleUserHostKeyReset = (req: AuthedRequest, res: Response) => {
    const { serverId, ipAddress, port } = req.body ?? {};
    let targetIp = '';
    let targetPort: number | undefined;

    if (typeof serverId === 'string' && serverId.trim()) {
      const server = store.getAccessibleServer(serverId.trim(), req.user!.id);
      if (!server) {
        res.status(404).json({ error: 'Server nicht gefunden oder keine Berechtigung.' });
        return;
      }
      targetIp = server.ipAddress;
      targetPort = server.port;
    } else {
      const rawIp = typeof ipAddress === 'string' ? ipAddress.trim() : '';
      if (!validateTargetIp(rawIp)) {
        res.status(400).json({ error: `Ungültige Ziel-IP-Adresse: ${rawIp || '(leer)'}` });
        return;
      }
      targetIp = rawIp;
      if (port !== undefined && port !== null && port !== '') {
        const parsedPort = Number(port);
        if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
          res.status(400).json({ error: 'Ungültiger SSH-Port (1–65535).' });
          return;
        }
        targetPort = parsedPort;
      }
    }

    try {
      const result = removeUserHostKey(req.user!.id, targetIp, targetPort);
      res.json({
        ok: true,
        ipAddress: targetIp,
        port: targetPort ?? 22,
        removedCount: result.removedCount,
        remainingCount: result.remainingCount,
      });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Host-Key konnte nicht gelöscht werden.',
      });
    }
  };

  app.post('/api/host-keys/reset', requireAuth, requireSecurityCompliant, handleUserHostKeyReset);
  app.delete('/api/host-keys', requireAuth, requireSecurityCompliant, handleUserHostKeyReset);

  app.get('/api/admin/host-keys', requireAuth, requireAdmin, (_req: AuthedRequest, res) => {
    res.json(getGlobalKnownHostsStats());
  });

  app.delete('/api/admin/host-keys', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    const { ipAddress, port } = req.body ?? {};
    let filter: { ipAddress?: string; port?: number } | undefined;
    if (typeof ipAddress === 'string' && ipAddress.trim()) {
      const rawIp = ipAddress.trim();
      if (!validateTargetIp(rawIp)) {
        res.status(400).json({ error: `Ungültige Ziel-IP-Adresse: ${rawIp}` });
        return;
      }
      const parsedPort = port !== undefined && port !== null && port !== '' ? Number(port) : undefined;
      if (
        parsedPort !== undefined &&
        (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535)
      ) {
        res.status(400).json({ error: 'Ungültiger SSH-Port (1–65535).' });
        return;
      }
      filter = { ipAddress: rawIp, port: parsedPort };
    }
    try {
      const result = clearGlobalHostKeys(filter);
      res.json({ ok: true, ...result });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Host-Keys konnten nicht gelöscht werden.',
      });
    }
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
      hasStoredPassphrase: Boolean(c.passphraseEncrypted),
      metadata: c.metadata,
      sharedWithAll: c.sharedWithAll,
      sharedWithUserIds: c.sharedWithUserIds,
      uploadedAt: c.uploadedAt,
    };
  }

  app.get('/api/certificates', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    const list = store.listAccessibleCertificates(req.user!.id).map(serializeCertificate);
    res.json({ certificates: list });
  });

  app.post('/api/certificates', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    const {
      name,
      privateKeyFileName,
      publicKeyFileName,
      certFileName,
      privateKeyContent,
      publicKeyContent,
      certContent,
      passphrase,
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
    const cleanPassphrase = typeof passphrase === 'string' && passphrase.length > 0 ? passphrase : undefined;
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
        passphrase: cleanPassphrase,
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

  interface ParsedCertUpdatePayload {
    id?: string;
    name?: string;
    privateKeyContent?: string;
    privateKeyFileName?: string;
    publicKeyContent?: string;
    publicKeyFileName?: string;
    certContent?: string;
    certFileName?: string;
    passphrase?: string;
    clearPassphrase: boolean;
    removeCert: boolean;
  }

  async function parseIncomingCertificatePayload(req: Request): Promise<ParsedCertUpdatePayload> {
    const contentType = String(req.headers['content-type'] ?? '').toLowerCase();
    const result: ParsedCertUpdatePayload = { removeCert: false, clearPassphrase: false };

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

      const idField = (parsed.fields.id ?? parsed.fields.certificate_id ?? '').trim();
      if (idField) result.id = idField;

      const nameField = (parsed.fields.name ?? parsed.fields.label ?? '').trim();
      if (nameField) result.name = nameField;

      const removeFlag = (parsed.fields.remove_cert ?? parsed.fields.removeCert ?? '').trim().toLowerCase();
      if (removeFlag === 'true' || removeFlag === '1' || removeFlag === 'yes') {
        result.removeCert = true;
      }

      const passField = parsed.fields.passphrase ?? parsed.fields.key_passphrase;
      if (typeof passField === 'string' && passField.length > 0) {
        result.passphrase = passField;
      }
      const clearPassFlag = (parsed.fields.clear_passphrase ?? parsed.fields.clearPassphrase ?? '').trim().toLowerCase();
      if (clearPassFlag === 'true' || clearPassFlag === '1' || clearPassFlag === 'yes') {
        result.clearPassphrase = true;
      }

      const priv = pickPart(['private_key', 'privateKey', 'privateKeyContent', 'zertifikat', 'key']);
      const pub = pickPart(['public_key', 'publicKey', 'publicKeyContent', 'zertifikat_pub', 'pub']);
      const cert = pickPart(['cert', 'certificate', 'cert_pub', 'zertifikat_cert', 'certContent']);

      if (priv) {
        result.privateKeyContent = priv.content;
        result.privateKeyFileName = priv.filename ? path.basename(priv.filename) : undefined;
      }
      if (pub) {
        result.publicKeyContent = pub.content;
        result.publicKeyFileName = pub.filename ? path.basename(pub.filename) : undefined;
      }
      if (cert) {
        result.certContent = cert.content;
        result.certFileName = cert.filename ? path.basename(cert.filename) : undefined;
      }
      return result;
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const readStr = (...keys: string[]): string | undefined => {
      for (const k of keys) {
        if (typeof body[k] === 'string' && (body[k] as string).trim()) {
          return body[k] as string;
        }
      }
      return undefined;
    };

    const idVal = readStr('id', 'certificate_id', 'certificateId');
    if (idVal) result.id = idVal.trim();

    const nameVal = readStr('name', 'label');
    if (nameVal) result.name = nameVal.trim();

    const removeRaw = body.removeCert ?? body.remove_cert;
    if (removeRaw === true || removeRaw === 'true' || removeRaw === '1' || removeRaw === 1) {
      result.removeCert = true;
    }

    const clearPassRaw = body.clearPassphrase ?? body.clear_passphrase;
    if (clearPassRaw === true || clearPassRaw === 'true' || clearPassRaw === '1' || clearPassRaw === 1) {
      result.clearPassphrase = true;
    }
    const rawPass = body.passphrase ?? body.key_passphrase;
    if (typeof rawPass === 'string' && rawPass.length > 0) {
      result.passphrase = rawPass;
    }

    result.privateKeyContent = readStr('private_key', 'privateKey', 'privateKeyContent', 'zertifikat', 'key');
    result.publicKeyContent = readStr('public_key', 'publicKey', 'publicKeyContent', 'zertifikat_pub', 'pub');
    result.certContent = readStr('cert', 'certificate', 'certContent', 'cert_pub', 'zertifikat_cert');
    result.privateKeyFileName = readStr('privateKeyFileName', 'private_key_file');
    result.publicKeyFileName = readStr('publicKeyFileName', 'public_key_file');
    result.certFileName = readStr('certFileName', 'cert_file');
    return result;
  }

  function applyPartialCertificateUpdate(
    existing: UserCertificateBundle,
    ownerUserId: string,
    payload: ParsedCertUpdatePayload
  ): UserCertificateBundle {
    if (existing.userId !== ownerUserId) {
      throw new Error('Sie können nur selbst angelegte Zertifikatspakete bearbeiten.');
    }

    const hasAnyChange =
      payload.name !== undefined ||
      payload.privateKeyContent !== undefined ||
      payload.publicKeyContent !== undefined ||
      payload.certContent !== undefined ||
      payload.passphrase !== undefined ||
      payload.clearPassphrase ||
      payload.removeCert;

    if (!hasAnyChange) {
      throw new Error(
        'Keine Änderungen übermittelt. Senden Sie mindestens eines der Felder: "name", "cert", "private_key", "public_key", "passphrase", "clearPassphrase" oder "remove_cert".'
      );
    }

    const effectivePriv =
      payload.privateKeyContent !== undefined
        ? payload.privateKeyContent
        : decryptSecret(existing.privateKeyEncrypted);
    const effectivePub =
      payload.publicKeyContent !== undefined ? payload.publicKeyContent : existing.publicKeyContent;
    const effectiveCert = payload.removeCert
      ? ''
      : payload.certContent !== undefined
        ? payload.certContent
        : existing.certContent;

    const metadata = validateAndParseCertificateBundle(
      effectivePriv,
      effectivePub,
      effectiveCert
    );

    return store.updateCertificate(existing.id, ownerUserId, {
      name: payload.name,
      privateKeyContent: payload.privateKeyContent,
      privateKeyFileName: payload.privateKeyFileName,
      publicKeyContent: payload.publicKeyContent,
      publicKeyFileName: payload.publicKeyFileName,
      certContent: payload.removeCert ? '' : payload.certContent,
      certFileName: payload.removeCert
        ? ''
        : payload.certContent !== undefined
          ? payload.certFileName || existing.certFileName || 'zertifikat-cert.pub'
          : undefined,
      passphrase: payload.passphrase,
      clearPassphrase: payload.clearPassphrase,
      metadata,
    });
  }

  app.patch('/api/certificates/:id', requireAuth, async (req: AuthedRequest, res) => {
    const existing = store.getCertificateById(req.params.id);
    if (!existing) {
      res.status(404).json({ error: 'Zertifikatspaket nicht gefunden.' });
      return;
    }
    if (existing.userId !== req.user!.id) {
      res.status(403).json({ error: 'Sie können nur selbst angelegte Zertifikatspakete bearbeiten.' });
      return;
    }

    let payload: ParsedCertUpdatePayload;
    try {
      payload = await parseIncomingCertificatePayload(req);
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Anfrage konnte nicht verarbeitet werden.',
      });
      return;
    }

    try {
      const updated = applyPartialCertificateUpdate(existing, req.user!.id, payload);
      res.json({
        ok: true,
        certificate: serializeCertificate(updated),
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

  // Simple API-Key Endpoints for curl (list, upload, and partial update e.g. cert-only replacement)
  app.get('/api/v1/certificates', (req: Request, res: Response) => {
    const apiKey = extractApiKey(req);
    const user = store.getUserByApiKey(apiKey);
    if (!user) {
      res.status(401).json({
        error:
          'Ungültiger oder fehlender API-Schlüssel. Senden Sie ihn als Header "X-API-Key: sshc_..." oder "Authorization: Bearer sshc_...".',
      });
      return;
    }
    const list = store
      .listAccessibleCertificates(user.id)
      .filter((c) => c.userId === user.id)
      .map(serializeCertificate);
    res.json({ ok: true, certificates: list });
  });

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

    let payload: ParsedCertUpdatePayload;
    try {
      payload = await parseIncomingCertificatePayload(req);
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Anfrage konnte nicht verarbeitet werden.',
      });
      return;
    }

    const privateKeyContent = payload.privateKeyContent ?? '';
    const publicKeyContent = payload.publicKeyContent ?? '';
    const privateKeyFileName = payload.privateKeyFileName || 'zertifikat';
    const publicKeyFileName = payload.publicKeyFileName || 'zertifikat.pub';
    const certFileName = payload.certFileName || 'zertifikat-cert.pub';
    const cleanCertContent = (payload.certContent ?? '').trim();

    // Smart partial update: if private_key or public_key is omitted, allow updating an existing bundle by id or name
    if (!privateKeyContent.trim() || !publicKeyContent.trim()) {
      const lookupKey = payload.id || payload.name || '';
      const existing = lookupKey ? store.findUserCertificateByIdOrName(user.id, lookupKey) : undefined;
      if (existing) {
        try {
          const updated = applyPartialCertificateUpdate(existing, user.id, {
            ...payload,
            name: undefined, // keep matched name unless changed via PATCH /api/v1/certificates/:idOrName
          });
          res.status(200).json({
            ok: true,
            replaced: true,
            updated: true,
            certificate: serializeCertificate(updated),
          });
          return;
        } catch (err) {
          res.status(400).json({
            error: err instanceof Error ? err.message : 'Zertifikatsprüfung fehlgeschlagen.',
          });
          return;
        }
      }

      res.status(400).json({
        error:
          'Für ein neues Paket sind "private_key" (zertifikat) und "public_key" (zertifikat.pub) erforderlich. Um nur zertifikat-cert.pub eines bestehenden Pakets zu tauschen, geben Sie dessen "name" an oder nutzen Sie PATCH /api/v1/certificates/<name-oder-id>.',
      });
      return;
    }

    try {
      const metadata = validateAndParseCertificateBundle(
        privateKeyContent,
        publicKeyContent,
        cleanCertContent
      );
      const effectiveName =
        payload.name ||
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
        passphrase: payload.passphrase,
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

  const handleApiV1UpdateCert = async (req: Request, res: Response) => {
    const apiKey = extractApiKey(req);
    const user = store.getUserByApiKey(apiKey);
    if (!user) {
      res.status(401).json({
        error:
          'Ungültiger oder fehlender API-Schlüssel. Senden Sie ihn als Header "X-API-Key: sshc_..." oder "Authorization: Bearer sshc_...".',
      });
      return;
    }

    const idOrName = decodeURIComponent(req.params.idOrName || '').trim();
    const existing = store.findUserCertificateByIdOrName(user.id, idOrName);
    if (!existing) {
      res.status(404).json({
        error: `Zertifikatspaket „${idOrName}“ nicht gefunden (nur eigene Pakete können bearbeitet werden).`,
      });
      return;
    }

    let payload: ParsedCertUpdatePayload;
    try {
      payload = await parseIncomingCertificatePayload(req);
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Anfrage konnte nicht verarbeitet werden.',
      });
      return;
    }

    try {
      const updated = applyPartialCertificateUpdate(existing, user.id, payload);
      res.json({
        ok: true,
        updated: true,
        certificate: serializeCertificate(updated),
      });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Zertifikatsprüfung fehlgeschlagen.',
      });
    }
  };

  app.patch('/api/v1/certificates/:idOrName', handleApiV1UpdateCert);
  app.put('/api/v1/certificates/:idOrName', handleApiV1UpdateCert);

  // Execute SSH Command on One or Multiple Target IPs (own or admin-shared)
  app.post('/api/execute', requireAuth, requireSecurityCompliant, async (req: AuthedRequest, res) => {
    const { commandId, certificateId, targets, dryRun, passphrase, workflowVars } = req.body ?? {};

    const command = store.getAccessibleCommand(String(commandId ?? ''), req.user!.id);
    if (!command) {
      res.status(404).json({ error: 'Ausgewählter SSH-Befehl ist nicht verfügbar oder deaktiviert.' });
      return;
    }

    const sanitizedVars = sanitizeRuntimeVarsInput(workflowVars);
    if (!sanitizedVars.ok) {
      res.status(400).json({ error: sanitizedVars.error });
      return;
    }
    if (command.kind === 'workflow') {
      const parsedWf = parseAndValidateWorkflow(command.workflowJson || '');
      if (!parsedWf.ok) {
        res.status(400).json({ error: `Ungültiger JSON-Workflow: ${parsedWf.error}` });
        return;
      }
      const checkedVars = resolveWorkflowRuntimeVars(parsedWf.workflow, sanitizedVars.vars);
      if (!checkedVars.ok) {
        res.status(400).json({ error: checkedVars.error });
        return;
      }
    }

    const certificate = store.getAccessibleCertificate(String(certificateId ?? ''), req.user!.id);
    if (!certificate) {
      res.status(404).json({ error: 'Bitte wählen Sie ein gültiges SSH-Zertifikatspaket aus.' });
      return;
    }

    const suppliedPassphrase = typeof passphrase === 'string' && passphrase.length > 0 ? passphrase : undefined;
    if (certificate.metadata.privateKeyEncrypted && !certificate.passphraseEncrypted && !suppliedPassphrase) {
      res.status(400).json({
        error:
          'Dieser private Schlüssel ist passwortgeschützt. Bitte geben Sie das Schlüssel-Passwort ein oder hinterlegen Sie es beim Zertifikat.',
      });
      return;
    }

    if (!Array.isArray(targets) || targets.length === 0 || targets.length > 20) {
      res.status(400).json({ error: 'Bitte wählen Sie zwischen 1 und 20 Ziel-IPs aus.' });
      return;
    }

    const allowInsecureHostKey = store.getSettings().allowInsecureHostKey;
    const resolvedTargets: Array<{
      ipAddress: string;
      port: number;
      sshUser: string;
      label: string;
      ignoreHostKey: boolean;
    }> = [];
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
          ignoreHostKey: allowInsecureHostKey && Boolean(srv.ignoreHostKey),
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
          ignoreHostKey: allowInsecureHostKey && Boolean(t?.ignoreHostKey),
        });
      }
    }

    const logs = await mapWithConcurrency(
      resolvedTargets,
      MAX_CONCURRENT_SSH_JOBS,
      async (target) => {
        const result = await executeSshCommand({
          userId: req.user!.id,
          ipAddress: target.ipAddress,
          port: target.port,
          sshUser: target.sshUser,
          serverLabel: target.label,
          command,
          certificate,
          passphrase: suppliedPassphrase,
          workflowVars: sanitizedVars.vars,
          ignoreHostKey: target.ignoreHostKey,
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
      }
    );

    res.json({ results: logs });
  });

  // Dashboard: Ping Status, User & Admin Ping Settings, Manual Ping Trigger
  app.get('/api/dashboard/status', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    res.json(pingMonitor.getUserStatuses(req.user!.id));
  });

  app.post('/api/dashboard/ping', requireAuth, requireSecurityCompliant, async (req: AuthedRequest, res) => {
    const serverId = typeof req.body?.serverId === 'string' ? req.body.serverId : undefined;
    if (serverId) {
      const srv = store.getAccessibleServer(serverId, req.user!.id);
      if (!srv) {
        res.status(404).json({ error: 'Server nicht gefunden.' });
        return;
      }
    }
    await pingMonitor.pingUserServers(req.user!.id, serverId, { manual: true });
    res.json(pingMonitor.getUserStatuses(req.user!.id));
  });

  app.patch('/api/dashboard/ping-settings', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
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
    const { pingAllowed, pingIntervalSec, pingOfflineThreshold, pingOfflineMultiplier } =
      req.body ?? {};
    const prevAllowed = store.getSettings().pingAllowed;
    try {
      const settings = store.updateGlobalPingSettings({
        pingAllowed: typeof pingAllowed === 'boolean' ? pingAllowed : undefined,
        pingIntervalSec: pingIntervalSec !== undefined ? Number(pingIntervalSec) : undefined,
        pingOfflineThreshold:
          pingOfflineThreshold !== undefined ? Number(pingOfflineThreshold) : undefined,
        pingOfflineMultiplier:
          pingOfflineMultiplier !== undefined ? Number(pingOfflineMultiplier) : undefined,
      });
      const becameEnabled = !prevAllowed && settings.pingAllowed;
      pingMonitor.reschedule(becameEnabled);
      res.json({
        settings: serializePublicSettings(),
        dashboardStatus: pingMonitor.getUserStatuses(req.user!.id),
      });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Ping-Einstellungen konnten nicht gespeichert werden.',
      });
    }
  });

  // Dashboard Batch Execution: Execute assigned commands across multiple IPs in one go
  app.post('/api/execute/batch', requireAuth, requireSecurityCompliant, async (req: AuthedRequest, res) => {
    const { certificateId, jobs, dryRun, passphrase, workflowVars } = req.body ?? {};

    const certificate = store.getAccessibleCertificate(String(certificateId ?? ''), req.user!.id);
    if (!certificate) {
      res.status(404).json({ error: 'Bitte wählen Sie zuerst ein gültiges 3-Dateien-SSH-Zertifikat aus.' });
      return;
    }

    const suppliedPassphrase = typeof passphrase === 'string' && passphrase.length > 0 ? passphrase : undefined;
    if (certificate.metadata.privateKeyEncrypted && !certificate.passphraseEncrypted && !suppliedPassphrase) {
      res.status(400).json({
        error:
          'Dieser private Schlüssel ist passwortgeschützt. Bitte geben Sie das Schlüssel-Passwort ein oder hinterlegen Sie es beim Zertifikat.',
      });
      return;
    }

    const baseVarsRes = sanitizeRuntimeVarsInput(workflowVars);
    if (!baseVarsRes.ok) {
      res.status(400).json({ error: baseVarsRes.error });
      return;
    }

    if (!Array.isArray(jobs) || jobs.length === 0 || jobs.length > 50) {
      res.status(400).json({ error: 'Bitte wählen Sie zwischen 1 und 50 Aufträge für die Sammelausführung aus.' });
      return;
    }

    const allowInsecureHostKey = store.getSettings().allowInsecureHostKey;
    const resolvedJobs: Array<{
      server: { ipAddress: string; port: number; sshUser: string; label: string; ignoreHostKey: boolean };
      command: NonNullable<ReturnType<typeof store.getCommand>>;
      vars: Record<string, string>;
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
      const itemVarsRes = sanitizeRuntimeVarsInput(item?.workflowVars);
      if (!itemVarsRes.ok) {
        res.status(400).json({ error: itemVarsRes.error });
        return;
      }
      const mergedVars = { ...baseVarsRes.vars, ...itemVarsRes.vars };
      if (cmd.kind === 'workflow') {
        const parsedWf = parseAndValidateWorkflow(cmd.workflowJson || '');
        if (!parsedWf.ok) {
          res.status(400).json({ error: `Ungültiger JSON-Workflow "${cmd.name}": ${parsedWf.error}` });
          return;
        }
        const checkedVars = resolveWorkflowRuntimeVars(parsedWf.workflow, mergedVars);
        if (!checkedVars.ok) {
          res.status(400).json({ error: checkedVars.error });
          return;
        }
      }
      resolvedJobs.push({
        server: {
          ipAddress: srv.ipAddress,
          port: srv.port,
          sshUser: srv.sshUser,
          label: srv.label,
          ignoreHostKey: allowInsecureHostKey && Boolean(srv.ignoreHostKey),
        },
        command: cmd,
        vars: mergedVars,
      });
    }

    const logs = await mapWithConcurrency(
      resolvedJobs,
      MAX_CONCURRENT_SSH_JOBS,
      async ({ server, command, vars }) => {
        const result = await executeSshCommand({
          userId: req.user!.id,
          ipAddress: server.ipAddress,
          port: server.port,
          sshUser: server.sshUser,
          serverLabel: server.label,
          command,
          certificate,
          passphrase: suppliedPassphrase,
          workflowVars: vars,
          ignoreHostKey: server.ignoreHostKey,
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
      }
    );

    res.json({ results: logs });
  });

  // Asynchronous Dashboard Batch Execution: dispatches in background and returns immediately (202 Accepted)
  app.post('/api/execute/batch/async', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    const { certificateId, jobs, dryRun, passphrase, workflowVars } = req.body ?? {};

    const certificate = store.getAccessibleCertificate(String(certificateId ?? ''), req.user!.id);
    if (!certificate) {
      res.status(404).json({ error: 'Bitte wählen Sie zuerst ein gültiges SSH-Schlüssel- oder Zertifikatspaket aus.' });
      return;
    }

    const suppliedPassphrase = typeof passphrase === 'string' && passphrase.length > 0 ? passphrase : undefined;
    if (certificate.metadata.privateKeyEncrypted && !certificate.passphraseEncrypted && !suppliedPassphrase) {
      res.status(400).json({
        error:
          'Dieser private Schlüssel ist passwortgeschützt. Bitte geben Sie das Schlüssel-Passwort ein oder hinterlegen Sie es beim Zertifikat.',
      });
      return;
    }

    const baseVarsRes = sanitizeRuntimeVarsInput(workflowVars);
    if (!baseVarsRes.ok) {
      res.status(400).json({ error: baseVarsRes.error });
      return;
    }

    if (!Array.isArray(jobs) || jobs.length === 0 || jobs.length > 50) {
      res.status(400).json({ error: 'Bitte wählen Sie zwischen 1 und 50 Aufträge für die Sammelausführung aus.' });
      return;
    }

    const allowInsecureHostKey = store.getSettings().allowInsecureHostKey;
    const resolvedJobs: Array<{
      server: { ipAddress: string; port: number; sshUser: string; label: string; ignoreHostKey: boolean };
      command: NonNullable<ReturnType<typeof store.getCommand>>;
      vars: Record<string, string>;
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
      const itemVarsRes = sanitizeRuntimeVarsInput(item?.workflowVars);
      if (!itemVarsRes.ok) {
        res.status(400).json({ error: itemVarsRes.error });
        return;
      }
      const mergedVars = { ...baseVarsRes.vars, ...itemVarsRes.vars };
      if (cmd.kind === 'workflow') {
        const parsedWf = parseAndValidateWorkflow(cmd.workflowJson || '');
        if (!parsedWf.ok) {
          res.status(400).json({ error: `Ungültiger JSON-Workflow "${cmd.name}": ${parsedWf.error}` });
          return;
        }
        const checkedVars = resolveWorkflowRuntimeVars(parsedWf.workflow, mergedVars);
        if (!checkedVars.ok) {
          res.status(400).json({ error: checkedVars.error });
          return;
        }
      }
      resolvedJobs.push({
        server: {
          ipAddress: srv.ipAddress,
          port: srv.port,
          sshUser: srv.sshUser,
          label: srv.label,
          ignoreHostKey: allowInsecureHostKey && Boolean(srv.ignoreHostKey),
        },
        command: cmd,
        vars: mergedVars,
      });
    }

    const started = backgroundJobs.startBatchJob({
      userId: req.user!.id,
      username: req.user!.username,
      certificate,
      passphrase: suppliedPassphrase,
      dryRun: Boolean(dryRun),
      resolvedJobs,
    });

    if (!started.ok) {
      res.status(429).json({
        error: started.error,
        activeCount: started.activeCount,
        maxBackgroundJobs: started.maxBackgroundJobs,
      });
      return;
    }

    res.status(202).json({
      job: started.job,
      activeCount: started.activeCount,
      maxBackgroundJobs: started.maxBackgroundJobs,
    });
  });

  // Background Jobs (Notifications & Detailed Results — strictly scoped to current user)
  app.get('/api/jobs', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    res.json(backgroundJobs.listUserJobs(req.user!.id, req.user!.role === 'admin'));
  });

  app.post('/api/jobs/read-all', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    const unreadCount = backgroundJobs.markAllRead(req.user!.id);
    res.json({ ok: true, unreadCount });
  });

  app.get('/api/jobs/:id', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    const job = backgroundJobs.getUserJob(req.user!.id, req.params.id);
    if (!job) {
      res.status(404).json({ error: 'Hintergrundauftrag nicht gefunden.' });
      return;
    }
    res.json({ job });
  });

  app.post('/api/jobs/:id/read', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    const updated = backgroundJobs.markRead(req.user!.id, req.params.id);
    if (!updated) {
      res.status(404).json({ error: 'Hintergrundauftrag nicht gefunden.' });
      return;
    }
    res.json(updated);
  });

  app.delete('/api/jobs/:id', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    const result = backgroundJobs.deleteUserJob(req.user!.id, req.params.id);
    if (!result.ok) {
      res.status(result.status).json({ error: result.error });
      return;
    }
    res.json({ ok: true });
  });

  // Admin: List all background processes across all users & configure concurrency limit
  app.get('/api/admin/jobs', requireAuth, requireAdmin, (_req: AuthedRequest, res) => {
    res.json(backgroundJobs.listAllJobs());
  });

  app.patch('/api/admin/jobs/settings', requireAuth, requireAdmin, (req: AuthedRequest, res) => {
    const raw = req.body?.maxBackgroundJobs;
    if (raw === undefined || raw === null || raw === '') {
      res.status(400).json({ error: 'Bitte geben Sie ein gültiges Limit (1–50) an.' });
      return;
    }
    try {
      const updated = store.updateMaxBackgroundJobs(Number(raw));
      res.json({
        settings: serializePublicSettings(),
        maxBackgroundJobs: updated.maxBackgroundJobs,
        activeCount: backgroundJobs.getUserActiveCount(req.user!.id),
        totalActiveCount: backgroundJobs.getActiveCount(),
      });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Hintergrundprozess-Limit konnte nicht gespeichert werden.',
      });
    }
  });

  // Interactive SSH Shell: issue short-lived one-time WebSocket ticket
  app.post('/api/shell/ticket', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    const { serverId, ipAddress, port, sshUser, certificateId, passphrase, ignoreHostKey, cols, rows } =
      req.body ?? {};
    if (typeof certificateId !== 'string' || !certificateId.trim()) {
      res.status(400).json({ error: 'Bitte ein SSH-Zertifikatspaket auswählen.' });
      return;
    }
    const certificate = store.getAccessibleCertificate(certificateId, req.user!.id);
    if (!certificate) {
      res.status(400).json({ error: 'Zertifikatspaket nicht gefunden oder keine Berechtigung.' });
      return;
    }
    const suppliedPassphrase = typeof passphrase === 'string' && passphrase.length > 0 ? passphrase : undefined;

    const allowInsecureHostKey = store.getSettings().allowInsecureHostKey;
    let targetIp = '';
    let targetPort = 22;
    let targetSshUser = req.user!.defaultSshUser || 'root';
    let serverLabel = '';
    let targetIgnoreHostKey = false;

    if (typeof serverId === 'string' && serverId.trim()) {
      const server = store.getAccessibleServer(serverId.trim(), req.user!.id);
      if (!server) {
        res.status(400).json({ error: 'Ausgewählter Server nicht gefunden oder keine Berechtigung.' });
        return;
      }
      targetIp = server.ipAddress;
      targetPort = server.port;
      targetSshUser = server.sshUser;
      serverLabel = server.label;
      targetIgnoreHostKey = allowInsecureHostKey && Boolean(server.ignoreHostKey);
      if (typeof sshUser === 'string' && sshUser.trim()) {
        if (!validateSshUsername(sshUser)) {
          res.status(400).json({ error: `Ungültiger SSH-Benutzername: ${sshUser}` });
          return;
        }
        targetSshUser = sshUser.trim();
      }
    } else {
      const rawIp = typeof ipAddress === 'string' ? ipAddress.trim() : '';
      if (!validateTargetIp(rawIp)) {
        res.status(400).json({ error: `Ungültige Ziel-IP-Adresse: ${rawIp || '(leer)'}` });
        return;
      }
      const rawUser =
        typeof sshUser === 'string' && sshUser.trim()
          ? sshUser.trim()
          : req.user!.defaultSshUser || 'root';
      if (!validateSshUsername(rawUser)) {
        res.status(400).json({ error: `Ungültiger SSH-Benutzername: ${rawUser}` });
        return;
      }
      const parsedPort = Number(port);
      targetIp = rawIp;
      targetPort =
        Number.isFinite(parsedPort) && parsedPort >= 1 && parsedPort <= 65535
          ? Math.floor(parsedPort)
          : 22;
      targetSshUser = rawUser;
      serverLabel = rawIp;
      if (Boolean(ignoreHostKey) && !allowInsecureHostKey) {
        res.status(403).json({
          error:
            'Das Deaktivieren der SSH-Host-Key-Prüfung (StrictHostKeyChecking=no) ist vom Administrator global verboten.',
        });
        return;
      }
      targetIgnoreHostKey = allowInsecureHostKey && Boolean(ignoreHostKey);
    }

    const ticket = issueShellTicket({
      userId: req.user!.id,
      username: req.user!.username,
      serverLabel,
      ipAddress: targetIp,
      port: targetPort,
      sshUser: targetSshUser,
      certificateId: certificate.id,
      passphrase: suppliedPassphrase,
      ignoreHostKey: targetIgnoreHostKey,
      cols: Number(cols) || 100,
      rows: Number(rows) || 30,
    });

    res.json({
      ticket,
      targetIp,
      targetPort,
      sshUser: targetSshUser,
      serverLabel,
      certificateName: certificate.name,
      opensshAvailable: Boolean(findOpenSshBinary()),
    });
  });

  // Execution History / Audit Logs (regular users strictly receive only their own logs; admins see all)
  app.get('/api/logs', requireAuth, requireSecurityCompliant, (req: AuthedRequest, res) => {
    const filterUserId = typeof req.query.userId === 'string' ? req.query.userId.trim() : undefined;
    res.json({ logs: store.listLogs(req.user!, filterUserId) });
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

  // Structured JSON error handler for malformed JSON bodies or unexpected API errors
  app.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) {
      next(err);
      return;
    }
    if (err instanceof SyntaxError && 'status' in err && (err as { status?: number }).status === 400) {
      res.status(400).json({ error: 'Ungültiges JSON-Format im Anfragekörper.' });
      return;
    }
    if (req.path.startsWith('/api/')) {
      res.status(500).json({ error: 'Interner Serverfehler.' });
      return;
    }
    next(err);
  });

  const httpServer = http.createServer(app);

  // Vite middleware in development, static dist in production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: { server: httpServer },
        watch: process.env.DISABLE_HMR === 'true' ? null : undefined,
      },
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
  attachSshShellWebSocket(httpServer);
  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`SSH Console server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
