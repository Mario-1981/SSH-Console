import crypto from 'node:crypto';
import type { Request } from 'express';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticatorTransport,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import type { StoredWebAuthnCredential, WebAuthnCredentialKind } from './store.ts';

// ── Ephemeral challenge stores (short TTL, single-use) ───────────────────────

export interface SsoStateEntry {
  mode: 'login' | 'test';
  adminUserId?: string;
  codeVerifier: string;
  redirectUri: string;
  expiresAt: number;
}

export interface PendingTwoFactorTicket {
  userId: string;
  webauthnChallenge?: string;
  expiresAt: number;
}

export interface PendingWebAuthnChallenge {
  challenge: string;
  userId?: string;
  kind: WebAuthnCredentialKind | 'passkey-login';
  name?: string;
  rpId: string;
  origin: string;
  expiresAt: number;
}

export interface PendingTotpSetup {
  userId: string;
  secret: string;
  expiresAt: number;
}

const ssoStates = new Map<string, SsoStateEntry>();
const twoFactorTickets = new Map<string, PendingTwoFactorTicket>();
const webauthnChallenges = new Map<string, PendingWebAuthnChallenge>();
const totpPending = new Map<string, PendingTotpSetup>();

function pruneMap<T extends { expiresAt: number }>(map: Map<string, T>) {
  const now = Date.now();
  for (const [k, v] of map.entries()) {
    if (v.expiresAt <= now) map.delete(k);
  }
}

export function createSsoState(entry: Omit<SsoStateEntry, 'expiresAt'>): {
  state: string;
  codeChallenge: string;
} {
  pruneMap(ssoStates);
  const state = crypto.randomBytes(24).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(entry.codeVerifier)
    .digest('base64url');
  ssoStates.set(state, { ...entry, expiresAt: Date.now() + 10 * 60_000 });
  return { state, codeChallenge };
}

export function consumeSsoState(state: string): SsoStateEntry | null {
  pruneMap(ssoStates);
  const entry = ssoStates.get(state);
  if (!entry) return null;
  ssoStates.delete(state);
  return entry.expiresAt > Date.now() ? entry : null;
}

export function createTwoFactorTicket(userId: string, webauthnChallenge?: string): string {
  pruneMap(twoFactorTickets);
  const ticket = crypto.randomBytes(24).toString('hex');
  twoFactorTickets.set(ticket, {
    userId,
    webauthnChallenge,
    expiresAt: Date.now() + 5 * 60_000,
  });
  return ticket;
}

export function peekTwoFactorTicket(ticket: string): PendingTwoFactorTicket | null {
  pruneMap(twoFactorTickets);
  const entry = twoFactorTickets.get(ticket);
  return entry && entry.expiresAt > Date.now() ? entry : null;
}

export function consumeTwoFactorTicket(ticket: string): PendingTwoFactorTicket | null {
  pruneMap(twoFactorTickets);
  const entry = twoFactorTickets.get(ticket);
  if (!entry) return null;
  twoFactorTickets.delete(ticket);
  return entry.expiresAt > Date.now() ? entry : null;
}

export function storePendingTotpSetup(userId: string, secret: string) {
  pruneMap(totpPending);
  totpPending.set(userId, { userId, secret, expiresAt: Date.now() + 15 * 60_000 });
}

export function consumePendingTotpSetup(userId: string): PendingTotpSetup | null {
  pruneMap(totpPending);
  const entry = totpPending.get(userId);
  if (!entry) return null;
  totpPending.delete(userId);
  return entry.expiresAt > Date.now() ? entry : null;
}

export function peekPendingTotpSetup(userId: string): PendingTotpSetup | null {
  pruneMap(totpPending);
  const entry = totpPending.get(userId);
  return entry && entry.expiresAt > Date.now() ? entry : null;
}

export function storeWebAuthnChallenge(
  entry: Omit<PendingWebAuthnChallenge, 'expiresAt'>
): string {
  pruneMap(webauthnChallenges);
  const challengeId = crypto.randomBytes(20).toString('hex');
  webauthnChallenges.set(challengeId, {
    ...entry,
    expiresAt: Date.now() + 5 * 60_000,
  });
  return challengeId;
}

export function consumeWebAuthnChallenge(challengeId: string): PendingWebAuthnChallenge | null {
  pruneMap(webauthnChallenges);
  const entry = webauthnChallenges.get(challengeId);
  if (!entry) return null;
  webauthnChallenges.delete(challengeId);
  return entry.expiresAt > Date.now() ? entry : null;
}

// ── Origin / RP ID helpers ───────────────────────────────────────────────────

export function getPublicAppOrigin(req: Request): string {
  const envUrl = (process.env.APP_URL || '').trim().replace(/\/+$/, '');
  if (envUrl) return envUrl;
  const originHeader = typeof req.headers.origin === 'string' ? req.headers.origin.trim() : '';
  if (originHeader && /^https?:\/\/[^/\s]+$/i.test(originHeader)) {
    return originHeader.replace(/\/+$/, '');
  }
  const proto =
    String(req.headers['x-forwarded-proto'] ?? '').split(',')[0].trim() ||
    (req.secure ? 'https' : 'http');
  const host =
    String(req.headers['x-forwarded-host'] ?? '').split(',')[0].trim() ||
    String(req.headers.host ?? 'localhost:3000').trim();
  return `${proto}://${host}`;
}

export function getSsoCallbackUrl(req: Request): string {
  return `${getPublicAppOrigin(req)}/api/auth/sso/callback`;
}

export function getWebAuthnContext(req: Request): { origin: string; rpId: string } {
  const originHeader = typeof req.headers.origin === 'string' ? req.headers.origin.trim() : '';
  const baseOrigin =
    originHeader && /^https?:\/\/[^/\s]+$/i.test(originHeader)
      ? originHeader.replace(/\/+$/, '')
      : getPublicAppOrigin(req);
  try {
    const parsed = new URL(baseOrigin);
    return {
      origin: parsed.origin,
      rpId: parsed.hostname,
    };
  } catch {
    return {
      origin: 'http://localhost:3000',
      rpId: 'localhost',
    };
  }
}

// ── OIDC Discovery & Token/UserInfo Exchange ─────────────────────────────────

export function validateExternalEndpointUrl(rawUrl: string): string {
  const trimmed = rawUrl.trim();
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`Ungültige URL: ${rawUrl}`);
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('SSO-Endpunkte müssen mit https:// (oder http:// im lokalen Netz) beginnen.');
  }
  const host = parsed.hostname.toLowerCase();
  // Block cloud metadata endpoints
  if (host === '169.254.169.254' || host === 'metadata.google.internal' || host === 'fd00:ec2::254') {
    throw new Error('Metadaten-Adressen sind als SSO-Endpunkt nicht zulässig.');
  }
  return parsed.toString();
}

export async function discoverOidcConfiguration(issuerUrl: string): Promise<{
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint: string;
}> {
  const cleanIssuer = validateExternalEndpointUrl(issuerUrl).replace(/\/+$/, '');
  const discoveryUrl = cleanIssuer.endsWith('/.well-known/openid-configuration')
    ? cleanIssuer
    : `${cleanIssuer}/.well-known/openid-configuration`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const res = await fetch(discoveryUrl, {
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`OIDC Discovery fehlgeschlagen (HTTP ${res.status}).`);
    }
    const data = (await res.json()) as {
      issuer?: string;
      authorization_endpoint?: string;
      token_endpoint?: string;
      userinfo_endpoint?: string;
    };
    if (!data.authorization_endpoint || !data.token_endpoint) {
      throw new Error('OIDC Discovery-Antwort enthält keine gültigen Authorization/Token-Endpunkte.');
    }
    return {
      issuer: data.issuer || cleanIssuer,
      authorizationEndpoint: validateExternalEndpointUrl(data.authorization_endpoint),
      tokenEndpoint: validateExternalEndpointUrl(data.token_endpoint),
      userinfoEndpoint: data.userinfo_endpoint
        ? validateExternalEndpointUrl(data.userinfo_endpoint)
        : '',
    };
  } finally {
    clearTimeout(timer);
  }
}

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.');
  if (parts.length < 2) return {};
  try {
    const json = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return {};
  }
}

export interface SsoUserProfile {
  sub: string;
  username: string;
  displayName: string;
  email: string;
}

export async function exchangeSsoCodeForProfile(params: {
  tokenUrl: string;
  userinfoUrl: string;
  clientId: string;
  clientSecret: string;
  code: string;
  codeVerifier: string;
  redirectUri: string;
}): Promise<SsoUserProfile> {
  const tokenEndpoint = validateExternalEndpointUrl(params.tokenUrl);
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: params.redirectUri,
    client_id: params.clientId,
    code_verifier: params.codeVerifier,
  });
  if (params.clientSecret) {
    body.set('client_secret', params.clientSecret);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12_000);
  let tokenJson: {
    access_token?: string;
    id_token?: string;
    error?: string;
    error_description?: string;
  };
  try {
    const tokenRes = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: body.toString(),
      signal: controller.signal,
    });
    tokenJson = (await tokenRes.json().catch(() => ({}))) as typeof tokenJson;
    if (!tokenRes.ok || tokenJson.error) {
      throw new Error(
        tokenJson.error_description ||
          tokenJson.error ||
          `SSO Token-Austausch fehlgeschlagen (HTTP ${tokenRes.status}).`
      );
    }
  } finally {
    clearTimeout(timer);
  }

  let claims: Record<string, unknown> = {};
  if (tokenJson.id_token) {
    claims = { ...claims, ...decodeJwtPayload(tokenJson.id_token) };
  }

  if (params.userinfoUrl && tokenJson.access_token) {
    const userinfoEndpoint = validateExternalEndpointUrl(params.userinfoUrl);
    const uiCtrl = new AbortController();
    const uiTimer = setTimeout(() => uiCtrl.abort(), 10_000);
    try {
      const uiRes = await fetch(userinfoEndpoint, {
        headers: {
          Authorization: `Bearer ${tokenJson.access_token}`,
          Accept: 'application/json',
        },
        signal: uiCtrl.signal,
      });
      if (uiRes.ok) {
        const uiJson = (await uiRes.json().catch(() => ({}))) as Record<string, unknown>;
        claims = { ...claims, ...uiJson };
      }
    } finally {
      clearTimeout(uiTimer);
    }
  }

  const sub = String(claims.sub || claims.id || '').trim();
  if (!sub) {
    throw new Error('SSO-Anbieter hat keine eindeutige Benutzer-ID (sub) zurückgegeben.');
  }

  const email = typeof claims.email === 'string' ? claims.email.trim() : '';
  const preferred =
    typeof claims.preferred_username === 'string' && claims.preferred_username.trim()
      ? claims.preferred_username.trim()
      : typeof claims.login === 'string' && claims.login.trim()
        ? claims.login.trim()
        : email
          ? email.split('@')[0]
          : `sso-${sub.slice(0, 10)}`;

  const sanitizedUsername = preferred
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, '_')
    .replace(/^[^a-z0-9]+/, '')
    .slice(0, 32) || `sso_${crypto.createHash('sha256').update(sub).digest('hex').slice(0, 8)}`;

  const displayName =
    (typeof claims.name === 'string' && claims.name.trim()) ||
    (typeof claims.given_name === 'string' && claims.given_name.trim()) ||
    sanitizedUsername;

  return {
    sub,
    username: sanitizedUsername,
    displayName: displayName.slice(0, 64),
    email,
  };
}

// ── WebAuthn Registration & Authentication (@simplewebauthn/server v14) ─────

export async function createWebAuthnRegistrationOptions(params: {
  rpName: string;
  rpId: string;
  userId: string;
  username: string;
  displayName: string;
  kind: WebAuthnCredentialKind;
  existingCredentials: StoredWebAuthnCredential[];
}) {
  const isPasskey = params.kind === 'passkey';
  return generateRegistrationOptions({
    rpName: params.rpName || 'SSH Console',
    rpID: params.rpId,
    userID: Buffer.from(params.userId, 'utf8'),
    userName: params.username,
    userDisplayName: params.displayName || params.username,
    attestationType: 'none',
    excludeCredentials: params.existingCredentials.map((c) => ({
      id: c.credentialId,
      transports: c.transports as AuthenticatorTransport[],
    })),
    authenticatorSelection: isPasskey
      ? {
          residentKey: 'required',
          requireResidentKey: true,
          userVerification: 'required',
        }
      : {
          residentKey: 'discouraged',
          userVerification: 'preferred',
        },
  });
}

export async function verifyWebAuthnRegistration(params: {
  response: RegistrationResponseJSON;
  expectedChallenge: string;
  expectedOrigin: string;
  expectedRPID: string;
  kind: WebAuthnCredentialKind;
}) {
  const verification = await verifyRegistrationResponse({
    response: params.response,
    expectedChallenge: params.expectedChallenge,
    expectedOrigin: params.expectedOrigin,
    expectedRPID: params.expectedRPID,
    requireUserPresence: true,
    requireUserVerification: params.kind === 'passkey',
  });
  if (!verification.verified || !verification.registrationInfo) {
    throw new Error('WebAuthn-Registrierung konnte nicht verifiziert werden.');
  }
  const { credential } = verification.registrationInfo;
  return {
    credentialId: credential.id,
    publicKey: Buffer.from(credential.publicKey).toString('base64url'),
    counter: credential.counter,
    transports: (credential.transports ?? []) as string[],
  };
}

export async function createWebAuthnAuthenticationOptions(params: {
  rpId: string;
  allowCredentials?: StoredWebAuthnCredential[];
  requireUserVerification: boolean;
}) {
  return generateAuthenticationOptions({
    rpID: params.rpId,
    userVerification: params.requireUserVerification ? 'required' : 'preferred',
    ...(params.allowCredentials && params.allowCredentials.length > 0
      ? {
          allowCredentials: params.allowCredentials.map((c) => ({
            id: c.credentialId,
            transports: c.transports as AuthenticatorTransport[],
          })),
        }
      : {}),
  });
}

export async function verifyWebAuthnAuthentication(params: {
  response: AuthenticationResponseJSON;
  expectedChallenge: string;
  expectedOrigin: string;
  expectedRPID: string;
  credential: StoredWebAuthnCredential;
  requireUserVerification: boolean;
}) {
  const verification = await verifyAuthenticationResponse({
    response: params.response,
    expectedChallenge: params.expectedChallenge,
    expectedOrigin: params.expectedOrigin,
    expectedRPID: params.expectedRPID,
    requireUserVerification: params.requireUserVerification,
    credential: {
      id: params.credential.credentialId,
      publicKey: new Uint8Array(Buffer.from(params.credential.publicKey, 'base64url')),
      counter: params.credential.counter,
      transports: params.credential.transports as AuthenticatorTransport[],
    },
  });
  if (!verification.verified) {
    throw new Error('WebAuthn-Signatur konnte nicht verifiziert werden.');
  }
  return {
    newCounter: verification.authenticationInfo.newCounter,
  };
}
