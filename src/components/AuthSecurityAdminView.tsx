import React, { useEffect, useState } from 'react';
import {
  CheckCircle2,
  Copy,
  ExternalLink,
  Fingerprint,
  Globe,
  KeyRound,
  Lock,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
} from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import type { AdminAuthSettings, AppSettings, User } from '../types';

interface AuthSecurityAdminViewProps {
  onSettingsUpdated: (settings: AppSettings, updatedUser?: User | null) => void;
}

export function AuthSecurityAdminView({ onSettingsUpdated }: AuthSecurityAdminViewProps) {
  const { tr, formatDateTime } = useI18n();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [testingSso, setTestingSso] = useState(false);
  const [copiedCallback, setCopiedCallback] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Form state
  const [ssoEnabled, setSsoEnabled] = useState(false);
  const [ssoProviderName, setSsoProviderName] = useState('SSO');
  const [ssoIssuerUrl, setSsoIssuerUrl] = useState('');
  const [ssoAuthUrl, setSsoAuthUrl] = useState('');
  const [ssoTokenUrl, setSsoTokenUrl] = useState('');
  const [ssoUserinfoUrl, setSsoUserinfoUrl] = useState('');
  const [ssoClientId, setSsoClientId] = useState('');
  const [ssoClientSecret, setSsoClientSecret] = useState('');
  const [ssoHasClientSecret, setSsoHasClientSecret] = useState(false);
  const [clearSsoClientSecret, setClearSsoClientSecret] = useState(false);
  const [ssoScopes, setSsoScopes] = useState('openid profile email');
  const [ssoAutoCreateUsers, setSsoAutoCreateUsers] = useState(true);
  const [ssoConfigured, setSsoConfigured] = useState(false);
  const [ssoTestedAt, setSsoTestedAt] = useState<string | null>(null);
  const [localLoginDisabled, setLocalLoginDisabled] = useState(false);
  const [callbackUrl, setCallbackUrl] = useState('');

  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false);
  const [twoFactorEnforced, setTwoFactorEnforced] = useState(false);
  const [passkeyEnabled, setPasskeyEnabled] = useState(false);
  const [passkeyEnforced, setPasskeyEnforced] = useState(false);
  const [allowInsecureHostKey, setAllowInsecureHostKey] = useState(false);
  const [hostKeyStats, setHostKeyStats] = useState<{ totalEntries: number; userFiles: number } | null>(null);
  const [confirmClearHostKeys, setConfirmClearHostKeys] = useState(false);
  const [clearingHostKeys, setClearingHostKeys] = useState(false);

  function applyLoaded(a: AdminAuthSettings) {
    setSsoEnabled(a.ssoEnabled);
    setSsoProviderName(a.ssoProviderName || 'SSO');
    setSsoIssuerUrl(a.ssoIssuerUrl || '');
    setSsoAuthUrl(a.ssoAuthUrl || '');
    setSsoTokenUrl(a.ssoTokenUrl || '');
    setSsoUserinfoUrl(a.ssoUserinfoUrl || '');
    setSsoClientId(a.ssoClientId || '');
    setSsoHasClientSecret(a.ssoHasClientSecret);
    setSsoClientSecret('');
    setClearSsoClientSecret(false);
    setSsoScopes(a.ssoScopes || 'openid profile email');
    setSsoAutoCreateUsers(a.ssoAutoCreateUsers);
    setSsoConfigured(a.ssoConfigured);
    setSsoTestedAt(a.ssoTestedAt);
    setLocalLoginDisabled(a.localLoginDisabled);
    setTwoFactorEnabled(a.twoFactorEnabled);
    setTwoFactorEnforced(a.twoFactorEnforced);
    setPasskeyEnabled(a.passkeyEnabled);
    setPasskeyEnforced(a.passkeyEnforced);
    setAllowInsecureHostKey(Boolean(a.allowInsecureHostKey));
    setCallbackUrl(a.callbackUrl);
  }

  async function loadSettings() {
    setLoading(true);
    setError(null);
    try {
      const [res, hkStats] = await Promise.all([
        api.getAdminAuthSettings(),
        api.getAdminHostKeyStats().catch(() => null),
      ]);
      applyLoaded(res.authSettings);
      if (hkStats) setHostKeyStats(hkStats);
      onSettingsUpdated(res.settings);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Einstellungen konnten nicht geladen werden.', 'Could not load settings.')
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadSettings();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    function handleMessage(event: MessageEvent) {
      if (event.origin !== window.location.origin) return;
      const data = event.data as {
        type?: string;
        testedAt?: string;
        error?: string;
        profile?: { username?: string; displayName?: string; email?: string };
      };
      if (!data || typeof data.type !== 'string') return;
      if (data.type === 'SSO_TEST_SUCCESS') {
        setTestingSso(false);
        setError(null);
        const who = data.profile?.displayName || data.profile?.email || data.profile?.username || '';
        setSuccess(
          tr(
            `SSO-Test erfolgreich abgeschlossen${who ? ` (${who})` : ''}. Die lokale Anmeldung kann jetzt bei Bedarf abgeschaltet werden.`,
            `SSO test succeeded${who ? ` (${who})` : ''}. Local login can now be disabled if desired.`
          )
        );
        void loadSettings();
      } else if (data.type === 'SSO_ERROR') {
        setTestingSso(false);
        setError(
          data.error ||
            tr('SSO-Test fehlgeschlagen. Bitte prüfen Sie die Konfiguration.', 'SSO test failed. Please check your configuration.')
        );
      }
    }
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tr]);

  async function handleDiscover() {
    setError(null);
    setSuccess(null);
    if (!ssoIssuerUrl.trim()) {
      setError(tr('Bitte zuerst eine OIDC Issuer-URL eingeben.', 'Please enter an OIDC Issuer URL first.'));
      return;
    }
    setDiscovering(true);
    try {
      const { discovered } = await api.discoverOidc(ssoIssuerUrl.trim());
      setSsoIssuerUrl(discovered.issuer);
      setSsoAuthUrl(discovered.authorizationEndpoint);
      setSsoTokenUrl(discovered.tokenEndpoint);
      setSsoUserinfoUrl(discovered.userinfoEndpoint);
      setSuccess(
        tr(
          'OIDC-Endpunkte erfolgreich automatisch ermittelt. Bitte anschließend speichern und testen.',
          'OIDC endpoints discovered automatically. Save and test your configuration next.'
        )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('OIDC Auto-Discovery fehlgeschlagen.', 'OIDC auto-discovery failed.')
      );
    } finally {
      setDiscovering(false);
    }
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setSaving(true);
    try {
      const res = await api.updateAdminAuthSettings({
        ssoEnabled,
        ssoProviderName,
        ssoIssuerUrl,
        ssoAuthUrl,
        ssoTokenUrl,
        ssoUserinfoUrl,
        ssoClientId,
        ...(ssoClientSecret.trim() ? { ssoClientSecret: ssoClientSecret.trim() } : {}),
        ...(clearSsoClientSecret ? { clearSsoClientSecret: true } : {}),
        ssoScopes,
        ssoAutoCreateUsers,
        localLoginDisabled,
        twoFactorEnabled,
        twoFactorEnforced,
        passkeyEnabled,
        passkeyEnforced,
        allowInsecureHostKey,
      });
      applyLoaded(res.authSettings);
      onSettingsUpdated(res.settings, res.user);
      setSuccess(
        tr(
          'Authentifizierungs- und Sicherheitsrichtlinien wurden gespeichert.',
          'Authentication and security policies have been saved.'
        )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Speichern fehlgeschlagen.', 'Could not save settings.')
      );
    } finally {
      setSaving(false);
    }
  }

  async function handleTestSso() {
    setError(null);
    setSuccess(null);
    setTestingSso(true);
    try {
      // Save current SSO fields first so test uses the latest values
      const saved = await api.updateAdminAuthSettings({
        ssoEnabled: true,
        ssoProviderName,
        ssoIssuerUrl,
        ssoAuthUrl,
        ssoTokenUrl,
        ssoUserinfoUrl,
        ssoClientId,
        ...(ssoClientSecret.trim() ? { ssoClientSecret: ssoClientSecret.trim() } : {}),
        ...(clearSsoClientSecret ? { clearSsoClientSecret: true } : {}),
        ssoScopes,
        ssoAutoCreateUsers,
      });
      applyLoaded(saved.authSettings);
      onSettingsUpdated(saved.settings, saved.user);

      const { url } = await api.getSsoUrl('test');
      const popup = window.open(
        url,
        'ssh_console_sso_test',
        'width=560,height=700,noopener=no,noreferrer=no'
      );
      if (!popup) {
        setTestingSso(false);
        setError(
          tr(
            'Popup-Fenster wurde vom Browser blockiert. Bitte erlauben Sie Popups für diese Seite und starten Sie den Test erneut.',
            'Popup window was blocked by the browser. Please allow popups for this site and retry.'
          )
        );
      }
    } catch (err) {
      setTestingSso(false);
      setError(
        err instanceof Error
          ? err.message
          : tr('SSO-Test konnte nicht gestartet werden.', 'Could not start SSO test.')
      );
    }
  }

  async function copyCallback() {
    if (!callbackUrl) return;
    try {
      await navigator.clipboard.writeText(callbackUrl);
      setCopiedCallback(true);
      setTimeout(() => setCopiedCallback(false), 1800);
    } catch {
      // clipboard unavailable
    }
  }

  async function handleClearAllHostKeys() {
    setClearingHostKeys(true);
    setError(null);
    setSuccess(null);
    try {
      const res = await api.clearAllAdminHostKeys();
      setHostKeyStats({ totalEntries: res.totalEntries, userFiles: 0 });
      setConfirmClearHostKeys(false);
      setSuccess(
        res.removedCount > 0
          ? tr(
              `Alle gespeicherten SSH Host-Keys wurden global gelöscht (${res.removedCount} Einträge aus ${res.affectedFiles} Benutzerdatei(en) entfernt).`,
              `All stored SSH host keys have been globally deleted (${res.removedCount} entries removed across ${res.affectedFiles} user file(s)).`
            )
          : tr(
              'Keine gespeicherten SSH Host-Keys vorhanden – es mussten keine Einträge gelöscht werden.',
              'No stored SSH host keys found — nothing to remove.'
            )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Host-Keys konnten nicht gelöscht werden.', 'Could not delete host keys.')
      );
    } finally {
      setClearingHostKeys(false);
    }
  }

  const canDisableLocalLogin = Boolean(ssoEnabled && ssoConfigured && ssoTestedAt);

  if (loading) {
    return (
      <div className="bg-white border border-slate-200 rounded-lg p-8 text-sm text-slate-500">
        {tr('Lade Authentifizierungseinstellungen...', 'Loading authentication settings...')}
      </div>
    );
  }

  return (
    <form onSubmit={handleSave} className="space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
            {tr('Authentifizierung, SSO, 2FA & Passkeys', 'Authentication, SSO, 2FA & Passkeys')}
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            {tr(
              'Konfigurieren Sie OpenID Connect / OAuth 2.0 Single Sign-On sowie systemweite Richtlinien für 2FA und Passkeys.',
              'Configure OpenID Connect / OAuth 2.0 Single Sign-On as well as system-wide policies for 2FA and Passkeys.'
            )}
          </p>
        </div>

        <button
          type="submit"
          disabled={saving}
          className="inline-flex items-center justify-center gap-2 px-5 py-2.5 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
        >
          <ShieldCheck className="w-4 h-4" />
          {saving ? tr('Speichert...', 'Saving...') : tr('Änderungen speichern', 'Save Changes')}
        </button>
      </div>

      {error && (
        <div role="alert" className="px-4 py-3 rounded-md bg-red-50 border border-red-200 text-sm text-red-800">
          {error}
        </div>
      )}

      {success && (
        <div className="px-4 py-3 rounded-md bg-emerald-50 border border-emerald-200 text-sm text-emerald-900 flex items-start gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-emerald-700" />
          <span>{success}</span>
        </div>
      )}

      {/* Section 1: SSO / OpenID Connect */}
      <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-slate-200">
          <div className="flex items-start gap-3">
            <Globe className="w-5 h-5 text-blue-700 mt-0.5 shrink-0" />
            <div>
              <h2 className="font-display text-base font-semibold text-slate-900">
                {tr('Single Sign-On (OIDC / OAuth 2.0)', 'Single Sign-On (OIDC / OAuth 2.0)')}
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                {tr(
                  'Unterstützt Keycloak, Authentik, Microsoft Entra ID, Google Workspace, GitLab, Okta und jeden OIDC-Anbieter (mit PKCE S256).',
                  'Supports Keycloak, Authentik, Microsoft Entra ID, Google Workspace, GitLab, Okta, and any OIDC provider (with PKCE S256).'
                )}
              </p>
            </div>
          </div>

          <label className="inline-flex items-center gap-2.5 cursor-pointer shrink-0">
            <input
              type="checkbox"
              checked={ssoEnabled}
              onChange={(e) => {
                const next = e.target.checked;
                setSsoEnabled(next);
                if (!next) setLocalLoginDisabled(false);
              }}
              className="w-4 h-4 rounded border-slate-300 text-blue-700 focus:ring-blue-600"
            />
            <span className="text-sm font-medium text-slate-800">
              {tr('SSO aktivieren', 'Enable SSO')}
            </span>
          </label>
        </div>

        {/* Callback URL Box */}
        <div className="p-4 rounded-md bg-slate-50 border border-slate-200 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-medium text-slate-700">
              {tr('Redirect / Callback-URL (beim SSO-Anbieter eintragen)', 'Redirect / Callback URL (register at your IdP)')}
            </span>
            <button
              type="button"
              onClick={copyCallback}
              className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-700 hover:text-blue-900 cursor-pointer"
            >
              <Copy className="w-3.5 h-3.5" />
              {copiedCallback ? tr('Kopiert', 'Copied') : tr('Kopieren', 'Copy')}
            </button>
          </div>
          <code className="block text-xs font-mono text-slate-900 bg-white border border-slate-200 rounded px-3 py-2 break-all">
            {callbackUrl || `${window.location.origin}/api/auth/sso/callback`}
          </code>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label htmlFor="sso-provider" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr('Anzeigename des SSO-Buttons', 'SSO Button Display Name')}
            </label>
            <input
              id="sso-provider"
              type="text"
              value={ssoProviderName}
              onChange={(e) => setSsoProviderName(e.target.value)}
              placeholder="Keycloak / Firmen-SSO"
              className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          <div>
            <label htmlFor="sso-scopes" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr('OAuth Scopes', 'OAuth Scopes')}
            </label>
            <input
              id="sso-scopes"
              type="text"
              value={ssoScopes}
              onChange={(e) => setSsoScopes(e.target.value)}
              placeholder="openid profile email"
              className="w-full px-3 py-2 text-sm font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          <div className="md:col-span-2">
            <label htmlFor="sso-issuer" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr('OIDC Issuer-URL (für Auto-Discovery)', 'OIDC Issuer URL (for Auto-Discovery)')}
            </label>
            <div className="flex flex-col sm:flex-row gap-2">
              <input
                id="sso-issuer"
                type="url"
                value={ssoIssuerUrl}
                onChange={(e) => setSsoIssuerUrl(e.target.value)}
                placeholder="https://idp.example.com/realms/main"
                className="flex-1 px-3 py-2 text-sm font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
              <button
                type="button"
                onClick={handleDiscover}
                disabled={discovering}
                className="inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-medium text-slate-800 bg-slate-100 hover:bg-slate-200 border border-slate-300 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                <Sparkles className="w-3.5 h-3.5" />
                {discovering
                  ? tr('Ermittle...', 'Discovering...')
                  : tr('Endpunkte automatisch laden', 'Auto-Discover Endpoints')}
              </button>
            </div>
          </div>

          <div>
            <label htmlFor="sso-auth-url" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr('Authorization-URL *', 'Authorization URL *')}
            </label>
            <input
              id="sso-auth-url"
              type="url"
              value={ssoAuthUrl}
              onChange={(e) => setSsoAuthUrl(e.target.value)}
              placeholder="https://idp.example.com/.../auth"
              className="w-full px-3 py-2 text-sm font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          <div>
            <label htmlFor="sso-token-url" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr('Token-URL *', 'Token URL *')}
            </label>
            <input
              id="sso-token-url"
              type="url"
              value={ssoTokenUrl}
              onChange={(e) => setSsoTokenUrl(e.target.value)}
              placeholder="https://idp.example.com/.../token"
              className="w-full px-3 py-2 text-sm font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          <div className="md:col-span-2">
            <label htmlFor="sso-userinfo-url" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr('UserInfo-URL (empfohlen)', 'UserInfo URL (recommended)')}
            </label>
            <input
              id="sso-userinfo-url"
              type="url"
              value={ssoUserinfoUrl}
              onChange={(e) => setSsoUserinfoUrl(e.target.value)}
              placeholder="https://idp.example.com/.../userinfo"
              className="w-full px-3 py-2 text-sm font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          <div>
            <label htmlFor="sso-client-id" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr('Client ID *', 'Client ID *')}
            </label>
            <input
              id="sso-client-id"
              type="text"
              value={ssoClientId}
              onChange={(e) => setSsoClientId(e.target.value)}
              placeholder="ssh-console"
              className="w-full px-3 py-2 text-sm font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label htmlFor="sso-client-secret" className="block text-xs font-medium text-slate-700">
                {tr('Client Secret (verschlüsselt gespeichert)', 'Client Secret (stored encrypted)')}
              </label>
              {ssoHasClientSecret && !clearSsoClientSecret && (
                <button
                  type="button"
                  onClick={() => setClearSsoClientSecret(true)}
                  className="text-xs text-red-700 hover:underline cursor-pointer"
                >
                  {tr('Entfernen', 'Clear')}
                </button>
              )}
            </div>
            <input
              id="sso-client-secret"
              type="password"
              value={ssoClientSecret}
              onChange={(e) => {
                setSsoClientSecret(e.target.value);
                if (e.target.value) setClearSsoClientSecret(false);
              }}
              placeholder={
                clearSsoClientSecret
                  ? tr('Wird beim Speichern gelöscht', 'Will be cleared on save')
                  : ssoHasClientSecret
                    ? tr('•••••••• (hinterlegt – leer lassen zum Beibehalten)', '•••••••• (configured – leave blank to keep)')
                    : tr('Optional bei PKCE Public Clients', 'Optional for PKCE public clients')
              }
              className="w-full px-3 py-2 text-sm font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
        </div>

        {/* Auto-create users option */}
        <div className="pt-2 border-t border-slate-100 space-y-4">
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={ssoAutoCreateUsers}
              onChange={(e) => setSsoAutoCreateUsers(e.target.checked)}
              className="w-4 h-4 mt-0.5 rounded border-slate-300 text-blue-700 focus:ring-blue-600"
            />
            <div>
              <span className="block text-sm font-medium text-slate-900">
                {tr(
                  'Unbekannte SSO-Benutzer automatisch als Benutzer anlegen',
                  'Automatically create new SSO users with User role'
                )}
              </span>
              <span className="block text-xs text-slate-500 mt-0.5">
                {tr(
                  'Meldet sich eine Person erstmals per SSO an und existiert noch kein passendes Konto, wird automatisch ein neues Konto mit der Rolle „Benutzer“ erstellt.',
                  'When someone signs in via SSO for the first time without an existing account, a new account with the "User" role is created automatically.'
                )}
              </span>
            </div>
          </label>

          {/* SSO Test Gate & Local Login Disable */}
          <div className="p-4 rounded-lg border border-slate-200 bg-slate-50 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-900">
                  {tr('SSO-Verbindungstest (Voraussetzung zum Abschalten der lokalen Anmeldung)', 'SSO Connection Test (required before disabling local login)')}
                </h3>
                <p className="text-xs text-slate-600 mt-0.5">
                  {ssoTestedAt ? (
                    <span className="inline-flex items-center gap-1.5 text-emerald-700 font-medium">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      {tr(
                        `Erfolgreich getestet am ${formatDateTime(ssoTestedAt)}`,
                        `Verified on ${formatDateTime(ssoTestedAt)}`
                      )}
                    </span>
                  ) : (
                    tr(
                      'Noch nicht getestet. Änderungen an den SSO-URLs oder der Client-ID setzen den Teststatus aus Sicherheitsgründen zurück.',
                      'Not tested yet. Editing SSO URLs or Client ID resets the verified status to prevent lockouts.'
                    )
                  )}
                </p>
              </div>

              <button
                type="button"
                onClick={handleTestSso}
                disabled={testingSso || !ssoAuthUrl.trim() || !ssoTokenUrl.trim() || !ssoClientId.trim()}
                className="inline-flex items-center justify-center gap-2 px-4 py-2 text-xs font-medium text-blue-800 bg-blue-50 hover:bg-blue-100 border border-blue-200 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
              >
                {testingSso ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <ExternalLink className="w-3.5 h-3.5" />
                )}
                {testingSso
                  ? tr('Warte auf SSO-Fenster...', 'Waiting for SSO window...')
                  : tr('SSO-Verbindung jetzt testen', 'Test SSO Connection Now')}
              </button>
            </div>

            <div className="pt-3 border-t border-slate-200">
              <label
                className={`flex items-start gap-3 ${
                  canDisableLocalLogin ? 'cursor-pointer' : 'opacity-60 cursor-not-allowed'
                }`}
              >
                <input
                  type="checkbox"
                  checked={localLoginDisabled}
                  disabled={!canDisableLocalLogin}
                  onChange={(e) => setLocalLoginDisabled(e.target.checked)}
                  className="w-4 h-4 mt-0.5 rounded border-slate-300 text-blue-700 focus:ring-blue-600"
                />
                <div>
                  <span className="block text-sm font-medium text-slate-900">
                    {tr('Lokale Anmeldung abschalten (nur SSO erlauben)', 'Disable local login (SSO only)')}
                  </span>
                  <span className="block text-xs text-slate-500 mt-0.5">
                    {canDisableLocalLogin
                      ? tr(
                          'Blendet Benutzername/Passwort und Passkey auf der Anmeldeseite aus und sperrt lokale Logins serverseitig.',
                          'Hides username/password and passkey login on the sign-in screen and blocks local logins server-side.'
                        )
                      : tr(
                          'Erst verfügbar, sobald SSO aktiviert, vollständig konfiguriert und erfolgreich getestet wurde.',
                          'Available once SSO is enabled, fully configured, and successfully tested.'
                        )}
                  </span>
                </div>
              </label>
            </div>
          </div>
        </div>
      </section>

      {/* Section 2: 2FA Policy for Local Login */}
      <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
        <div className="flex items-start gap-3 pb-4 border-b border-slate-200">
          <KeyRound className="w-5 h-5 text-blue-700 mt-0.5 shrink-0" />
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900">
              {tr('2-Faktor-Authentifizierung (2FA) für lokale Anmeldung', 'Two-Factor Authentication (2FA) for Local Login')}
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              {tr(
                'Unterstützt Authenticator-Apps (TOTP mit QR-Code & Wiederherstellungscodes) sowie Hardware-Sicherheitsschlüssel (FIDO2 / WebAuthn, z. B. YubiKey).',
                'Supports Authenticator Apps (TOTP with QR code & recovery codes) and Hardware Security Keys (FIDO2 / WebAuthn, e.g. YubiKey).'
              )}
            </p>
          </div>
        </div>

        <div className="space-y-4">
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={twoFactorEnabled}
              onChange={(e) => {
                const next = e.target.checked;
                setTwoFactorEnabled(next);
                if (!next) setTwoFactorEnforced(false);
              }}
              className="w-4 h-4 mt-0.5 rounded border-slate-300 text-blue-700 focus:ring-blue-600"
            />
            <div>
              <span className="block text-sm font-medium text-slate-900">
                {tr('2FA für lokale Konten einschalten (App & Sicherheitsschlüssel)', 'Enable 2FA for local accounts (App & Security Key)')}
              </span>
              <span className="block text-xs text-slate-500 mt-0.5">
                {tr(
                  'Benutzer können unter „Konto & Sicherheit“ eine Authenticator-App und/oder Hardware-Sicherheitsschlüssel einrichten.',
                  'Users can enroll an Authenticator App and/or Hardware Security Keys under "Account & Security".'
                )}
              </span>
            </div>
          </label>

          <label
            className={`flex items-start gap-3 pl-7 ${
              twoFactorEnabled ? 'cursor-pointer' : 'opacity-50 cursor-not-allowed'
            }`}
          >
            <input
              type="checkbox"
              checked={twoFactorEnforced}
              disabled={!twoFactorEnabled}
              onChange={(e) => setTwoFactorEnforced(e.target.checked)}
              className="w-4 h-4 mt-0.5 rounded border-slate-300 text-blue-700 focus:ring-blue-600"
            />
            <div>
              <span className="block text-sm font-medium text-slate-900">
                {tr('2FA für alle lokalen Konten erzwingen', 'Enforce 2FA for all local accounts')}
              </span>
              <span className="block text-xs text-slate-500 mt-0.5">
                {tr(
                  'Lokale Benutzer ohne aktives 2FA werden nach dem Login automatisch zur Einrichtung geleitet, bevor sie auf Dashboard, Server, Befehle oder SSH-Shell zugreifen dürfen.',
                  'Local users without active 2FA are guided directly to security setup after sign-in before accessing Dashboard, Servers, Commands, or SSH Shell.'
                )}
              </span>
            </div>
          </label>
        </div>
      </section>

      {/* Section 3: Passkey Policy */}
      <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
        <div className="flex items-start gap-3 pb-4 border-b border-slate-200">
          <Fingerprint className="w-5 h-5 text-blue-700 mt-0.5 shrink-0" />
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900">
              {tr('Passkeys (Passwortlose WebAuthn-Anmeldung)', 'Passkeys (Passwordless WebAuthn Sign-In)')}
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              {tr(
                'Ermöglicht sichere Anmeldung per Touch ID, Face ID, Windows Hello, Passwortmanager oder FIDO2-Stick mit Benutzerverifizierung.',
                'Enables secure sign-in with Touch ID, Face ID, Windows Hello, password managers, or FIDO2 keys with user verification.'
              )}
            </p>
          </div>
        </div>

        <div className="space-y-4">
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={passkeyEnabled}
              onChange={(e) => {
                const next = e.target.checked;
                setPasskeyEnabled(next);
                if (!next) setPasskeyEnforced(false);
              }}
              className="w-4 h-4 mt-0.5 rounded border-slate-300 text-blue-700 focus:ring-blue-600"
            />
            <div>
              <span className="block text-sm font-medium text-slate-900">
                {tr('Passkeys einschalten', 'Enable Passkeys')}
              </span>
              <span className="block text-xs text-slate-500 mt-0.5">
                {tr(
                  'Zeigt „Mit Passkey anmelden“ auf der Anmeldeseite an und erlaubt Benutzern die Registrierung eigener Passkeys.',
                  'Shows "Sign in with Passkey" on the login screen and allows users to register their own Passkeys.'
                )}
              </span>
            </div>
          </label>

          <label
            className={`flex items-start gap-3 pl-7 ${
              passkeyEnabled ? 'cursor-pointer' : 'opacity-50 cursor-not-allowed'
            }`}
          >
            <input
              type="checkbox"
              checked={passkeyEnforced}
              disabled={!passkeyEnabled}
              onChange={(e) => setPasskeyEnforced(e.target.checked)}
              className="w-4 h-4 mt-0.5 rounded border-slate-300 text-blue-700 focus:ring-blue-600"
            />
            <div>
              <span className="block text-sm font-medium text-slate-900">
                {tr('Passkeys für alle lokalen Konten erzwingen', 'Enforce Passkeys for all local accounts')}
              </span>
              <span className="block text-xs text-slate-500 mt-0.5">
                {tr(
                  'Lokale Benutzer ohne Passkey müssen sofort nach dem Login einen Passkey registrieren. Sobald ein Passkey hinterlegt ist, ist die Passwort-Anmeldung für dieses Konto gesperrt.',
                  'Local users without a Passkey must enroll one immediately after sign-in. Once a Passkey is registered, password login is blocked for that account.'
                )}
              </span>
            </div>
          </label>

          <div className="p-3.5 rounded-md bg-amber-50 border border-amber-200 text-xs text-amber-900 flex items-start gap-2.5">
            <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-amber-700" />
            <span>
              {tr(
                'Hinweis: Passkeys und Hardware-Sicherheitsschlüssel erfordern im Browser eine sichere Umgebung (HTTPS oder localhost). Bei Geräteverlust können Administratoren 2FA und Passkeys eines Benutzers unter „Benutzerverwaltung“ zurücksetzen.',
                'Note: Passkeys and Hardware Security Keys require a secure browser context (HTTPS or localhost). If a device is lost, administrators can reset a user’s 2FA and Passkeys under "User Management".'
              )}
            </span>
          </div>
        </div>
      </section>

      {/* Section 4: SSH Host-Key Checking Policy */}
      <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
        <div className="flex items-start gap-3 pb-4 border-b border-slate-200">
          <ShieldAlert className="w-5 h-5 text-blue-700 mt-0.5 shrink-0" />
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900">
              {tr('SSH-Sicherheit: Host-Key-Prüfung (pro IP)', 'SSH Security: Host Key Checking (per IP)')}
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              {tr(
                'Steuert global, ob Benutzer für einzelne Ziel-IPs die OpenSSH-Optionen StrictHostKeyChecking=no und UserKnownHostsFile=/dev/null aktivieren dürfen.',
                'Globally controls whether users are allowed to enable StrictHostKeyChecking=no and UserKnownHostsFile=/dev/null on individual target IPs.'
              )}
            </p>
          </div>
        </div>

        <div className="space-y-4">
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={allowInsecureHostKey}
              onChange={(e) => setAllowInsecureHostKey(e.target.checked)}
              className="w-4 h-4 mt-0.5 rounded border-slate-300 text-blue-700 focus:ring-blue-600"
            />
            <div>
              <span className="block text-sm font-medium text-slate-900">
                {tr(
                  'Deaktivieren der Host-Key-Prüfung pro IP erlauben',
                  'Allow disabling Host Key Checking per IP'
                )}
              </span>
              <span className="block text-xs text-slate-500 mt-0.5">
                {tr(
                  'Wenn aktiviert, können Benutzer unter „Meine Server (IPs)“ und in der „SSH-Shell“ pro Ziel-IP auswählen, ob OpenSSH mit -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null verbinden soll (z. B. für Labor-, Test- oder neu provisionierte Systeme). Ist dieser Schalter aus, wird die Host-Key-Prüfung serverseitig für alle Verbindungen erzwungen.',
                  'When enabled, users can choose per target IP under "My Servers (IPs)" and in "SSH Shell" to connect with -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null (e.g. for lab, staging, or frequently reimaged hosts). When disabled, host key verification is enforced server-side for all connections.'
                )}
              </span>
            </div>
          </label>

          <div className="pt-4 border-t border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium text-slate-900">
                {tr(
                  'Gespeicherte SSH Host-Keys (known_hosts) global zurücksetzen',
                  'Globally Reset Stored SSH Host Keys (known_hosts)'
                )}
              </p>
              <p className="text-xs text-slate-500 mt-0.5">
                {hostKeyStats !== null
                  ? tr(
                      `Aktuell gespeichert: ${hostKeyStats.totalEntries} Host-Key-Einträge (${hostKeyStats.userFiles} Benutzer). Bei erneutem Verbinden werden neue Host-Keys automatisch per accept-new akzeptiert.`,
                      `Currently stored: ${hostKeyStats.totalEntries} host key entries (${hostKeyStats.userFiles} users). New host keys will be accepted automatically via accept-new on next connection.`
                    )
                  : tr(
                      'Löscht alle gespeicherten SSH Host-Keys aller Benutzer, damit neu installierte Zielsysteme wieder per accept-new verbunden werden können.',
                      'Clears all stored SSH host keys across all users so reinstalled hosts can be trusted again via accept-new.'
                    )}
              </p>
            </div>

            {confirmClearHostKeys ? (
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={handleClearAllHostKeys}
                  disabled={clearingHostKeys}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  {clearingHostKeys
                    ? tr('Löscht...', 'Deleting...')
                    : tr('Ja, alle Host-Keys löschen', 'Yes, Delete All Host Keys')}
                </button>
                <button
                  type="button"
                  onClick={() => setConfirmClearHostKeys(false)}
                  disabled={clearingHostKeys}
                  className="px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                >
                  {tr('Abbrechen', 'Cancel')}
                </button>
              </div>
            ) : (
              <button
                type="button"
                onClick={() => setConfirmClearHostKeys(true)}
                className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 text-xs font-medium text-red-700 bg-red-50 hover:bg-red-100 border border-red-200 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
              >
                <Trash2 className="w-3.5 h-3.5" />
                {tr('Alle Host-Keys global löschen', 'Delete All Host Keys Globally')}
              </button>
            )}
          </div>
        </div>
      </section>

      <div className="flex items-center justify-between pt-2">
        <span className="inline-flex items-center gap-1.5 text-xs text-slate-500">
          <Lock className="w-3.5 h-3.5" />
          {tr(
            'Alle Geheimnisse (SSO Client Secret, TOTP-Schlüssel) werden serverseitig mit AES-256-GCM verschlüsselt gespeichert.',
            'All secrets (SSO Client Secret, TOTP keys) are encrypted server-side with AES-256-GCM.'
          )}
        </span>
        <button
          type="submit"
          disabled={saving}
          className="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
        >
          <ShieldCheck className="w-4 h-4" />
          {saving ? tr('Speichert...', 'Saving...') : tr('Änderungen speichern', 'Save Changes')}
        </button>
      </div>
    </form>
  );
}
