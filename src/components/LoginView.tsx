import React, { useEffect, useState } from 'react';
import { startAuthentication } from '@simplewebauthn/browser';
import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/browser';
import {
  ArrowLeft,
  Fingerprint,
  Globe,
  KeyRound,
  Lock,
  Smartphone,
} from 'lucide-react';
import { api, setSessionToken } from '../api';
import { LanguageSwitcher, useI18n } from '../i18n';
import type { AppSettings, User } from '../types';

interface LoginViewProps {
  settings: AppSettings;
  onLogin: (user: User) => void;
}

interface TwoFactorChallengeState {
  ticket: string;
  methods: {
    totp: boolean;
    securityKey: boolean;
  };
  webauthnOptions: Record<string, unknown> | null;
}

export function LoginView({ settings, onLogin }: LoginViewProps) {
  const { tr } = useI18n();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [ssoBusy, setSsoBusy] = useState(false);
  const [passkeyBusy, setPasskeyBusy] = useState(false);

  // Step 2: 2FA Verification State
  const [twoFactor, setTwoFactor] = useState<TwoFactorChallengeState | null>(null);
  const [twoFactorTab, setTwoFactorTab] = useState<'totp' | 'recovery' | 'security-key'>('totp');
  const [twoFactorCode, setTwoFactorCode] = useState('');

  useEffect(() => {
    function handleMessage(event: MessageEvent) {
      if (event.origin !== window.location.origin) return;
      const data = event.data as {
        type?: string;
        sessionToken?: string;
        error?: string;
      };
      if (!data || typeof data.type !== 'string') return;
      if (data.type === 'SSO_LOGIN_SUCCESS') {
        if (data.sessionToken) {
          setSessionToken(data.sessionToken);
        }
        void api
          .getStatus()
          .then((status) => {
            setSsoBusy(false);
            if (status.user) {
              onLogin(status.user);
            } else {
              setError(
                tr(
                  'SSO-Sitzung konnte nicht übernommen werden. Bitte erneut versuchen.',
                  'Could not complete SSO session. Please try again.'
                )
              );
            }
          })
          .catch((err) => {
            setSsoBusy(false);
            setError(
              err instanceof Error ? err.message : tr('SSO-Anmeldung fehlgeschlagen.', 'SSO sign-in failed.')
            );
          });
      } else if (data.type === 'SSO_ERROR') {
        setSsoBusy(false);
        setError(data.error || tr('SSO-Anmeldung fehlgeschlagen.', 'SSO sign-in failed.'));
      }
    }
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, [onLogin, tr]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await api.login(username, password);
      if (res.requiresTwoFactor) {
        setTwoFactor({
          ticket: res.ticket,
          methods: res.methods,
          webauthnOptions: res.webauthnOptions,
        });
        setTwoFactorTab(res.methods.totp ? 'totp' : 'security-key');
        setTwoFactorCode('');
      } else {
        onLogin(res.user);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : tr('Anmeldung fehlgeschlagen.', 'Sign-in failed.'));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleVerifyTotpOrRecovery(e: React.FormEvent) {
    e.preventDefault();
    if (!twoFactor) return;
    setError(null);
    setSubmitting(true);
    try {
      const res = await api.verifyTwoFactorLogin({
        ticket: twoFactor.ticket,
        method: twoFactorTab === 'recovery' ? 'recovery' : 'totp',
        code: twoFactorCode.trim(),
      });
      onLogin(res.user);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('2FA-Prüfung fehlgeschlagen.', '2FA verification failed.')
      );
    } finally {
      setSubmitting(false);
    }
  }

  async function handleVerifySecurityKey() {
    if (!twoFactor || !twoFactor.webauthnOptions) return;
    setError(null);
    setSubmitting(true);
    try {
      const assertion = await startAuthentication({
        optionsJSON: twoFactor.webauthnOptions as unknown as PublicKeyCredentialRequestOptionsJSON,
      });
      const res = await api.verifyTwoFactorLogin({
        ticket: twoFactor.ticket,
        method: 'security-key',
        assertion,
      });
      onLogin(res.user);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Hardware-Sicherheitsschlüssel fehlgeschlagen.', 'Hardware security key failed.')
      );
    } finally {
      setSubmitting(false);
    }
  }

  async function handlePasskeyLogin() {
    setError(null);
    setPasskeyBusy(true);
    try {
      const { challengeId, options } = await api.getPasskeyLoginOptions();
      const assertion = await startAuthentication({
        optionsJSON: options as unknown as PublicKeyCredentialRequestOptionsJSON,
      });
      const res = await api.verifyPasskeyLogin(challengeId, assertion);
      onLogin(res.user);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Passkey-Anmeldung abgebrochen oder fehlgeschlagen.', 'Passkey sign-in cancelled or failed.')
      );
    } finally {
      setPasskeyBusy(false);
    }
  }

  async function handleSsoLogin() {
    setError(null);
    setSsoBusy(true);
    try {
      const { url } = await api.getSsoUrl('login');
      const popup = window.open(
        url,
        'ssh_console_sso_login',
        'width=560,height=700,noopener=no,noreferrer=no'
      );
      if (!popup) {
        setSsoBusy(false);
        setError(
          tr(
            'Popup-Fenster wurde blockiert. Bitte erlauben Sie Popups für diese Seite.',
            'Popup window was blocked. Please allow popups for this site.'
          )
        );
      }
    } catch (err) {
      setSsoBusy(false);
      setError(
        err instanceof Error ? err.message : tr('SSO konnte nicht gestartet werden.', 'Could not start SSO.')
      );
    }
  }

  const ssoAvailable = Boolean(settings.ssoEnabled && settings.ssoConfigured);
  const localEnabled = !settings.localLoginDisabled;
  const passkeyAvailable = localEnabled && settings.passkeyEnabled;

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      <header className="border-b border-slate-200 bg-white px-8 py-4 flex items-center justify-between gap-4">
        <span className="font-display text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0">
          {settings.instanceName}
        </span>
        <div className="flex items-center gap-4 shrink-0">
          <span className="hidden sm:inline text-xs text-slate-500 whitespace-nowrap">
            {tr('SSH-Befehls- & Zertifikatskonsole', 'SSH Command & Certificate Console')}
          </span>
          <LanguageSwitcher />
        </div>
      </header>

      <main className="flex-1 flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-md bg-white border border-slate-200 rounded-lg p-8">
          {twoFactor ? (
            /* Step 2: 2FA Verification */
            <div>
              <button
                type="button"
                onClick={() => {
                  setTwoFactor(null);
                  setError(null);
                }}
                className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 mb-4 cursor-pointer"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                {tr('Zurück zur Anmeldung', 'Back to sign in')}
              </button>

              <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
                {tr('2-Faktor-Bestätigung', 'Two-Factor Verification')}
              </h1>
              <p className="text-sm text-slate-600 mt-1.5">
                {tr(
                  'Bestätigen Sie Ihre Anmeldung mit Ihrem zweiten Faktor.',
                  'Confirm your sign-in using your second authentication factor.'
                )}
              </p>

              {error && (
                <div
                  role="alert"
                  className="mt-5 px-4 py-3 rounded-md bg-red-50 border border-red-200 text-sm text-red-800"
                >
                  {error}
                </div>
              )}

              {/* Method selector tabs */}
              <div className="mt-5 flex flex-wrap gap-2 border-b border-slate-200 pb-3">
                {twoFactor.methods.totp && (
                  <>
                    <button
                      type="button"
                      onClick={() => {
                        setTwoFactorTab('totp');
                        setTwoFactorCode('');
                        setError(null);
                      }}
                      className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md cursor-pointer ${
                        twoFactorTab === 'totp'
                          ? 'bg-blue-50 text-blue-800 border border-blue-200'
                          : 'text-slate-600 hover:bg-slate-100 border border-transparent'
                      }`}
                    >
                      <Smartphone className="w-3.5 h-3.5" />
                      {tr('Authenticator-App', 'Authenticator App')}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setTwoFactorTab('recovery');
                        setTwoFactorCode('');
                        setError(null);
                      }}
                      className={`px-3 py-1.5 text-xs font-medium rounded-md cursor-pointer ${
                        twoFactorTab === 'recovery'
                          ? 'bg-blue-50 text-blue-800 border border-blue-200'
                          : 'text-slate-600 hover:bg-slate-100 border border-transparent'
                      }`}
                    >
                      {tr('Backup-Code', 'Recovery Code')}
                    </button>
                  </>
                )}
                {twoFactor.methods.securityKey && (
                  <button
                    type="button"
                    onClick={() => {
                      setTwoFactorTab('security-key');
                      setError(null);
                    }}
                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md cursor-pointer ${
                      twoFactorTab === 'security-key'
                        ? 'bg-blue-50 text-blue-800 border border-blue-200'
                        : 'text-slate-600 hover:bg-slate-100 border border-transparent'
                    }`}
                  >
                    <KeyRound className="w-3.5 h-3.5" />
                    {tr('Sicherheitsschlüssel', 'Security Key')}
                  </button>
                )}
              </div>

              {twoFactorTab === 'security-key' ? (
                <div className="mt-5 space-y-4">
                  <p className="text-xs text-slate-600">
                    {tr(
                      'Stecken Sie Ihren Hardware-Sicherheitsschlüssel (z. B. YubiKey) an und tippen Sie ihn an, sobald Ihr Browser dazu auffordert.',
                      'Insert your hardware security key (e.g. YubiKey) and touch it when prompted by your browser.'
                    )}
                  </p>
                  <button
                    type="button"
                    disabled={submitting}
                    onClick={handleVerifySecurityKey}
                    className="w-full inline-flex items-center justify-center gap-2 py-2.5 px-4 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer"
                  >
                    <KeyRound className="w-4 h-4" />
                    {submitting
                      ? tr('Warte auf Schlüssel...', 'Waiting for key...')
                      : tr('Mit Sicherheitsschlüssel bestätigen', 'Verify with Security Key')}
                  </button>
                </div>
              ) : (
                <form onSubmit={handleVerifyTotpOrRecovery} className="mt-5 space-y-4">
                  <div>
                    <label
                      htmlFor="login-2fa-code"
                      className="block text-sm font-medium text-slate-700 mb-1.5"
                    >
                      {twoFactorTab === 'recovery'
                        ? tr('Einmal-Wiederherstellungscode', 'One-time Recovery Code')
                        : tr('6-stelliger Code aus Ihrer App', '6-digit code from your app')}
                    </label>
                    <input
                      id="login-2fa-code"
                      type="text"
                      inputMode={twoFactorTab === 'recovery' ? 'text' : 'numeric'}
                      autoComplete="one-time-code"
                      value={twoFactorCode}
                      onChange={(e) => setTwoFactorCode(e.target.value)}
                      placeholder={twoFactorTab === 'recovery' ? 'ABCD-EFGH' : '123456'}
                      className="w-full px-3.5 py-2.5 text-sm font-mono bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                      required
                      autoFocus
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full py-2.5 px-4 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer"
                  >
                    {submitting
                      ? tr('Wird geprüft...', 'Verifying...')
                      : tr('Anmeldung abschließen', 'Complete Sign-In')}
                  </button>
                </form>
              )}
            </div>
          ) : (
            /* Step 1: Primary Login */
            <div>
              <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
                {tr('Anmelden', 'Sign in')}
              </h1>
              <p className="text-sm text-slate-600 mt-1.5">
                {localEnabled
                  ? tr(
                      'Melden Sie sich mit Ihrem Benutzerkonto, einem Passkey oder über SSO an.',
                      'Sign in with your user account, Passkey, or SSO.'
                    )
                  : tr(
                      'Die lokale Anmeldung ist deaktiviert. Bitte melden Sie sich über Ihren SSO-Anbieter an.',
                      'Local login is disabled. Please sign in using your SSO provider.'
                    )}
              </p>

              {error && (
                <div
                  role="alert"
                  className="mt-5 px-4 py-3 rounded-md bg-red-50 border border-red-200 text-sm text-red-800"
                >
                  {error}
                </div>
              )}

              {/* SSO & Passkey Quick Buttons */}
              {(ssoAvailable || passkeyAvailable) && (
                <div className="mt-6 space-y-2.5">
                  {ssoAvailable && (
                    <button
                      type="button"
                      disabled={ssoBusy}
                      onClick={handleSsoLogin}
                      className="w-full inline-flex items-center justify-center gap-2 py-2.5 px-4 text-sm font-medium text-white bg-slate-900 hover:bg-slate-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                    >
                      <Globe className="w-4 h-4" />
                      {ssoBusy
                        ? tr('SSO-Anmeldung läuft...', 'Signing in via SSO...')
                        : tr(
                            `Mit ${settings.ssoProviderName || 'SSO'} anmelden (SSO)`,
                            `Sign in with ${settings.ssoProviderName || 'SSO'} (SSO)`
                          )}
                    </button>
                  )}

                  {passkeyAvailable && (
                    <button
                      type="button"
                      disabled={passkeyBusy}
                      onClick={handlePasskeyLogin}
                      className="w-full inline-flex items-center justify-center gap-2 py-2.5 px-4 text-sm font-medium text-slate-800 bg-white hover:bg-slate-50 border border-slate-300 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                    >
                      <Fingerprint className="w-4 h-4 text-blue-700" />
                      {passkeyBusy
                        ? tr('Warte auf Passkey...', 'Waiting for Passkey...')
                        : tr('Mit Passkey anmelden', 'Sign in with Passkey')}
                    </button>
                  )}
                </div>
              )}

              {localEnabled && (ssoAvailable || passkeyAvailable) && (
                <div className="my-5 flex items-center gap-3 text-xs text-slate-400">
                  <div className="flex-1 h-px bg-slate-200" />
                  <span>{tr('oder lokal mit Passwort', 'or local with password')}</span>
                  <div className="flex-1 h-px bg-slate-200" />
                </div>
              )}

              {localEnabled && (
                <form onSubmit={handleSubmit} className={ssoAvailable || passkeyAvailable ? 'space-y-4' : 'mt-6 space-y-4'}>
                  <div>
                    <label htmlFor="login-user" className="block text-sm font-medium text-slate-700 mb-1.5">
                      {tr('Benutzername', 'Username')}
                    </label>
                    <input
                      id="login-user"
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      autoComplete="username"
                      className="w-full px-3.5 py-2.5 text-sm font-mono bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                      required
                    />
                  </div>

                  <div>
                    <label htmlFor="login-pass" className="block text-sm font-medium text-slate-700 mb-1.5">
                      {tr('Passwort', 'Password')}
                    </label>
                    <input
                      id="login-pass"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete="current-password"
                      className="w-full px-3.5 py-2.5 text-sm bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                      required
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full py-2.5 px-4 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                  >
                    {submitting ? tr('Wird geprüft...', 'Verifying...') : tr('Anmelden', 'Sign in')}
                  </button>
                </form>
              )}

              <div className="mt-6 pt-5 border-t border-slate-200 flex items-start gap-2.5 text-xs text-slate-500">
                <Lock className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                <span>
                  {ssoAvailable && settings.ssoAutoCreateUsers
                    ? tr(
                        'Neue SSO-Benutzer werden bei der ersten Anmeldung automatisch als Benutzer angelegt.',
                        'New SSO users are created automatically with the User role on first sign-in.'
                      )
                    : tr(
                        'Selbstregistrierung ist deaktiviert. Wenden Sie sich für neue Zugänge an Ihren Administrator.',
                        'Self-registration is disabled. Contact your administrator to request an account.'
                      )}
                </span>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
