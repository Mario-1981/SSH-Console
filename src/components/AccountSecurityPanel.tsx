import React, { useEffect, useState } from 'react';
import { startRegistration } from '@simplewebauthn/browser';
import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/browser';
import QRCode from 'qrcode';
import {
  CheckCircle2,
  Copy,
  Fingerprint,
  KeyRound,
  Plus,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  Trash2,
} from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import type { AppSettings, User, UserSecurityStatus } from '../types';

interface AccountSecurityPanelProps {
  user: User;
  settings: AppSettings;
  onUserUpdated: (user: User) => void;
}

export function AccountSecurityPanel({
  user,
  settings,
  onUserUpdated,
}: AccountSecurityPanelProps) {
  const { tr, formatDateTime } = useI18n();
  const [security, setSecurity] = useState<UserSecurityStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // TOTP Setup State
  const [totpSetup, setTotpSetup] = useState<{
    secret: string;
    otpauthUri: string;
    qrDataUrl: string;
  } | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [totpBusy, setTotpBusy] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [copiedRecovery, setCopiedRecovery] = useState(false);

  // Security Key State
  const [secKeyName, setSecKeyName] = useState('');
  const [secKeyBusy, setSecKeyBusy] = useState(false);

  // Passkey State
  const [passkeyName, setPasskeyName] = useState('');
  const [passkeyBusy, setPasskeyBusy] = useState(false);

  async function loadSecurity() {
    setLoading(true);
    try {
      const res = await api.getUserSecurity();
      setSecurity(res);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Sicherheitsstatus konnte nicht geladen werden.', 'Could not load security status.')
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadSecurity();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user.id]);

  async function handleStartTotpSetup() {
    setError(null);
    setSuccess(null);
    setRecoveryCodes(null);
    setTotpBusy(true);
    try {
      const res = await api.setupTotp();
      const qrDataUrl = await QRCode.toDataURL(res.otpauthUri, {
        width: 220,
        margin: 1,
      });
      setTotpSetup({ ...res, qrDataUrl });
      setTotpCode('');
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Authenticator-Einrichtung fehlgeschlagen.', 'Could not start Authenticator setup.')
      );
    } finally {
      setTotpBusy(false);
    }
  }

  async function handleVerifyTotp(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setTotpBusy(true);
    try {
      const res = await api.verifyTotp(totpCode.trim());
      setTotpSetup(null);
      setTotpCode('');
      setRecoveryCodes(res.recoveryCodes);
      onUserUpdated(res.user);
      await loadSecurity();
      setSuccess(
        tr(
          'Authenticator-App wurde aktiviert. Bitte sichern Sie Ihre Wiederherstellungscodes an einem sicheren Ort.',
          'Authenticator App enabled. Please store your recovery codes in a safe place.'
        )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Code konnte nicht bestätigt werden.', 'Could not verify code.')
      );
    } finally {
      setTotpBusy(false);
    }
  }

  async function handleDisableTotp() {
    setError(null);
    setSuccess(null);
    setTotpBusy(true);
    try {
      const res = await api.disableTotp();
      setRecoveryCodes(null);
      onUserUpdated(res.user);
      await loadSecurity();
      setSuccess(tr('Authenticator-App wurde entfernt.', 'Authenticator App has been removed.'));
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Authenticator-App konnte nicht entfernt werden.', 'Could not remove Authenticator App.')
      );
    } finally {
      setTotpBusy(false);
    }
  }

  async function handleRegisterWebAuthn(kind: 'security-key' | 'passkey') {
    setError(null);
    setSuccess(null);
    const label =
      kind === 'passkey'
        ? passkeyName.trim() || tr('Mein Passkey', 'My Passkey')
        : secKeyName.trim() || tr('Hardware-Sicherheitsschlüssel', 'Hardware Security Key');

    if (kind === 'passkey') setPasskeyBusy(true);
    else setSecKeyBusy(true);

    try {
      const { challengeId, options } = await api.getWebAuthnRegisterOptions(kind, label);
      const attestation = await startRegistration({
        optionsJSON: options as unknown as PublicKeyCredentialCreationOptionsJSON,
      });
      const res = await api.verifyWebAuthnRegister(challengeId, attestation, label);
      if (kind === 'passkey') setPasskeyName('');
      else setSecKeyName('');
      onUserUpdated(res.user);
      await loadSecurity();
      setSuccess(
        kind === 'passkey'
          ? tr(`Passkey „${label}“ wurde registriert.`, `Passkey "${label}" has been registered.`)
          : tr(
              `Sicherheitsschlüssel „${label}“ wurde registriert.`,
              `Security Key "${label}" has been registered.`
            )
      );
    } catch (err) {
      const msg =
        err instanceof Error
          ? err.message
          : tr('Registrierung abgebrochen oder fehlgeschlagen.', 'Registration cancelled or failed.');
      setError(msg);
    } finally {
      if (kind === 'passkey') setPasskeyBusy(false);
      else setSecKeyBusy(false);
    }
  }

  async function handleDeleteCredential(id: string) {
    setError(null);
    setSuccess(null);
    try {
      const res = await api.deleteWebAuthnCredential(id);
      onUserUpdated(res.user);
      await loadSecurity();
      setSuccess(tr('Schlüssel wurde entfernt.', 'Key has been removed.'));
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Schlüssel konnte nicht entfernt werden.', 'Could not remove key.')
      );
    }
  }

  async function handleCopyRecovery() {
    if (!recoveryCodes) return;
    try {
      await navigator.clipboard.writeText(recoveryCodes.join('\n'));
      setCopiedRecovery(true);
      setTimeout(() => setCopiedRecovery(false), 1800);
    } catch {
      // ignore
    }
  }

  const isSsoUser = user.authProvider === 'sso';
  const showEnforcementBanner = user.mustSetupTwoFactor || user.mustSetupPasskey;

  return (
    <div className="space-y-6">
      {showEnforcementBanner && (
        <div
          role="alert"
          className="p-4 rounded-lg bg-amber-50 border border-amber-300 text-amber-950 flex items-start gap-3"
        >
          <ShieldAlert className="w-5 h-5 text-amber-700 shrink-0 mt-0.5" />
          <div className="text-sm space-y-1">
            <p className="font-semibold">
              {tr('Sicherheitseinrichtung erforderlich', 'Security Setup Required')}
            </p>
            <p className="text-xs text-amber-900">
              {user.mustSetupTwoFactor && user.mustSetupPasskey
                ? tr(
                    'Ihr Administrator erzwingt sowohl 2-Faktor-Authentifizierung (App oder Sicherheitsschlüssel) als auch einen Passkey. Bitte richten Sie beides unten ein, um den Arbeitsbereich freizuschalten.',
                    'Your administrator enforces both Two-Factor Authentication (App or Security Key) and a Passkey. Complete both below to unlock your workspace.'
                  )
                : user.mustSetupTwoFactor
                  ? tr(
                      'Ihr Administrator erzwingt 2-Faktor-Authentifizierung für lokale Konten. Bitte richten Sie unten eine Authenticator-App oder einen Hardware-Sicherheitsschlüssel ein.',
                      'Your administrator enforces Two-Factor Authentication for local accounts. Please enroll an Authenticator App or Hardware Security Key below.'
                    )
                  : tr(
                      'Ihr Administrator erzwingt die Anmeldung per Passkey. Bitte registrieren Sie unten mindestens einen Passkey, um fortzufahren.',
                      'Your administrator enforces Passkey sign-in. Please register at least one Passkey below to continue.'
                    )}
            </p>
          </div>
        </div>
      )}

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

      {/* One-time Recovery Codes display */}
      {recoveryCodes && (
        <div className="p-5 rounded-lg bg-slate-900 text-slate-100 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-semibold text-white">
                {tr('Wiederherstellungscodes (nur jetzt sichtbar)', 'Recovery Codes (shown once)')}
              </h3>
              <p className="text-xs text-slate-400">
                {tr(
                  'Jeder Code kann einmalig anstelle des 6-stelligen App-Codes verwendet werden.',
                  'Each code can be used once instead of your 6-digit authenticator code.'
                )}
              </p>
            </div>
            <button
              type="button"
              onClick={handleCopyRecovery}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md cursor-pointer"
            >
              <Copy className="w-3.5 h-3.5" />
              {copiedRecovery ? tr('Kopiert', 'Copied') : tr('Alle kopieren', 'Copy All')}
            </button>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {recoveryCodes.map((c) => (
              <code
                key={c}
                className="px-2.5 py-1.5 rounded bg-slate-800 text-center font-mono text-xs tracking-wider text-emerald-300"
              >
                {c}
              </code>
            ))}
          </div>
        </div>
      )}

      {isSsoUser ? (
        <section className="bg-white border border-slate-200 rounded-lg p-6 text-sm text-slate-600 flex items-start gap-3">
          <ShieldCheck className="w-5 h-5 text-blue-700 shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-slate-900">
              {tr('SSO-verwaltetes Konto', 'SSO-Managed Account')}
            </p>
            <p className="text-xs text-slate-500 mt-1">
              {tr(
                'Ihre Anmeldung (inkl. MFA/Passwort) wird zentral über Ihren SSO-Anbieter verwaltet.',
                'Your sign-in (including MFA and password) is managed centrally by your SSO provider.'
              )}
            </p>
          </div>
        </section>
      ) : loading ? (
        <div className="bg-white border border-slate-200 rounded-lg p-6 text-sm text-slate-500">
          {tr('Lade Sicherheitsoptionen...', 'Loading security options...')}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* 2FA Card: Authenticator App + Hardware Security Keys */}
          <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
            <div className="flex items-start justify-between gap-3 pb-4 border-b border-slate-200">
              <div className="flex items-start gap-2.5">
                <Smartphone className="w-5 h-5 text-blue-700 mt-0.5 shrink-0" />
                <div>
                  <h2 className="font-display text-base font-semibold text-slate-900">
                    {tr('2-Faktor-Authentifizierung (2FA)', 'Two-Factor Authentication (2FA)')}
                  </h2>
                  <p className="text-xs text-slate-500 mt-0.5">
                    {tr(
                      'Authenticator-App (TOTP) und Hardware-Sicherheitsschlüssel (FIDO2).',
                      'Authenticator App (TOTP) and Hardware Security Keys (FIDO2).'
                    )}
                  </p>
                </div>
              </div>
              <span
                className={`text-xs font-medium px-2 py-0.5 rounded ${
                  user.hasTwoFactor
                    ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                    : settings.twoFactorEnforced
                      ? 'bg-amber-50 text-amber-800 border border-amber-200'
                      : 'bg-slate-100 text-slate-600'
                }`}
              >
                {user.hasTwoFactor
                  ? tr('Aktiv', 'Active')
                  : settings.twoFactorEnforced
                    ? tr('Erforderlich', 'Required')
                    : tr('Inaktiv', 'Inactive')}
              </span>
            </div>

            {!settings.twoFactorEnabled ? (
              <p className="text-xs text-slate-500">
                {tr(
                  '2FA wurde vom Administrator noch nicht eingeschaltet.',
                  '2FA has not been enabled by your administrator yet.'
                )}
              </p>
            ) : (
              <>
                {/* Authenticator App Sub-block */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <p className="text-sm font-medium text-slate-900">
                        {tr('Authenticator-App (TOTP)', 'Authenticator App (TOTP)')}
                      </p>
                      <p className="text-xs text-slate-500">
                        {security?.totpEnabled
                          ? tr(
                              `Aktiv · ${security.recoveryCodesRemaining} Wiederherstellungscodes verbleibend`,
                              `Enabled · ${security.recoveryCodesRemaining} recovery codes remaining`
                            )
                          : tr('Google Authenticator, Aegis, 1Password, Bitwarden, etc.', 'Google Authenticator, Aegis, 1Password, Bitwarden, etc.')}
                      </p>
                    </div>
                    {security?.totpEnabled ? (
                      <button
                        type="button"
                        disabled={totpBusy}
                        onClick={handleDisableTotp}
                        className="text-xs font-medium text-red-700 hover:text-red-900 cursor-pointer whitespace-nowrap"
                      >
                        {tr('Deaktivieren', 'Disable')}
                      </button>
                    ) : !totpSetup ? (
                      <button
                        type="button"
                        disabled={totpBusy}
                        onClick={handleStartTotpSetup}
                        className="px-3 py-1.5 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                      >
                        {tr('App einrichten', 'Set up App')}
                      </button>
                    ) : null}
                  </div>

                  {totpSetup && (
                    <form
                      onSubmit={handleVerifyTotp}
                      className="p-4 rounded-md bg-slate-50 border border-slate-200 space-y-3"
                    >
                      <div className="flex flex-col sm:flex-row items-center gap-4">
                        <img
                          src={totpSetup.qrDataUrl}
                          alt="TOTP QR Code"
                          className="w-36 h-36 rounded border border-slate-200 bg-white p-1 shrink-0"
                        />
                        <div className="text-xs text-slate-600 space-y-2 min-w-0">
                          <p className="font-medium text-slate-900">
                            {tr('1. QR-Code mit Ihrer Authenticator-App scannen', '1. Scan QR code with your Authenticator App')}
                          </p>
                          <p>{tr('Oder Schlüssel manuell eingeben:', 'Or enter key manually:')}</p>
                          <code className="block font-mono text-xs bg-white border border-slate-200 rounded px-2 py-1 text-slate-900 break-all">
                            {totpSetup.secret}
                          </code>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 pt-1">
                        <input
                          type="text"
                          inputMode="numeric"
                          pattern="[0-9\s]{6,8}"
                          value={totpCode}
                          onChange={(e) => setTotpCode(e.target.value)}
                          placeholder={tr('6-stelliger Code', '6-digit code')}
                          className="flex-1 px-3 py-1.5 text-sm font-mono border border-slate-300 rounded-md bg-white focus:outline-none focus:ring-2 focus:ring-blue-600"
                          required
                        />
                        <button
                          type="submit"
                          disabled={totpBusy}
                          className="px-3.5 py-1.5 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 rounded-md cursor-pointer whitespace-nowrap"
                        >
                          {tr('Bestätigen', 'Verify')}
                        </button>
                        <button
                          type="button"
                          onClick={() => setTotpSetup(null)}
                          className="px-2.5 py-1.5 text-xs text-slate-600 hover:text-slate-900 cursor-pointer"
                        >
                          {tr('Abbrechen', 'Cancel')}
                        </button>
                      </div>
                    </form>
                  )}
                </div>

                {/* Hardware Security Keys Sub-block */}
                <div className="pt-4 border-t border-slate-200 space-y-3">
                  <div className="flex items-center gap-2">
                    <KeyRound className="w-4 h-4 text-slate-600" />
                    <p className="text-sm font-medium text-slate-900">
                      {tr('Hardware-Sicherheitsschlüssel (FIDO2 / WebAuthn)', 'Hardware Security Keys (FIDO2 / WebAuthn)')}
                    </p>
                  </div>

                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={secKeyName}
                      onChange={(e) => setSecKeyName(e.target.value)}
                      placeholder={tr('z. B. YubiKey 5C Büro', 'e.g. YubiKey 5C Office')}
                      className="flex-1 px-3 py-1.5 text-xs border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                    />
                    <button
                      type="button"
                      disabled={secKeyBusy}
                      onClick={() => handleRegisterWebAuthn('security-key')}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-800 bg-slate-100 hover:bg-slate-200 border border-slate-300 rounded-md cursor-pointer whitespace-nowrap"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      {secKeyBusy
                        ? tr('Schlüssel berühren...', 'Touch key...')
                        : tr('Schlüssel hinzufügen', 'Add Key')}
                    </button>
                  </div>

                  {security && security.securityKeys.length > 0 ? (
                    <ul className="divide-y divide-slate-200 border border-slate-200 rounded-md">
                      {security.securityKeys.map((k) => (
                        <li key={k.id} className="px-3 py-2 flex items-center justify-between gap-2 text-xs">
                          <div className="min-w-0">
                            <p className="font-medium text-slate-900 truncate">{k.name}</p>
                            <p className="text-slate-500">
                              {k.lastUsedAt
                                ? tr(`Zuletzt genutzt: ${formatDateTime(k.lastUsedAt)}`, `Last used: ${formatDateTime(k.lastUsedAt)}`)
                                : tr(`Hinzugefügt: ${formatDateTime(k.createdAt)}`, `Added: ${formatDateTime(k.createdAt)}`)}
                            </p>
                          </div>
                          <button
                            type="button"
                            onClick={() => handleDeleteCredential(k.id)}
                            className="p-1.5 text-red-600 hover:bg-red-50 rounded cursor-pointer shrink-0"
                            title={tr('Entfernen', 'Remove')}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-xs text-slate-400">
                      {tr('Noch kein Hardware-Sicherheitsschlüssel registriert.', 'No hardware security keys registered yet.')}
                    </p>
                  )}
                </div>
              </>
            )}
          </section>

          {/* Passkeys Card */}
          <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
            <div className="flex items-start justify-between gap-3 pb-4 border-b border-slate-200">
              <div className="flex items-start gap-2.5">
                <Fingerprint className="w-5 h-5 text-blue-700 mt-0.5 shrink-0" />
                <div>
                  <h2 className="font-display text-base font-semibold text-slate-900">
                    {tr('Passkeys (Passwortlose Anmeldung)', 'Passkeys (Passwordless Sign-In)')}
                  </h2>
                  <p className="text-xs text-slate-500 mt-0.5">
                    {tr(
                      'Direkte Anmeldung ohne Passwort per Touch ID, Face ID, Windows Hello oder FIDO2-Stick.',
                      'Direct passwordless sign-in with Touch ID, Face ID, Windows Hello, or FIDO2 key.'
                    )}
                  </p>
                </div>
              </div>
              <span
                className={`text-xs font-medium px-2 py-0.5 rounded ${
                  user.passkeyCount > 0
                    ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                    : settings.passkeyEnforced
                      ? 'bg-amber-50 text-amber-800 border border-amber-200'
                      : 'bg-slate-100 text-slate-600'
                }`}
              >
                {user.passkeyCount > 0
                  ? `${user.passkeyCount} ${tr('aktiv', 'active')}`
                  : settings.passkeyEnforced
                    ? tr('Erforderlich', 'Required')
                    : tr('Keine', 'None')}
              </span>
            </div>

            {!settings.passkeyEnabled ? (
              <p className="text-xs text-slate-500">
                {tr(
                  'Passkeys wurden vom Administrator noch nicht eingeschaltet.',
                  'Passkeys have not been enabled by your administrator yet.'
                )}
              </p>
            ) : (
              <div className="space-y-4">
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={passkeyName}
                    onChange={(e) => setPasskeyName(e.target.value)}
                    placeholder={tr('z. B. MacBook Touch ID / Smartphone', 'e.g. MacBook Touch ID / Phone')}
                    className="flex-1 px-3 py-1.5 text-xs border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                  />
                  <button
                    type="button"
                    disabled={passkeyBusy}
                    onClick={() => handleRegisterWebAuthn('passkey')}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md cursor-pointer whitespace-nowrap"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    {passkeyBusy
                      ? tr('Bestätigen...', 'Confirm...')
                      : tr('Passkey hinzufügen', 'Add Passkey')}
                  </button>
                </div>

                {security && security.passkeys.length > 0 ? (
                  <ul className="divide-y divide-slate-200 border border-slate-200 rounded-md">
                    {security.passkeys.map((pk) => (
                      <li key={pk.id} className="px-3 py-2.5 flex items-center justify-between gap-2 text-xs">
                        <div className="min-w-0">
                          <p className="font-medium text-slate-900 truncate">{pk.name}</p>
                          <p className="text-slate-500">
                            {pk.lastUsedAt
                              ? tr(`Zuletzt genutzt: ${formatDateTime(pk.lastUsedAt)}`, `Last used: ${formatDateTime(pk.lastUsedAt)}`)
                              : tr(`Registriert: ${formatDateTime(pk.createdAt)}`, `Registered: ${formatDateTime(pk.createdAt)}`)}
                          </p>
                        </div>
                        <button
                          type="button"
                          onClick={() => handleDeleteCredential(pk.id)}
                          className="p-1.5 text-red-600 hover:bg-red-50 rounded cursor-pointer shrink-0"
                          title={tr('Entfernen', 'Remove')}
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-slate-400">
                    {tr('Noch kein Passkey für dieses Konto registriert.', 'No Passkeys registered for this account yet.')}
                  </p>
                )}
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
