import React, { useState } from 'react';
import { ShieldCheck, Terminal, KeyRound, Lock } from 'lucide-react';
import { api } from '../api';
import { LanguageSwitcher, useI18n } from '../i18n';
import { ThemeSwitcher } from '../theme';
import { getPasswordComplexityError } from '../passwordPolicy';
import { PasswordStrengthHint } from './PasswordStrengthHint';
import type { AppSettings, User } from '../types';

interface SetupViewProps {
  onComplete: (user: User, settings: AppSettings) => void;
}

export function SetupView({ onComplete }: SetupViewProps) {
  const { tr } = useI18n();
  const [instanceName, setInstanceName] = useState('SSH Console');
  const [username, setUsername] = useState('admin');
  const [displayName, setDisplayName] = useState('Administrator');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    const passwordError = getPasswordComplexityError(password, tr);
    if (passwordError) {
      setError(passwordError);
      return;
    }
    if (password !== confirmPassword) {
      setError(
        tr(
          'Die beiden Passwort-Eingaben stimmen nicht überein.',
          'The two password entries do not match.'
        )
      );
      return;
    }

    setSubmitting(true);
    try {
      const res = await api.setupAdmin({
        username,
        displayName,
        password,
        instanceName,
      });
      onComplete(res.user, res.settings);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : tr('Ersteinrichtung fehlgeschlagen.', 'Initial setup failed.')
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex flex-col">
      <header className="border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-8 py-4 flex items-center justify-between gap-4">
        <span className="font-display text-lg font-bold tracking-tight text-slate-900 dark:text-slate-100 whitespace-nowrap shrink-0">
          SSH Console
        </span>
        <div className="flex items-center gap-3 shrink-0">
          <span className="hidden sm:inline text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
            {tr('Debian 13 (Trixie) · Ersteinrichtung', 'Debian 13 (Trixie) · Initial Setup')}
          </span>
          <ThemeSwitcher />
          <LanguageSwitcher />
        </div>
      </header>

      <main className="flex-1 flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-12 gap-10 items-stretch">
          <section className="lg:col-span-6 flex flex-col justify-between py-2">
            <div>
              <p className="text-xs font-medium text-blue-700 dark:text-blue-400 mb-3">
                {tr('Einmalige Systeminitialisierung', 'One-Time System Initialization')}
              </p>
              <h1 className="font-display text-3xl sm:text-4xl font-bold tracking-tight text-slate-900 dark:text-slate-100 leading-tight">
                {tr(
                  'Administrator-Konto für SSH Console einrichten',
                  'Set up the administrator account for SSH Console'
                )}
              </h1>
              <p className="mt-4 text-sm sm:text-base text-slate-600 dark:text-slate-400 leading-relaxed max-w-xl">
                {tr(
                  'Legen Sie das erste Administratorkonto fest. Nach Abschluss dieser Einrichtung wird die Setup-Route dauerhaft gesperrt — eine öffentliche Selbstregistrierung existiert nicht.',
                  'Create the initial administrator account. Once setup completes, this setup route is permanently locked — public self-registration does not exist.'
                )}
              </p>

              <div className="mt-8 space-y-5 border-t border-slate-200 dark:border-slate-800 pt-6">
                <div className="flex items-start gap-3.5">
                  <ShieldCheck className="w-5 h-5 text-slate-700 dark:text-slate-300 shrink-0 mt-0.5" />
                  <div>
                    <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {tr('01. Zentrale Befehlsfreigabe', '01. Central Command Management')}
                    </h2>
                    <p className="text-sm text-slate-600 dark:text-slate-400 mt-0.5">
                      {tr(
                        'Definieren Sie Einzelbefehle und Befehlsketten. Administratoren können Einträge gezielt oder für alle Benutzer freigeben.',
                        'Define reusable single commands and multi-step command chains. Administrators can share entries with selected users or everyone.'
                      )}
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3.5">
                  <KeyRound className="w-5 h-5 text-slate-700 dark:text-slate-300 shrink-0 mt-0.5" />
                  <div>
                    <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {tr('02. Passwortlose OpenSSH-Schlüssel & Zertifikate', '02. Passwordless OpenSSH Keys & Certificates')}
                    </h2>
                    <p className="text-sm text-slate-600 dark:text-slate-400 mt-0.5">
                      {tr(
                        'Unterstützt sowohl klassische Schlüsselpaare (2 Dateien) als auch CA-signierte OpenSSH-Zertifikate (3 Dateien) inklusive curl-Upload-API.',
                        'Supports both classic SSH keypairs (2 files) and CA-signed OpenSSH certificates (3 files), including a curl upload API.'
                      )}
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3.5">
                  <Terminal className="w-5 h-5 text-slate-700 dark:text-slate-300 shrink-0 mt-0.5" />
                  <div>
                    <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {tr('03. Rust-Backend für Debian Trixie', '03. Native Rust Backend for Debian Trixie')}
                    </h2>
                    <p className="text-sm text-slate-600 dark:text-slate-400 mt-0.5">
                      {tr(
                        'Inklusive vollständigem Rust-Quellcode (Axum, SQLite, Argon2, AES-256-GCM), systemd-Unit und Debian-Paket.',
                        'Includes full Rust backend (Axum, SQLite, Argon2, AES-256-GCM), systemd service unit, and Debian packaging.'
                      )}
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-8 pt-6 border-t border-slate-200 dark:border-slate-800 flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
              <Lock className="w-3.5 h-3.5 shrink-0" />
              <span>
                {tr(
                  'Private Schlüssel werden verschlüsselt gespeichert und nur für die Dauer der SSH-Sitzung (0600) bereitgestellt.',
                  'Private keys are stored encrypted at rest and materialized with 0600 permissions strictly for the duration of each SSH session.'
                )}
              </span>
            </div>
          </section>

          <section className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-8 flex flex-col justify-center">
            <h2 className="font-display text-lg font-semibold text-slate-900 dark:text-slate-100">
              {tr('Ersten Administrator erstellen', 'Create Initial Administrator')}
            </h2>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
              {tr(
                'Alle Felder können später in der Benutzerverwaltung angepasst werden.',
                'All fields can be adjusted later in User Management.'
              )}
            </p>

            {error && (
              <div
                role="alert"
                className="mt-5 px-4 py-3 rounded-md bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800/70 text-sm text-red-800 dark:text-red-300"
              >
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="mt-6 space-y-4">
              <div>
                <label htmlFor="setup-instance" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                  {tr('Instanzbezeichnung', 'Instance Name')}
                </label>
                <input
                  id="setup-instance"
                  type="text"
                  value={instanceName}
                  onChange={(e) => setInstanceName(e.target.value)}
                  placeholder={tr('z. B. SSH Console Produktion', 'e.g. SSH Console Production')}
                  className="w-full px-3.5 py-2.5 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                  required
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="setup-username" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                    {tr('Admin-Benutzername', 'Admin Username')}
                  </label>
                  <input
                    id="setup-username"
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="admin"
                    autoComplete="username"
                    className="w-full px-3.5 py-2.5 text-sm font-mono bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                    required
                  />
                </div>
                <div>
                  <label htmlFor="setup-display" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                    {tr('Anzeigename', 'Display Name')}
                  </label>
                  <input
                    id="setup-display"
                    type="text"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    placeholder={tr('Systemadministrator', 'System Administrator')}
                    className="w-full px-3.5 py-2.5 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                    required
                  />
                </div>
              </div>

              <div>
                <label htmlFor="setup-password" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                  {tr('Passwort (mindestens 8 Zeichen)', 'Password (at least 8 characters)')}
                </label>
                <input
                  id="setup-password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="new-password"
                  className="w-full px-3.5 py-2.5 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                  required
                  minLength={8}
                />
                <PasswordStrengthHint password={password} />
              </div>

              <div>
                <label htmlFor="setup-password-confirm" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                  {tr('Passwort bestätigen', 'Confirm Password')}
                </label>
                <input
                  id="setup-password-confirm"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  autoComplete="new-password"
                  className="w-full px-3.5 py-2.5 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                  required
                  minLength={8}
                />
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  disabled={submitting}
                  className="w-full py-2.5 px-4 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                >
                  {submitting
                    ? tr('Einrichtung wird abgeschlossen...', 'Completing setup...')
                    : tr('Ersteinrichtung abschließen', 'Complete Setup')}
                </button>
              </div>
            </form>
          </section>
        </div>
      </main>
    </div>
  );
}
