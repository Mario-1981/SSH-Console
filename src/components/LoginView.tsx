import React, { useState } from 'react';
import { Lock } from 'lucide-react';
import { api } from '../api';
import { LanguageSwitcher, useI18n } from '../i18n';
import type { User } from '../types';

interface LoginViewProps {
  instanceName: string;
  onLogin: (user: User) => void;
}

export function LoginView({ instanceName, onLogin }: LoginViewProps) {
  const { tr } = useI18n();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await api.login(username, password);
      onLogin(res.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : tr('Anmeldung fehlgeschlagen.', 'Sign-in failed.'));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      <header className="border-b border-slate-200 bg-white px-8 py-4 flex items-center justify-between gap-4">
        <span className="font-display text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0">
          {instanceName}
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
          <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
            {tr('Anmelden', 'Sign in')}
          </h1>
          <p className="text-sm text-slate-600 mt-1.5">
            {tr(
              'Melden Sie sich mit Ihrem vom Administrator zugewiesenen Benutzerkonto an.',
              'Sign in with the user account assigned by your administrator.'
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

          <form onSubmit={handleSubmit} className="mt-6 space-y-4">
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

          <div className="mt-6 pt-5 border-t border-slate-200 flex items-start gap-2.5 text-xs text-slate-500">
            <Lock className="w-3.5 h-3.5 shrink-0 mt-0.5" />
            <span>
              {tr(
                'Selbstregistrierung ist deaktiviert. Wenden Sie sich für neue Zugänge an Ihren Administrator.',
                'Self-registration is disabled. Contact your administrator to request an account.'
              )}
            </span>
          </div>
        </div>
      </main>
    </div>
  );
}
