import React, { useState } from 'react';
import { Lock, CheckCircle2, Eye, EyeOff } from 'lucide-react';
import { api } from '../api';
import type { User } from '../types';

interface AccountViewProps {
  user: User;
}

function formatDateTime(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString('de-DE', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function AccountView({ user }: AccountViewProps) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPasswords, setShowPasswords] = useState(false);

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (newPassword.length < 8) {
      setError('Das neue Passwort muss mindestens 8 Zeichen lang sein.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('Die beiden neuen Passwörter stimmen nicht überein.');
      return;
    }
    if (newPassword === currentPassword) {
      setError('Das neue Passwort muss sich vom aktuellen Passwort unterscheiden.');
      return;
    }

    setSaving(true);
    try {
      await api.changePassword(currentPassword, newPassword);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setSuccess(
        'Ihr Passwort wurde erfolgreich geändert. Andere aktive Sitzungen Ihres Kontos wurden abgemeldet.'
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Passwort konnte nicht geändert werden.');
    } finally {
      setSaving(false);
    }
  }

  const inputType = showPasswords ? 'text' : 'password';

  return (
    <div className="space-y-8">
      <div>
        <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
          Konto &amp; Passwort
        </h1>
        <p className="text-sm text-slate-600 mt-1">
          Verwalten Sie Ihr persönliches Zugangspasswort für diese SSH Console-Instanz.
        </p>
      </div>

      {/* Account Overview */}
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <h2 className="font-display text-base font-semibold text-slate-900 mb-4">
          Kontoinformationen
        </h2>
        <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 text-sm">
          <div>
            <dt className="text-xs text-slate-500">Anzeigename</dt>
            <dd className="mt-1 font-medium text-slate-900">{user.displayName}</dd>
          </div>
          <div>
            <dt className="text-xs text-slate-500">Benutzername</dt>
            <dd className="mt-1 font-mono text-slate-900">{user.username}</dd>
          </div>
          <div>
            <dt className="text-xs text-slate-500">Rolle &amp; Freigaberecht</dt>
            <dd className="mt-1 text-slate-900">
              {user.role === 'admin'
                ? 'Administrator (darf Befehle, IPs & Zertifikate teilen)'
                : 'Benutzer (eigene Einträge privat)'}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-slate-500">Standard-SSH-Benutzer · Letzter Login</dt>
            <dd className="mt-1 font-mono text-xs text-slate-800 tabular-nums">
              {user.defaultSshUser} · {formatDateTime(user.lastLoginAt)}
            </dd>
          </div>
        </dl>
      </section>

      {/* Change Password Form */}
      <form
        onSubmit={handleSubmit}
        className="bg-white border border-slate-200 rounded-lg p-6 space-y-5 max-w-xl"
      >
        <div className="flex items-center justify-between gap-4 pb-4 border-b border-slate-200">
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900">
              Passwort ändern
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Mindestens 8 Zeichen. Ihre aktuelle Sitzung bleibt bestehen.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowPasswords((v) => !v)}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 cursor-pointer whitespace-nowrap shrink-0"
          >
            {showPasswords ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            {showPasswords ? 'Verbergen' : 'Anzeigen'}
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

        <div>
          <label htmlFor="pw-current" className="block text-xs font-medium text-slate-700 mb-1.5">
            Aktuelles Passwort
          </label>
          <input
            id="pw-current"
            type={inputType}
            autoComplete="current-password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            className="w-full px-3.5 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            required
          />
        </div>

        <div>
          <label htmlFor="pw-new" className="block text-xs font-medium text-slate-700 mb-1.5">
            Neues Passwort (mindestens 8 Zeichen)
          </label>
          <input
            id="pw-new"
            type={inputType}
            autoComplete="new-password"
            minLength={8}
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            className="w-full px-3.5 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            required
          />
        </div>

        <div>
          <label htmlFor="pw-confirm" className="block text-xs font-medium text-slate-700 mb-1.5">
            Neues Passwort bestätigen
          </label>
          <input
            id="pw-confirm"
            type={inputType}
            autoComplete="new-password"
            minLength={8}
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            className="w-full px-3.5 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            required
          />
        </div>

        <div className="pt-2 flex justify-end">
          <button
            type="submit"
            disabled={saving}
            className="inline-flex items-center gap-2 px-5 py-2 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
          >
            <Lock className="w-4 h-4" />
            {saving ? 'Speichert...' : 'Passwort aktualisieren'}
          </button>
        </div>
      </form>
    </div>
  );
}
