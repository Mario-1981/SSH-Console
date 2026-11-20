import React, { useState } from 'react';
import { Lock, CheckCircle2, Eye, EyeOff } from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { ApiKeyCurlPanel } from './ApiKeyCurlPanel';
import type { User } from '../types';

interface AccountViewProps {
  user: User;
}

export function AccountView({ user }: AccountViewProps) {
  const { tr, formatDateTime } = useI18n();
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
      setError(
        tr(
          'Das neue Passwort muss mindestens 8 Zeichen lang sein.',
          'The new password must be at least 8 characters long.'
        )
      );
      return;
    }
    if (newPassword !== confirmPassword) {
      setError(
        tr(
          'Die beiden neuen Passwörter stimmen nicht überein.',
          'The two new passwords do not match.'
        )
      );
      return;
    }
    if (newPassword === currentPassword) {
      setError(
        tr(
          'Das neue Passwort muss sich vom aktuellen Passwort unterscheiden.',
          'The new password must be different from your current password.'
        )
      );
      return;
    }

    setSaving(true);
    try {
      await api.changePassword(currentPassword, newPassword);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setSuccess(
        tr(
          'Ihr Passwort wurde erfolgreich geändert. Andere aktive Sitzungen Ihres Kontos wurden abgemeldet.',
          'Your password has been updated. Other active sessions for your account have been signed out.'
        )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Passwort konnte nicht geändert werden.', 'Password could not be updated.')
      );
    } finally {
      setSaving(false);
    }
  }

  const inputType = showPasswords ? 'text' : 'password';

  return (
    <div className="space-y-8">
      <div>
        <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
          {tr('Konto, Passwort & API-Schlüssel', 'Account, Password & API Keys')}
        </h1>
        <p className="text-sm text-slate-600 mt-1">
          {tr(
            'Verwalten Sie Ihr persönliches Zugangspasswort sowie API-Schlüssel für den automatisierten Zertifikats-Upload per ',
            'Manage your personal password and API keys for automated certificate uploads via '
          )}
          <code className="font-mono text-xs text-slate-800">curl</code>.
        </p>
      </div>

      {/* Account Overview */}
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <h2 className="font-display text-base font-semibold text-slate-900 mb-4">
          {tr('Kontoinformationen', 'Account Information')}
        </h2>
        <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 text-sm">
          <div>
            <dt className="text-xs text-slate-500">{tr('Anzeigename', 'Display Name')}</dt>
            <dd className="mt-1 font-medium text-slate-900">{user.displayName}</dd>
          </div>
          <div>
            <dt className="text-xs text-slate-500">{tr('Benutzername', 'Username')}</dt>
            <dd className="mt-1 font-mono text-slate-900">{user.username}</dd>
          </div>
          <div>
            <dt className="text-xs text-slate-500">
              {tr('Rolle & Freigaberecht', 'Role & Sharing Rights')}
            </dt>
            <dd className="mt-1 text-slate-900">
              {user.role === 'admin'
                ? tr(
                    'Administrator (darf Befehle, IPs & Zertifikate teilen)',
                    'Administrator (can share commands, IPs & certificates)'
                  )
                : tr('Benutzer (eigene Einträge privat)', 'User (own entries are private)')}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-slate-500">
              {tr('Standard-SSH-Benutzer · Letzter Login', 'Default SSH User · Last Sign-In')}
            </dt>
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
              {tr('Passwort ändern', 'Change Password')}
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              {tr(
                'Mindestens 8 Zeichen. Ihre aktuelle Sitzung bleibt bestehen.',
                'At least 8 characters. Your current session will stay active.'
              )}
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowPasswords((v) => !v)}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 cursor-pointer whitespace-nowrap shrink-0"
          >
            {showPasswords ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            {showPasswords ? tr('Verbergen', 'Hide') : tr('Anzeigen', 'Show')}
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
            {tr('Aktuelles Passwort', 'Current Password')}
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
            {tr('Neues Passwort (mindestens 8 Zeichen)', 'New Password (at least 8 characters)')}
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
            {tr('Neues Passwort bestätigen', 'Confirm New Password')}
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
            {saving ? tr('Speichert...', 'Saving...') : tr('Passwort aktualisieren', 'Update Password')}
          </button>
        </div>
      </form>

      {/* Personal API Keys & curl Upload */}
      <ApiKeyCurlPanel defaultCertName={`${user.username}-ssh`} />
    </div>
  );
}
