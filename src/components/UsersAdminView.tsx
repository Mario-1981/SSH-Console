import React, { useState } from 'react';
import { UserPlus, Trash2, KeyRound, Check, X } from 'lucide-react';
import { api } from '../api';
import type { User, UserRole } from '../types';

interface UsersAdminViewProps {
  currentUser: User;
  users: User[];
  onRefresh: () => Promise<void>;
}

function formatDate(iso: string | null): string {
  if (!iso) return 'Noch nie';
  return new Date(iso).toLocaleString('de-DE', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function UsersAdminView({ currentUser, users, onRefresh }: UsersAdminViewProps) {
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<UserRole>('user');
  const [defaultSshUser, setDefaultSshUser] = useState('root');

  const [resetUserId, setResetUserId] = useState<string | null>(null);
  const [resetPasswordVal, setResetPasswordVal] = useState('');

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setSaving(true);
    try {
      const res = await api.createUser({
        username: username.trim(),
        displayName: displayName.trim() || username.trim(),
        password,
        role,
        defaultSshUser: defaultSshUser.trim() || 'root',
      });
      await onRefresh();
      setUsername('');
      setDisplayName('');
      setPassword('');
      setRole('user');
      setDefaultSshUser('root');
      setSuccess(`Benutzerkonto „${res.user.username}“ wurde angelegt.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Benutzer konnte nicht angelegt werden.');
    } finally {
      setSaving(false);
    }
  }

  async function handleToggleActive(u: User) {
    setError(null);
    setSuccess(null);
    try {
      await api.updateUser(u.id, { active: !u.active });
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Status konnte nicht aktualisiert werden.');
    }
  }

  async function handleResetPassword(userId: string) {
    setError(null);
    setSuccess(null);
    if (resetPasswordVal.length < 8) {
      setError('Das neue Passwort muss mindestens 8 Zeichen lang sein.');
      return;
    }
    try {
      await api.updateUser(userId, { newPassword: resetPasswordVal });
      setResetUserId(null);
      setResetPasswordVal('');
      setSuccess('Passwort wurde aktualisiert.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Passwort konnte nicht geändert werden.');
    }
  }

  async function handleDelete(u: User) {
    setError(null);
    setSuccess(null);
    try {
      await api.deleteUser(u.id);
      await onRefresh();
      setSuccess(`Benutzer „${u.username}“ wurde entfernt.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Benutzer konnte nicht gelöscht werden.');
    }
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
          Benutzerverwaltung
        </h1>
        <p className="text-sm text-slate-600 mt-1">
          Legen Sie neue Benutzerkonten direkt an. Eine Selbstregistrierung ist systemweit deaktiviert.
        </p>
      </div>

      {error && (
        <div role="alert" className="px-4 py-3 rounded-md bg-red-50 border border-red-200 text-sm text-red-800">
          {error}
        </div>
      )}

      {success && (
        <div className="px-4 py-3 rounded-md bg-emerald-50 border border-emerald-200 text-sm text-emerald-900">
          {success}
        </div>
      )}

      {/* Create User Form */}
      <form onSubmit={handleCreate} className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
        <h2 className="font-display text-base font-semibold text-slate-900">
          Neuen Benutzer anlegen
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-12 gap-4">
          <div className="lg:col-span-2">
            <label htmlFor="usr-name" className="block text-xs font-medium text-slate-700 mb-1.5">
              Benutzername
            </label>
            <input
              id="usr-name"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="m.mueller"
              className="w-full px-3 py-2 text-sm font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              required
            />
          </div>

          <div className="lg:col-span-3">
            <label htmlFor="usr-display" className="block text-xs font-medium text-slate-700 mb-1.5">
              Anzeigename
            </label>
            <input
              id="usr-display"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="Max Müller"
              className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          <div className="lg:col-span-3">
            <label htmlFor="usr-pass" className="block text-xs font-medium text-slate-700 mb-1.5">
              Initialpasswort (min. 8 Zeichen)
            </label>
            <input
              id="usr-pass"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              minLength={8}
              className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              required
            />
          </div>

          <div className="lg:col-span-2">
            <label htmlFor="usr-role" className="block text-xs font-medium text-slate-700 mb-1.5">
              Rolle
            </label>
            <select
              id="usr-role"
              value={role}
              onChange={(e) => setRole(e.target.value as UserRole)}
              className="w-full px-3 py-2 text-sm bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            >
              <option value="user">Benutzer</option>
              <option value="admin">Administrator</option>
            </select>
          </div>

          <div className="lg:col-span-2">
            <label htmlFor="usr-ssh" className="block text-xs font-medium text-slate-700 mb-1.5">
              Standard-SSH-User
            </label>
            <input
              id="usr-ssh"
              type="text"
              value={defaultSshUser}
              onChange={(e) => setDefaultSshUser(e.target.value)}
              placeholder="root"
              className="w-full px-3 py-2 text-sm font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
        </div>

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={saving}
            className="inline-flex items-center gap-1.5 px-5 py-2 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
          >
            <UserPlus className="w-4 h-4" />
            {saving ? 'Wird angelegt...' : 'Benutzer anlegen'}
          </button>
        </div>
      </form>

      {/* Users Table */}
      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200">
          <h2 className="font-display text-base font-semibold text-slate-900">
            Angelegte Konten ({users.length})
          </h2>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                <th className="py-2.5 px-6">Benutzer</th>
                <th className="py-2.5 px-4">Rolle</th>
                <th className="py-2.5 px-4">Standard-SSH</th>
                <th className="py-2.5 px-4">Letzte Anmeldung</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-6 text-right">Aktionen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 text-sm">
              {users.map((u) => {
                const isSelf = u.id === currentUser.id;
                const isResetting = resetUserId === u.id;
                return (
                  <tr key={u.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="py-3 px-6">
                      <p className="font-medium text-slate-900">
                        {u.displayName}
                        {isSelf && <span className="text-xs text-slate-500 font-normal"> (Sie)</span>}
                      </p>
                      <p className="text-xs font-mono text-slate-500">{u.username}</p>
                    </td>
                    <td className="py-3 px-4 text-xs text-slate-700 whitespace-nowrap">
                      {u.role === 'admin' ? 'Administrator' : 'Benutzer'}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-slate-700 whitespace-nowrap">
                      {u.defaultSshUser}
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-slate-600 tabular-nums whitespace-nowrap">
                      {formatDate(u.lastLoginAt)}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <button
                        type="button"
                        disabled={isSelf}
                        onClick={() => handleToggleActive(u)}
                        className={`text-xs font-medium ${
                          isSelf
                            ? 'text-emerald-700 cursor-default'
                            : u.active
                            ? 'text-emerald-700 hover:text-emerald-900 cursor-pointer'
                            : 'text-red-700 hover:text-red-900 cursor-pointer'
                        }`}
                      >
                        {u.active ? 'Aktiv' : 'Gesperrt'}
                      </button>
                    </td>
                    <td className="py-3 px-6 text-right whitespace-nowrap">
                      {isResetting ? (
                        <div className="inline-flex items-center gap-2">
                          <input
                            type="password"
                            value={resetPasswordVal}
                            onChange={(e) => setResetPasswordVal(e.target.value)}
                            placeholder="Neues Passwort..."
                            className="px-2.5 py-1 text-xs border border-slate-300 rounded w-36 focus:outline-none focus:ring-2 focus:ring-blue-600"
                          />
                          <button
                            type="button"
                            onClick={() => handleResetPassword(u.id)}
                            className="p-1 text-emerald-700 hover:bg-emerald-50 rounded cursor-pointer"
                            title="Speichern"
                          >
                            <Check className="w-4 h-4" />
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setResetUserId(null);
                              setResetPasswordVal('');
                            }}
                            className="p-1 text-slate-500 hover:bg-slate-100 rounded cursor-pointer"
                            title="Abbrechen"
                          >
                            <X className="w-4 h-4" />
                          </button>
                        </div>
                      ) : (
                        <div className="inline-flex items-center gap-3">
                          <button
                            type="button"
                            onClick={() => {
                              setResetUserId(u.id);
                              setResetPasswordVal('');
                            }}
                            className="inline-flex items-center gap-1 text-xs font-medium text-slate-700 hover:text-blue-700 cursor-pointer"
                          >
                            <KeyRound className="w-3.5 h-3.5" />
                            Passwort
                          </button>
                          {!isSelf && (
                            <button
                              type="button"
                              onClick={() => handleDelete(u)}
                              className="inline-flex items-center gap-1 text-xs font-medium text-red-700 hover:text-red-900 cursor-pointer"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                              Löschen
                            </button>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
