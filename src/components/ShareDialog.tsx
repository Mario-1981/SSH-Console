import React, { useState } from 'react';
import { X, Share2, Lock, Users, UserCheck } from 'lucide-react';
import { useI18n, type Locale } from '../i18n';
import type { User } from '../types';

export interface ShareDialogProps {
  title: string;
  itemName: string;
  securityHint?: string;
  currentUserId: string;
  users: User[];
  initialSharedWithAll: boolean;
  initialSharedWithUserIds: string[];
  onClose: () => void;
  onSave: (payload: { sharedWithAll: boolean; sharedWithUserIds: string[] }) => Promise<void>;
}

type ShareMode = 'private' | 'all' | 'selected';

export function ShareDialog({
  title,
  itemName,
  securityHint,
  currentUserId,
  users,
  initialSharedWithAll,
  initialSharedWithUserIds,
  onClose,
  onSave,
}: ShareDialogProps) {
  const { tr } = useI18n();
  const initialMode: ShareMode = initialSharedWithAll
    ? 'all'
    : initialSharedWithUserIds.length > 0
    ? 'selected'
    : 'private';

  const [mode, setMode] = useState<ShareMode>(initialMode);
  const [selectedIds, setSelectedIds] = useState<string[]>(initialSharedWithUserIds);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const otherUsers = users.filter((u) => u.id !== currentUserId);

  function toggleUser(uid: string) {
    setSelectedIds((prev) =>
      prev.includes(uid) ? prev.filter((id) => id !== uid) : [...prev, uid]
    );
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (mode === 'selected' && selectedIds.length === 0) {
      setError(
        tr(
          'Bitte wählen Sie mindestens einen Benutzer aus oder stellen Sie auf „Privat“ um.',
          'Please select at least one user or switch visibility to "Private".'
        )
      );
      return;
    }

    setSaving(true);
    try {
      await onSave({
        sharedWithAll: mode === 'all',
        sharedWithUserIds: mode === 'selected' ? selectedIds : [],
      });
      onClose();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Freigabe konnte nicht gespeichert werden.', 'Sharing settings could not be saved.')
      );
    } finally {
      setSaving(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/45 px-4 py-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby="share-dialog-title"
    >
      <div className="w-full max-w-lg bg-white border border-slate-200 rounded-lg overflow-hidden shadow-lg">
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between gap-4">
          <div className="min-w-0">
            <h2 id="share-dialog-title" className="font-display text-base font-semibold text-slate-900">
              {title}
            </h2>
            <p className="text-xs text-slate-500 mt-0.5 truncate">{itemName}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label={tr('Schließen', 'Close')}
            className="p-1.5 text-slate-500 hover:text-slate-900 hover:bg-slate-100 rounded-md cursor-pointer shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          {error && (
            <div role="alert" className="px-3.5 py-2.5 rounded-md bg-red-50 border border-red-200 text-xs text-red-800">
              {error}
            </div>
          )}

          <div className="space-y-2.5">
            <p className="text-xs font-medium text-slate-700">
              {tr('Sichtbarkeit & Freigabe (Administratorrecht)', 'Visibility & Sharing (Admin Permission)')}
            </p>

            <label
              className={`flex items-start gap-3 p-3 rounded-md border cursor-pointer transition-colors ${
                mode === 'private'
                  ? 'border-blue-600 bg-blue-50/40'
                  : 'border-slate-200 hover:bg-slate-50'
              }`}
            >
              <input
                type="radio"
                name="share-mode"
                checked={mode === 'private'}
                onChange={() => setMode('private')}
                className="mt-0.5 text-blue-700 focus:ring-blue-600"
              />
              <div className="min-w-0">
                <p className="text-sm font-medium text-slate-900 flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-slate-500" />
                  {tr('Privat (nur für mich sichtbar)', 'Private (visible only to me)')}
                </p>
                <p className="text-xs text-slate-500 mt-0.5">
                  {tr(
                    'Andere Benutzer können diesen Eintrag weder sehen noch verwenden.',
                    'Other users cannot view or use this entry.'
                  )}
                </p>
              </div>
            </label>

            <label
              className={`flex items-start gap-3 p-3 rounded-md border cursor-pointer transition-colors ${
                mode === 'all'
                  ? 'border-blue-600 bg-blue-50/40'
                  : 'border-slate-200 hover:bg-slate-50'
              }`}
            >
              <input
                type="radio"
                name="share-mode"
                checked={mode === 'all'}
                onChange={() => setMode('all')}
                className="mt-0.5 text-blue-700 focus:ring-blue-600"
              />
              <div className="min-w-0">
                <p className="text-sm font-medium text-slate-900 flex items-center gap-1.5">
                  <Users className="w-3.5 h-3.5 text-slate-500" />
                  {tr('Mit allen Benutzern teilen', 'Share with all users')}
                </p>
                <p className="text-xs text-slate-500 mt-0.5">
                  {tr(
                    'Alle aktiven Benutzer (inkl. künftig angelegter Konten) können diesen Eintrag nutzen, aber nicht ändern oder löschen.',
                    'All active users (including future accounts) can use this entry, but cannot edit or delete it.'
                  )}
                </p>
              </div>
            </label>

            <label
              className={`flex items-start gap-3 p-3 rounded-md border cursor-pointer transition-colors ${
                mode === 'selected'
                  ? 'border-blue-600 bg-blue-50/40'
                  : 'border-slate-200 hover:bg-slate-50'
              }`}
            >
              <input
                type="radio"
                name="share-mode"
                checked={mode === 'selected'}
                onChange={() => setMode('selected')}
                className="mt-0.5 text-blue-700 focus:ring-blue-600"
              />
              <div className="min-w-0">
                <p className="text-sm font-medium text-slate-900 flex items-center gap-1.5">
                  <UserCheck className="w-3.5 h-3.5 text-slate-500" />
                  {tr('Mit ausgewählten Benutzern teilen', 'Share with selected users')}
                </p>
                <p className="text-xs text-slate-500 mt-0.5">
                  {tr(
                    'Freigabe gezielt auf einzelne Benutzerkonten einschränken.',
                    'Restrict access to specific user accounts.'
                  )}
                </p>
              </div>
            </label>
          </div>

          {mode === 'selected' && (
            <div className="space-y-2">
              <p className="text-xs font-medium text-slate-700">
                {tr(
                  `Berechtigte Benutzer (${selectedIds.length} ausgewählt)`,
                  `Authorized users (${selectedIds.length} selected)`
                )}
              </p>
              {otherUsers.length === 0 ? (
                <p className="text-xs text-slate-500 px-3 py-3 rounded-md bg-slate-50 border border-slate-200">
                  {tr(
                    'Es wurden noch keine weiteren Benutzerkonten angelegt. Legen Sie zuerst Benutzer unter „Benutzerverwaltung“ an.',
                    'No other user accounts exist yet. Create users under "User Management" first.'
                  )}
                </p>
              ) : (
                <div className="border border-slate-200 rounded-md divide-y divide-slate-200 max-h-48 overflow-y-auto">
                  {otherUsers.map((u) => {
                    const checked = selectedIds.includes(u.id);
                    return (
                      <label
                        key={u.id}
                        className="flex items-center justify-between gap-3 px-3.5 py-2.5 hover:bg-slate-50 cursor-pointer"
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={() => toggleUser(u.id)}
                            className="rounded border-slate-300 text-blue-700 focus:ring-blue-600"
                          />
                          <div className="min-w-0">
                            <p className="text-sm font-medium text-slate-900 truncate">
                              {u.displayName}
                            </p>
                            <p className="text-xs text-slate-500 truncate">
                              <span className="font-mono">{u.username}</span> ·{' '}
                              {u.role === 'admin' ? 'Administrator' : tr('Benutzer', 'User')}
                              {!u.active ? tr(' · Deaktiviert', ' · Disabled') : ''}
                            </p>
                          </div>
                        </div>
                      </label>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {securityHint && mode !== 'private' && (
            <p className="text-xs text-slate-600 px-3.5 py-2.5 rounded-md bg-slate-50 border border-slate-200">
              {securityHint}
            </p>
          )}

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-200">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
            >
              {tr('Abbrechen', 'Cancel')}
            </button>
            <button
              type="submit"
              disabled={saving}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
            >
              <Share2 className="w-3.5 h-3.5" />
              {saving ? tr('Speichert...', 'Saving...') : tr('Freigabe speichern', 'Save Sharing')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export function formatShareSummary(
  sharedWithAll: boolean,
  sharedWithUserIds: string[],
  locale: Locale = 'de'
): string {
  const isEn = locale === 'en';
  if (sharedWithAll) return isEn ? 'Shared (All)' : 'Geteilt (Alle)';
  if (sharedWithUserIds.length > 0) {
    return isEn ? `Shared (${sharedWithUserIds.length})` : `Geteilt (${sharedWithUserIds.length})`;
  }
  return isEn ? 'Private' : 'Privat';
}
