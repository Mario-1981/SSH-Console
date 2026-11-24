import React, { useState } from 'react';
import {
  X,
  Check,
  Plus,
  Activity,
  Ban,
  ShieldCheck,
  ShieldAlert,
  Tag,
  Share2,
  Lock,
  Users,
  UserCheck,
  SlidersHorizontal,
} from 'lucide-react';
import { translateCategory, useI18n } from '../i18n';
import type { SshCommand, User, UserServer } from '../types';

type ShareBulkMode = 'unchanged' | 'private' | 'all' | 'selected';
type TriState = 'unchanged' | 'on' | 'off';
type CategoryBulkAction = 'unchanged' | 'add' | 'remove' | 'replace';

export interface BulkServersPayload {
  pingEnabled?: boolean;
  ignoreHostKey?: boolean;
  categoriesAction?: 'add' | 'remove' | 'replace';
  categories?: string[];
  sharing?: { sharedWithAll: boolean; sharedWithUserIds: string[] };
}

interface BulkServersDialogProps {
  selectedServers: UserServer[];
  isAdmin: boolean;
  currentUserId: string;
  users: User[];
  allowInsecureHostKey: boolean;
  selectableCategories: string[];
  initialFocus?: 'all' | 'categories' | 'sharing';
  onCreateCategory?: (name: string) => Promise<string | null>;
  onClose: () => void;
  onSave: (payload: BulkServersPayload) => Promise<void>;
}

export function BulkServersDialog({
  selectedServers,
  isAdmin,
  currentUserId,
  users,
  allowInsecureHostKey,
  selectableCategories,
  initialFocus = 'all',
  onCreateCategory,
  onClose,
  onSave,
}: BulkServersDialogProps) {
  const { tr } = useI18n();
  const [pingMode, setPingMode] = useState<TriState>('unchanged');
  const [hostKeyMode, setHostKeyMode] = useState<TriState>('unchanged');
  const [catAction, setCatAction] = useState<CategoryBulkAction>(
    initialFocus === 'categories' ? 'add' : 'unchanged'
  );
  const [chosenCategories, setChosenCategories] = useState<string[]>([]);
  const [localExtraCategories, setLocalExtraCategories] = useState<string[]>([]);
  const [newCatInput, setNewCatInput] = useState('');
  const [creatingCat, setCreatingCat] = useState(false);

  const [shareMode, setShareMode] = useState<ShareBulkMode>(
    initialFocus === 'sharing' && isAdmin ? 'all' : 'unchanged'
  );
  const [shareUserIds, setShareUserIds] = useState<string[]>([]);

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const otherUsers = users.filter((u) => u.id !== currentUserId);

  const allCategoryChoices = Array.from(
    new Map(
      [...selectableCategories, ...localExtraCategories, ...chosenCategories].map((c) => [
        c.toLowerCase(),
        c,
      ])
    ).values()
  );

  function toggleCategory(name: string) {
    const lower = name.toLowerCase();
    setChosenCategories((prev) =>
      prev.some((c) => c.toLowerCase() === lower)
        ? prev.filter((c) => c.toLowerCase() !== lower)
        : [...prev, name]
    );
  }

  async function handleQuickAddCategory() {
    const trimmed = newCatInput.trim().replace(/\s+/g, ' ').slice(0, 48);
    if (!trimmed) return;
    setError(null);
    setCreatingCat(true);
    try {
      let canonical = trimmed;
      if (onCreateCategory) {
        const created = await onCreateCategory(trimmed);
        if (created) canonical = created;
      }
      setLocalExtraCategories((prev) =>
        prev.some((c) => c.toLowerCase() === canonical.toLowerCase()) ? prev : [...prev, canonical]
      );
      setChosenCategories((prev) =>
        prev.some((c) => c.toLowerCase() === canonical.toLowerCase()) ? prev : [...prev, canonical]
      );
      setNewCatInput('');
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Kategorie konnte nicht angelegt werden.', 'Could not create category.')
      );
    } finally {
      setCreatingCat(false);
    }
  }

  function toggleUser(uid: string) {
    setShareUserIds((prev) =>
      prev.includes(uid) ? prev.filter((id) => id !== uid) : [...prev, uid]
    );
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    const payload: BulkServersPayload = {};
    if (pingMode !== 'unchanged') {
      payload.pingEnabled = pingMode === 'on';
    }
    if (hostKeyMode !== 'unchanged') {
      // 'on' => verify host keys (ignoreHostKey = false); 'off' => bypass (ignoreHostKey = true)
      payload.ignoreHostKey = hostKeyMode === 'off';
    }
    if (catAction !== 'unchanged') {
      if ((catAction === 'add' || catAction === 'remove') && chosenCategories.length === 0) {
        setError(
          tr(
            'Bitte wählen Sie mindestens eine IP-Kategorie zum Hinzufügen oder Entfernen aus.',
            'Please select at least one IP category to add or remove.'
          )
        );
        return;
      }
      payload.categoriesAction = catAction;
      payload.categories = chosenCategories;
    }
    if (isAdmin && shareMode !== 'unchanged') {
      if (shareMode === 'selected' && shareUserIds.length === 0) {
        setError(
          tr(
            'Bitte wählen Sie mindestens einen Benutzer zum Teilen aus oder stellen Sie auf „Privat“ um.',
            'Please select at least one user to share with or choose "Private".'
          )
        );
        return;
      }
      payload.sharing = {
        sharedWithAll: shareMode === 'all',
        sharedWithUserIds: shareMode === 'selected' ? shareUserIds : [],
      };
    }

    if (
      payload.pingEnabled === undefined &&
      payload.ignoreHostKey === undefined &&
      payload.categoriesAction === undefined &&
      payload.sharing === undefined
    ) {
      setError(
        tr(
          'Bitte wählen Sie mindestens eine Einstellung aus, die geändert werden soll.',
          'Please select at least one setting to change.'
        )
      );
      return;
    }

    setSaving(true);
    try {
      await onSave(payload);
      onClose();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Sammeleinstellungen konnten nicht gespeichert werden.', 'Could not save bulk settings.')
      );
    } finally {
      setSaving(false);
    }
  }

  const previewNames = selectedServers
    .slice(0, 4)
    .map((s) => `${s.label} (${s.ipAddress})`)
    .join(', ');
  const extraCount = Math.max(0, selectedServers.length - 4);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/45 px-4 py-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby="bulk-servers-title"
    >
      <div className="w-full max-w-2xl max-h-[90vh] flex flex-col bg-white border border-slate-200 rounded-lg overflow-hidden shadow-lg">
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between gap-4 shrink-0">
          <div className="min-w-0">
            <h2
              id="bulk-servers-title"
              className="font-display text-base font-semibold text-slate-900 flex items-center gap-2"
            >
              <SlidersHorizontal className="w-4 h-4 text-blue-700 shrink-0" />
              {tr(
                `Sammeleinstellungen für ${selectedServers.length} Server (IPs)`,
                `Bulk Settings for ${selectedServers.length} Servers (IPs)`
              )}
            </h2>
            <p className="text-xs text-slate-500 mt-0.5 truncate">
              {previewNames}
              {extraCount > 0 ? tr(` + ${extraCount} weitere`, ` + ${extraCount} more`) : ''}
            </p>
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

        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto p-6 space-y-5">
          {error && (
            <div
              role="alert"
              className="px-3.5 py-2.5 rounded-md bg-red-50 border border-red-200 text-xs text-red-800"
            >
              {error}
            </div>
          )}

          <p className="text-xs text-slate-500">
            {tr(
              'Wählen Sie genau die Optionen aus, die auf alle markierten IPs angewendet werden sollen. Felder auf „Unverändert“ bleiben je Server erhalten.',
              'Choose only the options you want to apply to all selected IPs. Settings left on "Unchanged" keep each server’s existing value.'
            )}
          </p>

          {/* 1. Ping On/Off */}
          <div className="border border-slate-200 rounded-md p-4 space-y-2.5">
            <p className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-slate-500" />
              {tr('Ping-Erreichbarkeitsprüfung', 'Ping Reachability Check')}
            </p>
            <div className="grid grid-cols-3 gap-2">
              {(
                [
                  { id: 'unchanged', label: tr('Unverändert', 'Unchanged') },
                  { id: 'on', label: tr('Ping an (Aktiv)', 'Ping On'), icon: Activity },
                  { id: 'off', label: tr('Ping aus', 'Ping Off'), icon: Ban },
                ] as const
              ).map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => setPingMode(opt.id)}
                  className={`inline-flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md border transition-colors cursor-pointer ${
                    pingMode === opt.id
                      ? opt.id === 'on'
                        ? 'bg-emerald-50 text-emerald-900 border-emerald-400'
                        : opt.id === 'off'
                        ? 'bg-slate-800 text-white border-slate-800'
                        : 'bg-blue-50 text-blue-900 border-blue-400'
                      : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
                  }`}
                >
                  {'icon' in opt && <opt.icon className="w-3.5 h-3.5 shrink-0" />}
                  <span>{opt.label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* 2. Host-Key Checking */}
          <div className="border border-slate-200 rounded-md p-4 space-y-2.5">
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-slate-500" />
                {tr('SSH-Host-Key-Überprüfung', 'SSH Host Key Verification')}
              </p>
              {!allowInsecureHostKey && (
                <span className="text-[11px] text-amber-700 font-medium">
                  {tr('Ignorieren vom Admin global verboten', 'Bypass globally prohibited by admin')}
                </span>
              )}
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setHostKeyMode('unchanged')}
                className={`px-3 py-2 text-xs font-medium rounded-md border transition-colors cursor-pointer ${
                  hostKeyMode === 'unchanged'
                    ? 'bg-blue-50 text-blue-900 border-blue-400'
                    : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
                }`}
              >
                {tr('Unverändert', 'Unchanged')}
              </button>
              <button
                type="button"
                onClick={() => setHostKeyMode('on')}
                className={`inline-flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md border transition-colors cursor-pointer ${
                  hostKeyMode === 'on'
                    ? 'bg-emerald-50 text-emerald-900 border-emerald-400'
                    : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
                }`}
              >
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-700 shrink-0" />
                <span>{tr('Ja · Prüfen', 'Yes · Verify')}</span>
              </button>
              <button
                type="button"
                disabled={!allowInsecureHostKey}
                onClick={() => setHostKeyMode('off')}
                className={`inline-flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md border transition-colors disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer ${
                  hostKeyMode === 'off'
                    ? 'bg-amber-50 text-amber-900 border-amber-400'
                    : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
                }`}
              >
                <ShieldAlert className="w-3.5 h-3.5 text-amber-700 shrink-0" />
                <span>{tr('Nein · Ignorieren', 'No · Bypass')}</span>
              </button>
            </div>
          </div>

          {/* 3. IP Categories */}
          <div className="border border-slate-200 rounded-md p-4 space-y-3">
            <p className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
              <Tag className="w-3.5 h-3.5 text-slate-500" />
              {tr('IP-Kategorien', 'IP Categories')}
            </p>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {(
                [
                  { id: 'unchanged', label: tr('Unverändert', 'Unchanged') },
                  { id: 'add', label: tr('Hinzufügen', 'Add') },
                  { id: 'remove', label: tr('Entfernen', 'Remove') },
                  { id: 'replace', label: tr('Ersetzen', 'Replace') },
                ] as const
              ).map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => setCatAction(opt.id)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md border transition-colors cursor-pointer ${
                    catAction === opt.id
                      ? 'bg-blue-50 text-blue-900 border-blue-400'
                      : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>

            {catAction !== 'unchanged' && (
              <div className="space-y-2.5 pt-1">
                {catAction !== 'remove' && (
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      value={newCatInput}
                      onChange={(e) => setNewCatInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          e.preventDefault();
                          void handleQuickAddCategory();
                        }
                      }}
                      maxLength={48}
                      placeholder={tr('Neue Kategorie anlegen & auswählen...', 'Create & select new category...')}
                      className="flex-1 px-2.5 py-1.5 text-xs border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                    />
                    <button
                      type="button"
                      onClick={handleQuickAddCategory}
                      disabled={creatingCat || !newCatInput.trim()}
                      className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 disabled:opacity-40 rounded-md cursor-pointer whitespace-nowrap"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      {tr('Anlegen', 'Add')}
                    </button>
                  </div>
                )}

                {allCategoryChoices.length > 0 ? (
                  <div className="flex flex-wrap items-center gap-1.5">
                    {allCategoryChoices.map((catName) => {
                      const active = chosenCategories.some(
                        (c) => c.toLowerCase() === catName.toLowerCase()
                      );
                      return (
                        <button
                          key={catName}
                          type="button"
                          onClick={() => toggleCategory(catName)}
                          className={`inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-md border transition-colors cursor-pointer ${
                            active
                              ? catAction === 'remove'
                                ? 'bg-red-50 text-red-800 border-red-300'
                                : 'bg-blue-50 text-blue-800 border-blue-300'
                              : 'bg-white text-slate-600 border-slate-200 hover:border-slate-300 hover:text-slate-900'
                          }`}
                        >
                          {active && <Check className="w-3 h-3 shrink-0" />}
                          <span>{catName}</span>
                        </button>
                      );
                    })}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500">
                    {tr(
                      'Noch keine Kategorien vorhanden. Legen Sie oben eine Kategorie an.',
                      'No categories available yet. Create one above.'
                    )}
                  </p>
                )}

                {catAction === 'replace' && chosenCategories.length === 0 && (
                  <p className="text-[11px] text-amber-800 bg-amber-50 border border-amber-200 rounded px-2.5 py-1.5">
                    {tr(
                      'Hinweis: Ohne ausgewählte Kategorie werden bei „Ersetzen“ alle bestehenden Kategorien der gewählten Server entfernt.',
                      'Note: With no categories selected, "Replace" clears all existing categories on the selected servers.'
                    )}
                  </p>
                )}
              </div>
            )}
          </div>

          {/* 4. Sharing (Admin only) */}
          {isAdmin && (
            <div className="border border-slate-200 rounded-md p-4 space-y-3">
              <p className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
                <Share2 className="w-3.5 h-3.5 text-slate-500" />
                {tr('Teilen & Sichtbarkeit (Administrator)', 'Sharing & Visibility (Admin)')}
              </p>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {(
                  [
                    { id: 'unchanged', label: tr('Unverändert', 'Unchanged') },
                    { id: 'private', label: tr('Privat', 'Private'), icon: Lock },
                    { id: 'all', label: tr('Alle Benutzer', 'All Users'), icon: Users },
                    { id: 'selected', label: tr('Ausgewählte', 'Selected'), icon: UserCheck },
                  ] as const
                ).map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setShareMode(opt.id)}
                    className={`inline-flex items-center justify-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-md border transition-colors cursor-pointer ${
                      shareMode === opt.id
                        ? 'bg-blue-50 text-blue-900 border-blue-400'
                        : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
                    }`}
                  >
                    {'icon' in opt && <opt.icon className="w-3.5 h-3.5 shrink-0" />}
                    <span>{opt.label}</span>
                  </button>
                ))}
              </div>

              {shareMode === 'selected' && (
                <div className="space-y-1.5 pt-1">
                  <p className="text-xs text-slate-600">
                    {tr(
                      `Berechtigte Benutzer (${shareUserIds.length} ausgewählt)`,
                      `Authorized users (${shareUserIds.length} selected)`
                    )}
                  </p>
                  {otherUsers.length === 0 ? (
                    <p className="text-xs text-slate-500 px-3 py-2.5 rounded-md bg-slate-50 border border-slate-200">
                      {tr(
                        'Es wurden noch keine weiteren Benutzerkonten angelegt.',
                        'No other user accounts exist yet.'
                      )}
                    </p>
                  ) : (
                    <div className="border border-slate-200 rounded-md divide-y divide-slate-200 max-h-40 overflow-y-auto">
                      {otherUsers.map((u) => (
                        <label
                          key={u.id}
                          className="flex items-center gap-2.5 px-3 py-2 hover:bg-slate-50 cursor-pointer"
                        >
                          <input
                            type="checkbox"
                            checked={shareUserIds.includes(u.id)}
                            onChange={() => toggleUser(u.id)}
                            className="rounded border-slate-300 text-blue-700 focus:ring-blue-600"
                          />
                          <div className="min-w-0">
                            <p className="text-xs font-medium text-slate-900 truncate">
                              {u.displayName}{' '}
                              <span className="font-mono text-slate-500">({u.username})</span>
                            </p>
                          </div>
                        </label>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-200">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer"
            >
              {tr('Abbrechen', 'Cancel')}
            </button>
            <button
              type="submit"
              disabled={saving}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer"
            >
              <Check className="w-3.5 h-3.5" />
              {saving
                ? tr('Speichert...', 'Saving...')
                : tr(
                    `Auf ${selectedServers.length} Server anwenden`,
                    `Apply to ${selectedServers.length} Servers`
                  )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export interface BulkCommandsPayload {
  category?: string;
  enabled?: boolean;
  sharing?: { sharedWithAll: boolean; sharedWithUserIds: string[] };
}

interface BulkCommandsDialogProps {
  selectedCommands: SshCommand[];
  isAdmin: boolean;
  currentUserId: string;
  users: User[];
  categories: string[];
  initialFocus?: 'all' | 'sharing';
  onClose: () => void;
  onSave: (payload: BulkCommandsPayload) => Promise<void>;
}

export function BulkCommandsDialog({
  selectedCommands,
  isAdmin,
  currentUserId,
  users,
  categories,
  initialFocus = 'all',
  onClose,
  onSave,
}: BulkCommandsDialogProps) {
  const { locale, tr } = useI18n();
  const [enabledMode, setEnabledMode] = useState<TriState>('unchanged');
  const [categoryValue, setCategoryValue] = useState<string>('__unchanged__');
  const [shareMode, setShareMode] = useState<ShareBulkMode>(
    initialFocus === 'sharing' && isAdmin ? 'all' : 'unchanged'
  );
  const [shareUserIds, setShareUserIds] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const otherUsers = users.filter((u) => u.id !== currentUserId);

  function toggleUser(uid: string) {
    setShareUserIds((prev) =>
      prev.includes(uid) ? prev.filter((id) => id !== uid) : [...prev, uid]
    );
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    const payload: BulkCommandsPayload = {};
    if (enabledMode !== 'unchanged') {
      payload.enabled = enabledMode === 'on';
    }
    if (categoryValue !== '__unchanged__') {
      payload.category = categoryValue;
    }
    if (isAdmin && shareMode !== 'unchanged') {
      if (shareMode === 'selected' && shareUserIds.length === 0) {
        setError(
          tr(
            'Bitte wählen Sie mindestens einen Benutzer zum Teilen aus oder stellen Sie auf „Privat“ um.',
            'Please select at least one user to share with or choose "Private".'
          )
        );
        return;
      }
      payload.sharing = {
        sharedWithAll: shareMode === 'all',
        sharedWithUserIds: shareMode === 'selected' ? shareUserIds : [],
      };
    }

    if (
      payload.enabled === undefined &&
      payload.category === undefined &&
      payload.sharing === undefined
    ) {
      setError(
        tr(
          'Bitte wählen Sie mindestens eine Einstellung aus, die geändert werden soll.',
          'Please select at least one setting to change.'
        )
      );
      return;
    }

    setSaving(true);
    try {
      await onSave(payload);
      onClose();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Sammeleinstellungen konnten nicht gespeichert werden.', 'Could not save bulk settings.')
      );
    } finally {
      setSaving(false);
    }
  }

  const previewNames = selectedCommands
    .slice(0, 4)
    .map((c) => c.name)
    .join(', ');
  const extraCount = Math.max(0, selectedCommands.length - 4);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/45 px-4 py-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby="bulk-commands-title"
    >
      <div className="w-full max-w-xl max-h-[90vh] flex flex-col bg-white border border-slate-200 rounded-lg overflow-hidden shadow-lg">
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between gap-4 shrink-0">
          <div className="min-w-0">
            <h2
              id="bulk-commands-title"
              className="font-display text-base font-semibold text-slate-900 flex items-center gap-2"
            >
              <SlidersHorizontal className="w-4 h-4 text-blue-700 shrink-0" />
              {tr(
                `Sammeleinstellungen für ${selectedCommands.length} SSH-Befehle`,
                `Bulk Settings for ${selectedCommands.length} SSH Commands`
              )}
            </h2>
            <p className="text-xs text-slate-500 mt-0.5 truncate">
              {previewNames}
              {extraCount > 0 ? tr(` + ${extraCount} weitere`, ` + ${extraCount} more`) : ''}
            </p>
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

        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto p-6 space-y-5">
          {error && (
            <div
              role="alert"
              className="px-3.5 py-2.5 rounded-md bg-red-50 border border-red-200 text-xs text-red-800"
            >
              {error}
            </div>
          )}

          <p className="text-xs text-slate-500">
            {tr(
              'Ändern Sie Freigabe, Status oder Kategorie gebündelt für alle markierten Befehle. Einstellungen auf „Unverändert“ bleiben erhalten.',
              'Update sharing, status, or category across all selected commands at once. Settings left on "Unchanged" stay as-is.'
            )}
          </p>

          {/* 1. Sharing (Admin only) */}
          {isAdmin && (
            <div className="border border-slate-200 rounded-md p-4 space-y-3">
              <p className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
                <Share2 className="w-3.5 h-3.5 text-slate-500" />
                {tr('Teilen & Sichtbarkeit (Administrator)', 'Sharing & Visibility (Admin)')}
              </p>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {(
                  [
                    { id: 'unchanged', label: tr('Unverändert', 'Unchanged') },
                    { id: 'private', label: tr('Privat', 'Private'), icon: Lock },
                    { id: 'all', label: tr('Alle Benutzer', 'All Users'), icon: Users },
                    { id: 'selected', label: tr('Ausgewählte', 'Selected'), icon: UserCheck },
                  ] as const
                ).map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setShareMode(opt.id)}
                    className={`inline-flex items-center justify-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-md border transition-colors cursor-pointer ${
                      shareMode === opt.id
                        ? 'bg-blue-50 text-blue-900 border-blue-400'
                        : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
                    }`}
                  >
                    {'icon' in opt && <opt.icon className="w-3.5 h-3.5 shrink-0" />}
                    <span>{opt.label}</span>
                  </button>
                ))}
              </div>

              {shareMode === 'selected' && (
                <div className="space-y-1.5 pt-1">
                  <p className="text-xs text-slate-600">
                    {tr(
                      `Berechtigte Benutzer (${shareUserIds.length} ausgewählt)`,
                      `Authorized users (${shareUserIds.length} selected)`
                    )}
                  </p>
                  {otherUsers.length === 0 ? (
                    <p className="text-xs text-slate-500 px-3 py-2.5 rounded-md bg-slate-50 border border-slate-200">
                      {tr(
                        'Es wurden noch keine weiteren Benutzerkonten angelegt.',
                        'No other user accounts exist yet.'
                      )}
                    </p>
                  ) : (
                    <div className="border border-slate-200 rounded-md divide-y divide-slate-200 max-h-40 overflow-y-auto">
                      {otherUsers.map((u) => (
                        <label
                          key={u.id}
                          className="flex items-center gap-2.5 px-3 py-2 hover:bg-slate-50 cursor-pointer"
                        >
                          <input
                            type="checkbox"
                            checked={shareUserIds.includes(u.id)}
                            onChange={() => toggleUser(u.id)}
                            className="rounded border-slate-300 text-blue-700 focus:ring-blue-600"
                          />
                          <div className="min-w-0">
                            <p className="text-xs font-medium text-slate-900 truncate">
                              {u.displayName}{' '}
                              <span className="font-mono text-slate-500">({u.username})</span>
                            </p>
                          </div>
                        </label>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* 2. Status */}
          <div className="border border-slate-200 rounded-md p-4 space-y-2.5">
            <p className="text-xs font-semibold text-slate-900">
              {tr('Befehlsstatus', 'Command Status')}
            </p>
            <div className="grid grid-cols-3 gap-2">
              {(
                [
                  { id: 'unchanged', label: tr('Unverändert', 'Unchanged') },
                  { id: 'on', label: tr('Aktivieren', 'Enable') },
                  { id: 'off', label: tr('Deaktivieren', 'Disable') },
                ] as const
              ).map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => setEnabledMode(opt.id)}
                  className={`px-3 py-2 text-xs font-medium rounded-md border transition-colors cursor-pointer ${
                    enabledMode === opt.id
                      ? opt.id === 'on'
                        ? 'bg-emerald-50 text-emerald-900 border-emerald-400'
                        : opt.id === 'off'
                        ? 'bg-slate-800 text-white border-slate-800'
                        : 'bg-blue-50 text-blue-900 border-blue-400'
                      : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* 3. Category */}
          <div className="border border-slate-200 rounded-md p-4 space-y-2">
            <label htmlFor="bulk-cmd-category" className="block text-xs font-semibold text-slate-900">
              {tr('Befehlskategorie', 'Command Category')}
            </label>
            <select
              id="bulk-cmd-category"
              value={categoryValue}
              onChange={(e) => setCategoryValue(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            >
              <option value="__unchanged__">{tr('— Unverändert lassen —', '— Keep unchanged —')}</option>
              {categories.map((cat) => (
                <option key={cat} value={cat}>
                  {translateCategory(cat, locale)}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-200">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer"
            >
              {tr('Abbrechen', 'Cancel')}
            </button>
            <button
              type="submit"
              disabled={saving}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer"
            >
              <Check className="w-3.5 h-3.5" />
              {saving
                ? tr('Speichert...', 'Saving...')
                : tr(
                    `Auf ${selectedCommands.length} Befehle anwenden`,
                    `Apply to ${selectedCommands.length} Commands`
                  )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
