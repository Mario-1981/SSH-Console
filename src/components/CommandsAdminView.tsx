import React, { useMemo, useState } from 'react';
import {
  Plus,
  Trash2,
  Pencil,
  Check,
  X,
  Sparkles,
  Search,
  SlidersHorizontal,
  ArrowUp,
  ArrowDown,
  Clock,
  Share2,
} from 'lucide-react';
import { api } from '../api';
import { translateCategory, useI18n } from '../i18n';
import { ShareDialog, formatShareSummary } from './ShareDialog';
import type { CommandKind, CommandStep, SshCommand, User } from '../types';

interface CommandsAdminViewProps {
  currentUser: User;
  users: User[];
  commands: SshCommand[];
  onRefresh: () => Promise<void>;
}

const CATEGORIES = ['Diagnose', 'Dienste', 'Wartung', 'Netzwerk', 'Sicherheit', 'Allgemein'];

function buildPreviewCommand(steps: CommandStep[], stopOnError: boolean): string {
  const cleaned = steps
    .map((s) => ({
      command: s.command.trim(),
      sleepAfterSec: Math.min(600, Math.max(0, Math.floor(Number(s.sleepAfterSec) || 0))),
    }))
    .filter((s) => s.command.length > 0);

  if (cleaned.length === 0) return '';
  const sep = stopOnError ? ' && ' : '; ';
  const parts: string[] = [];
  cleaned.forEach((step, idx) => {
    parts.push(`{ ${step.command}; }`);
    if (idx < cleaned.length - 1 && step.sleepAfterSec > 0) {
      parts.push(`sleep ${step.sleepAfterSec}`);
    }
  });
  return parts.join(sep);
}

function getTotalSleepSec(steps: CommandStep[]): number {
  if (steps.length <= 1) return 0;
  return steps.slice(0, -1).reduce((sum, s) => sum + Math.max(0, Math.floor(Number(s.sleepAfterSec) || 0)), 0);
}

export function CommandsAdminView({ currentUser, users, commands, onRefresh }: CommandsAdminViewProps) {
  const { locale, tr } = useI18n();
  const isAdmin = currentUser.role === 'admin';
  const [kind, setKind] = useState<CommandKind>('single');
  const [name, setName] = useState('');
  const [category, setCategory] = useState('Diagnose');
  const [command, setCommand] = useState('');
  const [steps, setSteps] = useState<CommandStep[]>([
    { command: '', sleepAfterSec: 3 },
    { command: '', sleepAfterSec: 0 },
  ]);
  const [stopOnError, setStopOnError] = useState(true);
  const [description, setDescription] = useState('');
  const [timeoutSec, setTimeoutSec] = useState('30');
  const [shareOnCreate, setShareOnCreate] = useState(false);

  const [editingId, setEditingId] = useState<string | null>(null);
  const [sharingCmd, setSharingCmd] = useState<SshCommand | null>(null);
  const [search, setSearch] = useState('');
  const [filterKind, setFilterKind] = useState<'all' | 'single' | 'chain'>('all');
  const [saving, setSaving] = useState(false);
  const [loadingPresets, setLoadingPresets] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return commands.filter((c) => {
      if (filterKind !== 'all' && (c.kind || 'single') !== filterKind) return false;
      if (!q) return true;
      return (
        c.name.toLowerCase().includes(q) ||
        c.command.toLowerCase().includes(q) ||
        c.category.toLowerCase().includes(q) ||
        translateCategory(c.category, locale).toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q)
      );
    });
  }, [commands, search, filterKind, locale]);

  const chainPreview = useMemo(() => buildPreviewCommand(steps, stopOnError), [steps, stopOnError]);
  const totalChainSleep = useMemo(() => getTotalSleepSec(steps), [steps]);
  const recommendedMinTimeout = Math.max(15, totalChainSleep + 15);

  function resetForm() {
    setEditingId(null);
    setKind('single');
    setName('');
    setCategory('Diagnose');
    setCommand('');
    setSteps([
      { command: '', sleepAfterSec: 3 },
      { command: '', sleepAfterSec: 0 },
    ]);
    setStopOnError(true);
    setDescription('');
    setTimeoutSec('30');
    setShareOnCreate(false);
  }

  function startEdit(cmd: SshCommand) {
    setEditingId(cmd.id);
    const cmdKind: CommandKind = cmd.kind === 'chain' ? 'chain' : 'single';
    setKind(cmdKind);
    setName(cmd.name);
    setCategory(cmd.category);
    setCommand(cmd.command);
    setSteps(
      cmdKind === 'chain' && cmd.steps.length > 0
        ? cmd.steps.map((s) => ({ ...s }))
        : [
            { command: cmd.command, sleepAfterSec: 3 },
            { command: '', sleepAfterSec: 0 },
          ]
    );
    setStopOnError(cmd.stopOnError ?? true);
    setDescription(cmd.description);
    setTimeoutSec(String(cmd.timeoutSec));
    setError(null);
  }

  function updateStep(idx: number, patch: Partial<CommandStep>) {
    setSteps((prev) => prev.map((item, i) => (i === idx ? { ...item, ...patch } : item)));
  }

  function addStep() {
    setSteps((prev) => {
      const next = [...prev];
      if (next.length > 0 && next[next.length - 1].sleepAfterSec === 0) {
        next[next.length - 1] = { ...next[next.length - 1], sleepAfterSec: 3 };
      }
      next.push({ command: '', sleepAfterSec: 0 });
      return next;
    });
  }

  function removeStep(idx: number) {
    setSteps((prev) => {
      if (prev.length <= 1) return prev;
      return prev.filter((_, i) => i !== idx);
    });
  }

  function moveStep(idx: number, direction: -1 | 1) {
    setSteps((prev) => {
      const target = idx + direction;
      if (target < 0 || target >= prev.length) return prev;
      const copy = [...prev];
      const temp = copy[idx];
      copy[idx] = copy[target];
      copy[target] = temp;
      return copy;
    });
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (kind === 'chain') {
      const validSteps = steps.filter((s) => s.command.trim().length > 0);
      if (validSteps.length === 0) {
        setError(
          tr(
            'Bitte tragen Sie mindestens einen Befehlsschritt für die Befehlskette ein.',
            'Please enter at least one command step for the command chain.'
          )
        );
        return;
      }
    }

    setSaving(true);
    try {
      const effectiveTimeout =
        kind === 'chain'
          ? Math.max(Number(timeoutSec) || 30, totalChainSleep + 10)
          : Number(timeoutSec) || 30;

      const payload = {
        name: name.trim(),
        category: category.trim() || 'Allgemein',
        kind,
        command: kind === 'chain' ? chainPreview : command.trim(),
        steps: kind === 'chain' ? steps.filter((s) => s.command.trim().length > 0) : [],
        stopOnError,
        description: description.trim(),
        timeoutSec: effectiveTimeout,
      };
      if (editingId) {
        await api.updateCommand(editingId, payload);
      } else {
        await api.createCommand({
          ...payload,
          ...(isAdmin && shareOnCreate ? { sharedWithAll: true, sharedWithUserIds: [] } : {}),
        });
      }
      await onRefresh();
      resetForm();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Befehl konnte nicht gespeichert werden.', 'Could not save command.')
      );
    } finally {
      setSaving(false);
    }
  }

  async function handleToggleEnabled(cmd: SshCommand) {
    setError(null);
    try {
      await api.updateCommand(cmd.id, { enabled: !cmd.enabled });
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Status konnte nicht geändert werden.', 'Could not update status.')
      );
    }
  }

  async function handleDelete(id: string) {
    setError(null);
    try {
      await api.deleteCommand(id);
      if (editingId === id) resetForm();
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Befehl konnte nicht gelöscht werden.', 'Could not delete command.')
      );
    }
  }

  async function handleLoadPresets() {
    setError(null);
    setLoadingPresets(true);
    try {
      await api.loadPresetCommands();
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Standardbefehle konnten nicht geladen werden.', 'Could not load preset commands.')
      );
    } finally {
      setLoadingPresets(false);
    }
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
            {tr('SSH-Befehle & Befehlsketten', 'SSH Commands & Command Chains')}
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            {isAdmin
              ? tr(
                  'Ihre Befehle und Befehlsketten sind standardmäßig privat. Als Administrator können Sie Einträge gezielt oder für alle Benutzer teilen.',
                  'Your commands and chains are private by default. As an administrator, you can share entries with specific users or everyone.'
                )
              : tr(
                  'Legen Sie Ihre eigenen Einzelbefehle oder Befehlsketten mit Sleep an. Ihre Einträge sind nur für Sie sichtbar; vom Administrator geteilte Befehle erscheinen zusätzlich in Ihrer Liste.',
                  'Create your own single commands or command chains with sleep intervals. Your entries are visible only to you; commands shared by an administrator also appear in your list.'
                )}
          </p>
        </div>

        <button
          type="button"
          onClick={handleLoadPresets}
          disabled={loadingPresets}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
        >
          <Sparkles className="w-3.5 h-3.5" />
          {loadingPresets
            ? tr('Lädt...', 'Loading...')
            : tr('Debian-Standardbefehle & Ketten laden', 'Load Debian Preset Commands & Chains')}
        </button>
      </div>

      {error && (
        <div role="alert" className="px-4 py-3 rounded-md bg-red-50 border border-red-200 text-sm text-red-800">
          {error}
        </div>
      )}

      {/* Command Create / Edit Form */}
      <form onSubmit={handleSubmit} className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-200">
          <div className="flex items-center gap-3">
            <h2 className="font-display text-base font-semibold text-slate-900">
              {editingId
                ? tr('Eintrag bearbeiten', 'Edit Entry')
                : tr('Neuen SSH-Befehl anlegen', 'Create New SSH Command')}
            </h2>
            {editingId && (
              <button
                type="button"
                onClick={resetForm}
                className="inline-flex items-center gap-1 text-xs text-slate-600 hover:text-slate-900 cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
                {tr('Abbrechen', 'Cancel')}
              </button>
            )}
          </div>

          <div className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-md self-start">
            <button
              type="button"
              onClick={() => setKind('single')}
              className={`px-3 py-1.5 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                kind === 'single'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {tr('Einzelbefehl', 'Single Command')}
            </button>
            <button
              type="button"
              onClick={() => {
                setKind('chain');
                if (steps.length === 0) {
                  setSteps([
                    { command: command.trim(), sleepAfterSec: 3 },
                    { command: '', sleepAfterSec: 0 },
                  ]);
                }
              }}
              className={`px-3 py-1.5 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                kind === 'chain'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {tr('Befehlskette (mit Sleep)', 'Command Chain (with sleep)')}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-12 gap-4">
          <div className="lg:col-span-5">
            <label htmlFor="cmd-name" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr('Bezeichnung', 'Name')}
            </label>
            <input
              id="cmd-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={
                kind === 'chain'
                  ? tr('z. B. Dienst stoppen, warten & neu starten', 'e.g. Stop service, wait & restart')
                  : tr('z. B. Nginx-Konfiguration prüfen', 'e.g. Validate Nginx configuration')
              }
              className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              required
            />
          </div>

          <div className="lg:col-span-4">
            <label htmlFor="cmd-cat" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr('Kategorie', 'Category')}
            </label>
            <select
              id="cmd-cat"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              className="w-full px-3 py-2 text-sm bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            >
              {CATEGORIES.map((cat) => (
                <option key={cat} value={cat}>
                  {translateCategory(cat, locale)}
                </option>
              ))}
            </select>
          </div>

          <div className="lg:col-span-3">
            <label htmlFor="cmd-timeout" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr(
                `Timeout (Sekunden${kind === 'chain' ? `, min. ${recommendedMinTimeout}s` : ''})`,
                `Timeout (seconds${kind === 'chain' ? `, min. ${recommendedMinTimeout}s` : ''})`
              )}
            </label>
            <input
              id="cmd-timeout"
              type="number"
              min={5}
              max={3600}
              value={timeoutSec}
              onChange={(e) => setTimeoutSec(e.target.value)}
              className="w-full px-3 py-2 text-sm font-mono tabular-nums border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              required
            />
          </div>
        </div>

        {kind === 'single' ? (
          <div>
            <label htmlFor="cmd-shell" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr(
                'Exakter SSH-Befehl (wird per OpenSSH an den Zielserver gesendet)',
                'Exact SSH Command (sent to the target server via OpenSSH)'
              )}
            </label>
            <input
              id="cmd-shell"
              type="text"
              value={command}
              onChange={(e) => setCommand(e.target.value)}
              placeholder="nginx -t && systemctl reload nginx"
              className="w-full px-3 py-2 text-sm font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              required
            />
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <p className="text-xs font-medium text-slate-700">
                {tr('Schritte der Befehlskette & Pausen dazwischen', 'Chain Steps & Wait Intervals')}
              </p>
              <label className="inline-flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                <input
                  type="checkbox"
                  checked={stopOnError}
                  onChange={(e) => setStopOnError(e.target.checked)}
                  className="rounded border-slate-300 text-blue-700 focus:ring-blue-600"
                />
                <span>
                  {tr('Bei Fehler sofort abbrechen (verknüpft mit ', 'Abort immediately on error (joined with ')}
                  <code className="font-mono">&amp;&amp;</code>)
                </span>
              </label>
            </div>

            <div className="space-y-2.5">
              {steps.map((step, idx) => {
                const isLast = idx === steps.length - 1;
                return (
                  <div key={idx} className="space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="w-7 text-xs font-mono text-slate-500 tabular-nums shrink-0 text-right">
                        {idx + 1}.
                      </span>
                      <input
                        type="text"
                        value={step.command}
                        onChange={(e) => updateStep(idx, { command: e.target.value })}
                        placeholder={
                          idx === 0
                            ? tr('z. B. systemctl stop myapp', 'e.g. systemctl stop myapp')
                            : idx === 1
                            ? tr('z. B. systemctl start myapp', 'e.g. systemctl start myapp')
                            : tr('z. B. systemctl is-active myapp', 'e.g. systemctl is-active myapp')
                        }
                        className="flex-1 px-3 py-2 text-sm font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                        required
                      />
                      <div className="flex items-center gap-1 shrink-0">
                        <button
                          type="button"
                          onClick={() => moveStep(idx, -1)}
                          disabled={idx === 0}
                          title={tr('Nach oben', 'Move up')}
                          aria-label={tr('Schritt nach oben', 'Move step up')}
                          className="p-2 text-slate-500 hover:text-slate-900 disabled:opacity-30 rounded-md hover:bg-slate-100 cursor-pointer"
                        >
                          <ArrowUp className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => moveStep(idx, 1)}
                          disabled={isLast}
                          title={tr('Nach unten', 'Move down')}
                          aria-label={tr('Schritt nach unten', 'Move step down')}
                          className="p-2 text-slate-500 hover:text-slate-900 disabled:opacity-30 rounded-md hover:bg-slate-100 cursor-pointer"
                        >
                          <ArrowDown className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => removeStep(idx)}
                          disabled={steps.length <= 1}
                          title={tr('Schritt entfernen', 'Remove step')}
                          aria-label={tr('Schritt entfernen', 'Remove step')}
                          className="p-2 text-red-600 hover:text-red-800 disabled:opacity-30 rounded-md hover:bg-red-50 cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>

                    {!isLast && (
                      <div className="pl-9 flex items-center gap-2.5 text-xs text-slate-600">
                        <Clock className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                        <span>
                          {tr(`Pause vor Schritt ${idx + 2} (`, `Wait before step ${idx + 2} (`)}
                          <code className="font-mono">sleep</code>):
                        </span>
                        <input
                          type="number"
                          min={0}
                          max={600}
                          value={step.sleepAfterSec}
                          onChange={(e) =>
                            updateStep(idx, {
                              sleepAfterSec: Math.min(600, Math.max(0, Math.floor(Number(e.target.value) || 0))),
                            })
                          }
                          className="w-20 px-2.5 py-1 text-xs font-mono tabular-nums border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                        />
                        <span className="text-slate-500">
                          {tr('Sekunden (0 = ohne Pause)', 'seconds (0 = no pause)')}
                        </span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            <div className="pl-9">
              <button
                type="button"
                onClick={addStep}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                <Plus className="w-3.5 h-3.5" />
                {tr('Weiteren Schritt hinzufügen', 'Add Another Step')}
              </button>
            </div>

            {/* Live compiled single SSH command preview */}
            <div className="rounded-md bg-slate-50 border border-slate-200 p-3.5 space-y-1.5">
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
                <span className="font-medium text-slate-700">
                  {tr(
                    'Resultierender einzelner SSH-Befehl (eine SSH-Sitzung)',
                    'Compiled Single SSH Command (one SSH session)'
                  )}
                </span>
                <span className="font-mono tabular-nums">
                  {steps.filter((s) => s.command.trim()).length} {tr('Schritte', 'steps')} ·{' '}
                  {tr('Gesamt-Sleep', 'Total sleep')}: {totalChainSleep}s
                </span>
              </div>
              <code className="block font-mono text-xs text-slate-900 break-all">
                {chainPreview ||
                  tr(
                    '— Bitte mindestens einen Befehlsschritt eingeben —',
                    '— Enter at least one command step —'
                  )}
              </code>
            </div>
          </div>
        )}

        <div className="space-y-4 pt-2 border-t border-slate-200">
          <div className="flex flex-col sm:flex-row sm:items-end gap-4">
            <div className="flex-1">
              <label htmlFor="cmd-desc" className="block text-xs font-medium text-slate-700 mb-1.5">
                {tr('Beschreibung', 'Description')}
              </label>
              <input
                id="cmd-desc"
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder={tr(
                  'Erklärt den Zweck und Ablauf des Befehls.',
                  'Explains the purpose and behavior of this command.'
                )}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
            <button
              type="submit"
              disabled={saving}
              className="inline-flex items-center justify-center gap-1.5 px-5 py-2 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
            >
              {editingId ? <Check className="w-4 h-4" /> : <Plus className="w-4 h-4" />}
              {saving
                ? tr('Speichert...', 'Saving...')
                : editingId
                ? tr('Änderungen speichern', 'Save Changes')
                : kind === 'chain'
                ? tr('Befehlskette speichern', 'Save Command Chain')
                : tr('Befehl speichern', 'Save Command')}
            </button>
          </div>

          {isAdmin && !editingId && (
            <label className="inline-flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
              <input
                type="checkbox"
                checked={shareOnCreate}
                onChange={(e) => setShareOnCreate(e.target.checked)}
                className="rounded border-slate-300 text-blue-700 focus:ring-blue-600"
              />
              <span>
                {tr(
                  'Direkt mit allen Benutzern teilen (ansonsten nur für mich sichtbar)',
                  'Share immediately with all users (otherwise visible only to me)'
                )}
              </span>
            </label>
          )}
        </div>
      </form>

      {/* Commands Table */}
      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center gap-4 flex-wrap">
            <h2 className="font-display text-base font-semibold text-slate-900">
              {tr(`Sichtbare Befehle (${filtered.length})`, `Visible Commands (${filtered.length})`)}
            </h2>
            <div className="inline-flex items-center gap-1 p-0.5 bg-slate-100 rounded-md">
              {(
                [
                  { id: 'all', label: tr('Alle', 'All') },
                  { id: 'single', label: tr('Einzelbefehle', 'Single Commands') },
                  { id: 'chain', label: tr('Befehlsketten', 'Command Chains') },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setFilterKind(tab.id)}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                    filterKind === tab.id
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          <div className="relative w-full md:w-64">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={tr('Befehle durchsuchen...', 'Search commands...')}
              className="w-full pl-9 pr-3 py-1.5 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <SlidersHorizontal className="w-7 h-7 text-slate-400 mx-auto mb-3" />
            <p className="text-sm font-medium text-slate-900">
              {tr('Keine SSH-Befehle vorhanden', 'No SSH commands available')}
            </p>
            <p className="text-xs text-slate-500 mt-1">
              {tr(
                'Legen Sie oben einen Einzelbefehl oder eine Befehlskette an oder laden Sie die Debian-Standardbefehle.',
                'Create a single command or chain above, or load the Debian preset commands.'
              )}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                  <th className="py-2.5 px-6">{tr('Bezeichnung', 'Name')}</th>
                  <th className="py-2.5 px-4">{tr('Typ · Kategorie', 'Type · Category')}</th>
                  <th className="py-2.5 px-4">{tr('SSH-Befehl', 'SSH Command')}</th>
                  <th className="py-2.5 px-4">{tr('Sichtbarkeit', 'Visibility')}</th>
                  <th className="py-2.5 px-4 text-right">Timeout</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-6 text-right">{tr('Aktionen', 'Actions')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 text-sm">
                {filtered.map((cmd) => {
                  const isChain = cmd.kind === 'chain';
                  const sleepSum = isChain ? getTotalSleepSec(cmd.steps) : 0;
                  const isOwner = cmd.userId === currentUser.id;
                  const catLabel = translateCategory(cmd.category, locale);
                  const shareLabel = isOwner
                    ? formatShareSummary(cmd.sharedWithAll, cmd.sharedWithUserIds, locale)
                    : tr(`Geteilt von ${cmd.createdBy}`, `Shared by ${cmd.createdBy}`);
                  return (
                    <tr key={cmd.id} className="hover:bg-slate-50/80 transition-colors">
                      <td className="py-3 px-6">
                        <p className="font-medium text-slate-900">{cmd.name}</p>
                        {cmd.description && (
                          <p className="text-xs text-slate-500 mt-0.5 max-w-sm truncate">
                            {cmd.description}
                          </p>
                        )}
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-600 whitespace-nowrap tabular-nums">
                        {isChain ? (
                          <span>
                            <span className="font-medium text-blue-800">
                              {tr(
                                `Kette (${cmd.steps.length} Schritte${sleepSum > 0 ? `, ${sleepSum}s Sleep` : ''})`,
                                `Chain (${cmd.steps.length} steps${sleepSum > 0 ? `, ${sleepSum}s sleep` : ''})`
                              )}
                            </span>{' '}
                            · {catLabel}
                          </span>
                        ) : (
                          <span>
                            {tr('Einzelbefehl', 'Single')} · {catLabel}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <code
                          className="font-mono text-xs text-slate-800 block max-w-md truncate"
                          title={cmd.command}
                        >
                          {cmd.command}
                        </code>
                      </td>
                      <td className="py-3 px-4 text-xs whitespace-nowrap">
                        <span
                          className={
                            !isOwner || cmd.sharedWithAll || cmd.sharedWithUserIds.length > 0
                              ? 'text-blue-800 font-medium'
                              : 'text-slate-500'
                          }
                        >
                          {shareLabel}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-xs text-slate-600 tabular-nums text-right whitespace-nowrap">
                        {cmd.timeoutSec}s
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        {isOwner ? (
                          <button
                            type="button"
                            onClick={() => handleToggleEnabled(cmd)}
                            className={`text-xs font-medium cursor-pointer ${
                              cmd.enabled
                                ? 'text-emerald-700 hover:text-emerald-900'
                                : 'text-slate-500 hover:text-slate-800'
                            }`}
                          >
                            {cmd.enabled ? tr('Aktiv', 'Active') : tr('Deaktiviert', 'Disabled')}
                          </button>
                        ) : (
                          <span className="text-xs font-medium text-emerald-700">
                            {cmd.enabled ? tr('Aktiv', 'Active') : tr('Deaktiviert', 'Disabled')}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-6 text-right whitespace-nowrap">
                        {isOwner ? (
                          <div className="inline-flex items-center gap-3">
                            {isAdmin && (
                              <button
                                type="button"
                                onClick={() => setSharingCmd(cmd)}
                                className="inline-flex items-center gap-1 text-xs font-medium text-blue-700 hover:text-blue-900 cursor-pointer"
                              >
                                <Share2 className="w-3.5 h-3.5" />
                                {tr('Teilen', 'Share')}
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={() => startEdit(cmd)}
                              className="inline-flex items-center gap-1 text-xs font-medium text-slate-700 hover:text-blue-700 cursor-pointer"
                            >
                              <Pencil className="w-3.5 h-3.5" />
                              {tr('Bearbeiten', 'Edit')}
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDelete(cmd.id)}
                              className="inline-flex items-center gap-1 text-xs font-medium text-red-700 hover:text-red-900 cursor-pointer"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                              {tr('Löschen', 'Delete')}
                            </button>
                          </div>
                        ) : (
                          <span className="text-xs text-slate-400">
                            {tr('Nur ausführen', 'Execute only')}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {sharingCmd && isAdmin && (
        <ShareDialog
          title={tr('SSH-Befehl teilen', 'Share SSH Command')}
          itemName={`${sharingCmd.name} (${translateCategory(sharingCmd.category, locale)})`}
          currentUserId={currentUser.id}
          users={users}
          initialSharedWithAll={sharingCmd.sharedWithAll}
          initialSharedWithUserIds={sharingCmd.sharedWithUserIds}
          onClose={() => setSharingCmd(null)}
          onSave={async (payload) => {
            await api.shareCommand(sharingCmd.id, payload);
            await onRefresh();
          }}
        />
      )}
    </div>
  );
}
