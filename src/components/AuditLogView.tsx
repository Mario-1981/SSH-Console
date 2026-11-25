import React, { useMemo, useState } from 'react';
import { Search, ChevronDown, ChevronRight, History, RefreshCw, Users, User as UserIcon } from 'lucide-react';
import { useI18n } from '../i18n';
import type { ExecutionLog, User } from '../types';

interface AuditLogViewProps {
  currentUser: User;
  users: User[];
  logs: ExecutionLog[];
  onRefresh: () => Promise<void>;
}

const BENIGN_KNOWN_HOSTS_ADDED_RE =
  /^Warning:\s+Permanently added\s+'[^']+'(?:\s+\([^)]+\))?\s+to the list of known hosts\.$/i;

function filterBenignSshStderr(stderr: string): string {
  if (!stderr) return '';
  const kept = stderr
    .split(/\r?\n/)
    .filter((line) => !BENIGN_KNOWN_HOSTS_ADDED_RE.test(line.trim()));
  const joined = kept.join('\n');
  return joined.trim() ? joined.trimEnd() : '';
}

export function AuditLogView({ currentUser, users, logs, onRefresh }: AuditLogViewProps) {
  const { tr, formatDateTime } = useI18n();
  const isAdmin = currentUser.role === 'admin';

  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'ok' | 'err'>('all');
  const [userFilter, setUserFilter] = useState<string>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  // Defense-in-depth: regular users strictly see only their own logs (also enforced server-side)
  const scopedLogs = useMemo(() => {
    if (isAdmin) return logs;
    return logs.filter((log) => log.userId === currentUser.id);
  }, [isAdmin, logs, currentUser.id]);

  // Build user filter options for admins (combining active accounts and historical log entries)
  const adminUserOptions = useMemo(() => {
    if (!isAdmin) return [];
    const byId = new Map<string, { id: string; label: string; count: number }>();
    for (const u of users) {
      byId.set(u.id, {
        id: u.id,
        label: u.displayName && u.displayName !== u.username
          ? `${u.displayName} (${u.username})`
          : u.username,
        count: 0,
      });
    }
    for (const log of scopedLogs) {
      const existing = byId.get(log.userId);
      if (existing) {
        existing.count += 1;
      } else {
        byId.set(log.userId, {
          id: log.userId,
          label: log.username || log.userId,
          count: 1,
        });
      }
    }
    return Array.from(byId.values()).sort((a, b) => a.label.localeCompare(b.label));
  }, [isAdmin, users, scopedLogs]);

  const userScopedLogs = useMemo(() => {
    if (!isAdmin || userFilter === 'all') return scopedLogs;
    return scopedLogs.filter((log) => log.userId === userFilter);
  }, [isAdmin, userFilter, scopedLogs]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return userScopedLogs.filter((log) => {
      if (statusFilter === 'ok' && log.exitCode !== 0) return false;
      if (statusFilter === 'err' && log.exitCode === 0) return false;
      if (!q) return true;
      return (
        log.targetIp.toLowerCase().includes(q) ||
        log.commandName.toLowerCase().includes(q) ||
        log.commandText.toLowerCase().includes(q) ||
        (isAdmin && log.username.toLowerCase().includes(q)) ||
        log.certificateKeyId.toLowerCase().includes(q)
      );
    });
  }, [userScopedLogs, search, statusFilter, isAdmin]);

  async function handleRefresh() {
    setRefreshing(true);
    try {
      await onRefresh();
    } finally {
      setRefreshing(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5 flex-wrap">
            <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
              {tr('Ausführungsprotokoll', 'Execution Log')}
            </h1>
            <span
              className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 text-xs font-medium rounded-md border ${
                isAdmin
                  ? 'bg-blue-50 dark:bg-blue-950/40 text-blue-800 dark:text-blue-300 border-blue-200 dark:border-blue-800/70'
                  : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-800'
              }`}
            >
              {isAdmin ? (
                <>
                  <Users className="w-3.5 h-3.5" />
                  {tr('Admin-Ansicht · Alle Benutzer', 'Admin View · All Users')}
                </>
              ) : (
                <>
                  <UserIcon className="w-3.5 h-3.5" />
                  {tr(`Nur eigene Einträge (${currentUser.username})`, `Own Entries Only (${currentUser.username})`)}
                </>
              )}
            </span>
          </div>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            {isAdmin
              ? tr(
                  'Vollständige Historie aller über OpenSSH ausgeführten Befehle und SSH-Shell-Sitzungen sämtlicher Benutzer inklusive Rückgabecode und Konsolenausgabe.',
                  'Complete history of all SSH commands and SSH shell sessions across all users, including exit code and console output.'
                )
              : tr(
                  'Ihre persönliche Historie aller über OpenSSH ausgeführten Befehle und SSH-Shell-Sitzungen inklusive Rückgabecode und Konsolenausgabe.',
                  'Your personal history of executed SSH commands and SSH shell sessions, including exit code and console output.'
                )}
          </p>
        </div>

        <button
          type="button"
          onClick={handleRefresh}
          disabled={refreshing}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
          {refreshing ? tr('Aktualisiere...', 'Refreshing...') : tr('Aktualisieren', 'Refresh')}
        </button>
      </div>

      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <div className="inline-flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800 rounded-md self-start">
              {(
                [
                  { id: 'all', label: tr(`Alle (${userScopedLogs.length})`, `All (${userScopedLogs.length})`) },
                  { id: 'ok', label: tr('Erfolgreich', 'Successful') },
                  { id: 'err', label: tr('Fehlgeschlagen', 'Failed') },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setStatusFilter(tab.id)}
                  className={`px-3 py-1 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                    statusFilter === tab.id
                      ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {isAdmin && (
              <div className="flex items-center gap-2">
                <label htmlFor="audit-user-filter" className="text-xs font-medium text-slate-600 dark:text-slate-400 whitespace-nowrap">
                  {tr('Benutzer:', 'User:')}
                </label>
                <select
                  id="audit-user-filter"
                  value={userFilter}
                  onChange={(e) => setUserFilter(e.target.value)}
                  className="px-3 py-1.5 text-xs bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                >
                  <option value="all">
                    {tr(`Alle Benutzer (${scopedLogs.length})`, `All Users (${scopedLogs.length})`)}
                  </option>
                  {adminUserOptions.map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.label} ({u.count})
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>

          <div className="relative w-full lg:w-72">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={
                isAdmin
                  ? tr('Nach IP, Befehl oder Benutzer suchen...', 'Search by IP, command, or user...')
                  : tr('Nach IP, Befehl oder Zertifikat suchen...', 'Search by IP, command, or certificate...')
              }
              className="w-full pl-9 pr-3 py-1.5 text-sm border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <History className="w-7 h-7 text-slate-400 mx-auto mb-3" />
            <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
              {tr('Keine Protokolleinträge vorhanden', 'No log entries yet')}
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              {isAdmin
                ? tr(
                    'Für den gewählten Filter liegen noch keine SSH-Ausführungen vor.',
                    'No SSH executions match the selected filter yet.'
                  )
                : tr(
                    'Sobald Sie SSH-Befehle oder eine SSH-Shell ausführen, erscheinen Ihre Ergebnisse hier.',
                    'Your results will appear here as soon as you run SSH commands or an SSH shell.'
                  )}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/60 text-xs font-medium text-slate-500 dark:text-slate-400">
                  <th className="py-2.5 px-4 w-8"></th>
                  <th className="py-2.5 px-4">{tr('Zeitpunkt', 'Timestamp')}</th>
                  <th className="py-2.5 px-4">{tr('Zielserver', 'Target Server')}</th>
                  <th className="py-2.5 px-4">{tr('Befehl', 'Command')}</th>
                  <th className="py-2.5 px-4">
                    {isAdmin
                      ? tr('Benutzer · Zertifikat', 'User · Certificate')
                      : tr('Zertifikat', 'Certificate')}
                  </th>
                  <th className="py-2.5 px-4 text-right">{tr('Dauer', 'Duration')}</th>
                  <th className="py-2.5 px-6 text-right">Exit</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800 text-sm">
                {filtered.map((log) => {
                  const isOpen = expandedId === log.id;
                  const ok = log.exitCode === 0;
                  return (
                    <React.Fragment key={log.id}>
                      <tr
                        onClick={() => setExpandedId(isOpen ? null : log.id)}
                        className="hover:bg-slate-50 dark:hover:bg-slate-800/60 cursor-pointer transition-colors"
                      >
                        <td className="py-3 px-4 text-slate-400">
                          {isOpen ? (
                            <ChevronDown className="w-4 h-4" />
                          ) : (
                            <ChevronRight className="w-4 h-4" />
                          )}
                        </td>
                        <td className="py-3 px-4 font-mono text-xs text-slate-600 dark:text-slate-400 tabular-nums whitespace-nowrap">
                          {formatDateTime(log.executedAt, { seconds: true })}
                        </td>
                        <td className="py-3 px-4 font-mono text-xs text-slate-900 dark:text-slate-100 tabular-nums whitespace-nowrap">
                          {log.sshUser}@{log.targetIp}:{log.targetPort}
                        </td>
                        <td className="py-3 px-4 text-slate-900 dark:text-slate-100 font-medium whitespace-nowrap">
                          {log.commandName}
                        </td>
                        <td className="py-3 px-4 text-xs text-slate-600 dark:text-slate-400 whitespace-nowrap">
                          {isAdmin ? (
                            <>
                              <span className="font-mono font-medium text-slate-900 dark:text-slate-100">{log.username}</span>{' '}
                              · <span className="font-mono text-slate-500 dark:text-slate-400">{log.certificateKeyId}</span>
                            </>
                          ) : (
                            <span className="font-mono text-slate-700 dark:text-slate-300">{log.certificateKeyId}</span>
                          )}
                        </td>
                        <td className="py-3 px-4 font-mono text-xs text-slate-600 dark:text-slate-400 tabular-nums text-right whitespace-nowrap">
                          {log.durationMs} ms
                        </td>
                        <td
                          className={`py-3 px-6 font-mono text-xs font-semibold tabular-nums text-right whitespace-nowrap ${
                            ok ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'
                          }`}
                        >
                          Exit {log.exitCode}
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-slate-50 dark:bg-slate-800/60">
                          <td colSpan={7} className="p-5">
                            <div className="rounded-md bg-[#0B1120] text-slate-100 p-4 font-mono text-xs space-y-3 overflow-x-auto">
                              <div className="text-slate-400 border-b border-slate-800 pb-2">
                                $ {log.sshInvocation}
                              </div>
                              {log.stdout && (
                                <pre className="text-slate-200 whitespace-pre-wrap break-words">
                                  {log.stdout}
                                </pre>
                              )}
                              {(() => {
                                const visibleStderr = filterBenignSshStderr(log.stderr);
                                return visibleStderr ? (
                                  <pre className="text-amber-300 whitespace-pre-wrap break-words border-t border-slate-800 pt-2">
                                    {visibleStderr}
                                  </pre>
                                ) : null;
                              })()}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
