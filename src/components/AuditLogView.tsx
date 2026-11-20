import React, { useMemo, useState } from 'react';
import { Search, ChevronDown, ChevronRight, History } from 'lucide-react';
import { useI18n } from '../i18n';
import type { ExecutionLog } from '../types';

interface AuditLogViewProps {
  logs: ExecutionLog[];
}

export function AuditLogView({ logs }: AuditLogViewProps) {
  const { tr, formatDateTime } = useI18n();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'ok' | 'err'>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return logs.filter((log) => {
      if (statusFilter === 'ok' && log.exitCode !== 0) return false;
      if (statusFilter === 'err' && log.exitCode === 0) return false;
      if (!q) return true;
      return (
        log.targetIp.toLowerCase().includes(q) ||
        log.commandName.toLowerCase().includes(q) ||
        log.commandText.toLowerCase().includes(q) ||
        log.username.toLowerCase().includes(q) ||
        log.certificateKeyId.toLowerCase().includes(q)
      );
    });
  }, [logs, search, statusFilter]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
          {tr('Ausführungsprotokoll', 'Execution Log')}
        </h1>
        <p className="text-sm text-slate-600 mt-1">
          {tr(
            'Vollständige Historie aller über OpenSSH-Schlüssel und Zertifikate ausgeführten Befehle inklusive Rückgabecode und Konsolenausgabe.',
            'Complete history of all SSH commands executed with OpenSSH keys and certificates, including exit code and console output.'
          )}
        </p>
      </div>

      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-md self-start">
            {(
              [
                { id: 'all', label: tr(`Alle (${logs.length})`, `All (${logs.length})`) },
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
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="relative w-full md:w-72">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={tr('Nach IP, Befehl oder Benutzer suchen...', 'Search by IP, command, or user...')}
              className="w-full pl-9 pr-3 py-1.5 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <History className="w-7 h-7 text-slate-400 mx-auto mb-3" />
            <p className="text-sm font-medium text-slate-900">
              {tr('Keine Protokolleinträge vorhanden', 'No log entries yet')}
            </p>
            <p className="text-xs text-slate-500 mt-1">
              {tr(
                'Sobald SSH-Befehle ausgeführt werden, erscheinen die Ergebnisse hier.',
                'Results will appear here as soon as SSH commands are executed.'
              )}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                  <th className="py-2.5 px-4 w-8"></th>
                  <th className="py-2.5 px-4">{tr('Zeitpunkt', 'Timestamp')}</th>
                  <th className="py-2.5 px-4">{tr('Zielserver', 'Target Server')}</th>
                  <th className="py-2.5 px-4">{tr('Befehl', 'Command')}</th>
                  <th className="py-2.5 px-4">{tr('Benutzer · Zertifikat', 'User · Certificate')}</th>
                  <th className="py-2.5 px-4 text-right">{tr('Dauer', 'Duration')}</th>
                  <th className="py-2.5 px-6 text-right">Exit</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 text-sm">
                {filtered.map((log) => {
                  const isOpen = expandedId === log.id;
                  const ok = log.exitCode === 0;
                  return (
                    <React.Fragment key={log.id}>
                      <tr
                        onClick={() => setExpandedId(isOpen ? null : log.id)}
                        className="hover:bg-slate-50 cursor-pointer transition-colors"
                      >
                        <td className="py-3 px-4 text-slate-400">
                          {isOpen ? (
                            <ChevronDown className="w-4 h-4" />
                          ) : (
                            <ChevronRight className="w-4 h-4" />
                          )}
                        </td>
                        <td className="py-3 px-4 font-mono text-xs text-slate-600 tabular-nums whitespace-nowrap">
                          {formatDateTime(log.executedAt, { seconds: true })}
                        </td>
                        <td className="py-3 px-4 font-mono text-xs text-slate-900 tabular-nums whitespace-nowrap">
                          {log.sshUser}@{log.targetIp}:{log.targetPort}
                        </td>
                        <td className="py-3 px-4 text-slate-900 font-medium whitespace-nowrap">
                          {log.commandName}
                        </td>
                        <td className="py-3 px-4 text-xs text-slate-600 whitespace-nowrap">
                          <span className="font-mono">{log.username}</span> ·{' '}
                          <span className="font-mono text-slate-500">{log.certificateKeyId}</span>
                        </td>
                        <td className="py-3 px-4 font-mono text-xs text-slate-600 tabular-nums text-right whitespace-nowrap">
                          {log.durationMs} ms
                        </td>
                        <td
                          className={`py-3 px-6 font-mono text-xs font-semibold tabular-nums text-right whitespace-nowrap ${
                            ok ? 'text-emerald-700' : 'text-red-700'
                          }`}
                        >
                          Exit {log.exitCode}
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-slate-50">
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
                              {log.stderr && (
                                <pre className="text-amber-300 whitespace-pre-wrap break-words border-t border-slate-800 pt-2">
                                  {log.stderr}
                                </pre>
                              )}
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
