import React, { useMemo, useState } from 'react';
import { Search, ChevronDown, ChevronRight, History } from 'lucide-react';
import type { ExecutionLog } from '../types';

interface AuditLogViewProps {
  logs: ExecutionLog[];
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString('de-DE', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function AuditLogView({ logs }: AuditLogViewProps) {
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
          Ausführungsprotokoll
        </h1>
        <p className="text-sm text-slate-600 mt-1">
          Vollständige Historie aller über OpenSSH-Zertifikate ausgeführten Befehle inklusive Rückgabecode und Konsolenausgabe.
        </p>
      </div>

      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-md self-start">
            {(
              [
                { id: 'all', label: `Alle (${logs.length})` },
                { id: 'ok', label: 'Erfolgreich' },
                { id: 'err', label: 'Fehlgeschlagen' },
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
              placeholder="Nach IP, Befehl oder Benutzer suchen..."
              className="w-full pl-9 pr-3 py-1.5 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <History className="w-7 h-7 text-slate-400 mx-auto mb-3" />
            <p className="text-sm font-medium text-slate-900">Keine Protokolleinträge vorhanden</p>
            <p className="text-xs text-slate-500 mt-1">
              Sobald SSH-Befehle ausgeführt werden, erscheinen die Ergebnisse hier.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                  <th className="py-2.5 px-4 w-8"></th>
                  <th className="py-2.5 px-4">Zeitpunkt</th>
                  <th className="py-2.5 px-4">Zielserver</th>
                  <th className="py-2.5 px-4">Befehl</th>
                  <th className="py-2.5 px-4">Benutzer · Zertifikat</th>
                  <th className="py-2.5 px-4 text-right">Dauer</th>
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
                          {formatTime(log.executedAt)}
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
