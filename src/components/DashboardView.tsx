import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  RefreshCw,
  Play,
  CheckCircle2,
  XCircle,
  Clock,
  Search,
  Server,
  KeyRound,
  Terminal,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  CheckSquare,
  ExternalLink,
  ShieldCheck,
} from 'lucide-react';
import { api } from '../api';
import type {
  ActiveTab,
  BmcCheckResult,
  DashboardPingResponse,
  ExecutionLog,
  SshCommand,
  User,
  UserCertificate,
  UserServer,
} from '../types';

interface DashboardViewProps {
  currentUser: User;
  servers: UserServer[];
  commands: SshCommand[];
  certificates: UserCertificate[];
  onNavigate: (tab: ActiveTab) => void;
  onExecutionComplete: () => Promise<void>;
}

function formatClockTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleTimeString('de-DE', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function formatBmcUrl(ipAddress: string): string {
  const clean = ipAddress.trim();
  const host = clean.includes(':') ? `[${clean}]` : clean;
  return `https://${host}`;
}

export function DashboardView({
  currentUser,
  servers,
  commands,
  certificates,
  onNavigate,
  onExecutionComplete,
}: DashboardViewProps) {
  const activeCommands = useMemo(() => commands.filter((c) => c.enabled), [commands]);

  const [pingData, setPingData] = useState<DashboardPingResponse | null>(null);
  const [pingingAll, setPingingAll] = useState(false);
  const [pingingServerId, setPingingServerId] = useState<string | null>(null);
  const [secondsToNext, setSecondsToNext] = useState<number>(60);

  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [quickCommandId, setQuickCommandId] = useState<string>('');
  const [rowCommandOverrides, setRowCommandOverrides] = useState<Record<string, string>>({});
  const [selectedCertId, setSelectedCertId] = useState<string>('');

  const [statusFilter, setStatusFilter] = useState<'all' | 'online' | 'offline'>('all');
  const [search, setSearch] = useState('');

  const [runningBatch, setRunningBatch] = useState(false);
  const [batchResults, setBatchResults] = useState<ExecutionLog[]>([]);
  const [expandedInvocations, setExpandedInvocations] = useState<Record<string, boolean>>({});
  const [checkingBmcId, setCheckingBmcId] = useState<string | null>(null);
  const [bmcResults, setBmcResults] = useState<Record<string, BmcCheckResult>>({});
  const [error, setError] = useState<string | null>(null);

  const fetchPingStatus = useCallback(async () => {
    try {
      const data = await api.getDashboardStatus();
      setPingData(data);
    } catch {
      // keep existing state on transient poll error
    }
  }, []);

  // Poll backend status every 15s (server runs actual ping cycle every 60s)
  useEffect(() => {
    void fetchPingStatus();
    const poll = setInterval(() => {
      void fetchPingStatus();
    }, 15_000);
    return () => clearInterval(poll);
  }, [fetchPingStatus, servers.length]);

  // Live 1-second countdown synced to backend nextCycleAt
  useEffect(() => {
    const tick = setInterval(() => {
      if (!pingData?.nextCycleAt) return;
      const diff = Math.max(0, Math.ceil((Date.parse(pingData.nextCycleAt) - Date.now()) / 1000));
      setSecondsToNext(diff);
      if (diff === 0) {
        void fetchPingStatus();
      }
    }, 1000);
    return () => clearInterval(tick);
  }, [pingData?.nextCycleAt, fetchPingStatus]);

  useEffect(() => {
    if (activeCommands.length === 0) {
      setQuickCommandId('');
    } else if (!activeCommands.some((c) => c.id === quickCommandId)) {
      setQuickCommandId(activeCommands[0].id);
    }
  }, [activeCommands, quickCommandId]);

  useEffect(() => {
    if (certificates.length === 0) {
      setSelectedCertId('');
    } else if (!certificates.some((c) => c.id === selectedCertId)) {
      setSelectedCertId(certificates[0].id);
    }
  }, [certificates, selectedCertId]);

  // Clean up deleted server IDs from selection
  useEffect(() => {
    const valid = new Set(servers.map((s) => s.id));
    setSelectedIds((prev) => prev.filter((id) => valid.has(id)));
  }, [servers]);

  const statuses = pingData?.statuses ?? {};

  const counts = useMemo(() => {
    let online = 0;
    let offline = 0;
    let pending = 0;
    for (const srv of servers) {
      const st = statuses[srv.id];
      if (!st) pending++;
      else if (st.online) online++;
      else offline++;
    }
    return { total: servers.length, online, offline, pending };
  }, [servers, statuses]);

  const filteredServers = useMemo(() => {
    const q = search.trim().toLowerCase();
    return servers.filter((srv) => {
      const st = statuses[srv.id];
      if (statusFilter === 'online' && !st?.online) return false;
      if (statusFilter === 'offline' && (!st || st.online)) return false;
      if (!q) return true;
      return (
        srv.label.toLowerCase().includes(q) ||
        srv.ipAddress.toLowerCase().includes(q) ||
        (srv.bmcIpAddress || '').toLowerCase().includes(q) ||
        srv.sshUser.toLowerCase().includes(q) ||
        srv.notes.toLowerCase().includes(q)
      );
    });
  }, [servers, statuses, statusFilter, search]);

  async function handleManualPingAll() {
    setError(null);
    setPingingAll(true);
    try {
      const res = await api.triggerPing();
      setPingData(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ping-Prüfung fehlgeschlagen.');
    } finally {
      setPingingAll(false);
    }
  }

  async function handleManualPingOne(serverId: string) {
    setError(null);
    setPingingServerId(serverId);
    try {
      const res = await api.triggerPing(serverId);
      setPingData(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Einzel-Ping fehlgeschlagen.');
    } finally {
      setPingingServerId(null);
    }
  }

  async function handleCheckBmc(serverId: string) {
    setError(null);
    setCheckingBmcId(serverId);
    try {
      const { result } = await api.checkServerBmc(serverId);
      setBmcResults((prev) => ({ ...prev, [serverId]: result }));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'BMC HTTPS-Prüfung fehlgeschlagen.');
    } finally {
      setCheckingBmcId(null);
    }
  }

  function toggleRow(id: string) {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  }

  function selectAllVisible() {
    const ids = filteredServers.map((s) => s.id);
    setSelectedIds(ids);
  }

  function selectOnlineOnly() {
    const ids = servers.filter((s) => statuses[s.id]?.online).map((s) => s.id);
    setSelectedIds(ids);
  }

  function clearSelection() {
    setSelectedIds([]);
  }

  function applyQuickCommandToSelected() {
    if (!quickCommandId || selectedIds.length === 0) return;
    setRowCommandOverrides((prev) => {
      const next = { ...prev };
      for (const id of selectedIds) {
        next[id] = quickCommandId;
      }
      return next;
    });
  }

  function setRowCommand(serverId: string, cmdId: string) {
    setRowCommandOverrides((prev) => ({ ...prev, [serverId]: cmdId }));
    if (cmdId && !selectedIds.includes(serverId)) {
      setSelectedIds((prev) => [...prev, serverId]);
    }
  }

  // Resolve final jobs: every checked server with either its row-specific command or the quick-select command
  const preparedJobs = useMemo(() => {
    const jobs: Array<{ serverId: string; commandId: string }> = [];
    for (const serverId of selectedIds) {
      const cmdId = rowCommandOverrides[serverId] || quickCommandId;
      if (cmdId) {
        jobs.push({ serverId, commandId: cmdId });
      }
    }
    return jobs;
  }, [selectedIds, rowCommandOverrides, quickCommandId]);

  async function handleDispatchBatch() {
    setError(null);
    if (!selectedCertId) {
      setError('Bitte laden Sie zuerst ein 3-Dateien-SSH-Zertifikatspaket hoch und wählen Sie es aus.');
      return;
    }
    if (preparedJobs.length === 0) {
      setError('Bitte markieren Sie mindestens eine IP-Adresse und wählen Sie einen SSH-Befehl aus.');
      return;
    }

    setRunningBatch(true);
    try {
      const res = await api.executeBatch({
        certificateId: selectedCertId,
        jobs: preparedJobs,
      });
      setBatchResults(res.results);
      await onExecutionComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sammelausführung fehlgeschlagen.');
    } finally {
      setRunningBatch(false);
    }
  }

  const allVisibleSelected =
    filteredServers.length > 0 && filteredServers.every((s) => selectedIds.includes(s.id));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
            Server-Dashboard
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            Erreichbarkeit aller Ziel-IPs im 60-Sekunden-Ping-Takt sowie direkte Befehls-Schnellauswahl und Sammelausführung.
          </p>
        </div>

        <button
          type="button"
          onClick={handleManualPingAll}
          disabled={pingingAll || servers.length === 0}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${pingingAll ? 'animate-spin' : ''}`} />
          {pingingAll ? 'Prüfe alle IPs...' : 'Alle IPs jetzt pingen'}
        </button>
      </div>

      {error && (
        <div role="alert" className="px-4 py-3 rounded-md bg-red-50 border border-red-200 text-sm text-red-800">
          {error}
        </div>
      )}

      {/* Single-elevation KPI Strip */}
      <section className="bg-white border border-slate-200 rounded-lg grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 lg:divide-x divide-slate-200">
        <div className="p-5">
          <p className="text-xs text-slate-500">Überwachte IPs</p>
          <p className="mt-1 font-display text-2xl font-bold text-slate-900 tabular-nums">
            {counts.total}
          </p>
        </div>
        <div className="p-5">
          <p className="text-xs text-slate-500">Online</p>
          <p className="mt-1 font-display text-2xl font-bold text-emerald-700 tabular-nums">
            {counts.online}
          </p>
        </div>
        <div className="p-5">
          <p className="text-xs text-slate-500">Offline</p>
          <p className="mt-1 font-display text-2xl font-bold text-red-700 tabular-nums">
            {counts.offline}
          </p>
        </div>
        <div className="p-5">
          <p className="text-xs text-slate-500">Auto-Ping (60s-Takt)</p>
          <p className="mt-1 font-mono text-sm font-semibold text-slate-900 tabular-nums">
            Nächster in {secondsToNext}s
          </p>
          <p className="text-xs text-slate-500 mt-0.5 tabular-nums">
            Letzter Lauf: {formatClockTime(pingData?.lastCycleAt)}
          </p>
        </div>
      </section>

      {/* Quick Command & Multi-IP Dispatch Bar */}
      <section className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-200">
          <div>
            <h2 className="font-display text-sm font-semibold text-slate-900">
              Schnellauswahl &amp; Sammelausführung
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Weisen Sie einen Befehl allen markierten IPs gemeinsam zu oder wählen Sie in der Tabelle pro IP einen eigenen Befehl und schicken Sie alles gesammelt ab.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-600 tabular-nums whitespace-nowrap shrink-0">
            {preparedJobs.length} Auftrag{preparedJobs.length === 1 ? '' : 'e'} bereit
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-end">
          {/* Quick Command Selector */}
          <div className="lg:col-span-5">
            <label htmlFor="dash-quick-cmd" className="block text-xs font-medium text-slate-700 mb-1.5">
              Schnellauswahl SSH-Befehl / Befehlskette
            </label>
            <div className="flex items-center gap-2">
              <select
                id="dash-quick-cmd"
                value={quickCommandId}
                onChange={(e) => setQuickCommandId(e.target.value)}
                disabled={activeCommands.length === 0}
                className="flex-1 min-w-0 px-3 py-2 text-sm bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600"
              >
                {activeCommands.length === 0 ? (
                  <option value="">Keine sichtbaren Befehle vorhanden</option>
                ) : (
                  activeCommands.map((cmd) => (
                    <option key={cmd.id} value={cmd.id}>
                      [{cmd.category}] {cmd.name}
                      {cmd.kind === 'chain' ? ` (Kette · ${cmd.steps.length})` : ''}
                      {cmd.userId !== currentUser.id ? ` · Geteilt` : ''}
                    </option>
                  ))
                )}
              </select>
              <button
                type="button"
                onClick={applyQuickCommandToSelected}
                disabled={!quickCommandId || selectedIds.length === 0}
                className="px-3 py-2 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 disabled:opacity-40 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
              >
                Auf markierte anwenden
              </button>
            </div>
          </div>

          {/* Certificate Selector */}
          <div className="lg:col-span-4">
            <label htmlFor="dash-cert" className="block text-xs font-medium text-slate-700 mb-1.5">
              SSH-Schlüssel / Zertifikatspaket
            </label>
            {certificates.length === 0 ? (
              <button
                type="button"
                onClick={() => onNavigate('certificates')}
                className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                <KeyRound className="w-3.5 h-3.5" />
                Schlüssel / Zertifikat hochladen
              </button>
            ) : (
              <select
                id="dash-cert"
                value={selectedCertId}
                onChange={(e) => setSelectedCertId(e.target.value)}
                className="w-full px-3 py-2 text-sm bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600"
              >
                {certificates.map((cert) => {
                  const hasCert = cert.metadata.hasCertificate !== false && Boolean(cert.certFileName);
                  return (
                    <option key={cert.id} value={cert.id}>
                      {cert.name} (
                      {hasCert
                        ? cert.metadata.keyId || cert.certFileName
                        : 'Schlüsselpaar'}
                      )
                      {cert.userId !== currentUser.id ? ' · Geteilt' : ''}
                    </option>
                  );
                })}
              </select>
            )}
          </div>

          {/* Dispatch All CTA */}
          <div className="lg:col-span-3">
            <button
              type="button"
              onClick={handleDispatchBatch}
              disabled={runningBatch || preparedJobs.length === 0 || !selectedCertId}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
            >
              <Play className="w-4 h-4" />
              {runningBatch
                ? 'Wird ausgeführt...'
                : `Gesamtpaket senden (${preparedJobs.length})`}
            </button>
          </div>
        </div>
      </section>

      {/* Main IP Table with Online/Offline Ping Status and Per-IP Command Selector */}
      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <div className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-md">
              {(
                [
                  { id: 'all', label: `Alle (${counts.total})` },
                  { id: 'online', label: `Online (${counts.online})` },
                  { id: 'offline', label: `Offline (${counts.offline})` },
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

            {servers.length > 0 && (
              <div className="flex items-center gap-3 text-xs text-slate-600">
                <button
                  type="button"
                  onClick={selectAllVisible}
                  className="hover:text-blue-700 font-medium cursor-pointer whitespace-nowrap"
                >
                  Alle markieren
                </button>
                <span aria-hidden="true" className="text-slate-300">·</span>
                <button
                  type="button"
                  onClick={selectOnlineOnly}
                  className="hover:text-blue-700 font-medium cursor-pointer whitespace-nowrap"
                >
                  Nur Online
                </button>
                <span aria-hidden="true" className="text-slate-300">·</span>
                <button
                  type="button"
                  onClick={clearSelection}
                  className="hover:text-slate-900 cursor-pointer whitespace-nowrap"
                >
                  Auswahl leeren
                </button>
              </div>
            )}
          </div>

          <div className="relative w-full lg:w-64">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="IP oder Servername suchen..."
              className="w-full pl-9 pr-3 py-1.5 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
        </div>

        {servers.length === 0 ? (
          <div className="px-6 py-14 text-center">
            <Server className="w-7 h-7 text-slate-400 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-slate-900">Noch keine Server-IPs hinterlegt</h3>
            <p className="text-sm text-slate-500 mt-1 max-w-md mx-auto">
              Fügen Sie Ihre Ziel-IPs unter „Meine Server (IPs)“ hinzu, um den 60-Sekunden-Ping-Status und die Sammelausführung zu nutzen.
            </p>
            <button
              type="button"
              onClick={() => onNavigate('servers')}
              className="mt-4 px-4 py-2 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 rounded-md transition-colors cursor-pointer whitespace-nowrap"
            >
              Server-IPs anlegen
            </button>
          </div>
        ) : filteredServers.length === 0 ? (
          <div className="px-6 py-10 text-center text-sm text-slate-500">
            Keine Server entsprechen dem aktuellen Filter.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                  <th className="py-2.5 pl-6 pr-2 w-10">
                    <input
                      type="checkbox"
                      checked={allVisibleSelected}
                      onChange={(e) => (e.target.checked ? selectAllVisible() : clearSelection())}
                      aria-label="Alle sichtbaren Server auswählen"
                      className="rounded border-slate-300 text-blue-700 focus:ring-blue-600 cursor-pointer"
                    />
                  </th>
                  <th className="py-2.5 px-4">Server · IP-Adresse</th>
                  <th className="py-2.5 px-4">BMC (HTTPS :443)</th>
                  <th className="py-2.5 px-4">Ping-Status</th>
                  <th className="py-2.5 px-4">Zugewiesener Befehl</th>
                  <th className="py-2.5 pl-4 pr-6 text-right">Ping</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 text-sm">
                {filteredServers.map((srv) => {
                  const st = statuses[srv.id];
                  const isChecked = selectedIds.includes(srv.id);
                  const assignedCmdId = rowCommandOverrides[srv.id] ?? '';
                  const isRowPinging = pingingServerId === srv.id || pingingAll;
                  const bmcRes = bmcResults[srv.id];
                  const isCheckingBmc = checkingBmcId === srv.id;
                  return (
                    <tr
                      key={srv.id}
                      className={`transition-colors ${
                        isChecked ? 'bg-blue-50/40 hover:bg-blue-50/60' : 'hover:bg-slate-50/80'
                      }`}
                    >
                      <td className="py-3 pl-6 pr-2">
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => toggleRow(srv.id)}
                          aria-label={`${srv.label} auswählen`}
                          className="rounded border-slate-300 text-blue-700 focus:ring-blue-600 cursor-pointer"
                        />
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <p className="font-medium text-slate-900">
                          {srv.label}
                          {srv.userId !== currentUser.id && (
                            <span className="ml-2 text-xs font-normal text-blue-800">
                              · Geteilt von {srv.ownerUsername || 'admin'}
                            </span>
                          )}
                        </p>
                        <p className="text-xs font-mono text-slate-500 tabular-nums">
                          {srv.sshUser}@{srv.ipAddress}:{srv.port}
                        </p>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        {srv.bmcIpAddress ? (
                          <div className="space-y-1">
                            <div className="flex items-center gap-2.5">
                              <a
                                href={formatBmcUrl(srv.bmcIpAddress)}
                                target="_blank"
                                rel="noopener noreferrer"
                                title={`${formatBmcUrl(srv.bmcIpAddress)} in neuem Tab öffnen`}
                                className="inline-flex items-center gap-1 font-mono text-xs font-medium text-blue-700 hover:text-blue-900 hover:underline tabular-nums"
                              >
                                <span>{srv.bmcIpAddress}</span>
                                <ExternalLink className="w-3 h-3 shrink-0" />
                              </a>
                              <button
                                type="button"
                                onClick={() => handleCheckBmc(srv.id)}
                                disabled={isCheckingBmc}
                                title="BMC über https:// Port 443 prüfen"
                                className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 disabled:opacity-50 rounded transition-colors cursor-pointer"
                              >
                                {isCheckingBmc ? (
                                  <RefreshCw className="w-3 h-3 animate-spin" />
                                ) : (
                                  <ShieldCheck className="w-3 h-3" />
                                )}
                                <span>{isCheckingBmc ? 'Prüft...' : '443 prüfen'}</span>
                              </button>
                            </div>
                            {bmcRes && (
                              <p
                                className={`inline-flex items-center gap-1 text-[11px] font-mono tabular-nums ${
                                  bmcRes.reachable ? 'text-emerald-700' : 'text-red-700'
                                }`}
                                title={bmcRes.error || bmcRes.url}
                              >
                                {bmcRes.reachable ? (
                                  <>
                                    <CheckCircle2 className="w-3 h-3 shrink-0" />
                                    <span>
                                      HTTPS OK
                                      {bmcRes.httpStatus ? ` · ${bmcRes.httpStatus}` : ''}
                                      {bmcRes.latencyMs !== null ? ` · ${bmcRes.latencyMs} ms` : ''}
                                    </span>
                                  </>
                                ) : (
                                  <>
                                    <XCircle className="w-3 h-3 shrink-0" />
                                    <span>{bmcRes.error || 'Nicht erreichbar'}</span>
                                  </>
                                )}
                              </p>
                            )}
                          </div>
                        ) : (
                          <span className="text-xs text-slate-400">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        {!st ? (
                          <span className="inline-flex items-center gap-1.5 text-xs text-slate-500">
                            <Clock className="w-3.5 h-3.5" />
                            Ausstehend
                          </span>
                        ) : st.online ? (
                          <div>
                            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-700 tabular-nums">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              Online{st.latencyMs !== null ? ` · ${st.latencyMs} ms` : ''}
                            </span>
                            <p className="text-[11px] font-mono text-slate-500 tabular-nums mt-0.5">
                              {formatClockTime(st.checkedAt)}
                            </p>
                          </div>
                        ) : (
                          <div>
                            <span
                              className="inline-flex items-center gap-1.5 text-xs font-medium text-red-700"
                              title={st.error || 'Nicht erreichbar'}
                            >
                              <XCircle className="w-3.5 h-3.5" />
                              Offline
                            </span>
                            <p className="text-[11px] font-mono text-slate-500 tabular-nums mt-0.5">
                              {formatClockTime(st.checkedAt)}
                            </p>
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4 min-w-[220px]">
                        <select
                          value={assignedCmdId}
                          onChange={(e) => setRowCommand(srv.id, e.target.value)}
                          disabled={activeCommands.length === 0}
                          aria-label={`Befehl für ${srv.label}`}
                          className="w-full px-2.5 py-1.5 text-xs bg-white border border-slate-300 rounded-md text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-600"
                        >
                          <option value="">
                            {quickCommandId
                              ? '↳ Schnellauswahl übernehmen'
                              : 'Befehl auswählen...'}
                          </option>
                          {activeCommands.map((cmd) => (
                            <option key={cmd.id} value={cmd.id}>
                              [{cmd.category}] {cmd.name}
                              {cmd.kind === 'chain' ? ` (Kette)` : ''}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td className="py-3 pl-4 pr-6 text-right whitespace-nowrap">
                        <button
                          type="button"
                          onClick={() => handleManualPingOne(srv.id)}
                          disabled={isRowPinging}
                          title="Diese IP sofort pingen"
                          className="inline-flex items-center gap-1 text-xs font-medium text-slate-600 hover:text-blue-700 disabled:opacity-40 cursor-pointer"
                        >
                          <RefreshCw className={`w-3.5 h-3.5 ${isRowPinging ? 'animate-spin' : ''}`} />
                          Prüfen
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Batch Execution Output Console */}
      {(runningBatch || batchResults.length > 0) && (
        <section className="bg-[#0B1120] text-slate-100 rounded-lg border border-slate-800 overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-950/60">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-slate-400" />
              <span className="text-xs font-medium text-slate-200">
                Ergebnisse der Sammelausführung
              </span>
            </div>
            {!runningBatch && (
              <div className="flex items-center gap-3 text-xs font-mono tabular-nums">
                <span className="text-emerald-400">
                  {batchResults.filter((r) => r.exitCode === 0).length} OK
                </span>
                <span className="text-slate-600">·</span>
                <span className="text-red-400">
                  {batchResults.filter((r) => r.exitCode !== 0).length} Fehler
                </span>
              </div>
            )}
          </div>

          <div className="p-5 space-y-4 font-mono text-xs leading-relaxed">
            {runningBatch ? (
              <div className="py-8 text-center text-slate-400 flex items-center justify-center gap-2">
                <CheckSquare className="w-4 h-4" />
                <span>Führe {preparedJobs.length} SSH-Aufträge parallel per Zertifikat aus...</span>
              </div>
            ) : (
              batchResults.map((res) => {
                const ok = res.exitCode === 0;
                const showCmd = Boolean(expandedInvocations[res.id]);
                return (
                  <div
                    key={res.id}
                    className="border border-slate-800 rounded-md overflow-hidden bg-slate-950/50"
                  >
                    <div className="px-4 py-2.5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2 bg-slate-900/70">
                      <div className="flex items-center gap-2">
                        {ok ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        ) : (
                          <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                        )}
                        <span className="text-slate-100 font-medium">
                          {res.serverLabel} ({res.sshUser}@{res.targetIp}:{res.targetPort})
                        </span>
                        <span className="text-slate-500">·</span>
                        <span className="text-blue-300">{res.commandName}</span>
                      </div>
                      <div className="flex items-center gap-3 tabular-nums">
                        <span className={ok ? 'text-emerald-400' : 'text-red-400'}>
                          Exit {res.exitCode}
                        </span>
                        <span className="text-slate-400">{res.durationMs} ms</span>
                      </div>
                    </div>

                    <div className="p-4 space-y-2.5">
                      <button
                        type="button"
                        onClick={() =>
                          setExpandedInvocations((prev) => ({ ...prev, [res.id]: !prev[res.id] }))
                        }
                        className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 cursor-pointer"
                      >
                        {showCmd ? (
                          <ChevronDown className="w-3.5 h-3.5" />
                        ) : (
                          <ChevronRight className="w-3.5 h-3.5" />
                        )}
                        OpenSSH-Aufruf anzeigen
                      </button>

                      {showCmd && (
                        <pre className="p-2.5 rounded bg-slate-900 text-slate-300 text-[11px] whitespace-pre-wrap break-all border border-slate-800">
                          {res.sshInvocation}
                        </pre>
                      )}

                      {res.stdout && (
                        <pre className="text-slate-200 whitespace-pre-wrap break-words">
                          {res.stdout}
                        </pre>
                      )}

                      {res.stderr && (
                        <pre className="text-amber-300 whitespace-pre-wrap break-words border-t border-slate-800 pt-2.5">
                          {res.stderr}
                        </pre>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </section>
      )}
    </div>
  );
}
