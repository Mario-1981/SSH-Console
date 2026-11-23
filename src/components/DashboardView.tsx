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
  ChevronLeft,
  ChevronRight,
  CheckSquare,
  ExternalLink,
  ShieldCheck,
  Ban,
  Activity,
  SlidersHorizontal,
  Tag,
  X,
} from 'lucide-react';
import { api } from '../api';
import { translateCategory, useI18n } from '../i18n';
import type {
  ActiveTab,
  AppSettings,
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
  settings: AppSettings;
  servers: UserServer[];
  commands: SshCommand[];
  certificates: UserCertificate[];
  onNavigate: (tab: ActiveTab) => void;
  onRefreshServers: () => Promise<void>;
  onUpdateUser: (user: User) => void;
  onUpdateSettings: (settings: AppSettings) => void;
  onExecutionComplete: () => Promise<void>;
}

function formatBmcUrl(ipAddress: string): string {
  const clean = ipAddress.trim();
  const host = clean.includes(':') ? `[${clean}]` : clean;
  return `https://${host}`;
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

type PageSizeOption = 10 | 20 | 50 | 'all';
const PAGE_SIZE_OPTIONS: PageSizeOption[] = [10, 20, 50, 'all'];
const PAGE_SIZE_STORAGE_KEY = 'ssh_console_dashboard_page_size';

function loadSavedPageSize(): PageSizeOption {
  try {
    const raw = window.localStorage.getItem(PAGE_SIZE_STORAGE_KEY);
    if (raw === '10') return 10;
    if (raw === '20') return 20;
    if (raw === '50') return 50;
    if (raw === 'all') return 'all';
  } catch {
    // ignore storage errors
  }
  return 20;
}

function buildPageNumbers(current: number, total: number): Array<number | 'ellipsis'> {
  if (total <= 7) {
    return Array.from({ length: total }, (_, idx) => idx + 1);
  }
  const pages: Array<number | 'ellipsis'> = [1];
  const start = Math.max(2, current - 1);
  const end = Math.min(total - 1, current + 1);

  if (start > 2) pages.push('ellipsis');
  for (let p = start; p <= end; p++) {
    pages.push(p);
  }
  if (end < total - 1) pages.push('ellipsis');
  pages.push(total);
  return pages;
}

export function DashboardView({
  currentUser,
  settings,
  servers,
  commands,
  certificates,
  onNavigate,
  onRefreshServers,
  onUpdateUser,
  onUpdateSettings,
  onExecutionComplete,
}: DashboardViewProps) {
  const { locale, tr, formatClockTime, formatDateTime } = useI18n();
  const isAdmin = currentUser.role === 'admin';
  const activeCommands = useMemo(() => commands.filter((c) => c.enabled), [commands]);

  const [pingData, setPingData] = useState<DashboardPingResponse | null>(null);
  const [pingingAll, setPingingAll] = useState(false);
  const [pingingServerId, setPingingServerId] = useState<string | null>(null);
  const [togglingServerPingId, setTogglingServerPingId] = useState<string | null>(null);
  const [savingUserPing, setSavingUserPing] = useState(false);
  const [savingAdminPing, setSavingAdminPing] = useState(false);
  const [intervalInput, setIntervalInput] = useState<string>(String(settings.pingIntervalSec || 60));
  const [intervalSavedNotice, setIntervalSavedNotice] = useState(false);
  const [secondsToNext, setSecondsToNext] = useState<number>(settings.pingIntervalSec || 60);

  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [quickCommandId, setQuickCommandId] = useState<string>('');
  const [selectedCertId, setSelectedCertId] = useState<string>('');

  const [statusFilter, setStatusFilter] = useState<'all' | 'online' | 'offline'>('all');
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [includeUncategorized, setIncludeUncategorized] = useState(false);
  const [categoryMatchMode, setCategoryMatchMode] = useState<'any' | 'all'>('any');
  const [search, setSearch] = useState('');
  const [pageSize, setPageSize] = useState<PageSizeOption>(loadSavedPageSize);
  const [currentPage, setCurrentPage] = useState<number>(1);

  const [runningBatch, setRunningBatch] = useState(false);
  const [batchResults, setBatchResults] = useState<ExecutionLog[]>([]);
  const [expandedInvocations, setExpandedInvocations] = useState<Record<string, boolean>>({});
  const [selectedBmcSlots, setSelectedBmcSlots] = useState<Record<string, 1 | 2>>({});
  const [checkingBmcKey, setCheckingBmcKey] = useState<string | null>(null);
  const [bmcResults, setBmcResults] = useState<Record<string, BmcCheckResult>>({});
  const [error, setError] = useState<string | null>(null);

  const globalPingAllowed = pingData?.globalPingAllowed ?? settings.pingAllowed ?? true;
  const userPingEnabled = pingData?.userPingEnabled ?? currentUser.pingEnabled ?? true;
  const intervalSec = pingData?.intervalSec ?? settings.pingIntervalSec ?? 60;
  const effectivePingActive = globalPingAllowed && userPingEnabled;

  useEffect(() => {
    setIntervalInput(String(intervalSec));
  }, [intervalSec]);

  const fetchPingStatus = useCallback(async () => {
    try {
      const data = await api.getDashboardStatus();
      setPingData(data);
    } catch {
      // keep existing state on transient poll error
    }
  }, []);

  // Poll backend status every 15s (server runs actual ping cycle based on configured interval)
  useEffect(() => {
    void fetchPingStatus();
    const poll = setInterval(() => {
      void fetchPingStatus();
    }, 15_000);
    return () => clearInterval(poll);
  }, [fetchPingStatus, servers.length]);

  // Live 1-second countdown synced to backend nextCycleAt
  useEffect(() => {
    if (!effectivePingActive || !pingData?.nextCycleAt) {
      return;
    }
    const updateCountdown = () => {
      const diff = Math.max(0, Math.ceil((Date.parse(pingData.nextCycleAt!) - Date.now()) / 1000));
      setSecondsToNext(diff);
      if (diff === 0) {
        void fetchPingStatus();
      }
    };
    updateCountdown();
    const tick = setInterval(updateCountdown, 1000);
    return () => clearInterval(tick);
  }, [effectivePingActive, pingData?.nextCycleAt, fetchPingStatus]);

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
    let autoPingOff = 0;
    for (const srv of servers) {
      if (!effectivePingActive || srv.pingEnabled === false) {
        autoPingOff++;
      }
      const st = statuses[srv.id];
      if (!st) pending++;
      else if (st.online) online++;
      else offline++;
    }
    return { total: servers.length, online, offline, pending, disabled: autoPingOff };
  }, [servers, statuses, effectivePingActive]);

  const { availableCategories, uncategorizedCount } = useMemo(() => {
    const map = new Map<string, { name: string; count: number }>();
    let withoutCat = 0;
    for (const srv of servers) {
      const cats = srv.categories ?? [];
      if (cats.length === 0) {
        withoutCat++;
        continue;
      }
      const seenForSrv = new Set<string>();
      for (const cat of cats) {
        const key = cat.toLowerCase();
        if (seenForSrv.has(key)) continue;
        seenForSrv.add(key);
        const existing = map.get(key);
        if (existing) {
          existing.count += 1;
        } else {
          map.set(key, { name: cat, count: 1 });
        }
      }
    }
    const list = Array.from(map.values()).sort((a, b) => a.name.localeCompare(b.name, locale));
    return { availableCategories: list, uncategorizedCount: withoutCat };
  }, [servers, locale]);

  // Remove selected categories that no longer exist on any visible server
  useEffect(() => {
    const valid = new Set(availableCategories.map((c) => c.name.toLowerCase()));
    setSelectedCategories((prev) => {
      const next = prev.filter((c) => valid.has(c.toLowerCase()));
      return next.length === prev.length ? prev : next;
    });
    if (uncategorizedCount === 0 && includeUncategorized) {
      setIncludeUncategorized(false);
    }
  }, [availableCategories, uncategorizedCount, includeUncategorized]);

  function toggleCategoryFilter(categoryName: string) {
    const lower = categoryName.toLowerCase();
    setSelectedCategories((prev) =>
      prev.some((c) => c.toLowerCase() === lower)
        ? prev.filter((c) => c.toLowerCase() !== lower)
        : [...prev, categoryName]
    );
  }

  function clearCategoryFilters() {
    setSelectedCategories([]);
    setIncludeUncategorized(false);
  }

  const hasCategoryFilter = selectedCategories.length > 0 || includeUncategorized;

  const filteredServers = useMemo(() => {
    const q = search.trim().toLowerCase();
    const selectedLower = selectedCategories.map((c) => c.toLowerCase());
    return servers.filter((srv) => {
      const st = statuses[srv.id];
      if (statusFilter === 'online' && !st?.online) return false;
      if (statusFilter === 'offline' && (!st || st.online)) return false;

      const cats = srv.categories ?? [];
      if (selectedLower.length > 0 || includeUncategorized) {
        const catsLower = cats.map((c) => c.toLowerCase());
        const matchesUncat = includeUncategorized && catsLower.length === 0;
        let matchesCats = false;
        if (selectedLower.length > 0) {
          matchesCats =
            categoryMatchMode === 'all'
              ? selectedLower.every((sel) => catsLower.includes(sel))
              : selectedLower.some((sel) => catsLower.includes(sel));
        }
        if (!matchesUncat && !matchesCats) return false;
      }

      if (!q) return true;
      return (
        srv.label.toLowerCase().includes(q) ||
        srv.ipAddress.toLowerCase().includes(q) ||
        (srv.bmcIpAddress || '').toLowerCase().includes(q) ||
        (srv.bmcIpAddress2 || '').toLowerCase().includes(q) ||
        srv.sshUser.toLowerCase().includes(q) ||
        srv.notes.toLowerCase().includes(q) ||
        cats.some((c) => c.toLowerCase().includes(q))
      );
    });
  }, [
    servers,
    statuses,
    statusFilter,
    selectedCategories,
    includeUncategorized,
    categoryMatchMode,
    search,
  ]);

  const totalPages =
    pageSize === 'all' ? 1 : Math.max(1, Math.ceil(filteredServers.length / pageSize));
  const safePage = Math.min(currentPage, totalPages);

  useEffect(() => {
    setCurrentPage(1);
  }, [statusFilter, selectedCategories, includeUncategorized, categoryMatchMode, search, pageSize]);

  useEffect(() => {
    if (currentPage > totalPages) {
      setCurrentPage(totalPages);
    }
  }, [currentPage, totalPages]);

  function handleChangePageSize(nextSize: PageSizeOption) {
    setPageSize(nextSize);
    setCurrentPage(1);
    try {
      window.localStorage.setItem(PAGE_SIZE_STORAGE_KEY, String(nextSize));
    } catch {
      // ignore storage errors
    }
  }

  const paginatedServers = useMemo(() => {
    if (pageSize === 'all') return filteredServers;
    const start = (safePage - 1) * pageSize;
    return filteredServers.slice(start, start + pageSize);
  }, [filteredServers, pageSize, safePage]);

  const pageRangeStart =
    filteredServers.length === 0
      ? 0
      : pageSize === 'all'
      ? 1
      : (safePage - 1) * pageSize + 1;
  const pageRangeEnd =
    filteredServers.length === 0
      ? 0
      : pageSize === 'all'
      ? filteredServers.length
      : Math.min(filteredServers.length, safePage * pageSize);

  async function handleManualPingAll() {
    setError(null);
    setPingingAll(true);
    try {
      const res = await api.triggerPing();
      setPingData(res);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : tr('Ping-Prüfung fehlgeschlagen.', 'Ping check failed.')
      );
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
      setError(
        err instanceof Error ? err.message : tr('Einzel-Ping fehlgeschlagen.', 'Single ping failed.')
      );
    } finally {
      setPingingServerId(null);
    }
  }

  async function handleToggleUserPing() {
    if (!globalPingAllowed) return;
    setError(null);
    setSavingUserPing(true);
    try {
      const res = await api.updateUserPingSettings(!userPingEnabled);
      onUpdateUser(res.user);
      setPingData(res.dashboardStatus);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Ping-Einstellung konnte nicht gespeichert werden.', 'Could not save ping setting.')
      );
    } finally {
      setSavingUserPing(false);
    }
  }

  async function handleToggleGlobalPing() {
    setError(null);
    setSavingAdminPing(true);
    try {
      const res = await api.updateAdminPingSettings({ pingAllowed: !globalPingAllowed });
      onUpdateSettings(res.settings);
      setPingData(res.dashboardStatus);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr(
              'Globale Ping-Einstellung konnte nicht geändert werden.',
              'Could not update global ping setting.'
            )
      );
    } finally {
      setSavingAdminPing(false);
    }
  }

  async function handleSaveInterval(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const parsed = Math.round(Number(intervalInput));
    if (!Number.isFinite(parsed) || parsed < 10 || parsed > 3600) {
      setError(
        tr(
          'Das Ping-Intervall muss zwischen 10 und 3600 Sekunden liegen.',
          'Ping interval must be between 10 and 3600 seconds.'
        )
      );
      return;
    }
    setSavingAdminPing(true);
    try {
      const res = await api.updateAdminPingSettings({ pingIntervalSec: parsed });
      onUpdateSettings(res.settings);
      setPingData(res.dashboardStatus);
      setIntervalSavedNotice(true);
      setTimeout(() => setIntervalSavedNotice(false), 2500);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Ping-Intervall konnte nicht gespeichert werden.', 'Could not save ping interval.')
      );
    } finally {
      setSavingAdminPing(false);
    }
  }

  async function handleToggleServerPing(srv: UserServer) {
    setError(null);
    setTogglingServerPingId(srv.id);
    try {
      await api.updateServer(srv.id, { pingEnabled: srv.pingEnabled === false });
      await onRefreshServers();
      await fetchPingStatus();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('IP-Ping-Status konnte nicht geändert werden.', 'Could not update IP ping setting.')
      );
    } finally {
      setTogglingServerPingId(null);
    }
  }

  async function handleCheckBmc(serverId: string, slot: 1 | 2) {
    const key = `${serverId}:${slot}`;
    setError(null);
    setCheckingBmcKey(key);
    try {
      const { result } = await api.checkServerBmc(serverId, slot);
      setBmcResults((prev) => ({ ...prev, [key]: result }));
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('BMC HTTPS-Prüfung fehlgeschlagen.', 'BMC HTTPS check failed.')
      );
    } finally {
      setCheckingBmcKey(null);
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
    const ids = filteredServers
      .filter((s) => Boolean(statuses[s.id]?.online))
      .map((s) => s.id);
    setSelectedIds(ids);
  }

  function clearSelection() {
    setSelectedIds([]);
  }

  // Resolve final jobs: every checked server executes the selected command from the top bar
  const preparedJobs = useMemo(() => {
    if (!quickCommandId) return [];
    return selectedIds.map((serverId) => ({ serverId, commandId: quickCommandId }));
  }, [selectedIds, quickCommandId]);

  async function handleDispatchBatch() {
    setError(null);
    if (!selectedCertId) {
      setError(
        tr(
          'Bitte laden Sie zuerst ein SSH-Schlüssel- oder Zertifikatspaket hoch und wählen Sie es aus.',
          'Please upload and select an SSH key or certificate bundle first.'
        )
      );
      return;
    }
    if (preparedJobs.length === 0) {
      setError(
        tr(
          'Bitte markieren Sie mindestens eine IP-Adresse und wählen Sie einen SSH-Befehl aus.',
          'Please select at least one IP address and an SSH command.'
        )
      );
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
      setError(
        err instanceof Error
          ? err.message
          : tr('Sammelausführung fehlgeschlagen.', 'Batch execution failed.')
      );
    } finally {
      setRunningBatch(false);
    }
  }

  const allPageSelected =
    paginatedServers.length > 0 && paginatedServers.every((s) => selectedIds.includes(s.id));

  function toggleCurrentPageSelection(checked: boolean) {
    const pageIds = paginatedServers.map((s) => s.id);
    if (checked) {
      setSelectedIds((prev) => Array.from(new Set([...prev, ...pageIds])));
    } else {
      const pageIdSet = new Set(pageIds);
      setSelectedIds((prev) => prev.filter((id) => !pageIdSet.has(id)));
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
            {tr('Server-Dashboard', 'Server Dashboard')}
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            {!globalPingAllowed
              ? tr(
                  'Der regelmäßige Auto-Ping ist durch den Administrator global deaktiviert. Manuelles Prüfen einzelner oder aller IPs sowie die Sammelausführung bleiben jederzeit möglich.',
                  'Periodic auto-ping is globally disabled by the administrator. Manual checks for individual or all IPs and batch execution remain available at any time.'
                )
              : !userPingEnabled
              ? tr(
                  'Der regelmäßige Auto-Ping ist für Ihr Konto deaktiviert. Manuelles Prüfen und die Sammelausführung bleiben jederzeit möglich.',
                  'Periodic auto-ping is disabled for your account. Manual checks and batch execution remain available at any time.'
                )
              : tr(
                  `Erreichbarkeit aller aktiven Ziel-IPs im ${intervalSec}-Sekunden-Auto-Ping-Takt, manuelle Sofortprüfung sowie Sammelausführung.`,
                  `Reachability of active target IPs on a ${intervalSec}-second auto-ping cycle, manual on-demand checks, and parallel batch execution.`
                )}
          </p>
        </div>

        <button
          type="button"
          onClick={handleManualPingAll}
          disabled={pingingAll || servers.length === 0}
          title={tr(
            'Alle sichtbaren Ziel-IPs jetzt manuell anpingen (auch bei deaktiviertem Auto-Ping)',
            'Manually ping all target IPs now (works even when auto-ping is disabled)'
          )}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${pingingAll ? 'animate-spin' : ''}`} />
          {pingingAll
            ? tr('Prüfe alle IPs...', 'Checking all IPs...')
            : tr('Alle IPs jetzt pingen', 'Ping All IPs Now')}
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
          <p className="text-xs text-slate-500">{tr('Server-IPs gesamt', 'Total Server IPs')}</p>
          <p className="mt-1 font-display text-2xl font-bold text-slate-900 tabular-nums">
            {counts.total}
          </p>
          {counts.disabled > 0 && (
            <p className="text-xs text-slate-500 mt-0.5 tabular-nums">
              {tr(`${counts.disabled} ohne Auto-Ping`, `${counts.disabled} auto-ping off`)}
            </p>
          )}
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
          <p className="text-xs text-slate-500">
            {tr(`Auto-Ping (${intervalSec}s-Takt)`, `Auto-Ping (${intervalSec}s cycle)`)}
          </p>
          {!globalPingAllowed ? (
            <>
              <p className="mt-1 font-mono text-sm font-semibold text-amber-800">
                {tr('Global aus (Admin)', 'Globally off (Admin)')}
              </p>
              <p className="text-xs text-slate-500 mt-0.5">
                {tr('Manuelles Prüfen weiterhin möglich', 'Manual checks still available')}
              </p>
            </>
          ) : !userPingEnabled ? (
            <>
              <p className="mt-1 font-mono text-sm font-semibold text-slate-700">
                {tr('Auto-Ping pausiert', 'Auto-ping paused')}
              </p>
              <p className="text-xs text-slate-500 mt-0.5">
                {tr('Manuelles Prüfen weiterhin möglich', 'Manual checks still available')}
              </p>
            </>
          ) : (
            <>
              <p className="mt-1 font-mono text-sm font-semibold text-slate-900 tabular-nums">
                {tr(`Nächster in ${secondsToNext}s`, `Next in ${secondsToNext}s`)}
              </p>
              <p className="text-xs text-slate-500 mt-0.5 tabular-nums">
                {tr('Letzter Lauf', 'Last run')}: {formatClockTime(pingData?.lastCycleAt)}
              </p>
            </>
          )}
        </div>
      </section>

      {/* Ping Controls Bar (User + Admin) */}
      <section className="bg-white border border-slate-200 rounded-lg px-5 py-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="inline-flex items-center gap-2 text-xs font-semibold text-slate-800">
            <SlidersHorizontal className="w-3.5 h-3.5 text-slate-500" />
            <span>{tr('Auto-Ping-Steuerung', 'Auto-Ping Controls')}</span>
          </div>
          <span aria-hidden="true" className="hidden sm:inline text-slate-300">|</span>
          <label
            className={`inline-flex items-center gap-2 text-xs ${
              globalPingAllowed ? 'text-slate-700 cursor-pointer' : 'text-slate-400 cursor-not-allowed'
            }`}
          >
            <input
              type="checkbox"
              checked={userPingEnabled}
              disabled={!globalPingAllowed || savingUserPing}
              onChange={handleToggleUserPing}
              className="rounded border-slate-300 text-blue-700 focus:ring-blue-600 disabled:opacity-50"
            />
            <span>
              {tr(
                'Regelmäßiges Anpingen für mein Konto aktivieren',
                'Enable periodic auto-ping for my account'
              )}
            </span>
          </label>
          {!globalPingAllowed && (
            <span className="text-xs text-amber-800 font-medium">
              ({tr('Auto-Ping vom Admin deaktiviert · Manuell aktiv', 'Auto-ping disabled by admin · Manual active')})
            </span>
          )}
        </div>

        {isAdmin && (
          <div className="flex flex-wrap items-center gap-3 pt-3 lg:pt-0 border-t lg:border-t-0 border-slate-200">
            <button
              type="button"
              onClick={handleToggleGlobalPing}
              disabled={savingAdminPing}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border transition-colors cursor-pointer disabled:opacity-50 whitespace-nowrap ${
                globalPingAllowed
                  ? 'text-red-700 bg-red-50 border-red-200 hover:bg-red-100'
                  : 'text-emerald-800 bg-emerald-50 border-emerald-200 hover:bg-emerald-100'
              }`}
            >
              {globalPingAllowed ? (
                <>
                  <Ban className="w-3.5 h-3.5" />
                  <span>{tr('Auto-Ping global aus', 'Disable auto-ping globally')}</span>
                </>
              ) : (
                <>
                  <Activity className="w-3.5 h-3.5" />
                  <span>{tr('Auto-Ping global an', 'Enable auto-ping globally')}</span>
                </>
              )}
            </button>

            <form onSubmit={handleSaveInterval} className="inline-flex items-center gap-2">
              <label htmlFor="admin-ping-interval" className="text-xs text-slate-600 whitespace-nowrap">
                {tr('Intervall (Sek.):', 'Interval (sec):')}
              </label>
              <input
                id="admin-ping-interval"
                type="number"
                min={10}
                max={3600}
                step={5}
                value={intervalInput}
                onChange={(e) => setIntervalInput(e.target.value)}
                disabled={savingAdminPing}
                className="w-20 px-2.5 py-1 text-xs font-mono tabular-nums border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
              <button
                type="submit"
                disabled={savingAdminPing}
                className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                {tr('Speichern', 'Save')}
              </button>
              {intervalSavedNotice && (
                <span className="text-xs text-emerald-700 font-medium whitespace-nowrap">
                  {tr('Gespeichert', 'Saved')}
                </span>
              )}
            </form>
          </div>
        )}
      </section>

      {/* Quick Command & Multi-IP Dispatch Bar */}
      <section className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-200">
          <div>
            <h2 className="font-display text-sm font-semibold text-slate-900">
              {tr('Schnellauswahl & Sammelausführung', 'Quick Select & Batch Execution')}
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              {tr(
                'Wählen Sie den gewünschten SSH-Befehl und das Zertifikat aus, markieren Sie die Ziel-IPs in der Tabelle und senden Sie den Auftrag gesammelt ab.',
                'Choose the SSH command and certificate, check the target IPs in the table, and dispatch them in one batch.'
              )}
            </p>
          </div>
          <span className="text-xs font-mono text-slate-600 tabular-nums whitespace-nowrap shrink-0">
            {tr(
              `${preparedJobs.length} Auftrag${preparedJobs.length === 1 ? '' : 'e'} bereit`,
              `${preparedJobs.length} job${preparedJobs.length === 1 ? '' : 's'} ready`
            )}
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-end">
          {/* Quick Command Selector */}
          <div className="lg:col-span-5">
            <label htmlFor="dash-quick-cmd" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr('SSH-Befehl / Befehlskette', 'SSH Command / Chain')}
            </label>
            <select
              id="dash-quick-cmd"
              value={quickCommandId}
              onChange={(e) => setQuickCommandId(e.target.value)}
              disabled={activeCommands.length === 0}
              className="w-full px-3 py-2 text-sm bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600"
            >
              {activeCommands.length === 0 ? (
                <option value="">{tr('Keine sichtbaren Befehle vorhanden', 'No visible commands available')}</option>
              ) : (
                activeCommands.map((cmd) => (
                  <option key={cmd.id} value={cmd.id}>
                    [{translateCategory(cmd.category, locale)}] {cmd.name}
                    {cmd.kind === 'chain'
                      ? tr(` (Kette · ${cmd.steps.length})`, ` (Chain · ${cmd.steps.length})`)
                      : ''}
                    {cmd.userId !== currentUser.id ? tr(' · Geteilt', ' · Shared') : ''}
                  </option>
                ))
              )}
            </select>
          </div>

          {/* Certificate Selector */}
          <div className="lg:col-span-4">
            <label htmlFor="dash-cert" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr('SSH-Schlüssel / Zertifikatspaket', 'SSH Key / Certificate Bundle')}
            </label>
            {certificates.length === 0 ? (
              <button
                type="button"
                onClick={() => onNavigate('certificates')}
                className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                <KeyRound className="w-3.5 h-3.5" />
                {tr('Schlüssel / Zertifikat hochladen', 'Upload Key / Certificate')}
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
                        : tr('Schlüsselpaar', 'Keypair')}
                      )
                      {cert.userId !== currentUser.id ? tr(' · Geteilt', ' · Shared') : ''}
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
                ? tr('Wird ausgeführt...', 'Running...')
                : tr(`Gesamtpaket senden (${preparedJobs.length})`, `Dispatch Batch (${preparedJobs.length})`)}
            </button>
          </div>
        </div>
      </section>

      {/* Batch Execution Output Console */}
      {(runningBatch || batchResults.length > 0) && (
        <section className="bg-[#0B1120] text-slate-100 rounded-lg border border-slate-800 overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-950/60">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-slate-400" />
              <span className="text-xs font-medium text-slate-200">
                {tr('Ergebnisse der Sammelausführung', 'Batch Execution Results')}
              </span>
            </div>
            {!runningBatch && (
              <div className="flex items-center gap-3 text-xs font-mono tabular-nums">
                <span className="text-emerald-400">
                  {batchResults.filter((r) => r.exitCode === 0).length} OK
                </span>
                <span className="text-slate-600">·</span>
                <span className="text-red-400">
                  {batchResults.filter((r) => r.exitCode !== 0).length} {tr('Fehler', 'Failed')}
                </span>
                <button
                  type="button"
                  onClick={() => setBatchResults([])}
                  title={tr('Ergebnisse schließen', 'Close results')}
                  aria-label={tr('Ergebnisse schließen', 'Close results')}
                  className="ml-1 p-1 text-slate-400 hover:text-white rounded hover:bg-slate-800 transition-colors cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>

          <div className="p-5 space-y-4 font-mono text-xs leading-relaxed">
            {runningBatch ? (
              <div className="py-8 text-center text-slate-400 flex items-center justify-center gap-2">
                <CheckSquare className="w-4 h-4" />
                <span>
                  {tr(
                    `Führe ${preparedJobs.length} SSH-Aufträge parallel per Schlüssel/Zertifikat aus...`,
                    `Executing ${preparedJobs.length} SSH jobs in parallel...`
                  )}
                </span>
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
                        {tr('OpenSSH-Aufruf anzeigen', 'Show OpenSSH invocation')}
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

                      {(() => {
                        const visibleStderr = filterBenignSshStderr(res.stderr);
                        return visibleStderr ? (
                          <pre className="text-amber-300 whitespace-pre-wrap break-words border-t border-slate-800 pt-2.5">
                            {visibleStderr}
                          </pre>
                        ) : null;
                      })()}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </section>
      )}

      {/* Main IP Table with Online/Offline Ping Status */}
      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <div className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-md">
              {(
                [
                  { id: 'all', label: tr(`Alle (${counts.total})`, `All (${counts.total})`) },
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
                  {tr('Alle markieren', 'Select all')}
                </button>
                <span aria-hidden="true" className="text-slate-300">·</span>
                <button
                  type="button"
                  onClick={selectOnlineOnly}
                  className="hover:text-blue-700 font-medium cursor-pointer whitespace-nowrap"
                >
                  {tr('Nur Online', 'Online only')}
                </button>
                <span aria-hidden="true" className="text-slate-300">·</span>
                <button
                  type="button"
                  onClick={clearSelection}
                  className="hover:text-slate-900 cursor-pointer whitespace-nowrap"
                >
                  {tr('Auswahl leeren', 'Clear selection')}
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
              placeholder={tr('IP, Kategorie oder Servername suchen...', 'Search IP, category, or server...')}
              className="w-full pl-9 pr-3 py-1.5 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
        </div>

        {/* Category Filter Strip */}
        {availableCategories.length > 0 && (
          <div className="px-6 py-3 border-b border-slate-200 bg-slate-50/70 flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 mr-1">
              <Tag className="w-3.5 h-3.5 text-slate-500" />
              {tr('Kategorien:', 'Categories:')}
            </span>

            <button
              type="button"
              onClick={clearCategoryFilters}
              className={`px-2.5 py-1 text-xs font-medium rounded-md border transition-colors cursor-pointer ${
                !hasCategoryFilter
                  ? 'bg-slate-900 text-white border-slate-900'
                  : 'bg-white text-slate-600 border-slate-200 hover:border-slate-300 hover:text-slate-900'
              }`}
            >
              {tr('Alle', 'All')}
            </button>

            {availableCategories.map((cat) => {
              const active = selectedCategories.some(
                (c) => c.toLowerCase() === cat.name.toLowerCase()
              );
              return (
                <button
                  key={cat.name}
                  type="button"
                  onClick={() => toggleCategoryFilter(cat.name)}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md border transition-colors cursor-pointer ${
                    active
                      ? 'bg-blue-50 text-blue-800 border-blue-300'
                      : 'bg-white text-slate-700 border-slate-200 hover:border-slate-300 hover:text-slate-900'
                  }`}
                >
                  <span>{cat.name}</span>
                  <span
                    className={`font-mono text-[11px] tabular-nums ${
                      active ? 'text-blue-700' : 'text-slate-400'
                    }`}
                  >
                    {cat.count}
                  </span>
                </button>
              );
            })}

            {uncategorizedCount > 0 && (
              <button
                type="button"
                onClick={() => setIncludeUncategorized((prev) => !prev)}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md border transition-colors cursor-pointer ${
                  includeUncategorized
                    ? 'bg-blue-50 text-blue-800 border-blue-300'
                    : 'bg-white text-slate-600 border-slate-200 hover:border-slate-300 hover:text-slate-900'
                }`}
              >
                <span>{tr('Ohne Kategorie', 'Uncategorized')}</span>
                <span
                  className={`font-mono text-[11px] tabular-nums ${
                    includeUncategorized ? 'text-blue-700' : 'text-slate-400'
                  }`}
                >
                  {uncategorizedCount}
                </span>
              </button>
            )}

            {selectedCategories.length >= 2 && (
              <div className="inline-flex items-center gap-1 ml-1 pl-2 border-l border-slate-200">
                <button
                  type="button"
                  onClick={() => setCategoryMatchMode('any')}
                  title={tr('Mindestens eine der gewählten Kategorien', 'Match any selected category')}
                  className={`px-2 py-0.5 text-[11px] font-medium rounded transition-colors cursor-pointer ${
                    categoryMatchMode === 'any'
                      ? 'bg-slate-800 text-white'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {tr('ODER', 'ANY')}
                </button>
                <button
                  type="button"
                  onClick={() => setCategoryMatchMode('all')}
                  title={tr('Alle gewählten Kategorien gleichzeitig', 'Match all selected categories')}
                  className={`px-2 py-0.5 text-[11px] font-medium rounded transition-colors cursor-pointer ${
                    categoryMatchMode === 'all'
                      ? 'bg-slate-800 text-white'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {tr('UND', 'ALL')}
                </button>
              </div>
            )}

            {hasCategoryFilter && (
              <button
                type="button"
                onClick={clearCategoryFilters}
                className="inline-flex items-center gap-1 ml-auto text-xs text-slate-500 hover:text-slate-900 cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
                {tr('Filter zurücksetzen', 'Reset filter')}
              </button>
            )}
          </div>
        )}

        {servers.length === 0 ? (
          <div className="px-6 py-14 text-center">
            <Server className="w-7 h-7 text-slate-400 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-slate-900">
              {tr('Noch keine Server-IPs hinterlegt', 'No server IPs added yet')}
            </h3>
            <p className="text-sm text-slate-500 mt-1 max-w-md mx-auto">
              {tr(
                `Fügen Sie Ihre Ziel-IPs unter „Meine Server (IPs)“ hinzu, um den ${intervalSec}-Sekunden-Ping-Status und die Sammelausführung zu nutzen.`,
                `Add your target IPs under "My Servers (IPs)" to enable ${intervalSec}-second ping monitoring and batch execution.`
              )}
            </p>
            <button
              type="button"
              onClick={() => onNavigate('servers')}
              className="mt-4 px-4 py-2 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 rounded-md transition-colors cursor-pointer whitespace-nowrap"
            >
              {tr('Server-IPs anlegen', 'Add Server IPs')}
            </button>
          </div>
        ) : filteredServers.length === 0 ? (
          <div className="px-6 py-10 text-center text-sm text-slate-500">
            {tr('Keine Server entsprechen dem aktuellen Filter.', 'No servers match the current filter.')}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                  <th className="py-2.5 pl-6 pr-2 w-10">
                    <input
                      type="checkbox"
                      checked={allPageSelected}
                      onChange={(e) => toggleCurrentPageSelection(e.target.checked)}
                      aria-label={tr(
                        'Alle Server dieser Seite auswählen',
                        'Select all servers on this page'
                      )}
                      className="rounded border-slate-300 text-blue-700 focus:ring-blue-600 cursor-pointer"
                    />
                  </th>
                  <th className="py-2.5 px-4">{tr('Server · IP-Adresse', 'Server · IP Address')}</th>
                  <th className="py-2.5 px-4">BMC (HTTPS :443)</th>
                  <th className="py-2.5 px-4">{tr('Ping-Status', 'Ping Status')}</th>
                  <th className="py-2.5 pl-4 pr-6 text-right">Ping</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 text-sm">
                {paginatedServers.map((srv) => {
                  const st = statuses[srv.id];
                  const isChecked = selectedIds.includes(srv.id);
                  const isRowPinging = pingingServerId === srv.id || pingingAll;
                  const hasBmc1 = Boolean(srv.bmcIpAddress);
                  const hasBmc2 = Boolean(srv.bmcIpAddress2);
                  const activeBmcSlot: 1 | 2 | null =
                    hasBmc1 && hasBmc2
                      ? selectedBmcSlots[srv.id] ?? 1
                      : hasBmc1
                      ? 1
                      : hasBmc2
                      ? 2
                      : null;
                  const activeBmcIp =
                    activeBmcSlot === 2
                      ? srv.bmcIpAddress2
                      : activeBmcSlot === 1
                      ? srv.bmcIpAddress
                      : '';
                  const bmcKey = activeBmcSlot ? `${srv.id}:${activeBmcSlot}` : '';
                  const bmcRes = bmcKey ? bmcResults[bmcKey] : undefined;
                  const isCheckingBmc = Boolean(bmcKey && checkingBmcKey === bmcKey);
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
                          aria-label={tr(`${srv.label} auswählen`, `Select ${srv.label}`)}
                          className="rounded border-slate-300 text-blue-700 focus:ring-blue-600 cursor-pointer"
                        />
                      </td>
                      <td className="py-3 px-4">
                        <p className="font-medium text-slate-900 whitespace-nowrap">
                          {srv.label}
                          {srv.userId !== currentUser.id && (
                            <span className="ml-2 text-xs font-normal text-blue-800">
                              ·{' '}
                              {tr(
                                `Geteilt von ${srv.ownerUsername || 'admin'}`,
                                `Shared by ${srv.ownerUsername || 'admin'}`
                              )}
                            </span>
                          )}
                        </p>
                        <p className="text-xs font-mono text-slate-500 tabular-nums whitespace-nowrap">
                          {srv.sshUser}@{srv.ipAddress}:{srv.port}
                        </p>
                        {(srv.categories?.length ?? 0) > 0 && (
                          <div className="flex flex-wrap items-center gap-1 mt-1">
                            {(srv.categories ?? []).map((cat) => {
                              const active = selectedCategories.some(
                                (c) => c.toLowerCase() === cat.toLowerCase()
                              );
                              return (
                                <button
                                  key={cat}
                                  type="button"
                                  onClick={() => toggleCategoryFilter(cat)}
                                  title={tr(
                                    `Filter für Kategorie „${cat}“ umschalten`,
                                    `Toggle filter for category "${cat}"`
                                  )}
                                  className={`px-1.5 py-0.5 text-[11px] font-medium rounded border transition-colors cursor-pointer ${
                                    active
                                      ? 'bg-blue-50 text-blue-800 border-blue-300'
                                      : 'bg-slate-50 text-slate-600 border-slate-200 hover:border-slate-300 hover:text-slate-900'
                                  }`}
                                >
                                  {cat}
                                </button>
                              );
                            })}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        {activeBmcSlot && activeBmcIp ? (
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              {hasBmc1 && hasBmc2 ? (
                                <select
                                  value={activeBmcSlot}
                                  onChange={(e) =>
                                    setSelectedBmcSlots((prev) => ({
                                      ...prev,
                                      [srv.id]: Number(e.target.value) === 2 ? 2 : 1,
                                    }))
                                  }
                                  aria-label={tr(
                                    `BMC-IP für ${srv.label} auswählen`,
                                    `Select BMC IP for ${srv.label}`
                                  )}
                                  className="px-2 py-1 text-xs font-mono tabular-nums bg-white border border-slate-300 rounded text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-600"
                                >
                                  <option value={1}>BMC 1 · {srv.bmcIpAddress}</option>
                                  <option value={2}>BMC 2 · {srv.bmcIpAddress2}</option>
                                </select>
                              ) : (
                                <a
                                  href={formatBmcUrl(activeBmcIp)}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  title={tr(
                                    `${formatBmcUrl(activeBmcIp)} in neuem Tab öffnen`,
                                    `Open ${formatBmcUrl(activeBmcIp)} in a new tab`
                                  )}
                                  className="inline-flex items-center gap-1 font-mono text-xs font-medium text-blue-700 hover:text-blue-900 hover:underline tabular-nums"
                                >
                                  {activeBmcSlot === 2 && (
                                    <span className="text-[11px] font-normal text-slate-400">
                                      BMC 2 ·
                                    </span>
                                  )}
                                  <span>{activeBmcIp}</span>
                                  <ExternalLink className="w-3 h-3 shrink-0" />
                                </a>
                              )}

                              {hasBmc1 && hasBmc2 && (
                                <a
                                  href={formatBmcUrl(activeBmcIp)}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  title={tr(
                                    `BMC ${activeBmcSlot} (${formatBmcUrl(activeBmcIp)}) in neuem Tab öffnen`,
                                    `Open BMC ${activeBmcSlot} (${formatBmcUrl(activeBmcIp)}) in a new tab`
                                  )}
                                  className="inline-flex items-center justify-center p-1 text-blue-700 hover:text-blue-900 hover:bg-blue-50 rounded transition-colors"
                                >
                                  <ExternalLink className="w-3.5 h-3.5 shrink-0" />
                                </a>
                              )}

                              <button
                                type="button"
                                onClick={() => handleCheckBmc(srv.id, activeBmcSlot)}
                                disabled={isCheckingBmc}
                                title={tr(
                                  `BMC ${activeBmcSlot} (${activeBmcIp}) über https:// Port 443 prüfen`,
                                  `Check BMC ${activeBmcSlot} (${activeBmcIp}) over https:// port 443`
                                )}
                                className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 disabled:opacity-50 rounded transition-colors cursor-pointer"
                              >
                                {isCheckingBmc ? (
                                  <RefreshCw className="w-3 h-3 animate-spin" />
                                ) : (
                                  <ShieldCheck className="w-3 h-3" />
                                )}
                                <span>
                                  {isCheckingBmc
                                    ? tr('Prüft...', 'Checking...')
                                    : tr('443 prüfen', 'Check 443')}
                                </span>
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
                                      {hasBmc1 && hasBmc2 ? `BMC ${activeBmcSlot} · ` : ''}
                                      HTTPS OK
                                      {bmcRes.httpStatus ? ` · ${bmcRes.httpStatus}` : ''}
                                      {bmcRes.latencyMs !== null ? ` · ${bmcRes.latencyMs} ms` : ''}
                                    </span>
                                  </>
                                ) : (
                                  <>
                                    <XCircle className="w-3 h-3 shrink-0" />
                                    <span>
                                      {hasBmc1 && hasBmc2 ? `BMC ${activeBmcSlot} · ` : ''}
                                      {bmcRes.error || tr('Nicht erreichbar', 'Unreachable')}
                                    </span>
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
                        {(() => {
                          const autoPingOffLabel = !globalPingAllowed
                            ? tr('Auto-Ping global aus', 'Auto-ping globally off')
                            : !userPingEnabled
                            ? tr('Auto-Ping aus (Konto)', 'Auto-ping off (account)')
                            : srv.pingEnabled === false
                            ? tr('Auto-Ping aus (IP)', 'Auto-ping off (IP)')
                            : null;
                          const lastOnlineAt = st?.lastOnlineAt ?? srv.lastOnlineAt ?? null;

                          return (
                            <div className="space-y-0.5">
                              {st ? (
                                <div className="flex flex-wrap items-center gap-1.5">
                                  {st.online ? (
                                    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-700 tabular-nums">
                                      <CheckCircle2 className="w-3.5 h-3.5" />
                                      Online{st.latencyMs !== null ? ` · ${st.latencyMs} ms` : ''}
                                    </span>
                                  ) : (
                                    <span
                                      className="inline-flex items-center gap-1.5 text-xs font-medium text-red-700"
                                      title={st.error || tr('Nicht erreichbar', 'Unreachable')}
                                    >
                                      <XCircle className="w-3.5 h-3.5" />
                                      Offline
                                    </span>
                                  )}
                                  {autoPingOffLabel && (
                                    <span
                                      title={autoPingOffLabel}
                                      className="px-1.5 py-0.5 text-[10px] font-medium rounded border border-slate-200 bg-slate-50 text-slate-500"
                                    >
                                      {tr('Auto aus', 'Auto off')}
                                    </span>
                                  )}
                                </div>
                              ) : autoPingOffLabel ? (
                                <span
                                  className={`inline-flex items-center gap-1.5 text-xs ${
                                    !globalPingAllowed ? 'text-amber-800' : 'text-slate-500'
                                  }`}
                                >
                                  <Ban className="w-3.5 h-3.5" />
                                  {autoPingOffLabel}
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1.5 text-xs text-slate-500">
                                  <Clock className="w-3.5 h-3.5" />
                                  {tr('Ausstehend', 'Pending')}
                                </span>
                              )}

                              {st && (
                                <p className="text-[11px] font-mono text-slate-500 tabular-nums">
                                  {tr('Geprüft:', 'Checked:')} {formatClockTime(st.checkedAt)}
                                </p>
                              )}

                              {lastOnlineAt ? (
                                <p
                                  className="text-[11px] font-mono text-emerald-700/90 tabular-nums"
                                  title={tr(
                                    'Zeitpunkt des letzten erfolgreichen Pings',
                                    'Timestamp of the last successful ping'
                                  )}
                                >
                                  {tr('Letzter OK:', 'Last OK:')}{' '}
                                  {formatDateTime(lastOnlineAt, { seconds: true })}
                                </p>
                              ) : (
                                st &&
                                !st.online && (
                                  <p className="text-[11px] font-mono text-slate-400 tabular-nums">
                                    {tr('Letzter OK: —', 'Last OK: —')}
                                  </p>
                                )
                              )}
                            </div>
                          );
                        })()}
                      </td>
                      <td className="py-3 pl-4 pr-6 text-right whitespace-nowrap">
                        <div className="inline-flex items-center gap-3">
                          {srv.userId === currentUser.id && (
                            <button
                              type="button"
                              onClick={() => handleToggleServerPing(srv)}
                              disabled={togglingServerPingId === srv.id}
                              title={
                                srv.pingEnabled !== false
                                  ? tr(
                                      'Regelmäßigen Auto-Ping für diese IP deaktivieren (manuelles Prüfen bleibt möglich)',
                                      'Disable periodic auto-ping for this IP (manual check still works)'
                                    )
                                  : tr(
                                      'Regelmäßigen Auto-Ping für diese IP aktivieren',
                                      'Enable periodic auto-ping for this IP'
                                    )
                              }
                              className={`inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium rounded transition-colors cursor-pointer disabled:opacity-40 ${
                                srv.pingEnabled !== false
                                  ? 'text-slate-600 bg-slate-100 hover:bg-slate-200'
                                  : 'text-emerald-800 bg-emerald-50 hover:bg-emerald-100'
                              }`}
                            >
                              {srv.pingEnabled !== false ? (
                                <>
                                  <Ban className="w-3 h-3" />
                                  <span>{tr('Auto aus', 'Auto off')}</span>
                                </>
                              ) : (
                                <>
                                  <Activity className="w-3 h-3" />
                                  <span>{tr('Auto an', 'Auto on')}</span>
                                </>
                              )}
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => handleManualPingOne(srv.id)}
                            disabled={isRowPinging}
                            title={tr(
                              'Diese IP jetzt manuell prüfen (funktioniert auch bei deaktiviertem Auto-Ping)',
                              'Check this IP manually now (works even when auto-ping is disabled)'
                            )}
                            className="inline-flex items-center gap-1 text-xs font-medium text-slate-600 hover:text-blue-700 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
                          >
                            <RefreshCw className={`w-3.5 h-3.5 ${isRowPinging ? 'animate-spin' : ''}`} />
                            {tr('Prüfen', 'Check')}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination & Page Size Footer */}
        {filteredServers.length > 0 && (
          <div className="px-6 py-3 border-t border-slate-200 bg-slate-50/70 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-4 text-xs text-slate-600">
              <span className="tabular-nums">
                {pageSize === 'all'
                  ? tr(
                      `Alle ${filteredServers.length} Einträge`,
                      `All ${filteredServers.length} entries`
                    )
                  : tr(
                      `Zeige ${pageRangeStart}–${pageRangeEnd} von ${filteredServers.length}`,
                      `Showing ${pageRangeStart}–${pageRangeEnd} of ${filteredServers.length}`
                    )}
              </span>

              <div className="inline-flex items-center gap-2">
                <span className="text-slate-500 whitespace-nowrap">
                  {tr('Pro Seite:', 'Per page:')}
                </span>
                <div
                  role="group"
                  aria-label={tr('Einträge pro Seite', 'Items per page')}
                  className="inline-flex items-center gap-0.5 p-0.5 bg-slate-200/70 rounded-md"
                >
                  {PAGE_SIZE_OPTIONS.map((opt) => {
                    const active = pageSize === opt;
                    return (
                      <button
                        key={String(opt)}
                        type="button"
                        onClick={() => handleChangePageSize(opt)}
                        className={`px-2.5 py-1 text-xs font-medium rounded transition-colors cursor-pointer tabular-nums ${
                          active
                            ? 'bg-white text-slate-900 shadow-xs'
                            : 'text-slate-600 hover:text-slate-900'
                        }`}
                      >
                        {opt === 'all' ? tr('Alle', 'All') : opt}
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>

            {pageSize !== 'all' && (
              <div className="flex items-center justify-between sm:justify-end gap-1.5">
                <span className="text-xs text-slate-500 mr-1.5 tabular-nums sm:hidden">
                  {tr(`Seite ${safePage} / ${totalPages}`, `Page ${safePage} / ${totalPages}`)}
                </span>

                <div className="inline-flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    disabled={safePage <= 1}
                    aria-label={tr('Vorherige Seite', 'Previous page')}
                    className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed rounded-md transition-colors cursor-pointer"
                  >
                    <ChevronLeft className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">{tr('Zurück', 'Prev')}</span>
                  </button>

                  <div className="hidden sm:inline-flex items-center gap-1">
                    {buildPageNumbers(safePage, totalPages).map((item, idx) =>
                      item === 'ellipsis' ? (
                        <span
                          key={`ellipsis-${idx}`}
                          className="px-1.5 text-xs text-slate-400 select-none"
                        >
                          …
                        </span>
                      ) : (
                        <button
                          key={item}
                          type="button"
                          onClick={() => setCurrentPage(item)}
                          aria-current={item === safePage ? 'page' : undefined}
                          className={`min-w-7 px-2 py-1 text-xs font-medium rounded-md border transition-colors cursor-pointer tabular-nums ${
                            item === safePage
                              ? 'bg-blue-700 text-white border-blue-700'
                              : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-50'
                          }`}
                        >
                          {item}
                        </button>
                      )
                    )}
                  </div>

                  <button
                    type="button"
                    onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                    disabled={safePage >= totalPages}
                    aria-label={tr('Nächste Seite', 'Next page')}
                    className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed rounded-md transition-colors cursor-pointer"
                  >
                    <span className="hidden sm:inline">{tr('Weiter', 'Next')}</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
