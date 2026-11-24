import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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
  Lock,
  Braces,
  Eye,
  EyeOff,
  Plus,
  Trash2,
  Loader2,
  Bell,
} from 'lucide-react';
import { api } from '../api';
import { translateCategory, useI18n } from '../i18n';
import {
  parseAndValidateWorkflow,
  resolveWorkflowRuntimeVars,
  type WorkflowInputDef,
} from '../workflowEngine';
import type {
  ActiveTab,
  AppSettings,
  BackgroundJob,
  BmcCheckResult,
  DashboardPingResponse,
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
  bgJobs: BackgroundJob[];
  bgActiveCount: number;
  bgMaxJobs: number;
  onBackgroundJobStarted: (job: BackgroundJob, activeCount: number, maxBackgroundJobs: number) => void;
  onOpenBackgroundJob: (job: BackgroundJob) => void;
}

function formatBmcUrl(ipAddress: string): string {
  const clean = ipAddress.trim();
  const host = clean.includes(':') ? `[${clean}]` : clean;
  return `https://${host}`;
}

function formatPacingInterval(ms: number, locale: string): string {
  if (ms >= 1000) {
    const sec = ms / 1000;
    const formatted = sec.toLocaleString(locale === 'de' ? 'de-DE' : 'en-US', {
      minimumFractionDigits: sec >= 10 ? 0 : 1,
      maximumFractionDigits: 1,
    });
    return `${formatted} s`;
  }
  return `${ms} ms`;
}

function formatIntervalShort(sec: number): string {
  if (sec >= 3600 && sec % 3600 === 0) {
    return `${sec / 3600} h`;
  }
  if (sec >= 120 && sec % 60 === 0) {
    return `${sec / 60} min`;
  }
  return `${sec} s`;
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
  bgJobs,
  bgActiveCount,
  bgMaxJobs,
  onBackgroundJobStarted,
  onOpenBackgroundJob,
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
  const [offlineThresholdInput, setOfflineThresholdInput] = useState<string>(
    String(settings.pingOfflineThreshold ?? 5)
  );
  const [offlineMultiplierInput, setOfflineMultiplierInput] = useState<string>(
    String(settings.pingOfflineMultiplier ?? 5)
  );
  const [intervalSavedNotice, setIntervalSavedNotice] = useState(false);
  const [secondsToNext, setSecondsToNext] = useState<number>(settings.pingIntervalSec || 60);

  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [quickCommandId, setQuickCommandId] = useState<string>('');
  const [selectedCertId, setSelectedCertId] = useState<string>('');
  const [keyPassphrase, setKeyPassphrase] = useState<string>('');
  const [workflowVarValues, setWorkflowVarValues] = useState<Record<string, string>>({});
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, boolean>>({});
  const [customRuntimeVars, setCustomRuntimeVars] = useState<Array<{ key: string; value: string }>>([]);

  const [statusFilter, setStatusFilter] = useState<'all' | 'online' | 'offline'>('all');
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [includeUncategorized, setIncludeUncategorized] = useState(false);
  const [categoryMatchMode, setCategoryMatchMode] = useState<'any' | 'all'>('any');
  const [search, setSearch] = useState('');
  const [pageSize, setPageSize] = useState<PageSizeOption>(loadSavedPageSize);
  const [currentPage, setCurrentPage] = useState<number>(1);

  const [submittingBatch, setSubmittingBatch] = useState(false);
  const [recentDispatchedNotice, setRecentDispatchedNotice] = useState<{
    jobId: string;
    title: string;
    count: number;
  } | null>(null);
  const [selectedBmcSlots, setSelectedBmcSlots] = useState<Record<string, 1 | 2>>({});
  const [checkingBmcKey, setCheckingBmcKey] = useState<string | null>(null);
  const [bmcResults, setBmcResults] = useState<Record<string, BmcCheckResult>>({});
  const [error, setError] = useState<string | null>(null);

  const globalPingAllowed = pingData?.globalPingAllowed ?? settings.pingAllowed ?? true;
  const userPingEnabled = pingData?.userPingEnabled ?? currentUser.pingEnabled ?? true;
  const intervalSec = pingData?.intervalSec ?? settings.pingIntervalSec ?? 60;
  const offlineThreshold = pingData?.offlineThreshold ?? settings.pingOfflineThreshold ?? 5;
  const offlineMultiplier = pingData?.offlineMultiplier ?? settings.pingOfflineMultiplier ?? 5;
  const backoffCount = pingData?.backoffCount ?? 0;
  const effectivePingActive = globalPingAllowed && userPingEnabled;

  useEffect(() => {
    setIntervalInput(String(intervalSec));
  }, [intervalSec]);

  useEffect(() => {
    setOfflineThresholdInput(String(offlineThreshold));
  }, [offlineThreshold]);

  useEffect(() => {
    setOfflineMultiplierInput(String(offlineMultiplier));
  }, [offlineMultiplier]);

  const pollInFlightRef = useRef(false);
  const refreshedCycleRef = useRef<string | null>(null);
  const savedNoticeTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (savedNoticeTimerRef.current !== null) {
        window.clearTimeout(savedNoticeTimerRef.current);
      }
    };
  }, []);

  const fetchPingStatus = useCallback(async () => {
    if (pollInFlightRef.current) return;
    pollInFlightRef.current = true;
    try {
      const data = await api.getDashboardStatus();
      setPingData(data);
    } catch {
      // keep existing state on transient poll error
    } finally {
      pollInFlightRef.current = false;
    }
  }, []);

  // Poll backend status every 15s while tab is visible (server runs actual ping cycle based on configured interval)
  useEffect(() => {
    void fetchPingStatus();
    const poll = window.setInterval(() => {
      if (typeof document === 'undefined' || !document.hidden) {
        void fetchPingStatus();
      }
    }, 15_000);
    const onVisibilityChange = () => {
      if (typeof document !== 'undefined' && !document.hidden) {
        void fetchPingStatus();
      }
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => {
      window.clearInterval(poll);
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [fetchPingStatus, servers.length]);

  // Live 1-second countdown synced to backend nextCycleAt (trigger at most one refresh per cycle)
  useEffect(() => {
    if (!effectivePingActive || !pingData?.nextCycleAt) {
      return;
    }
    const targetCycleAt = pingData.nextCycleAt;
    const updateCountdown = () => {
      const diff = Math.max(0, Math.ceil((Date.parse(targetCycleAt) - Date.now()) / 1000));
      setSecondsToNext(diff);
      if (
        diff === 0 &&
        refreshedCycleRef.current !== targetCycleAt &&
        (typeof document === 'undefined' || !document.hidden)
      ) {
        refreshedCycleRef.current = targetCycleAt;
        void fetchPingStatus();
      }
    };
    updateCountdown();
    const tick = window.setInterval(updateCountdown, 1000);
    return () => window.clearInterval(tick);
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

  useEffect(() => {
    setKeyPassphrase('');
  }, [selectedCertId]);

  const selectedCommand = useMemo(
    () => activeCommands.find((c) => c.id === quickCommandId) ?? null,
    [activeCommands, quickCommandId]
  );

  const selectedWorkflow = useMemo(() => {
    if (!selectedCommand || selectedCommand.kind !== 'workflow' || !selectedCommand.workflowJson) {
      return null;
    }
    const parsed = parseAndValidateWorkflow(selectedCommand.workflowJson);
    return parsed.ok ? parsed.workflow : null;
  }, [selectedCommand]);

  const workflowInputs: WorkflowInputDef[] = useMemo(
    () => selectedWorkflow?.inputs ?? [],
    [selectedWorkflow]
  );

  const workflowStaticVarEntries = useMemo(() => {
    if (!selectedWorkflow?.vars) return [] as Array<[string, string]>;
    const declaredNames = new Set(workflowInputs.map((i) => i.name));
    return Object.entries(selectedWorkflow.vars)
      .filter(([k]) => !declaredNames.has(k))
      .map(([k, v]) => [k, String(v)] as [string, string]);
  }, [selectedWorkflow, workflowInputs]);

  useEffect(() => {
    const initial: Record<string, string> = {};
    if (selectedWorkflow?.vars) {
      for (const [k, v] of Object.entries(selectedWorkflow.vars)) {
        initial[k] = String(v);
      }
    }
    for (const inp of selectedWorkflow?.inputs ?? []) {
      if (initial[inp.name] === undefined) {
        if (inp.default !== undefined) {
          initial[inp.name] = String(inp.default);
        } else if (inp.type === 'select' && inp.options && inp.options.length > 0) {
          initial[inp.name] = inp.options[0];
        } else if (inp.type === 'boolean') {
          initial[inp.name] = 'false';
        } else {
          initial[inp.name] = '';
        }
      }
    }
    setWorkflowVarValues(initial);
    setRevealedSecrets({});
    setCustomRuntimeVars([]);
  }, [selectedCommand?.id, selectedCommand?.workflowJson, selectedWorkflow]);

  const selectedCert = useMemo(
    () => certificates.find((c) => c.id === selectedCertId) ?? null,
    [certificates, selectedCertId]
  );
  const needsRuntimePassphrase = Boolean(
    selectedCert?.metadata.privateKeyEncrypted && !selectedCert?.hasStoredPassphrase
  );

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
    const parsedThreshold = Math.round(Number(offlineThresholdInput));
    if (!Number.isFinite(parsedThreshold) || parsedThreshold < 0 || parsedThreshold > 100) {
      setError(
        tr(
          'Der Offline-Schwellwert muss zwischen 0 und 100 liegen (0 = aus).',
          'Offline threshold must be between 0 and 100 (0 = off).'
        )
      );
      return;
    }
    const parsedMultiplier = Math.round(Number(offlineMultiplierInput));
    if (!Number.isFinite(parsedMultiplier) || parsedMultiplier < 2 || parsedMultiplier > 60) {
      setError(
        tr(
          'Der Offline-Faktor muss zwischen 2 und 60 liegen.',
          'Offline multiplier must be between 2 and 60.'
        )
      );
      return;
    }
    setSavingAdminPing(true);
    try {
      const res = await api.updateAdminPingSettings({
        pingIntervalSec: parsed,
        pingOfflineThreshold: parsedThreshold,
        pingOfflineMultiplier: parsedMultiplier,
      });
      onUpdateSettings(res.settings);
      setPingData(res.dashboardStatus);
      setIntervalSavedNotice(true);
      if (savedNoticeTimerRef.current !== null) {
        window.clearTimeout(savedNoticeTimerRef.current);
      }
      savedNoticeTimerRef.current = window.setTimeout(() => {
        setIntervalSavedNotice(false);
        savedNoticeTimerRef.current = null;
      }, 2500);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Ping-Einstellungen konnten nicht gespeichert werden.', 'Could not save ping settings.')
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
    if (needsRuntimePassphrase && !keyPassphrase) {
      setError(
        tr(
          'Dieses Zertifikat ist passwortgeschützt. Bitte geben Sie das Schlüssel-Passwort zum Entsperren ein oder hinterlegen Sie es unter „Zertifikate“.',
          'This certificate is passphrase-protected. Please enter the key passphrase to unlock it, or store it under Certificates.'
        )
      );
      return;
    }

    let workflowVarsToSend: Record<string, string> | undefined;
    if (selectedWorkflow) {
      const combined: Record<string, string> = { ...workflowVarValues };
      for (const row of customRuntimeVars) {
        const k = row.key.trim();
        if (k) {
          combined[k] = row.value;
        }
      }
      const checked = resolveWorkflowRuntimeVars(selectedWorkflow, combined);
      if (!checked.ok) {
        setError(checked.error);
        return;
      }
      workflowVarsToSend = combined;
    }

    const passToUse = needsRuntimePassphrase ? keyPassphrase : undefined;
    setSubmittingBatch(true);
    try {
      const res = await api.executeBatchAsync({
        certificateId: selectedCertId,
        jobs: preparedJobs,
        ...(passToUse ? { passphrase: passToUse } : {}),
        ...(workflowVarsToSend ? { workflowVars: workflowVarsToSend } : {}),
      });
      onBackgroundJobStarted(res.job, res.activeCount, res.maxBackgroundJobs);
      setRecentDispatchedNotice({
        jobId: res.job.id,
        title: res.job.title,
        count: res.job.totalTargets,
      });
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Hintergrundauftrag konnte nicht gestartet werden.', 'Failed to start background job.')
      );
    } finally {
      setKeyPassphrase('');
      if (workflowInputs.some((i) => i.type === 'password' || i.secret)) {
        setWorkflowVarValues((prev) => {
          const next = { ...prev };
          for (const inp of workflowInputs) {
            if (inp.type === 'password' || inp.secret) {
              next[inp.name] = '';
            }
          }
          return next;
        });
        setRevealedSecrets({});
      }
      setSubmittingBatch(false);
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
              {pingData?.pacingMs != null && (pingData.activeTargetCount ?? 0) > 1 && (
                <p className="text-xs text-slate-500 mt-0.5 tabular-nums">
                  {tr(
                    `Verteilt: ~1 IP alle ${formatPacingInterval(pingData.pacingMs, locale)}`,
                    `Paced: ~1 IP every ${formatPacingInterval(pingData.pacingMs, locale)}`
                  )}
                </p>
              )}
              {backoffCount > 0 && offlineThreshold > 0 && (
                <p className="text-xs text-amber-800 mt-0.5 tabular-nums">
                  {tr(
                    `${backoffCount} Offline-IP${backoffCount === 1 ? '' : 's'} im ${formatIntervalShort(
                      Math.min(86400, intervalSec * offlineMultiplier)
                    )}-Takt`,
                    `${backoffCount} offline IP${backoffCount === 1 ? '' : 's'} at ${formatIntervalShort(
                      Math.min(86400, intervalSec * offlineMultiplier)
                    )} backoff`
                  )}
                </p>
              )}
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

            <form onSubmit={handleSaveInterval} className="flex flex-wrap items-center gap-2">
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
                className="w-16 px-2 py-1 text-xs font-mono tabular-nums border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
              <span aria-hidden="true" className="hidden sm:inline text-slate-300">|</span>
              <label
                htmlFor="admin-ping-offline-threshold"
                className="text-xs text-slate-600 whitespace-nowrap"
                title={tr(
                  'Nach dieser Anzahl aufeinanderfolgender Offline-Pings wird das Intervall pro IP verlängert (0 = deaktiviert). Bei Online-Antwort sofort wieder Standard.',
                  'After this many consecutive offline pings, the interval is extended per IP (0 = disabled). Resets immediately when online.'
                )}
              >
                {tr('Ab', 'After')}
              </label>
              <input
                id="admin-ping-offline-threshold"
                type="number"
                min={0}
                max={100}
                step={1}
                value={offlineThresholdInput}
                onChange={(e) => setOfflineThresholdInput(e.target.value)}
                disabled={savingAdminPing}
                title={tr('0 = Offline-Drosselung deaktiviert', '0 = offline backoff disabled')}
                className="w-14 px-2 py-1 text-xs font-mono tabular-nums border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
              <label
                htmlFor="admin-ping-offline-multiplier"
                className="text-xs text-slate-600 whitespace-nowrap"
              >
                {tr('× Offline → ×', '× offline → ×')}
              </label>
              <input
                id="admin-ping-offline-multiplier"
                type="number"
                min={2}
                max={60}
                step={1}
                value={offlineMultiplierInput}
                onChange={(e) => setOfflineMultiplierInput(e.target.value)}
                disabled={savingAdminPing || Number(offlineThresholdInput) === 0}
                title={tr(
                  `Verlängertes Intervall: ${formatIntervalShort(
                    Math.min(
                      86400,
                      Math.max(10, Number(intervalInput) || intervalSec) *
                        Math.max(2, Number(offlineMultiplierInput) || offlineMultiplier)
                    )
                  )}`,
                  `Extended interval: ${formatIntervalShort(
                    Math.min(
                      86400,
                      Math.max(10, Number(intervalInput) || intervalSec) *
                        Math.max(2, Number(offlineMultiplierInput) || offlineMultiplier)
                    )
                  )}`
                )}
                className="w-14 px-2 py-1 text-xs font-mono tabular-nums border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:bg-slate-100 disabled:text-slate-400"
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
                'Aufträge laufen direkt im Hintergrund weiter – Sie können sofort weitere Befehle absenden oder z. B. in die SSH-Shell wechseln. Ergebnisse erscheinen oben rechts an der Glocke.',
                'Jobs run asynchronously in the background—you can queue more commands right away or switch to the SSH Shell. Results appear in the top-right bell.'
              )}
            </p>
          </div>
          <div className="flex items-center gap-2.5 shrink-0">
            <span
              className={`px-2 py-0.5 text-xs font-mono tabular-nums rounded border whitespace-nowrap ${
                bgActiveCount >= bgMaxJobs
                  ? 'bg-amber-50 text-amber-800 border-amber-200 font-semibold'
                  : bgActiveCount > 0
                  ? 'bg-blue-50 text-blue-800 border-blue-200'
                  : 'bg-slate-50 text-slate-600 border-slate-200'
              }`}
              title={tr(
                'Ihre aktiven Hintergrundprozesse im Vergleich zum Admin-Limit pro Benutzer',
                'Your active background jobs versus the admin per-user concurrency limit'
              )}
            >
              {tr('Hintergrund', 'Background')}: {bgActiveCount}/{bgMaxJobs}
            </span>
            <span className="text-xs font-mono text-slate-600 tabular-nums whitespace-nowrap">
              {tr(
                `${preparedJobs.length} Auftrag${preparedJobs.length === 1 ? '' : 'e'} bereit`,
                `${preparedJobs.length} job${preparedJobs.length === 1 ? '' : 's'} ready`
              )}
            </span>
          </div>
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
                    {cmd.kind === 'workflow'
                      ? tr(' (JSON-Workflow)', ' (JSON Workflow)')
                      : cmd.kind === 'chain'
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
                  const lockHint = cert.metadata.privateKeyEncrypted
                    ? cert.hasStoredPassphrase
                      ? tr(' · Passwort hinterlegt', ' · Passphrase stored')
                      : tr(' · Passwort erforderlich', ' · Passphrase required')
                    : '';
                  return (
                    <option key={cert.id} value={cert.id}>
                      {cert.name} (
                      {hasCert
                        ? cert.metadata.keyId || cert.certFileName
                        : tr('Schlüsselpaar', 'Keypair')}
                      )
                      {cert.userId !== currentUser.id ? tr(' · Geteilt', ' · Shared') : ''}
                      {lockHint}
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
              disabled={
                submittingBatch ||
                preparedJobs.length === 0 ||
                !selectedCertId ||
                bgActiveCount >= bgMaxJobs
              }
              title={
                bgActiveCount >= bgMaxJobs
                  ? tr(
                      `Ihr Benutzer-Limit ist erreicht (${bgActiveCount}/${bgMaxJobs} aktive Hintergrundprozesse)`,
                      `Your per-user limit is reached (${bgActiveCount}/${bgMaxJobs} active background jobs)`
                    )
                  : undefined
              }
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
            >
              {submittingBatch ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Play className="w-4 h-4" />
              )}
              {submittingBatch
                ? tr('Wird gestartet...', 'Starting...')
                : bgActiveCount >= bgMaxJobs
                ? tr(`Limit erreicht (${bgActiveCount}/${bgMaxJobs})`, `Limit reached (${bgActiveCount}/${bgMaxJobs})`)
                : tr(`Im Hintergrund starten (${preparedJobs.length})`, `Run in Background (${preparedJobs.length})`)}
            </button>
          </div>
        </div>

        {selectedWorkflow && (
          <div className="pt-3.5 border-t border-slate-100 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Braces className="w-3.5 h-3.5 text-blue-700 shrink-0" />
                <span className="text-xs font-semibold text-slate-800">
                  {tr('Workflow-Variablen (Laufzeit-Parameter)', 'Workflow Variables (Runtime Parameters)')}
                </span>
                <span className="text-[11px] text-slate-500">
                  {tr('Verfügbar als', 'Available as')}{' '}
                  <code className="font-mono text-slate-700">{'{{vars.name}}'}</code>
                </span>
              </div>
              <button
                type="button"
                onClick={() =>
                  setCustomRuntimeVars((prev) => [...prev, { key: '', value: '' }])
                }
                className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                <Plus className="w-3.5 h-3.5" />
                {tr('Variable hinzufügen', 'Add Variable')}
              </button>
            </div>

            {(workflowInputs.length > 0 || workflowStaticVarEntries.length > 0) && (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {workflowInputs.map((inp) => {
                  const fieldId = `wf-var-${inp.name}`;
                  const isSecret = inp.type === 'password' || Boolean(inp.secret);
                  const revealed = Boolean(revealedSecrets[inp.name]);
                  const value = workflowVarValues[inp.name] ?? '';
                  return (
                    <div key={inp.name} className="space-y-1">
                      <label
                        htmlFor={fieldId}
                        className="flex items-center justify-between gap-2 text-xs font-medium text-slate-700"
                      >
                        <span className="inline-flex items-center gap-1 truncate">
                          {isSecret && <Lock className="w-3 h-3 text-amber-700 shrink-0" />}
                          <span>{inp.label || inp.name}</span>
                          {inp.required && <span className="text-red-600">*</span>}
                        </span>
                        <code className="text-[10px] font-mono text-slate-400 shrink-0">
                          {inp.name}
                        </code>
                      </label>

                      {inp.type === 'select' && inp.options ? (
                        <select
                          id={fieldId}
                          value={value}
                          onChange={(e) =>
                            setWorkflowVarValues((prev) => ({ ...prev, [inp.name]: e.target.value }))
                          }
                          className="w-full px-3 py-1.5 text-sm bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600"
                        >
                          {inp.options.map((opt) => (
                            <option key={opt} value={opt}>
                              {opt}
                            </option>
                          ))}
                        </select>
                      ) : inp.type === 'boolean' ? (
                        <label className="inline-flex items-center gap-2 px-3 py-1.5 text-sm bg-slate-50 border border-slate-300 rounded-md cursor-pointer w-full">
                          <input
                            id={fieldId}
                            type="checkbox"
                            checked={value.toLowerCase() === 'true' || value === '1'}
                            onChange={(e) =>
                              setWorkflowVarValues((prev) => ({
                                ...prev,
                                [inp.name]: e.target.checked ? 'true' : 'false',
                              }))
                            }
                            className="rounded border-slate-300 text-blue-700 focus:ring-blue-600"
                          />
                          <span className="text-xs text-slate-700 font-mono">
                            {value.toLowerCase() === 'true' || value === '1' ? 'true' : 'false'}
                          </span>
                        </label>
                      ) : isSecret ? (
                        <div className="relative">
                          <input
                            id={fieldId}
                            type={revealed ? 'text' : 'password'}
                            autoComplete="new-password"
                            value={value}
                            onChange={(e) =>
                              setWorkflowVarValues((prev) => ({ ...prev, [inp.name]: e.target.value }))
                            }
                            placeholder={inp.placeholder || tr('Geheimen Wert eingeben...', 'Enter secret value...')}
                            className="w-full pl-3 pr-9 py-1.5 text-sm bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                          />
                          <button
                            type="button"
                            onClick={() =>
                              setRevealedSecrets((prev) => ({ ...prev, [inp.name]: !prev[inp.name] }))
                            }
                            title={revealed ? tr('Verbergen', 'Hide') : tr('Anzeigen', 'Show')}
                            aria-label={revealed ? tr('Verbergen', 'Hide') : tr('Anzeigen', 'Show')}
                            className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-slate-700 cursor-pointer"
                          >
                            {revealed ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      ) : (
                        <input
                          id={fieldId}
                          type={inp.type === 'number' ? 'number' : 'text'}
                          value={value}
                          onChange={(e) =>
                            setWorkflowVarValues((prev) => ({ ...prev, [inp.name]: e.target.value }))
                          }
                          placeholder={inp.placeholder || ''}
                          className="w-full px-3 py-1.5 text-sm bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                        />
                      )}

                      {inp.description && (
                        <p className="text-[11px] text-slate-500">{inp.description}</p>
                      )}
                    </div>
                  );
                })}

                {workflowStaticVarEntries.map(([varName, defaultVal]) => {
                  const fieldId = `wf-static-var-${varName}`;
                  const value = workflowVarValues[varName] ?? defaultVal;
                  return (
                    <div key={varName} className="space-y-1">
                      <label
                        htmlFor={fieldId}
                        className="flex items-center justify-between gap-2 text-xs font-medium text-slate-700"
                      >
                        <span className="truncate">{varName}</span>
                        <code className="text-[10px] font-mono text-slate-400 shrink-0">vars</code>
                      </label>
                      <input
                        id={fieldId}
                        type="text"
                        value={value}
                        onChange={(e) =>
                          setWorkflowVarValues((prev) => ({ ...prev, [varName]: e.target.value }))
                        }
                        placeholder={defaultVal}
                        className="w-full px-3 py-1.5 text-sm bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                      />
                    </div>
                  );
                })}
              </div>
            )}

            {customRuntimeVars.length > 0 && (
              <div className="space-y-2">
                {customRuntimeVars.map((row, idx) => (
                  <div key={idx} className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                    <input
                      type="text"
                      value={row.key}
                      onChange={(e) =>
                        setCustomRuntimeVars((prev) =>
                          prev.map((item, i) => (i === idx ? { ...item, key: e.target.value } : item))
                        )
                      }
                      placeholder={tr('Variablenname (z. B. service)', 'Variable name (e.g. service)')}
                      className="sm:w-52 px-3 py-1.5 text-xs font-mono bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                    />
                    <input
                      type="text"
                      value={row.value}
                      onChange={(e) =>
                        setCustomRuntimeVars((prev) =>
                          prev.map((item, i) => (i === idx ? { ...item, value: e.target.value } : item))
                        )
                      }
                      placeholder={tr('Wert für diesen Lauf', 'Value for this run')}
                      className="flex-1 px-3 py-1.5 text-xs bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                    />
                    <button
                      type="button"
                      onClick={() =>
                        setCustomRuntimeVars((prev) => prev.filter((_, i) => i !== idx))
                      }
                      title={tr('Variable entfernen', 'Remove variable')}
                      aria-label={tr('Variable entfernen', 'Remove variable')}
                      className="p-1.5 text-red-600 hover:text-red-800 hover:bg-red-50 rounded-md cursor-pointer self-end sm:self-center"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}

            {workflowInputs.some((i) => i.type === 'password' || i.secret) && (
              <p className="text-[11px] text-slate-500">
                {tr(
                  'Passwort-/Geheim-Variablen werden nicht gespeichert, nach dem Ausführen geleert und im Audit-Log automatisch maskiert (********).',
                  'Password/secret variables are never stored, cleared after execution, and automatically masked (********) in the audit log.'
                )}
              </p>
            )}
          </div>
        )}

        {needsRuntimePassphrase && (
          <div className="pt-3 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center gap-3">
            <label
              htmlFor="dash-key-passphrase"
              className="inline-flex items-center gap-1.5 text-xs font-medium text-amber-900 whitespace-nowrap"
            >
              <Lock className="w-3.5 h-3.5 text-amber-700 shrink-0" />
              {tr('Schlüssel-Passwort zum Entsperren:', 'Key passphrase to unlock:')}
            </label>
            <input
              id="dash-key-passphrase"
              type="password"
              autoComplete="off"
              value={keyPassphrase}
              onChange={(e) => setKeyPassphrase(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !submittingBatch && preparedJobs.length > 0 && bgActiveCount < bgMaxJobs) {
                  e.preventDefault();
                  void handleDispatchBatch();
                }
              }}
              placeholder={tr('Passwort für diesen Lauf eingeben...', 'Enter passphrase for this run...')}
              className="w-full sm:max-w-xs px-3 py-1.5 text-sm bg-white border border-amber-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
            <span className="text-[11px] text-slate-500">
              {tr(
                'Wird nicht gespeichert und nach dem Ausführen sofort geleert.',
                'Not stored and cleared immediately after execution.'
              )}
            </span>
          </div>
        )}
      </section>

      {/* Non-blocking Live Background Jobs Activity Strip */}
      {(() => {
        const runningUserJobs = bgJobs.filter((j) => j.status === 'running');
        const noticeJob = recentDispatchedNotice
          ? bgJobs.find((j) => j.id === recentDispatchedNotice.jobId) ?? null
          : null;
        if (runningUserJobs.length === 0 && !noticeJob) return null;

        return (
          <section className="bg-white border border-blue-200 rounded-lg px-5 py-3.5 space-y-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-900">
                {runningUserJobs.length > 0 ? (
                  <Loader2 className="w-4 h-4 text-blue-600 animate-spin shrink-0" />
                ) : (
                  <Bell className="w-4 h-4 text-blue-600 shrink-0" />
                )}
                <span>
                  {runningUserJobs.length > 0
                    ? tr(
                        `${runningUserJobs.length} Hintergrundauftrag${runningUserJobs.length === 1 ? '' : 'e'} aktiv – Sie können das Dashboard verlassen oder weitere Befehle absenden.`,
                        `${runningUserJobs.length} background job${runningUserJobs.length === 1 ? '' : 's'} running — you can leave the Dashboard or queue more commands.`
                      )
                    : tr(
                        `Auftrag „${noticeJob?.title ?? ''}“ abgeschlossen.`,
                        `Job "${noticeJob?.title ?? ''}" finished.`
                      )}
                </span>
              </div>
              {runningUserJobs.length === 0 && recentDispatchedNotice && (
                <button
                  type="button"
                  onClick={() => setRecentDispatchedNotice(null)}
                  aria-label={tr('Hinweis schließen', 'Dismiss notice')}
                  className="p-1 text-slate-400 hover:text-slate-700 rounded cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            <div className="flex flex-wrap gap-2">
              {(runningUserJobs.length > 0 ? runningUserJobs : noticeJob ? [noticeJob] : []).map(
                (job) => {
                  const isRunning = job.status === 'running';
                  return (
                    <button
                      key={job.id}
                      type="button"
                      onClick={() => onOpenBackgroundJob(job)}
                      className={`inline-flex items-center gap-2 px-3 py-1.5 text-xs rounded-md border transition-colors cursor-pointer ${
                        isRunning
                          ? 'bg-blue-50 border-blue-200 text-blue-900 hover:bg-blue-100'
                          : job.status === 'completed'
                          ? 'bg-emerald-50 border-emerald-200 text-emerald-900 hover:bg-emerald-100'
                          : job.status === 'partial'
                          ? 'bg-amber-50 border-amber-200 text-amber-900 hover:bg-amber-100'
                          : 'bg-red-50 border-red-200 text-red-900 hover:bg-red-100'
                      }`}
                    >
                      {isRunning ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin shrink-0" />
                      ) : job.status === 'completed' ? (
                        <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                      ) : job.status === 'partial' ? (
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                      ) : (
                        <XCircle className="w-3.5 h-3.5 shrink-0" />
                      )}
                      <span className="font-medium truncate max-w-[14rem]">{job.title}</span>
                      <span className="font-mono tabular-nums text-[11px] opacity-80">
                        {isRunning
                          ? `${job.completedTargets}/${job.totalTargets}`
                          : `${job.successCount} OK${job.failedCount > 0 ? ` · ${job.failedCount} ${tr('Fehler', 'Err')}` : ''}`}
                      </span>
                      <span className="underline font-medium">
                        {isRunning ? tr('Status', 'Status') : tr('Ergebnis', 'Result')}
                      </span>
                    </button>
                  );
                }
              )}
            </div>
          </section>
        );
      })()}

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
                                      className="inline-flex items-center gap-1.5 text-xs font-medium text-red-700 tabular-nums"
                                      title={st.error || tr('Nicht erreichbar', 'Unreachable')}
                                    >
                                      <XCircle className="w-3.5 h-3.5" />
                                      Offline
                                      {(st.consecutiveFailures ?? 0) > 1 && (
                                        <span className="text-[11px] font-mono text-red-600/80">
                                          ({st.consecutiveFailures}×)
                                        </span>
                                      )}
                                    </span>
                                  )}
                                  {!st.online && st.backoffActive && !autoPingOffLabel && (
                                    <span
                                      title={tr(
                                        `Nach ${st.consecutiveFailures ?? offlineThreshold} Fehlversuchen auf ${formatIntervalShort(
                                          st.effectiveIntervalSec || intervalSec * offlineMultiplier
                                        )} verlängert. Bei Online-Antwort sofort wieder ${formatIntervalShort(
                                          intervalSec
                                        )}.`,
                                        `Extended to ${formatIntervalShort(
                                          st.effectiveIntervalSec || intervalSec * offlineMultiplier
                                        )} after ${st.consecutiveFailures ?? offlineThreshold} failed pings. Resets immediately to ${formatIntervalShort(
                                          intervalSec
                                        )} once online.`
                                      )}
                                      className="px-1.5 py-0.5 text-[10px] font-mono font-medium rounded border border-amber-200 bg-amber-50 text-amber-800 tabular-nums"
                                    >
                                      {tr(
                                        `alle ${formatIntervalShort(
                                          st.effectiveIntervalSec || intervalSec * offlineMultiplier
                                        )}`,
                                        `every ${formatIntervalShort(
                                          st.effectiveIntervalSec || intervalSec * offlineMultiplier
                                        )}`
                                      )}
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
