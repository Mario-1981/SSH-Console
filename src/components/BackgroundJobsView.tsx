import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Eye,
  Loader2,
  RefreshCw,
  Search,
  Server,
  Trash2,
  User as UserIcon,
  Users,
  XCircle,
} from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { computeJobProgress, formatSecondsCompact } from '../jobProgress';
import type { BackgroundJob, User } from '../types';

interface BackgroundJobsViewProps {
  currentUser: User;
  myJobs: BackgroundJob[];
  myActiveCount: number;
  totalActiveCount: number;
  maxBackgroundJobs: number;
  onRefreshMyJobs: () => Promise<void>;
  onSelectJob: (job: BackgroundJob) => void;
  onDeleteJob: (jobId: string) => Promise<void>;
  onUpdateLimit: (nextLimit: number) => Promise<void>;
  onSyncAdminJob?: (job: BackgroundJob) => void;
}

type StatusFilter = 'running' | 'all' | 'completed' | 'failed';
type ScopeMode = 'all' | 'mine';

function formatDurationShort(ms: number | null): string {
  if (ms === null || !Number.isFinite(ms)) return '–';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const sec = ms / 1000;
  if (sec < 60) return `${sec.toFixed(1)} s`;
  const mins = Math.floor(sec / 60);
  const rem = Math.round(sec % 60);
  return `${mins}m ${rem}s`;
}

export function BackgroundJobsView({
  currentUser,
  myJobs,
  myActiveCount,
  totalActiveCount,
  maxBackgroundJobs,
  onRefreshMyJobs,
  onSelectJob,
  onDeleteJob,
  onUpdateLimit,
  onSyncAdminJob,
}: BackgroundJobsViewProps) {
  const { tr, formatDateTime, formatClockTime } = useI18n();
  const isAdmin = currentUser.role === 'admin';

  const [scope, setScope] = useState<ScopeMode>(isAdmin ? 'all' : 'mine');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [search, setSearch] = useState('');

  const [adminJobs, setAdminJobs] = useState<BackgroundJob[]>([]);
  const [adminActiveCount, setAdminActiveCount] = useState<number>(totalActiveCount);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Admin inline limit editor
  const [limitInput, setLimitInput] = useState(String(maxBackgroundJobs));
  const [savingLimit, setSavingLimit] = useState(false);
  const [limitSavedNotice, setLimitSavedNotice] = useState(false);

  // 1-second live clock for timeout-oriented progress bars
  const [nowMs, setNowMs] = useState(() => Date.now());
  const adminPollInFlightRef = useRef(false);

  useEffect(() => {
    setLimitInput(String(maxBackgroundJobs));
  }, [maxBackgroundJobs]);

  const fetchAdminJobs = useCallback(async () => {
    if (!isAdmin || adminPollInFlightRef.current) return;
    adminPollInFlightRef.current = true;
    try {
      const res = await api.listAdminBackgroundJobs();
      setAdminJobs(res.jobs);
      setAdminActiveCount(res.activeCount);
      if (onSyncAdminJob) {
        for (const j of res.jobs) {
          onSyncAdminJob(j);
        }
      }
      setError(null);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Hintergrundprozesse konnten nicht geladen werden.', 'Could not load background jobs.')
      );
    } finally {
      adminPollInFlightRef.current = false;
    }
  }, [isAdmin, onSyncAdminJob, tr]);

  useEffect(() => {
    if (!isAdmin || scope !== 'all') return;
    void fetchAdminJobs();
    const intervalMs = Math.max(myActiveCount, totalActiveCount, adminActiveCount) > 0 ? 2000 : 10_000;
    const timer = window.setInterval(() => {
      if (
        Math.max(myActiveCount, totalActiveCount, adminActiveCount) > 0 ||
        typeof document === 'undefined' ||
        !document.hidden
      ) {
        void fetchAdminJobs();
      }
    }, intervalMs);
    return () => window.clearInterval(timer);
  }, [isAdmin, scope, myActiveCount, totalActiveCount, adminActiveCount, fetchAdminJobs]);

  const sourceJobs = isAdmin && scope === 'all' ? adminJobs : myJobs;
  const effectiveActiveTotal = isAdmin ? Math.max(adminActiveCount, myActiveCount) : myActiveCount;

  const hasRunningJobs = useMemo(
    () => sourceJobs.some((j) => j.status === 'running') || effectiveActiveTotal > 0,
    [sourceJobs, effectiveActiveTotal]
  );

  useEffect(() => {
    if (!hasRunningJobs) return;
    setNowMs(Date.now());
    const tick = window.setInterval(() => {
      setNowMs(Date.now());
    }, 1000);
    return () => window.clearInterval(tick);
  }, [hasRunningJobs]);

  const myRunningCount = useMemo(
    () => myJobs.filter((j) => j.status === 'running').length,
    [myJobs]
  );

  const counts = useMemo(() => {
    let running = 0;
    let completed = 0;
    let failed = 0;
    for (const j of sourceJobs) {
      if (j.status === 'running') running++;
      else if (j.status === 'completed') completed++;
      else failed++;
    }
    return { total: sourceJobs.length, running, completed, failed };
  }, [sourceJobs]);

  const filteredJobs = useMemo(() => {
    const q = search.trim().toLowerCase();
    return sourceJobs.filter((job) => {
      if (statusFilter === 'running' && job.status !== 'running') return false;
      if (statusFilter === 'completed' && job.status !== 'completed') return false;
      if (statusFilter === 'failed' && job.status !== 'partial' && job.status !== 'failed') {
        return false;
      }
      if (!q) return true;
      return (
        job.title.toLowerCase().includes(q) ||
        job.username.toLowerCase().includes(q) ||
        job.commandNames.some((c) => c.toLowerCase().includes(q)) ||
        job.targetLabels.some((t) => t.toLowerCase().includes(q))
      );
    });
  }, [sourceJobs, statusFilter, search]);

  async function handleManualRefresh() {
    setRefreshing(true);
    setError(null);
    try {
      await onRefreshMyJobs();
      if (isAdmin) {
        await fetchAdminJobs();
      }
    } finally {
      setRefreshing(false);
    }
  }

  async function handleSaveLimit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const parsed = Math.round(Number(limitInput));
    if (!Number.isFinite(parsed) || parsed < 1 || parsed > 50) {
      setError(
        tr(
          'Das Limit für Hintergrundprozesse muss zwischen 1 und 50 liegen.',
          'Background process limit must be between 1 and 50.'
        )
      );
      return;
    }
    setSavingLimit(true);
    try {
      await onUpdateLimit(parsed);
      setLimitSavedNotice(true);
      window.setTimeout(() => setLimitSavedNotice(false), 2200);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Limit konnte nicht gespeichert werden.', 'Could not save limit.')
      );
    } finally {
      setSavingLimit(false);
    }
  }

  async function handleDelete(jobId: string) {
    await onDeleteJob(jobId);
    if (isAdmin && scope === 'all') {
      setAdminJobs((prev) => prev.filter((j) => j.id !== jobId));
    }
  }

  const myAtCapacity = myRunningCount >= maxBackgroundJobs;
  const activeUsersCount = useMemo(() => {
    if (!isAdmin) return 0;
    return new Set(adminJobs.filter((j) => j.status === 'running').map((j) => j.userId)).size;
  }, [isAdmin, adminJobs]);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
            {tr('Hintergrundprozesse', 'Background Processes')}
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            {isAdmin
              ? tr(
                  'Live-Übersicht aller laufenden und abgeschlossenen SSH-Kurzbefehle – für Ihr eigenes Konto oder systemweit über alle Benutzer. Das konfigurierte Limit gilt jeweils pro Benutzer.',
                  'Live overview of all running and completed SSH quick commands—for your account or system-wide across all users. The configured limit applies per user.'
                )
              : tr(
                  'Live-Übersicht Ihrer im Hintergrund laufenden und kürzlich abgeschlossenen SSH-Kurzbefehle mit Timeout-orientierter Fortschrittsanzeige.',
                  'Live overview of your background running and recently completed SSH quick commands with timeout-based progress tracking.'
                )}
          </p>
        </div>

        <button
          type="button"
          onClick={handleManualRefresh}
          disabled={refreshing}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
          {tr('Aktualisieren', 'Refresh')}
        </button>
      </div>

      {error && (
        <div
          role="alert"
          className="px-4 py-3 rounded-md bg-red-50 border border-red-200 text-sm text-red-800"
        >
          {error}
        </div>
      )}

      {/* Single-elevation KPI Strip */}
      <section className="bg-white border border-slate-200 rounded-lg grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 lg:divide-x divide-slate-200">
        <div className="p-5">
          <p className="text-xs text-slate-500">
            {tr('Meine laufenden (Kontingent)', 'Running for Me (Quota)')}
          </p>
          <p
            className={`mt-1 font-display text-2xl font-bold tabular-nums ${
              myAtCapacity
                ? 'text-amber-700'
                : myRunningCount > 0
                ? 'text-blue-700'
                : 'text-slate-900'
            }`}
          >
            {myRunningCount} / {maxBackgroundJobs}
          </p>
          <p className="text-xs text-slate-500 mt-0.5">
            {myAtCapacity
              ? tr('Mein Limit erreicht', 'My quota full')
              : tr(
                  `${Math.max(0, maxBackgroundJobs - myRunningCount)} Plätze für mich frei`,
                  `${Math.max(0, maxBackgroundJobs - myRunningCount)} slots free for me`
                )}
          </p>
        </div>

        <div className="p-5">
          <p className="text-xs text-slate-500">
            {isAdmin
              ? tr('Aktiv gesamt (alle Benutzer)', 'Active Total (all users)')
              : tr('Aufträge im Verlauf', 'Jobs in History')}
          </p>
          <p
            className={`mt-1 font-display text-2xl font-bold tabular-nums ${
              isAdmin && effectiveActiveTotal > 0 ? 'text-blue-700' : 'text-slate-900'
            }`}
          >
            {isAdmin ? effectiveActiveTotal : myJobs.length}
          </p>
          <p className="text-xs text-slate-500 mt-0.5 tabular-nums">
            {isAdmin
              ? activeUsersCount > 0
                ? tr(
                    `verteilt auf ${activeUsersCount} Benutzer`,
                    `across ${activeUsersCount} user${activeUsersCount === 1 ? '' : 's'}`
                  )
                : tr('Derzeit keine aktiven Benutzer', 'No active users right now')
              : tr('Letzte 50 Aufträge gespeichert', 'Last 50 jobs kept')}
          </p>
        </div>

        <div className="p-5">
          <p className="text-xs text-slate-500">
            {tr('Abgeschlossen / Fehler', 'Completed / Errors')}
          </p>
          <p className="mt-1 font-display text-2xl font-bold tabular-nums">
            <span className="text-emerald-700">{counts.completed}</span>
            <span className="text-slate-300 mx-1.5">/</span>
            <span className={counts.failed > 0 ? 'text-red-700' : 'text-slate-400'}>
              {counts.failed}
            </span>
          </p>
          <p className="text-xs text-slate-500 mt-0.5">
            {isAdmin && scope === 'all'
              ? tr('Systemweit', 'System-wide')
              : tr('Eigenes Konto', 'Own account')}
          </p>
        </div>

        <div className="p-5">
          <p className="text-xs text-slate-500">
            {tr('Limit pro Benutzer (global)', 'Limit per User (global)')}
          </p>
          {isAdmin ? (
            <form onSubmit={handleSaveLimit} className="mt-1.5 flex items-center gap-2">
              <input
                type="number"
                min={1}
                max={50}
                value={limitInput}
                onChange={(e) => setLimitInput(e.target.value)}
                disabled={savingLimit}
                aria-label={tr('Max. Hintergrundprozesse pro Benutzer', 'Max background jobs per user')}
                className="w-16 px-2 py-1 text-sm font-mono tabular-nums bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
              <button
                type="submit"
                disabled={savingLimit}
                className="px-2.5 py-1 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer"
              >
                {savingLimit ? '...' : tr('Setzen', 'Set')}
              </button>
              {limitSavedNotice && (
                <span className="text-xs text-emerald-700 font-medium">
                  {tr('OK', 'OK')}
                </span>
              )}
            </form>
          ) : (
            <>
              <p className="mt-1 font-display text-2xl font-bold text-slate-900 tabular-nums">
                {maxBackgroundJobs}
              </p>
              <p className="text-xs text-slate-500 mt-0.5">
                {tr('Pro Benutzer (vom Admin)', 'Per user (set by admin)')}
              </p>
            </>
          )}
        </div>
      </section>

      {/* Filter & Admin Scope Bar */}
      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            {isAdmin && (
              <div className="inline-flex items-center gap-1 p-1 bg-blue-50 border border-blue-100 rounded-md">
                <button
                  type="button"
                  onClick={() => setScope('all')}
                  className={`inline-flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                    scope === 'all'
                      ? 'bg-white text-blue-800 shadow-xs'
                      : 'text-blue-900/70 hover:text-blue-900'
                  }`}
                >
                  <Users className="w-3.5 h-3.5" />
                  {tr(`Alle Benutzer (${adminActiveCount} aktiv)`, `All Users (${adminActiveCount} active)`)}
                </button>
                <button
                  type="button"
                  onClick={() => setScope('mine')}
                  className={`inline-flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                    scope === 'mine'
                      ? 'bg-white text-blue-800 shadow-xs'
                      : 'text-blue-900/70 hover:text-blue-900'
                  }`}
                >
                  <UserIcon className="w-3.5 h-3.5" />
                  {tr(`Meine (${myRunningCount} aktiv)`, `Mine (${myRunningCount} active)`)}
                </button>
              </div>
            )}

            <div className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-md">
              {(
                [
                  { id: 'all', label: tr(`Alle (${counts.total})`, `All (${counts.total})`) },
                  { id: 'running', label: tr(`Laufend (${counts.running})`, `Running (${counts.running})`) },
                  {
                    id: 'completed',
                    label: tr(`OK (${counts.completed})`, `OK (${counts.completed})`),
                  },
                  {
                    id: 'failed',
                    label: tr(`Fehler (${counts.failed})`, `Errors (${counts.failed})`),
                  },
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
          </div>

          <div className="relative w-full lg:w-72">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={
                isAdmin && scope === 'all'
                  ? tr('Befehl, IP oder Benutzer suchen...', 'Search command, IP, or user...')
                  : tr('Befehl oder Server-IP suchen...', 'Search command or server IP...')
              }
              className="w-full pl-9 pr-3 py-1.5 text-sm bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
        </div>

        {/* Job List */}
        {filteredJobs.length === 0 ? (
          <div className="px-6 py-14 text-center space-y-2">
            <Activity className="w-7 h-7 text-slate-300 mx-auto" />
            <p className="text-sm font-medium text-slate-700">
              {statusFilter === 'running'
                ? tr('Derzeit laufen keine Hintergrundprozesse.', 'No background processes are currently running.')
                : tr('Keine Hintergrundprozesse gefunden.', 'No background processes found.')}
            </p>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              {tr(
                'Sobald im Dashboard ein Kurzbefehl oder eine Sammelausführung gestartet wird, erscheint der Fortschritt hier in Echtzeit.',
                'As soon as a quick command or batch is dispatched from the Dashboard, live progress appears here.'
              )}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-200">
            {filteredJobs.map((job) => {
              const isRunning = job.status === 'running';
              const isOwnJob = job.userId === currentUser.id;
              const progress = computeJobProgress(job, nowMs);
              const previewTargets = job.targetLabels.slice(0, 4);
              const extraTargets = Math.max(0, job.targetLabels.length - 4);

              return (
                <div
                  key={job.id}
                  className={`px-6 py-4 transition-colors ${
                    isRunning ? 'bg-blue-50/30' : 'bg-white hover:bg-slate-50/60'
                  }`}
                >
                  <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                    {/* Left: Title, User, Targets, Progress */}
                    <div className="flex-1 min-w-0 space-y-2.5">
                      <div className="flex flex-wrap items-center gap-2">
                        {isRunning ? (
                          <Loader2 className="w-4 h-4 text-blue-600 animate-spin shrink-0" />
                        ) : job.status === 'completed' ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                        ) : job.status === 'partial' ? (
                          <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
                        ) : (
                          <XCircle className="w-4 h-4 text-red-600 shrink-0" />
                        )}

                        <h3 className="text-sm font-semibold text-slate-900 truncate">
                          {job.title}
                        </h3>

                        <span
                          className={`px-2 py-0.5 text-[11px] font-medium rounded border ${
                            isRunning
                              ? 'bg-blue-50 text-blue-800 border-blue-200'
                              : job.status === 'completed'
                              ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                              : job.status === 'partial'
                              ? 'bg-amber-50 text-amber-800 border-amber-200'
                              : 'bg-red-50 text-red-800 border-red-200'
                          }`}
                        >
                          {isRunning
                            ? tr('Läuft', 'Running')
                            : job.status === 'completed'
                            ? tr('Abgeschlossen', 'Completed')
                            : job.status === 'partial'
                            ? tr('Teilweise Fehler', 'Partial Errors')
                            : tr('Fehlgeschlagen', 'Failed')}
                        </span>

                        {isAdmin && scope === 'all' && (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-mono bg-slate-100 text-slate-700 border border-slate-200 rounded">
                            <UserIcon className="w-3 h-3 text-slate-500" />
                            {job.username}
                            {isOwnJob && (
                              <span className="text-slate-400 font-sans">({tr('ich', 'me')})</span>
                            )}
                          </span>
                        )}
                      </div>

                      {/* Target IPs */}
                      <div className="flex flex-wrap items-center gap-1.5 text-xs text-slate-600">
                        <Server className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                        {previewTargets.map((label, idx) => (
                          <span
                            key={`${job.id}-t-${idx}`}
                            className="px-2 py-0.5 text-[11px] font-mono bg-slate-100 text-slate-700 rounded border border-slate-200"
                          >
                            {label}
                          </span>
                        ))}
                        {extraTargets > 0 && (
                          <span className="text-[11px] text-slate-500 font-mono">
                            +{extraTargets} {tr('weitere', 'more')}
                          </span>
                        )}
                      </div>

                      {/* Timeout-Oriented Progress Bar (Live while running, Full bar when finished) */}
                      {isRunning ? (
                        <div className="space-y-1.5 max-w-2xl">
                          <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono tabular-nums">
                            <div className="flex items-center gap-2 text-slate-700">
                              <span className="font-semibold text-blue-800">
                                {progress.percent}%
                              </span>
                              <span className="text-slate-300">·</span>
                              <span>
                                {job.completedTargets}/{job.totalTargets}{' '}
                                {tr('Server fertig', 'servers done')}
                              </span>
                            </div>
                            <div
                              className={`inline-flex items-center gap-1.5 ${
                                progress.nearTimeout ? 'text-amber-700 font-medium' : 'text-slate-500'
                              }`}
                            >
                              <Clock className="w-3.5 h-3.5 shrink-0" />
                              <span>
                                {formatSecondsCompact(progress.elapsedSec)} / ~
                                {formatSecondsCompact(progress.timeoutSec)} {tr('Timeout', 'timeout')}
                                {progress.remainingSec > 0
                                  ? tr(
                                      ` (noch max. ${formatSecondsCompact(progress.remainingSec)})`,
                                      ` (${formatSecondsCompact(progress.remainingSec)} max left)`
                                    )
                                  : tr(' (Timeout erreicht, warte auf Abschluss)', ' (timeout reached, finalizing)')}
                              </span>
                            </div>
                          </div>

                          <div className="h-2 w-full bg-slate-200 rounded-full overflow-hidden">
                            <div
                              className={`h-full transition-all duration-700 ease-out rounded-full ${
                                progress.nearTimeout ? 'bg-amber-500' : 'bg-blue-600'
                              }`}
                              style={{ width: `${progress.percent}%` }}
                            />
                          </div>
                        </div>
                      ) : (
                        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs font-mono tabular-nums text-slate-600">
                          <span className="text-emerald-700 font-medium">{job.successCount} OK</span>
                          <span className={job.failedCount > 0 ? 'text-red-700 font-medium' : 'text-slate-400'}>
                            {job.failedCount} {tr('Fehler', 'Failed')}
                          </span>
                          <span className="text-slate-300">·</span>
                          <span>
                            {tr('Dauer', 'Duration')}: {formatDurationShort(job.durationMs)}
                          </span>
                          <span className="text-slate-300">·</span>
                          <span className="text-slate-500">
                            Timeout: {formatSecondsCompact(progress.timeoutSec)}
                          </span>
                        </div>
                      )}
                    </div>

                    {/* Right: Timestamps & Actions */}
                    <div className="flex flex-row lg:flex-col items-center lg:items-end justify-between gap-2 shrink-0">
                      <div className="text-[11px] text-slate-500 font-mono tabular-nums text-right">
                        <div>
                          {tr('Start', 'Start')}: {formatClockTime(job.startedAt)}
                        </div>
                        {job.finishedAt && (
                          <div className="text-slate-400">
                            {tr('Ende', 'End')}: {formatDateTime(job.finishedAt)}
                          </div>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => onSelectJob(job)}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 border border-blue-200 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          {isRunning
                            ? tr('Fortschritt & Ausgabe', 'Progress & Output')
                            : tr('Ergebnis ansehen', 'View Result')}
                        </button>

                        {!isRunning && isOwnJob && (
                          <button
                            type="button"
                            onClick={() => void handleDelete(job.id)}
                            title={tr('Eintrag entfernen', 'Remove entry')}
                            aria-label={tr('Eintrag entfernen', 'Remove entry')}
                            className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-md transition-colors cursor-pointer"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
