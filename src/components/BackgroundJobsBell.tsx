import React, { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  Bell,
  Check,
  CheckCheck,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  Eye,
  FileText,
  Loader2,
  SlidersHorizontal,
  Terminal,
  Trash2,
  X,
  XCircle,
  Activity,
} from 'lucide-react';
import { useI18n } from '../i18n';
import { computeJobProgress, formatSecondsCompact } from '../jobProgress';
import type { ActiveTab, BackgroundJob } from '../types';

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

function formatDurationShort(ms: number | null): string {
  if (ms === null || !Number.isFinite(ms)) return '–';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const sec = ms / 1000;
  if (sec < 60) return `${sec.toFixed(1)} s`;
  const mins = Math.floor(sec / 60);
  const rem = Math.round(sec % 60);
  return `${mins}m ${rem}s`;
}

interface BackgroundJobsBellProps {
  jobs: BackgroundJob[];
  activeCount: number;
  unreadCount: number;
  maxBackgroundJobs: number;
  isAdmin: boolean;
  selectedJob: BackgroundJob | null;
  toastJob: BackgroundJob | null;
  onSelectJob: (job: BackgroundJob | null) => void;
  onDismissToast: () => void;
  onMarkAllRead: () => Promise<void>;
  onDeleteJob: (jobId: string) => Promise<void>;
  onUpdateLimit: (nextLimit: number) => Promise<void>;
  onNavigateLogs: (tab: ActiveTab) => void;
}

export function BackgroundJobsBell({
  jobs,
  activeCount,
  unreadCount,
  maxBackgroundJobs,
  isAdmin,
  selectedJob,
  toastJob,
  onSelectJob,
  onDismissToast,
  onMarkAllRead,
  onDeleteJob,
  onUpdateLimit,
  onNavigateLogs,
}: BackgroundJobsBellProps) {
  const { tr, formatClockTime, formatDateTime } = useI18n();
  const [open, setOpen] = useState(false);
  const [showAdminLimit, setShowAdminLimit] = useState(false);
  const [limitInput, setLimitInput] = useState(String(maxBackgroundJobs));
  const [savingLimit, setSavingLimit] = useState(false);
  const [limitError, setLimitError] = useState<string | null>(null);
  const [limitSaved, setLimitSaved] = useState(false);
  const [expandedInvocations, setExpandedInvocations] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [nowMs, setNowMs] = useState(() => Date.now());

  const containerRef = useRef<HTMLDivElement | null>(null);

  const hasVisibleRunningJob =
    (open && jobs.some((j) => j.status === 'running')) ||
    selectedJob?.status === 'running';

  useEffect(() => {
    if (!hasVisibleRunningJob) return;
    setNowMs(Date.now());
    const tick = window.setInterval(() => {
      setNowMs(Date.now());
    }, 1000);
    return () => window.clearInterval(tick);
  }, [hasVisibleRunningJob]);

  useEffect(() => {
    setLimitInput(String(maxBackgroundJobs));
  }, [maxBackgroundJobs]);

  useEffect(() => {
    if (!open) return;
    function handleOutsideClick(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', handleOutsideClick);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleOutsideClick);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [open]);

  useEffect(() => {
    if (!selectedJob) return;
    function handleModalEscape(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        onSelectJob(null);
      }
    }
    document.addEventListener('keydown', handleModalEscape);
    return () => document.removeEventListener('keydown', handleModalEscape);
  }, [selectedJob, onSelectJob]);

  async function handleSaveLimit(e: React.FormEvent) {
    e.preventDefault();
    setLimitError(null);
    setLimitSaved(false);
    const parsed = Math.round(Number(limitInput));
    if (!Number.isFinite(parsed) || parsed < 1 || parsed > 50) {
      setLimitError(tr('Wert muss zwischen 1 und 50 liegen.', 'Value must be between 1 and 50.'));
      return;
    }
    setSavingLimit(true);
    try {
      await onUpdateLimit(parsed);
      setLimitSaved(true);
      window.setTimeout(() => setLimitSaved(false), 2000);
    } catch (err) {
      setLimitError(
        err instanceof Error ? err.message : tr('Limit konnte nicht gespeichert werden.', 'Could not save limit.')
      );
    } finally {
      setSavingLimit(false);
    }
  }

  function handleCopyOutput(logId: string, stdout: string, stderr: string) {
    const cleanErr = filterBenignSshStderr(stderr);
    const combined = [stdout, cleanErr].filter(Boolean).join('\n--- STDERR ---\n');
    if (!combined) return;
    void navigator.clipboard.writeText(combined).then(() => {
      setCopiedId(logId);
      window.setTimeout(() => {
        setCopiedId((prev) => (prev === logId ? null : prev));
      }, 1800);
    });
  }

  function renderStatusIcon(status: BackgroundJob['status'], className = 'w-4 h-4 shrink-0') {
    if (status === 'running') {
      return <Loader2 className={`${className} text-blue-600 animate-spin`} />;
    }
    if (status === 'completed') {
      return <CheckCircle2 className={`${className} text-emerald-600`} />;
    }
    if (status === 'partial') {
      return <AlertTriangle className={`${className} text-amber-600`} />;
    }
    return <XCircle className={`${className} text-red-600`} />;
  }

  function renderStatusLabel(status: BackgroundJob['status']) {
    if (status === 'running') return tr('Läuft', 'Running');
    if (status === 'completed') return tr('Abgeschlossen', 'Completed');
    if (status === 'partial') return tr('Teilweise Fehler', 'Partial Errors');
    return tr('Fehlgeschlagen', 'Failed');
  }

  const atCapacity = activeCount >= maxBackgroundJobs;

  return (
    <>
      {/* Header Notification Bell */}
      <div ref={containerRef} className="relative">
        <button
          type="button"
          onClick={() => setOpen((prev) => !prev)}
          aria-expanded={open}
          aria-label={tr(
            `Hintergrundaufträge (${activeCount} aktiv, ${unreadCount} ungelesen)`,
            `Background jobs (${activeCount} active, ${unreadCount} unread)`
          )}
          title={tr(
            `Hintergrundaufträge · Aktiv: ${activeCount}/${maxBackgroundJobs} · Ungelesen: ${unreadCount}`,
            `Background jobs · Active: ${activeCount}/${maxBackgroundJobs} · Unread: ${unreadCount}`
          )}
          className={`relative inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border text-xs font-medium transition-colors cursor-pointer ${
            open
              ? 'bg-slate-100 border-slate-300 text-slate-900'
              : activeCount > 0
              ? 'bg-blue-50 border-blue-200 text-blue-800 hover:bg-blue-100'
              : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50 hover:text-slate-900'
          }`}
        >
          <span className="relative inline-flex items-center justify-center">
            <Bell className="w-4 h-4" />
            {activeCount > 0 && (
              <span
                className="absolute -top-0.5 -left-0.5 w-2 h-2 rounded-full bg-blue-600 animate-ping"
                aria-hidden="true"
              />
            )}
          </span>

          {activeCount > 0 && (
            <span className="font-mono tabular-nums text-[11px] font-semibold">
              {activeCount}/{maxBackgroundJobs}
            </span>
          )}

          {unreadCount > 0 && (
            <span className="absolute -top-1.5 -right-1.5 min-w-[18px] h-[18px] px-1 rounded-full bg-red-600 text-white text-[10px] font-bold tabular-nums flex items-center justify-center shadow-xs">
              {unreadCount > 99 ? '99+' : unreadCount}
            </span>
          )}
        </button>

        {/* Dropdown Panel */}
        {open && (
          <div className="absolute right-0 mt-2 w-[23rem] sm:w-[27rem] bg-white border border-slate-200 rounded-lg shadow-xl z-40 overflow-hidden">
            {/* Panel Header */}
            <div className="px-4 py-3 border-b border-slate-200 bg-slate-50/80 flex items-center justify-between gap-2">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <h3 className="font-display text-sm font-semibold text-slate-900">
                    {tr('Hintergrundaufträge', 'Background Jobs')}
                  </h3>
                  <span
                    className={`px-1.5 py-0.5 text-[11px] font-mono tabular-nums rounded border ${
                      atCapacity
                        ? 'bg-amber-50 text-amber-800 border-amber-200 font-semibold'
                        : activeCount > 0
                        ? 'bg-blue-50 text-blue-800 border-blue-200'
                        : 'bg-white text-slate-600 border-slate-200'
                    }`}
                  >
                    {tr('Aktiv', 'Active')}: {activeCount}/{maxBackgroundJobs}
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-1.5 shrink-0">
                {unreadCount > 0 && (
                  <button
                    type="button"
                    onClick={() => void onMarkAllRead()}
                    title={tr('Alle als gelesen markieren', 'Mark all as read')}
                    className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium text-blue-700 hover:bg-blue-50 rounded transition-colors cursor-pointer"
                  >
                    <CheckCheck className="w-3.5 h-3.5" />
                    <span>{tr('Alle gelesen', 'Mark all read')}</span>
                  </button>
                )}
                {isAdmin && (
                  <button
                    type="button"
                    onClick={() => {
                      setShowAdminLimit((prev) => !prev);
                      setLimitError(null);
                    }}
                    title={tr('Admin: Limit für Hintergrundprozesse anpassen', 'Admin: Adjust background job limit')}
                    className={`p-1.5 rounded transition-colors cursor-pointer ${
                      showAdminLimit
                        ? 'bg-blue-100 text-blue-800'
                        : 'text-slate-500 hover:text-slate-900 hover:bg-slate-200/70'
                    }`}
                  >
                    <SlidersHorizontal className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>

            {/* Inline Admin Limit Bar */}
            {isAdmin && showAdminLimit && (
              <form
                onSubmit={handleSaveLimit}
                className="px-4 py-2.5 bg-blue-50/60 border-b border-blue-100 space-y-1.5"
              >
                <div className="flex items-center justify-between gap-2">
                  <label htmlFor="bell-max-bg-jobs" className="text-xs font-medium text-slate-800">
                    {tr('Max. Prozesse pro Benutzer (Admin):', 'Max jobs per user (Admin):')}
                  </label>
                  <div className="flex items-center gap-1.5">
                    <input
                      id="bell-max-bg-jobs"
                      type="number"
                      min={1}
                      max={50}
                      value={limitInput}
                      onChange={(e) => setLimitInput(e.target.value)}
                      disabled={savingLimit}
                      className="w-16 px-2 py-1 text-xs font-mono tabular-nums bg-white border border-slate-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-600"
                    />
                    <button
                      type="submit"
                      disabled={savingLimit}
                      className="px-2.5 py-1 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded transition-colors cursor-pointer"
                    >
                      {savingLimit ? '...' : tr('Speichern', 'Save')}
                    </button>
                  </div>
                </div>
                {limitError && <p className="text-[11px] text-red-700">{limitError}</p>}
                {limitSaved && (
                  <p className="text-[11px] text-emerald-700 font-medium">
                    {tr('Limit gespeichert.', 'Limit saved.')}
                  </p>
                )}
              </form>
            )}

            {/* Job List */}
            <div className="max-h-96 overflow-y-auto divide-y divide-slate-100">
              {jobs.length === 0 ? (
                <div className="px-5 py-10 text-center space-y-1.5">
                  <Bell className="w-6 h-6 text-slate-300 mx-auto" />
                  <p className="text-xs font-medium text-slate-700">
                    {tr('Noch keine Hintergrundaufträge', 'No background jobs yet')}
                  </p>
                  <p className="text-[11px] text-slate-500 max-w-xs mx-auto">
                    {tr(
                      'Starten Sie einen Kurzbefehl im Dashboard – er läuft hier im Hintergrund weiter, auch wenn Sie in die SSH-Shell wechseln.',
                      'Dispatch a quick command from the Dashboard—it continues running here even if you switch to the SSH Shell.'
                    )}
                  </p>
                </div>
              ) : (
                jobs.map((job) => {
                  const isRunning = job.status === 'running';
                  const isUnread = !isRunning && !job.read;
                  const progress = computeJobProgress(job, nowMs);
                  const previewTargets = job.targetLabels.slice(0, 2).join(', ');
                  const extraTargets = Math.max(0, job.targetLabels.length - 2);

                  return (
                    <div
                      key={job.id}
                      className={`px-4 py-3 transition-colors ${
                        isUnread ? 'bg-blue-50/40' : 'bg-white hover:bg-slate-50/70'
                      }`}
                    >
                      <div className="flex items-start gap-2.5">
                        <div className="mt-0.5">{renderStatusIcon(job.status)}</div>

                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between gap-2">
                            <div className="flex items-center gap-1.5 min-w-0">
                              <span className="text-xs font-semibold text-slate-900 truncate">
                                {job.title}
                              </span>
                              {isUnread && (
                                <span
                                  className="w-2 h-2 rounded-full bg-blue-600 shrink-0"
                                  title={tr('Ungelesen', 'Unread')}
                                />
                              )}
                            </div>
                            <span className="text-[11px] text-slate-400 font-mono tabular-nums shrink-0">
                              {formatClockTime(job.finishedAt || job.startedAt)}
                            </span>
                          </div>

                          <p className="text-[11px] text-slate-500 truncate mt-0.5">
                            {previewTargets}
                            {extraTargets > 0 && ` (+${extraTargets})`}
                          </p>

                          {isRunning ? (
                            <div className="mt-2 space-y-1">
                              <div className="flex items-center justify-between gap-2 text-[11px] font-mono tabular-nums">
                                <span className="text-blue-800 font-medium">
                                  {progress.percent}% · {job.completedTargets}/{job.totalTargets}
                                </span>
                                <span
                                  className={
                                    progress.nearTimeout ? 'text-amber-700 font-medium' : 'text-slate-500'
                                  }
                                >
                                  {formatSecondsCompact(progress.elapsedSec)} / ~
                                  {formatSecondsCompact(progress.timeoutSec)}
                                </span>
                              </div>
                              <div className="h-1.5 w-full bg-slate-200 rounded-full overflow-hidden">
                                <div
                                  className={`h-full transition-all duration-500 ${
                                    progress.nearTimeout ? 'bg-amber-500' : 'bg-blue-600'
                                  }`}
                                  style={{ width: `${progress.percent}%` }}
                                />
                              </div>
                            </div>
                          ) : (
                            <div className="mt-1.5 flex flex-wrap items-center gap-x-2.5 gap-y-0.5 text-[11px] font-mono tabular-nums">
                              <span className="text-emerald-700 font-medium">{job.successCount} OK</span>
                              {job.failedCount > 0 && (
                                <span className="text-red-700 font-medium">
                                  {job.failedCount} {tr('Fehler', 'Failed')}
                                </span>
                              )}
                              <span className="text-slate-400">·</span>
                              <span className="text-slate-500">{formatDurationShort(job.durationMs)}</span>
                            </div>
                          )}

                          <div className="mt-2 flex items-center justify-between gap-2">
                            <button
                              type="button"
                              onClick={() => {
                                setOpen(false);
                                onSelectJob(job);
                              }}
                              className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 rounded transition-colors cursor-pointer"
                            >
                              <Eye className="w-3 h-3" />
                              {isRunning
                                ? tr('Fortschritt ansehen', 'View Progress')
                                : tr('Ergebnis ansehen', 'View Result')}
                            </button>

                            {!isRunning && (
                              <button
                                type="button"
                                onClick={() => void onDeleteJob(job.id)}
                                title={tr('Benachrichtigung entfernen', 'Dismiss notification')}
                                aria-label={tr('Benachrichtigung entfernen', 'Dismiss notification')}
                                className="p-1 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded transition-colors cursor-pointer"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Panel Footer */}
            <div className="px-4 py-2.5 border-t border-slate-200 bg-slate-50/70 flex items-center justify-between gap-2">
              <button
                type="button"
                onClick={() => {
                  setOpen(false);
                  onNavigateLogs('jobs');
                }}
                className="inline-flex items-center gap-1 text-[11px] font-medium text-blue-700 hover:text-blue-900 whitespace-nowrap cursor-pointer"
              >
                <Activity className="w-3 h-3" />
                {tr('Alle Prozesse öffnen', 'Open All Processes')}
              </button>
              <button
                type="button"
                onClick={() => {
                  setOpen(false);
                  onNavigateLogs('logs');
                }}
                className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-600 hover:text-slate-900 whitespace-nowrap cursor-pointer"
              >
                <FileText className="w-3 h-3" />
                {tr('Protokoll', 'Logs')}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Non-blocking Completion Toast (works across all tabs incl. SSH-Shell) */}
      {toastJob && !selectedJob && (
        <div
          role="status"
          className="fixed bottom-5 right-5 z-40 w-[22rem] max-w-[calc(100vw-2rem)] bg-white border border-slate-200 rounded-lg shadow-xl p-4 flex items-start gap-3"
        >
          <div className="mt-0.5">{renderStatusIcon(toastJob.status, 'w-5 h-5 shrink-0')}</div>
          <div className="flex-1 min-w-0">
            <div className="flex items-start justify-between gap-2">
              <p className="text-xs font-semibold text-slate-900 truncate">
                {toastJob.title}
              </p>
              <button
                type="button"
                onClick={onDismissToast}
                aria-label={tr('Schließen', 'Close')}
                className="p-0.5 text-slate-400 hover:text-slate-700 rounded cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
            <p className="text-xs text-slate-600 mt-0.5">
              {renderStatusLabel(toastJob.status)} ·{' '}
              <span className="font-mono tabular-nums text-emerald-700">{toastJob.successCount} OK</span>
              {toastJob.failedCount > 0 && (
                <>
                  {' · '}
                  <span className="font-mono tabular-nums text-red-700">
                    {toastJob.failedCount} {tr('Fehler', 'Failed')}
                  </span>
                </>
              )}
              {' · '}
              <span className="font-mono tabular-nums text-slate-500">
                {formatDurationShort(toastJob.durationMs)}
              </span>
            </p>
            <div className="mt-2.5 flex items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  onDismissToast();
                  onSelectJob(toastJob);
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 rounded-md transition-colors cursor-pointer"
              >
                <Eye className="w-3.5 h-3.5" />
                {tr('Ergebnis ansehen', 'View Result')}
              </button>
              <button
                type="button"
                onClick={onDismissToast}
                className="px-2.5 py-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 rounded-md cursor-pointer"
              >
                {tr('Später', 'Later')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Detailed Job Result Modal (overlays current tab without disconnecting SSH-Shell) */}
      {selectedJob && (
        <div
          className="fixed inset-0 z-50 bg-slate-950/60 backdrop-blur-[1px] flex items-center justify-center p-4"
          onClick={() => onSelectJob(null)}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-label={selectedJob.title}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-4xl max-h-[88vh] bg-white border border-slate-200 rounded-xl shadow-2xl flex flex-col overflow-hidden"
          >
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-slate-200 bg-slate-50 flex items-start justify-between gap-4 shrink-0">
              <div className="flex items-start gap-3 min-w-0">
                <div className="mt-0.5">{renderStatusIcon(selectedJob.status, 'w-5 h-5 shrink-0')}</div>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="font-display text-base font-bold text-slate-900 truncate">
                      {selectedJob.title}
                    </h2>
                    <span
                      className={`px-2 py-0.5 text-[11px] font-medium rounded border ${
                        selectedJob.status === 'running'
                          ? 'bg-blue-50 text-blue-800 border-blue-200'
                          : selectedJob.status === 'completed'
                          ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                          : selectedJob.status === 'partial'
                          ? 'bg-amber-50 text-amber-800 border-amber-200'
                          : 'bg-red-50 text-red-800 border-red-200'
                      }`}
                    >
                      {renderStatusLabel(selectedJob.status)}
                    </span>
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500 font-mono tabular-nums">
                    <span>
                      {selectedJob.completedTargets}/{selectedJob.totalTargets}{' '}
                      {tr('Server', 'Servers')}
                    </span>
                    <span className="text-emerald-700 font-medium">{selectedJob.successCount} OK</span>
                    <span className={selectedJob.failedCount > 0 ? 'text-red-700 font-medium' : ''}>
                      {selectedJob.failedCount} {tr('Fehler', 'Failed')}
                    </span>
                    {selectedJob.durationMs !== null && (
                      <span>{formatDurationShort(selectedJob.durationMs)}</span>
                    )}
                    <span>
                      {tr('Start', 'Started')}: {formatDateTime(selectedJob.startedAt)}
                    </span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => {
                    onSelectJob(null);
                    onNavigateLogs('logs');
                  }}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer"
                >
                  <FileText className="w-3.5 h-3.5" />
                  {tr('Im Protokoll öffnen', 'Open in Log')}
                </button>
                <button
                  type="button"
                  onClick={() => onSelectJob(null)}
                  aria-label={tr('Schließen', 'Close')}
                  className="p-1.5 text-slate-500 hover:text-slate-900 hover:bg-slate-200/70 rounded-md transition-colors cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Live timeout-oriented progress bar while running */}
            {selectedJob.status === 'running' &&
              (() => {
                const modalProgress = computeJobProgress(selectedJob, nowMs);
                return (
                  <div className="px-6 py-2.5 bg-blue-50 border-b border-blue-100 flex items-center gap-3 shrink-0">
                    <Loader2 className="w-4 h-4 text-blue-700 animate-spin shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-blue-900 font-medium mb-1">
                        <span>
                          {tr(
                            `Fortschritt ${modalProgress.percent}% (${selectedJob.completedTargets}/${selectedJob.totalTargets} Server) – orientiert am Timeout`,
                            `Progress ${modalProgress.percent}% (${selectedJob.completedTargets}/${selectedJob.totalTargets} servers) — based on timeout`
                          )}
                        </span>
                        <span
                          className={`font-mono tabular-nums ${
                            modalProgress.nearTimeout ? 'text-amber-800' : 'text-blue-800'
                          }`}
                        >
                          {formatSecondsCompact(modalProgress.elapsedSec)} / ~
                          {formatSecondsCompact(modalProgress.timeoutSec)}
                        </span>
                      </div>
                      <div className="h-1.5 bg-blue-200 rounded-full overflow-hidden">
                        <div
                          className={`h-full transition-all duration-500 ${
                            modalProgress.nearTimeout ? 'bg-amber-500' : 'bg-blue-700'
                          }`}
                          style={{ width: `${modalProgress.percent}%` }}
                        />
                      </div>
                    </div>
                  </div>
                );
              })()}

            {/* Modal Body: Per-Server Console Results */}
            <div className="flex-1 overflow-y-auto p-5 bg-[#0B1120] space-y-4 font-mono text-xs leading-relaxed text-slate-100">
              {selectedJob.errorMessage && (
                <div className="p-3.5 rounded-md bg-red-950/60 border border-red-800 text-red-200">
                  {selectedJob.errorMessage}
                </div>
              )}

              {selectedJob.results.length === 0 ? (
                <div className="py-12 text-center text-slate-400 flex flex-col items-center gap-2">
                  <Terminal className="w-6 h-6 text-slate-600" />
                  <span>
                    {selectedJob.status === 'running'
                      ? tr(
                          'Warte auf erste Server-Antworten...',
                          'Waiting for first server responses...'
                        )
                      : tr('Keine Einzelausgaben vorhanden.', 'No per-server outputs available.')}
                  </span>
                </div>
              ) : (
                selectedJob.results.map((res) => {
                  const ok = res.exitCode === 0;
                  const showCmd = Boolean(expandedInvocations[res.id]);
                  const visibleStderr = filterBenignSshStderr(res.stderr);
                  const hasCopyable = Boolean(res.stdout || visibleStderr);

                  return (
                    <div
                      key={res.id}
                      className="border border-slate-800 rounded-md overflow-hidden bg-slate-950/60"
                    >
                      <div className="px-4 py-2.5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2 bg-slate-900/80">
                        <div className="flex items-center gap-2 min-w-0">
                          {ok ? (
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                          ) : (
                            <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                          )}
                          <span className="text-slate-100 font-medium truncate">
                            {res.serverLabel} ({res.sshUser}@{res.targetIp}:{res.targetPort})
                          </span>
                          <span className="text-slate-600">·</span>
                          <span className="text-blue-300 truncate">{res.commandName}</span>
                        </div>
                        <div className="flex items-center gap-3 tabular-nums shrink-0">
                          {hasCopyable && (
                            <button
                              type="button"
                              onClick={() => handleCopyOutput(res.id, res.stdout, res.stderr)}
                              className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded transition-colors cursor-pointer"
                            >
                              {copiedId === res.id ? (
                                <>
                                  <Check className="w-3 h-3 text-emerald-400" />
                                  <span>{tr('Kopiert', 'Copied')}</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" />
                                  <span>{tr('Kopieren', 'Copy')}</span>
                                </>
                              )}
                            </button>
                          )}
                          <span className={ok ? 'text-emerald-400' : 'text-red-400'}>
                            Exit {res.exitCode}
                          </span>
                          <span className="text-slate-400">{res.durationMs} ms</span>
                        </div>
                      </div>

                      <div className="p-4 space-y-2.5">
                        {res.sshInvocation && (
                          <>
                            <button
                              type="button"
                              onClick={() =>
                                setExpandedInvocations((prev) => ({
                                  ...prev,
                                  [res.id]: !prev[res.id],
                                }))
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
                          </>
                        )}

                        {res.stdout ? (
                          <pre className="text-slate-200 whitespace-pre-wrap break-words">
                            {res.stdout}
                          </pre>
                        ) : !visibleStderr ? (
                          <p className="text-slate-500 italic">
                            {tr('(keine Ausgabe)', '(no output)')}
                          </p>
                        ) : null}

                        {visibleStderr && (
                          <pre className="text-amber-300 whitespace-pre-wrap break-words border-t border-slate-800 pt-2.5">
                            {visibleStderr}
                          </pre>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
