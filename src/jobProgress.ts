import type { BackgroundJob } from './types';

export interface JobProgressEstimate {
  percent: number;
  elapsedSec: number;
  timeoutSec: number;
  remainingSec: number;
  nearTimeout: boolean;
}

export function formatSecondsCompact(sec: number): string {
  const safe = Math.max(0, Math.round(sec));
  if (safe < 60) return `${safe} s`;
  const mins = Math.floor(safe / 60);
  const rem = safe % 60;
  if (mins < 60) {
    return rem > 0 ? `${mins}m ${rem}s` : `${mins}m`;
  }
  const hrs = Math.floor(mins / 60);
  const remMins = mins % 60;
  return remMins > 0 ? `${hrs}h ${remMins}m` : `${hrs}h`;
}

export function computeJobProgress(job: BackgroundJob, nowMs: number): JobProgressEstimate {
  const estTimeout = Math.max(5, Math.round(job.estimatedTimeoutSec || job.timeoutSec || 30));

  if (job.status !== 'running') {
    const elapsedSec =
      job.durationMs !== null && Number.isFinite(job.durationMs)
        ? Math.max(0, Math.round(job.durationMs / 1000))
        : 0;
    return {
      percent: 100,
      elapsedSec,
      timeoutSec: estTimeout,
      remainingSec: 0,
      nearTimeout: false,
    };
  }

  const startedMs = Date.parse(job.startedAt);
  const elapsedMs = Number.isFinite(startedMs) ? Math.max(0, nowMs - startedMs) : 0;
  const elapsedSec = Math.floor(elapsedMs / 1000);
  const remainingSec = Math.max(0, estTimeout - elapsedSec);

  const timeFraction = Math.min(0.95, Math.max(0.03, elapsedMs / (estTimeout * 1000)));
  const total = Math.max(1, job.totalTargets);
  const completed = Math.min(total, Math.max(0, job.completedTargets));
  const remainingTargets = total - completed;

  const weightedPct = ((completed + remainingTargets * timeFraction) / total) * 100;
  const percent = Math.min(96, Math.max(3, Math.round(weightedPct)));

  return {
    percent,
    elapsedSec,
    timeoutSec: estTimeout,
    remainingSec,
    nearTimeout: elapsedSec >= estTimeout * 0.8,
  };
}
