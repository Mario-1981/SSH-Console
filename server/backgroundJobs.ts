import crypto from 'node:crypto';
import { executeSshCommand } from './sshRunner.ts';
import {
  store,
  type ExecutionLog,
  type SshCommand,
  type UserCertificateBundle,
} from './store.ts';

export type BackgroundJobStatus = 'running' | 'completed' | 'partial' | 'failed';

export interface BackgroundJob {
  id: string;
  userId: string;
  username: string;
  title: string;
  commandNames: string[];
  targetLabels: string[];
  totalTargets: number;
  completedTargets: number;
  successCount: number;
  failedCount: number;
  status: BackgroundJobStatus;
  startedAt: string;
  finishedAt: string | null;
  durationMs: number | null;
  timeoutSec: number;
  estimatedTimeoutSec: number;
  read: boolean;
  errorMessage: string | null;
  results: ExecutionLog[];
}

export interface PreparedBackgroundTarget {
  server: {
    ipAddress: string;
    port: number;
    sshUser: string;
    label: string;
    ignoreHostKey: boolean;
  };
  command: SshCommand;
  vars: Record<string, string>;
}

const MAX_JOBS_PER_USER = 50;
const MAX_CONCURRENT_TARGETS_PER_JOB = 8;

async function runWithBoundedConcurrency<T>(
  items: T[],
  limit: number,
  worker: (item: T, index: number) => Promise<void>
): Promise<void> {
  if (items.length === 0) return;
  const workerCount = Math.max(1, Math.min(limit, items.length));
  let cursor = 0;

  async function next() {
    while (true) {
      const idx = cursor++;
      if (idx >= items.length) return;
      await worker(items[idx], idx);
    }
  }

  await Promise.all(Array.from({ length: workerCount }, () => next()));
}

class BackgroundJobManager {
  private jobs: BackgroundJob[] = [];

  getActiveCount(): number {
    let count = 0;
    for (const job of this.jobs) {
      if (job.status === 'running') count++;
    }
    return count;
  }

  getUserActiveCount(userId: string): number {
    let count = 0;
    for (const job of this.jobs) {
      if (job.userId === userId && job.status === 'running') count++;
    }
    return count;
  }

  private pruneForUser(userId: string) {
    let seenForUser = 0;
    this.jobs = this.jobs.filter((job) => {
      if (job.userId !== userId) return true;
      if (job.status === 'running') {
        seenForUser++;
        return true;
      }
      seenForUser++;
      return seenForUser <= MAX_JOBS_PER_USER;
    });
  }

  startBatchJob(params: {
    userId: string;
    username: string;
    certificate: UserCertificateBundle;
    passphrase?: string;
    dryRun?: boolean;
    resolvedJobs: PreparedBackgroundTarget[];
  }): { ok: true; job: BackgroundJob; activeCount: number; maxBackgroundJobs: number } | {
    ok: false;
    activeCount: number;
    maxBackgroundJobs: number;
    error: string;
  } {
    const maxBackgroundJobs = store.getSettings().maxBackgroundJobs ?? 5;
    const activeCount = this.getUserActiveCount(params.userId);
    if (activeCount >= maxBackgroundJobs) {
      return {
        ok: false,
        activeCount,
        maxBackgroundJobs,
        error: `Maximale Anzahl gleichzeitiger Hintergrundprozesse pro Benutzer (${maxBackgroundJobs}) erreicht (${activeCount}/${maxBackgroundJobs} für Ihr Konto aktiv). Bitte warten Sie, bis einer Ihrer laufenden Aufträge abgeschlossen ist.`,
      };
    }

    const commandNames = Array.from(new Set(params.resolvedJobs.map((j) => j.command.name)));
    const targetLabels = Array.from(
      new Set(
        params.resolvedJobs.map((j) =>
          j.server.label && j.server.label !== j.server.ipAddress
            ? `${j.server.label} (${j.server.ipAddress})`
            : j.server.ipAddress
        )
      )
    );

    const title =
      commandNames.length === 1
        ? commandNames[0]
        : `${commandNames[0]} (+${commandNames.length - 1})`;

    let maxPerTargetTimeoutSec = 30;
    for (const item of params.resolvedJobs) {
      const baseTimeout = Math.max(5, Math.min(3600, Math.round(Number(item.command.timeoutSec) || 30)));
      let effective = baseTimeout;
      if (item.command.kind === 'chain' && Array.isArray(item.command.steps)) {
        const sleepSum = item.command.steps
          .slice(0, -1)
          .reduce((acc, st) => acc + Math.max(0, Math.round(Number(st.sleepAfterSec) || 0)), 0);
        effective = Math.min(7200, Math.max(baseTimeout, baseTimeout + sleepSum));
      }
      if (effective > maxPerTargetTimeoutSec) {
        maxPerTargetTimeoutSec = effective;
      }
    }
    const waves = Math.max(1, Math.ceil(params.resolvedJobs.length / MAX_CONCURRENT_TARGETS_PER_JOB));
    const estimatedTimeoutSec = Math.min(14400, maxPerTargetTimeoutSec * waves);

    const startedMs = Date.now();
    const job: BackgroundJob = {
      id: crypto.randomUUID(),
      userId: params.userId,
      username: params.username,
      title,
      commandNames,
      targetLabels,
      totalTargets: params.resolvedJobs.length,
      completedTargets: 0,
      successCount: 0,
      failedCount: 0,
      status: 'running',
      startedAt: new Date(startedMs).toISOString(),
      finishedAt: null,
      durationMs: null,
      timeoutSec: maxPerTargetTimeoutSec,
      estimatedTimeoutSec,
      read: false,
      errorMessage: null,
      results: [],
    };

    this.jobs.unshift(job);
    this.pruneForUser(params.userId);

    // Spawn asynchronous execution without blocking the HTTP response.
    // Passphrase & secret vars exist only in this closure and are never stored on `job`.
    const certSnapshot = params.certificate;
    const passSnapshot = params.passphrase;
    const dryRun = Boolean(params.dryRun);
    const items = params.resolvedJobs;

    void (async () => {
      try {
        const orderedResults: Array<ExecutionLog | undefined> = new Array(items.length);

        await runWithBoundedConcurrency(
          items,
          MAX_CONCURRENT_TARGETS_PER_JOB,
          async ({ server, command, vars }, idx) => {
            try {
              const result = await executeSshCommand({
                userId: params.userId,
                ipAddress: server.ipAddress,
                port: server.port,
                sshUser: server.sshUser,
                serverLabel: server.label,
                command,
                certificate: certSnapshot,
                passphrase: passSnapshot,
                workflowVars: vars,
                ignoreHostKey: server.ignoreHostKey,
                forceDryRun: dryRun,
              });

              const savedLog = store.addLog({
                userId: params.userId,
                username: params.username,
                commandId: command.id,
                commandName: command.name,
                commandText: command.command,
                targetIp: server.ipAddress,
                targetPort: server.port,
                sshUser: server.sshUser,
                serverLabel: server.label,
                certificateId: certSnapshot.id,
                certificateKeyId: certSnapshot.metadata.keyId || certSnapshot.name,
                mode: result.mode,
                sshInvocation: result.sshInvocation,
                exitCode: result.exitCode,
                stdout: result.stdout,
                stderr: result.stderr,
                durationMs: result.durationMs,
              });

              orderedResults[idx] = savedLog;
              job.completedTargets += 1;
              if (savedLog.exitCode === 0) {
                job.successCount += 1;
              } else {
                job.failedCount += 1;
              }
              job.results = orderedResults.filter((r): r is ExecutionLog => Boolean(r));
            } catch (err) {
              const msg = err instanceof Error ? err.message : 'Unbekannter Ausführungsfehler.';
              const savedLog = store.addLog({
                userId: params.userId,
                username: params.username,
                commandId: command.id,
                commandName: command.name,
                commandText: command.command,
                targetIp: server.ipAddress,
                targetPort: server.port,
                sshUser: server.sshUser,
                serverLabel: server.label,
                certificateId: certSnapshot.id,
                certificateKeyId: certSnapshot.metadata.keyId || certSnapshot.name,
                mode: 'openssh-live',
                sshInvocation: '',
                exitCode: 255,
                stdout: '',
                stderr: msg,
                durationMs: 0,
              });
              orderedResults[idx] = savedLog;
              job.completedTargets += 1;
              job.failedCount += 1;
              job.results = orderedResults.filter((r): r is ExecutionLog => Boolean(r));
            }
          }
        );

        job.finishedAt = new Date().toISOString();
        job.durationMs = Math.max(0, Date.now() - startedMs);
        if (job.failedCount === 0) {
          job.status = 'completed';
        } else if (job.successCount > 0) {
          job.status = 'partial';
        } else {
          job.status = 'failed';
        }
      } catch (err) {
        job.finishedAt = new Date().toISOString();
        job.durationMs = Math.max(0, Date.now() - startedMs);
        job.status = 'failed';
        job.errorMessage = err instanceof Error ? err.message : 'Hintergrundprozess fehlgeschlagen.';
      }
    })();

    return {
      ok: true,
      job: this.cloneJob(job),
      activeCount: this.getUserActiveCount(params.userId),
      maxBackgroundJobs,
    };
  }

  private cloneJob(job: BackgroundJob): BackgroundJob {
    return {
      ...job,
      commandNames: [...job.commandNames],
      targetLabels: [...job.targetLabels],
      results: [...job.results],
    };
  }

  listUserJobs(
    userId: string,
    includeTotalActive = false
  ): {
    jobs: BackgroundJob[];
    activeCount: number;
    totalActiveCount?: number;
    unreadCount: number;
    maxBackgroundJobs: number;
  } {
    const userJobs = this.jobs
      .filter((j) => j.userId === userId)
      .map((j) => this.cloneJob(j));
    const userActiveCount = userJobs.filter((j) => j.status === 'running').length;
    const unreadCount = userJobs.filter((j) => j.status !== 'running' && !j.read).length;
    return {
      jobs: userJobs,
      activeCount: userActiveCount,
      ...(includeTotalActive ? { totalActiveCount: this.getActiveCount() } : {}),
      unreadCount,
      maxBackgroundJobs: store.getSettings().maxBackgroundJobs ?? 5,
    };
  }

  listAllJobs(): {
    jobs: BackgroundJob[];
    activeCount: number;
    maxBackgroundJobs: number;
  } {
    const sorted = this.jobs
      .map((j) => this.cloneJob(j))
      .sort((a, b) => {
        if (a.status === 'running' && b.status !== 'running') return -1;
        if (a.status !== 'running' && b.status === 'running') return 1;
        return b.startedAt.localeCompare(a.startedAt);
      });
    return {
      jobs: sorted,
      activeCount: this.getActiveCount(),
      maxBackgroundJobs: store.getSettings().maxBackgroundJobs ?? 5,
    };
  }

  getUserJob(userId: string, jobId: string): BackgroundJob | null {
    const found = this.jobs.find((j) => j.id === jobId && j.userId === userId);
    return found ? this.cloneJob(found) : null;
  }

  markRead(userId: string, jobId: string): { job: BackgroundJob; unreadCount: number } | null {
    const found = this.jobs.find((j) => j.id === jobId && j.userId === userId);
    if (!found) return null;
    found.read = true;
    const unreadCount = this.jobs.filter(
      (j) => j.userId === userId && j.status !== 'running' && !j.read
    ).length;
    return { job: this.cloneJob(found), unreadCount };
  }

  markAllRead(userId: string): number {
    for (const job of this.jobs) {
      if (job.userId === userId && job.status !== 'running') {
        job.read = true;
      }
    }
    return 0;
  }

  deleteUserJob(userId: string, jobId: string): { ok: true } | { ok: false; status: number; error: string } {
    const idx = this.jobs.findIndex((j) => j.id === jobId && j.userId === userId);
    if (idx === -1) {
      return { ok: false, status: 404, error: 'Hintergrundauftrag nicht gefunden.' };
    }
    if (this.jobs[idx].status === 'running') {
      return {
        ok: false,
        status: 409,
        error: 'Ein noch laufender Hintergrundauftrag kann nicht entfernt werden.',
      };
    }
    this.jobs.splice(idx, 1);
    return { ok: true };
  }
}

export const backgroundJobs = new BackgroundJobManager();
