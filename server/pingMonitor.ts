import { execFile } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import { store, type UserServer } from './store.ts';

export interface ServerPingStatus {
  serverId: string;
  ipAddress: string;
  port: number;
  online: boolean;
  latencyMs: number | null;
  method: 'icmp-ping' | 'tcp-ping';
  checkedAt: string;
  lastOnlineAt: string | null;
  consecutiveFailures: number;
  backoffActive: boolean;
  effectiveIntervalSec: number;
  error?: string;
}

function computeOfflineBackoff(
  consecutiveFailures: number,
  baseIntervalSec: number,
  threshold: number,
  multiplier: number
): { backoffActive: boolean; effectiveIntervalSec: number } {
  if (threshold > 0 && consecutiveFailures >= threshold && multiplier > 1) {
    return {
      backoffActive: true,
      effectiveIntervalSec: Math.min(86400, baseIntervalSec * multiplier),
    };
  }
  return {
    backoffActive: false,
    effectiveIntervalSec: baseIntervalSec,
  };
}

let cachedPingBin: string | null | undefined;

function findPingBinary(): string | null {
  if (cachedPingBin !== undefined) return cachedPingBin;
  const candidates = ['/bin/ping', '/usr/bin/ping'];
  for (const c of candidates) {
    if (fs.existsSync(c)) {
      cachedPingBin = c;
      return c;
    }
  }
  cachedPingBin = null;
  return null;
}

function tcpPing(
  ip: string,
  port: number,
  timeoutMs = 2000
): Promise<{ online: boolean; latencyMs: number | null; error?: string }> {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = new net.Socket();
    let settled = false;

    const done = (res: { online: boolean; latencyMs: number | null; error?: string }) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(res);
    };

    socket.setTimeout(timeoutMs);
    socket.on('connect', () => {
      done({ online: true, latencyMs: Math.max(1, Date.now() - started) });
    });
    socket.on('timeout', () => {
      done({ online: false, latencyMs: null, error: 'Zeitüberschreitung' });
    });
    socket.on('error', (err) => {
      done({ online: false, latencyMs: null, error: err.message });
    });
    socket.connect(port, ip);
  });
}

function icmpPing(
  pingBin: string,
  ip: string
): Promise<{ online: boolean; latencyMs: number | null; permissionDenied?: boolean; error?: string }> {
  return new Promise((resolve) => {
    const isIpv6 = net.isIP(ip) === 6;
    const args = isIpv6 ? ['-6', '-c', '1', '-W', '2', ip] : ['-c', '1', '-W', '2', ip];
    const started = Date.now();

    execFile(pingBin, args, { timeout: 3500 }, (err, stdout, stderr) => {
      const out = `${stdout}\n${stderr}`;
      if (/Operation not permitted|cap_net_raw|socket: Permission denied/i.test(out)) {
        resolve({ online: false, latencyMs: null, permissionDenied: true });
        return;
      }
      if (!err) {
        const match = out.match(/time[=<]\s*([0-9.]+)\s*ms/i);
        const latencyMs = match
          ? Math.max(1, Math.round(parseFloat(match[1])))
          : Math.max(1, Date.now() - started);
        resolve({ online: true, latencyMs });
      } else {
        resolve({ online: false, latencyMs: null, error: 'Keine Antwort (ICMP)' });
      }
    });
  });
}

async function checkServer(
  server: UserServer,
  previousLastOnlineAt: string | null
): Promise<ServerPingStatus> {
  const checkedAt = new Date().toISOString();
  const pingBin = findPingBinary();

  if (pingBin) {
    const icmp = await icmpPing(pingBin, server.ipAddress);
    if (!icmp.permissionDenied) {
      return {
        serverId: server.id,
        ipAddress: server.ipAddress,
        port: server.port,
        online: icmp.online,
        latencyMs: icmp.latencyMs,
        method: 'icmp-ping',
        checkedAt,
        lastOnlineAt: icmp.online ? checkedAt : previousLastOnlineAt,
        consecutiveFailures: 0,
        backoffActive: false,
        effectiveIntervalSec: 0,
        error: icmp.error,
      };
    }
  }

  const tcp = await tcpPing(server.ipAddress, server.port, 2000);
  return {
    serverId: server.id,
    ipAddress: server.ipAddress,
    port: server.port,
    online: tcp.online,
    latencyMs: tcp.latencyMs,
    method: 'tcp-ping',
    checkedAt,
    lastOnlineAt: tcp.online ? checkedAt : previousLastOnlineAt,
    consecutiveFailures: 0,
    backoffActive: false,
    effectiveIntervalSec: 0,
    error: tcp.error,
  };
}

const MAX_CONCURRENT_AUTO_PINGS = 32;
const MAX_CONCURRENT_MANUAL_PINGS = 24;
const MANUAL_PING_STAGGER_MS = 15;

class AsyncSemaphore {
  private active = 0;
  private queue: Array<() => void> = [];

  constructor(private readonly max: number) {}

  async acquire(signal?: AbortSignal): Promise<(() => void) | null> {
    if (signal?.aborted) return null;
    if (this.active < this.max) {
      this.active += 1;
      return this.makeRelease();
    }
    return new Promise<(() => void) | null>((resolve) => {
      const cleanup = () => {
        signal?.removeEventListener('abort', onAbort);
      };
      const grant = () => {
        cleanup();
        this.active += 1;
        resolve(this.makeRelease());
      };
      const onAbort = () => {
        const idx = this.queue.indexOf(grant);
        if (idx >= 0) this.queue.splice(idx, 1);
        cleanup();
        resolve(null);
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      this.queue.push(grant);
    });
  }

  private makeRelease(): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.active = Math.max(0, this.active - 1);
      const next = this.queue.shift();
      if (next) next();
    };
  }
}

function sleepAbortable(ms: number, signal?: AbortSignal): Promise<boolean> {
  if (signal?.aborted) return Promise.resolve(false);
  if (ms <= 0) return Promise.resolve(true);
  return new Promise<boolean>((resolve) => {
    const onAbort = () => {
      clearTimeout(timer);
      resolve(false);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve(true);
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

class PingMonitor {
  private statuses = new Map<string, ServerPingStatus>();
  private lastCycleAt: string | null = null;
  private nextCycleAt: string | null = null;
  private pacingMs: number | null = null;
  private activeTargetCount = 0;
  private loopController: AbortController | null = null;
  private autoSemaphore = new AsyncSemaphore(MAX_CONCURRENT_AUTO_PINGS);
  private inFlightServerIds = new Set<string>();
  private started = false;

  private getPingConfig(): {
    intervalSec: number;
    intervalMs: number;
    offlineThreshold: number;
    offlineMultiplier: number;
  } {
    const settings = store.getSettings();
    const intervalSec = Math.min(3600, Math.max(10, Number(settings.pingIntervalSec) || 60));
    const offlineThreshold = Number.isFinite(Number(settings.pingOfflineThreshold))
      ? Math.min(100, Math.max(0, Math.round(Number(settings.pingOfflineThreshold))))
      : 5;
    const offlineMultiplier = Number.isFinite(Number(settings.pingOfflineMultiplier))
      ? Math.min(60, Math.max(2, Math.round(Number(settings.pingOfflineMultiplier))))
      : 5;
    return {
      intervalSec,
      intervalMs: intervalSec * 1000,
      offlineThreshold,
      offlineMultiplier,
    };
  }

  start() {
    if (this.started) return;
    this.started = true;
    this.reschedule(true);
  }

  stop() {
    this.started = false;
    if (this.loopController) {
      this.loopController.abort();
      this.loopController = null;
    }
  }

  clearServerStatus(serverId: string) {
    this.statuses.delete(serverId);
  }

  private recordResult(server: UserServer, res: ServerPingStatus): ServerPingStatus {
    const { intervalSec, offlineThreshold, offlineMultiplier } = this.getPingConfig();
    const prev = this.statuses.get(server.id);
    const consecutiveFailures = res.online ? 0 : (prev?.consecutiveFailures ?? 0) + 1;
    const { backoffActive, effectiveIntervalSec } = res.online
      ? { backoffActive: false, effectiveIntervalSec: intervalSec }
      : computeOfflineBackoff(
          consecutiveFailures,
          intervalSec,
          offlineThreshold,
          offlineMultiplier
        );

    const enriched: ServerPingStatus = {
      ...res,
      consecutiveFailures,
      backoffActive,
      effectiveIntervalSec,
    };
    this.statuses.set(server.id, enriched);
    if (enriched.online) {
      store.recordServerLastOnline(server.id, enriched.checkedAt);
    }
    return enriched;
  }

  private getKnownLastOnlineAt(server: UserServer): string | null {
    return this.statuses.get(server.id)?.lastOnlineAt ?? server.lastOnlineAt ?? null;
  }

  private isServerDueForCycle(
    serverId: string,
    cycleStart: number,
    cfg: { intervalSec: number; intervalMs: number; offlineThreshold: number; offlineMultiplier: number }
  ): boolean {
    const st = this.statuses.get(serverId);
    if (!st || st.online) return true;
    const { backoffActive, effectiveIntervalSec } = computeOfflineBackoff(
      st.consecutiveFailures,
      cfg.intervalSec,
      cfg.offlineThreshold,
      cfg.offlineMultiplier
    );
    if (!backoffActive) return true;

    const lastCheckedMs = Date.parse(st.checkedAt);
    if (!Number.isFinite(lastCheckedMs)) return true;

    const effectiveIntervalMs = effectiveIntervalSec * 1000;
    const guardMarginMs = Math.min(2000, Math.floor(cfg.intervalMs * 0.1));
    return lastCheckedMs + effectiveIntervalMs <= cycleStart + cfg.intervalMs - guardMarginMs;
  }

  private refreshPacingStats(cycleStart: number): UserServer[] {
    const cfg = this.getPingConfig();
    const allServers = store.listAllServers();
    // Only clean up deleted server IDs (preserve manual ping results for auto-ping-disabled servers)
    const existingIds = new Set(allServers.map((s) => s.id));
    for (const key of this.statuses.keys()) {
      if (!existingIds.has(key)) this.statuses.delete(key);
    }

    const dueTargets = allServers
      .filter(
        (srv) => store.shouldPingServer(srv) && this.isServerDueForCycle(srv.id, cycleStart, cfg)
      )
      .sort((a, b) => a.id.localeCompare(b.id));

    this.activeTargetCount = dueTargets.length;
    this.pacingMs =
      dueTargets.length > 0 ? Math.max(1, Math.round(cfg.intervalMs / dueTargets.length)) : null;
    return dueTargets;
  }

  reschedule(runImmediately = false) {
    if (this.loopController) {
      this.loopController.abort();
      this.loopController = null;
    }

    const settings = store.getSettings();
    if (!settings.pingAllowed) {
      // Only stop automatic periodic pinging; keep existing/manual statuses intact
      this.nextCycleAt = null;
      this.pacingMs = null;
      this.activeTargetCount = 0;
      return;
    }

    const controller = new AbortController();
    this.loopController = controller;
    void this.runLoop(controller, !runImmediately);
  }

  private async runLoop(controller: AbortController, initialDelay: boolean): Promise<void> {
    const { signal } = controller;

    if (initialDelay) {
      const cfg = this.getPingConfig();
      const nextStart = Date.now() + cfg.intervalMs;
      this.refreshPacingStats(nextStart);
      this.nextCycleAt = new Date(nextStart).toISOString();
      const ok = await sleepAbortable(cfg.intervalMs, signal);
      if (!ok) return;
    }

    while (!signal.aborted) {
      const settings = store.getSettings();
      if (!settings.pingAllowed) {
        this.nextCycleAt = null;
        this.pacingMs = null;
        this.activeTargetCount = 0;
        return;
      }

      const { intervalMs } = this.getPingConfig();
      const cycleStart = Date.now();
      this.lastCycleAt = new Date(cycleStart).toISOString();
      this.nextCycleAt = new Date(cycleStart + intervalMs).toISOString();

      await this.runPacedCycle(cycleStart, intervalMs, signal);
      if (signal.aborted) return;

      const remainingMs = cycleStart + intervalMs - Date.now();
      const ok = await sleepAbortable(remainingMs > 0 ? remainingMs : 50, signal);
      if (!ok) return;
    }
  }

  private async runPacedCycle(
    cycleStart: number,
    intervalMs: number,
    signal?: AbortSignal
  ): Promise<void> {
    const targets = this.refreshPacingStats(cycleStart);
    const total = targets.length;
    if (total === 0) return;

    for (let i = 0; i < total; i++) {
      if (signal?.aborted || !store.getSettings().pingAllowed) return;

      const targetStartAt = cycleStart + Math.floor((i * intervalMs) / total);
      const waitMs = targetStartAt - Date.now();
      if (waitMs > 0) {
        const ok = await sleepAbortable(waitMs, signal);
        if (!ok) return;
      }

      if (signal?.aborted || !store.getSettings().pingAllowed) return;

      const srv = targets[i];
      if (!store.shouldPingServer(srv)) continue;
      if (this.inFlightServerIds.has(srv.id)) continue;

      const release = await this.autoSemaphore.acquire(signal);
      if (!release) return;

      if (
        signal?.aborted ||
        !store.getSettings().pingAllowed ||
        !store.shouldPingServer(srv) ||
        this.inFlightServerIds.has(srv.id)
      ) {
        release();
        continue;
      }

      this.inFlightServerIds.add(srv.id);
      void (async () => {
        try {
          const res = await checkServer(srv, this.getKnownLastOnlineAt(srv));
          // Re-check in case admin disabled global auto-ping while in flight
          if (store.getSettings().pingAllowed && store.shouldPingServer(srv)) {
            this.recordResult(srv, res);
          }
        } finally {
          this.inFlightServerIds.delete(srv.id);
          release();
        }
      })();
    }
  }

  async pingAllRegisteredServers(): Promise<void> {
    const settings = store.getSettings();
    if (!settings.pingAllowed) {
      this.nextCycleAt = null;
      this.pacingMs = null;
      this.activeTargetCount = 0;
      return;
    }
    const { intervalMs } = this.getPingConfig();
    const cycleStart = Date.now();
    this.lastCycleAt = new Date(cycleStart).toISOString();
    this.nextCycleAt = new Date(cycleStart + intervalMs).toISOString();
    await this.runPacedCycle(cycleStart, intervalMs);
  }

  /**
   * Executes a ping for accessible servers of a user.
   * When `manual` is true, always pings regardless of global/user/per-IP auto-ping switches.
   * Uses bounded concurrency (and mild launch stagger for large lists) to avoid network bursts.
   */
  async pingUserServers(
    userId: string,
    singleServerId?: string,
    options?: { manual?: boolean }
  ): Promise<ServerPingStatus[]> {
    const manual = options?.manual === true;
    if (!manual) {
      const settings = store.getSettings();
      if (!settings.pingAllowed) {
        return [];
      }
      const user = store.findUserById(userId);
      if (!user || user.pingEnabled === false) {
        return [];
      }
    }

    const servers = store.listAccessibleServers(userId);
    const baseTargets = singleServerId ? servers.filter((s) => s.id === singleServerId) : servers;
    const targets = manual ? baseTargets : baseTargets.filter((s) => s.pingEnabled !== false);

    const semaphore = new AsyncSemaphore(MAX_CONCURRENT_MANUAL_PINGS);
    const staggerMs = targets.length > 20 ? MANUAL_PING_STAGGER_MS : 0;
    const tasks: Array<Promise<ServerPingStatus>> = [];

    for (let i = 0; i < targets.length; i++) {
      if (staggerMs > 0 && i > 0) {
        await sleepAbortable(staggerMs);
      }
      const release = await semaphore.acquire();
      if (!release) break;
      const srv = targets[i];
      tasks.push(
        (async () => {
          try {
            const res = await checkServer(srv, this.getKnownLastOnlineAt(srv));
            if (manual || (store.getSettings().pingAllowed && srv.pingEnabled !== false)) {
              return this.recordResult(srv, res);
            }
            return res;
          } finally {
            release();
          }
        })()
      );
    }

    const results = await Promise.all(tasks);

    if (!singleServerId && targets.length > 0 && !manual) {
      this.lastCycleAt = new Date().toISOString();
    }
    return results;
  }

  getUserStatuses(userId: string): {
    statuses: Record<string, ServerPingStatus>;
    intervalSec: number;
    offlineThreshold: number;
    offlineMultiplier: number;
    backoffCount: number;
    lastCycleAt: string | null;
    nextCycleAt: string | null;
    pacingMs: number | null;
    activeTargetCount: number;
    pingMode: 'icmp-ping' | 'tcp-ping';
    globalPingAllowed: boolean;
    userPingEnabled: boolean;
  } {
    const settings = store.getSettings();
    const { intervalSec, offlineThreshold, offlineMultiplier } = this.getPingConfig();
    const user = store.findUserById(userId);
    const globalPingAllowed = settings.pingAllowed !== false;
    const userPingEnabled = user ? user.pingEnabled !== false : true;
    const effectiveAutoPing = globalPingAllowed && userPingEnabled;

    const servers = store.listAccessibleServers(userId);
    const statuses: Record<string, ServerPingStatus> = {};
    let backoffCount = 0;

    for (const srv of servers) {
      const st = this.statuses.get(srv.id);
      if (st) {
        const { backoffActive, effectiveIntervalSec } = st.online
          ? { backoffActive: false, effectiveIntervalSec: intervalSec }
          : computeOfflineBackoff(
              st.consecutiveFailures ?? 0,
              intervalSec,
              offlineThreshold,
              offlineMultiplier
            );
        if (effectiveAutoPing && srv.pingEnabled !== false && backoffActive) {
          backoffCount += 1;
        }
        statuses[srv.id] = {
          ...st,
          lastOnlineAt: st.lastOnlineAt ?? srv.lastOnlineAt ?? null,
          consecutiveFailures: st.online ? 0 : st.consecutiveFailures ?? 0,
          backoffActive,
          effectiveIntervalSec,
        };
      }
    }

    return {
      statuses,
      intervalSec,
      offlineThreshold,
      offlineMultiplier,
      backoffCount,
      lastCycleAt: effectiveAutoPing ? this.lastCycleAt : null,
      nextCycleAt: effectiveAutoPing ? this.nextCycleAt : null,
      pacingMs: effectiveAutoPing ? this.pacingMs : null,
      activeTargetCount: effectiveAutoPing ? this.activeTargetCount : 0,
      pingMode: findPingBinary() ? 'icmp-ping' : 'tcp-ping',
      globalPingAllowed,
      userPingEnabled,
    };
  }
}

export const pingMonitor = new PingMonitor();
