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
  error?: string;
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
    error: tcp.error,
  };
}

class PingMonitor {
  private statuses = new Map<string, ServerPingStatus>();
  private lastCycleAt: string | null = null;
  private nextCycleAt: string | null = null;
  private timer: NodeJS.Timeout | null = null;
  private started = false;

  private getIntervalMs(): number {
    const sec = store.getSettings().pingIntervalSec;
    return Math.min(3600, Math.max(10, Number(sec) || 60)) * 1000;
  }

  start() {
    if (this.started) return;
    this.started = true;
    this.reschedule(true);
  }

  clearServerStatus(serverId: string) {
    this.statuses.delete(serverId);
  }

  private recordResult(server: UserServer, res: ServerPingStatus) {
    this.statuses.set(server.id, res);
    if (res.online) {
      store.recordServerLastOnline(server.id, res.checkedAt);
    }
  }

  private getKnownLastOnlineAt(server: UserServer): string | null {
    return this.statuses.get(server.id)?.lastOnlineAt ?? server.lastOnlineAt ?? null;
  }

  reschedule(runImmediately = false) {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    const settings = store.getSettings();
    if (!settings.pingAllowed) {
      // Only stop automatic periodic pinging; keep existing/manual statuses intact
      this.nextCycleAt = null;
      return;
    }

    if (runImmediately) {
      void this.runCycleAndScheduleNext();
    } else {
      this.scheduleNextTick();
    }
  }

  private scheduleNextTick() {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    const settings = store.getSettings();
    if (!settings.pingAllowed) {
      this.nextCycleAt = null;
      return;
    }
    const intervalMs = this.getIntervalMs();
    this.nextCycleAt = new Date(Date.now() + intervalMs).toISOString();
    this.timer = setTimeout(() => {
      void this.runCycleAndScheduleNext();
    }, intervalMs);
  }

  private async runCycleAndScheduleNext(): Promise<void> {
    await this.pingAllRegisteredServers();
    this.scheduleNextTick();
  }

  async pingAllRegisteredServers(): Promise<void> {
    const settings = store.getSettings();
    if (!settings.pingAllowed) {
      this.nextCycleAt = null;
      return;
    }

    const allServers = store.listAllServers();
    this.lastCycleAt = new Date().toISOString();

    // Only clean up deleted server IDs (preserve manual ping results for auto-ping-disabled servers)
    const existingIds = new Set(allServers.map((s) => s.id));
    for (const key of this.statuses.keys()) {
      if (!existingIds.has(key)) this.statuses.delete(key);
    }

    const targets = allServers.filter((srv) => store.shouldPingServer(srv));
    await Promise.all(
      targets.map(async (srv) => {
        const res = await checkServer(srv, this.getKnownLastOnlineAt(srv));
        // Re-check in case admin disabled global auto-ping while in flight
        if (store.getSettings().pingAllowed && store.shouldPingServer(srv)) {
          this.recordResult(srv, res);
        }
      })
    );
  }

  /**
   * Executes a ping for accessible servers of a user.
   * When `manual` is true, always pings regardless of global/user/per-IP auto-ping switches.
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

    const results = await Promise.all(
      targets.map(async (srv) => {
        const res = await checkServer(srv, this.getKnownLastOnlineAt(srv));
        if (manual || (store.getSettings().pingAllowed && srv.pingEnabled !== false)) {
          this.recordResult(srv, res);
        }
        return res;
      })
    );

    if (!singleServerId && targets.length > 0 && !manual) {
      this.lastCycleAt = new Date().toISOString();
    }
    return results;
  }

  getUserStatuses(userId: string): {
    statuses: Record<string, ServerPingStatus>;
    intervalSec: number;
    lastCycleAt: string | null;
    nextCycleAt: string | null;
    pingMode: 'icmp-ping' | 'tcp-ping';
    globalPingAllowed: boolean;
    userPingEnabled: boolean;
  } {
    const settings = store.getSettings();
    const user = store.findUserById(userId);
    const globalPingAllowed = settings.pingAllowed !== false;
    const userPingEnabled = user ? user.pingEnabled !== false : true;
    const effectiveAutoPing = globalPingAllowed && userPingEnabled;

    const servers = store.listAccessibleServers(userId);
    const statuses: Record<string, ServerPingStatus> = {};
    for (const srv of servers) {
      const st = this.statuses.get(srv.id);
      if (st) {
        statuses[srv.id] = {
          ...st,
          lastOnlineAt: st.lastOnlineAt ?? srv.lastOnlineAt ?? null,
        };
      }
    }

    return {
      statuses,
      intervalSec: settings.pingIntervalSec || 60,
      lastCycleAt: effectiveAutoPing ? this.lastCycleAt : null,
      nextCycleAt: effectiveAutoPing ? this.nextCycleAt : null,
      pingMode: findPingBinary() ? 'icmp-ping' : 'tcp-ping',
      globalPingAllowed,
      userPingEnabled,
    };
  }
}

export const pingMonitor = new PingMonitor();
