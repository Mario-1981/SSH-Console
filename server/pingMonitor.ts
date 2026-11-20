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

async function checkServer(server: UserServer): Promise<ServerPingStatus> {
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

  reschedule(runImmediately = false) {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    const settings = store.getSettings();
    if (!settings.pingAllowed) {
      this.statuses.clear();
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
      this.statuses.clear();
      this.nextCycleAt = null;
      return;
    }

    const allServers = store.listAllServers();
    this.lastCycleAt = new Date().toISOString();

    // Clean up deleted or ping-disabled server IDs
    const activePingIds = new Set(
      allServers.filter((s) => store.shouldPingServer(s)).map((s) => s.id)
    );
    for (const key of this.statuses.keys()) {
      if (!activePingIds.has(key)) this.statuses.delete(key);
    }

    const targets = allServers.filter((srv) => activePingIds.has(srv.id));
    await Promise.all(
      targets.map(async (srv) => {
        const res = await checkServer(srv);
        // Re-check in case admin disabled global ping while in flight
        if (store.getSettings().pingAllowed && store.shouldPingServer(srv)) {
          this.statuses.set(srv.id, res);
        }
      })
    );
  }

  async pingUserServers(userId: string, singleServerId?: string): Promise<ServerPingStatus[]> {
    const settings = store.getSettings();
    if (!settings.pingAllowed) {
      return [];
    }
    const user = store.findUserById(userId);
    if (!user || user.pingEnabled === false) {
      return [];
    }

    const servers = store.listAccessibleServers(userId);
    const targets = (singleServerId ? servers.filter((s) => s.id === singleServerId) : servers).filter(
      (s) => s.pingEnabled !== false
    );

    const results = await Promise.all(
      targets.map(async (srv) => {
        const res = await checkServer(srv);
        if (store.getSettings().pingAllowed && srv.pingEnabled !== false) {
          this.statuses.set(srv.id, res);
        }
        return res;
      })
    );

    if (!singleServerId && targets.length > 0) {
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
    const effectiveActive = globalPingAllowed && userPingEnabled;

    const servers = store.listAccessibleServers(userId);
    const statuses: Record<string, ServerPingStatus> = {};
    if (effectiveActive) {
      for (const srv of servers) {
        if (srv.pingEnabled === false) continue;
        const st = this.statuses.get(srv.id);
        if (st) {
          statuses[srv.id] = st;
        }
      }
    }

    return {
      statuses,
      intervalSec: settings.pingIntervalSec || 60,
      lastCycleAt: effectiveActive ? this.lastCycleAt : null,
      nextCycleAt: effectiveActive ? this.nextCycleAt : null,
      pingMode: findPingBinary() ? 'icmp-ping' : 'tcp-ping',
      globalPingAllowed,
      userPingEnabled,
    };
  }
}

export const pingMonitor = new PingMonitor();
