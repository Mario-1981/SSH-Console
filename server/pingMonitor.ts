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

const PING_INTERVAL_MS = 60_000;

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

function tcpPing(ip: string, port: number, timeoutMs = 2000): Promise<{ online: boolean; latencyMs: number | null; error?: string }> {
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

function icmpPing(pingBin: string, ip: string): Promise<{ online: boolean; latencyMs: number | null; permissionDenied?: boolean; error?: string }> {
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
        const latencyMs = match ? Math.max(1, Math.round(parseFloat(match[1]))) : Math.max(1, Date.now() - started);
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
  private nextCycleAt: string = new Date(Date.now() + PING_INTERVAL_MS).toISOString();
  private timer: NodeJS.Timeout | null = null;

  start() {
    if (this.timer) return;
    // Run initial ping pass shortly after boot, then every 60s
    void this.pingAllRegisteredServers();
    this.timer = setInterval(() => {
      void this.pingAllRegisteredServers();
    }, PING_INTERVAL_MS);
  }

  async pingAllRegisteredServers(): Promise<void> {
    const allServers = store.listAllServers();
    this.lastCycleAt = new Date().toISOString();
    this.nextCycleAt = new Date(Date.now() + PING_INTERVAL_MS).toISOString();

    // Clean up deleted server IDs
    const validIds = new Set(allServers.map((s) => s.id));
    for (const key of this.statuses.keys()) {
      if (!validIds.has(key)) this.statuses.delete(key);
    }

    await Promise.all(
      allServers.map(async (srv) => {
        const res = await checkServer(srv);
        this.statuses.set(srv.id, res);
      })
    );
  }

  async pingUserServers(userId: string, singleServerId?: string): Promise<ServerPingStatus[]> {
    const servers = store.listAccessibleServers(userId);
    const targets = singleServerId
      ? servers.filter((s) => s.id === singleServerId)
      : servers;

    const results = await Promise.all(
      targets.map(async (srv) => {
        const res = await checkServer(srv);
        this.statuses.set(srv.id, res);
        return res;
      })
    );

    if (!singleServerId) {
      this.lastCycleAt = new Date().toISOString();
    }
    return results;
  }

  getUserStatuses(userId: string): {
    statuses: Record<string, ServerPingStatus>;
    intervalSec: number;
    lastCycleAt: string | null;
    nextCycleAt: string;
    pingMode: 'icmp-ping' | 'tcp-ping';
  } {
    const servers = store.listAccessibleServers(userId);
    const statuses: Record<string, ServerPingStatus> = {};
    for (const srv of servers) {
      const st = this.statuses.get(srv.id);
      if (st) {
        statuses[srv.id] = st;
      }
    }
    return {
      statuses,
      intervalSec: PING_INTERVAL_MS / 1000,
      lastCycleAt: this.lastCycleAt,
      nextCycleAt: this.nextCycleAt,
      pingMode: findPingBinary() ? 'icmp-ping' : 'tcp-ping',
    };
  }
}

export const pingMonitor = new PingMonitor();
