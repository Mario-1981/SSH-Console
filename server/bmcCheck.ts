import https from 'node:https';
import tls from 'node:tls';

export interface BmcCheckResult {
  bmcIpAddress: string;
  url: string;
  port: number;
  reachable: boolean;
  httpStatus: number | null;
  tlsProtocol: string | null;
  latencyMs: number | null;
  checkedAt: string;
  error?: string;
}

export function formatBmcHttpsUrl(ipAddress: string): string {
  const trimmed = ipAddress.trim();
  const host = trimmed.includes(':') ? `[${trimmed}]` : trimmed;
  return `https://${host}`;
}

function formatNetworkError(err: NodeJS.ErrnoException): string {
  switch (err.code) {
    case 'ECONNREFUSED':
      return 'Verbindung auf Port 443 abgelehnt';
    case 'ETIMEDOUT':
      return 'Zeitüberschreitung auf Port 443';
    case 'EHOSTUNREACH':
      return 'BMC-Host nicht erreichbar';
    case 'ENETUNREACH':
      return 'Netzwerk zum BMC nicht erreichbar';
    case 'ECONNRESET':
      return 'Verbindung von Port 443 zurückgesetzt';
    default:
      return err.message || 'HTTPS-Prüfung auf Port 443 fehlgeschlagen';
  }
}

export async function checkBmcHttps(bmcIpAddress: string, timeoutMs = 4000): Promise<BmcCheckResult> {
  const cleanIp = bmcIpAddress.trim();
  const url = formatBmcHttpsUrl(cleanIp);
  const checkedAt = new Date().toISOString();
  const started = Date.now();

  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: BmcCheckResult) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const req = https.request(
      {
        host: cleanIp,
        port: 443,
        method: 'HEAD',
        path: '/',
        timeout: timeoutMs,
        rejectUnauthorized: false,
        headers: {
          Host: cleanIp.includes(':') ? `[${cleanIp}]` : cleanIp,
          'User-Agent': 'TrixieSSH-BMC-Check/1.0',
          Connection: 'close',
        },
      },
      (res) => {
        const latencyMs = Math.max(1, Date.now() - started);
        const tlsSocket = res.socket as tls.TLSSocket | undefined;
        const tlsProtocol =
          tlsSocket && typeof tlsSocket.getProtocol === 'function'
            ? tlsSocket.getProtocol()
            : null;
        res.resume();
        finish({
          bmcIpAddress: cleanIp,
          url,
          port: 443,
          reachable: true,
          httpStatus: res.statusCode ?? null,
          tlsProtocol,
          latencyMs,
          checkedAt,
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(Object.assign(new Error('Zeitüberschreitung auf Port 443'), { code: 'ETIMEDOUT' }));
    });

    req.on('error', (err: NodeJS.ErrnoException) => {
      finish({
        bmcIpAddress: cleanIp,
        url,
        port: 443,
        reachable: false,
        httpStatus: null,
        tlsProtocol: null,
        latencyMs: null,
        checkedAt,
        error: formatNetworkError(err),
      });
    });

    req.end();
  });
}
