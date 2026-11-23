import crypto from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import type http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import type { Writable } from 'node:stream';
import { WebSocket, WebSocketServer } from 'ws';
import { getUserKnownHostsPath } from './knownHosts.ts';
import { findOpenSshBinary } from './sshRunner.ts';
import { decryptSecret, store, type UserCertificateBundle } from './store.ts';

export interface ShellTicketPayload {
  userId: string;
  username: string;
  serverLabel: string;
  ipAddress: string;
  port: number;
  sshUser: string;
  certificateId: string;
  passphrase?: string;
  ignoreHostKey: boolean;
  cols: number;
  rows: number;
}

interface StoredShellTicket extends ShellTicketPayload {
  expiresAt: number;
}

const TICKET_TTL_MS = 30_000;
const tickets = new Map<string, StoredShellTicket>();

function pruneExpiredTickets() {
  const now = Date.now();
  for (const [key, value] of tickets.entries()) {
    if (value.expiresAt <= now) {
      tickets.delete(key);
    }
  }
}

export function issueShellTicket(payload: ShellTicketPayload): string {
  pruneExpiredTickets();
  const token = crypto.randomBytes(24).toString('hex');
  tickets.set(token, {
    ...payload,
    cols: Math.min(400, Math.max(20, Math.floor(payload.cols || 100))),
    rows: Math.min(200, Math.max(8, Math.floor(payload.rows || 30))),
    expiresAt: Date.now() + TICKET_TTL_MS,
  });
  return token;
}

function consumeShellTicket(token: string): ShellTicketPayload | null {
  pruneExpiredTickets();
  if (!token) return null;
  const entry = tickets.get(token);
  if (!entry) return null;
  tickets.delete(token);
  if (entry.expiresAt <= Date.now()) return null;
  return entry;
}

function wipeAndRemoveDir(dir: string) {
  for (const name of ['zertifikat', 'passphrase', 'askpass.sh']) {
    try {
      const target = path.join(dir, name);
      if (fs.existsSync(target)) {
        const size = fs.statSync(target).size;
        fs.writeFileSync(target, Buffer.alloc(size, 0));
      }
    } catch {
      // ignore cleanup error
    }
  }
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    // ignore cleanup error
  }
}

function probeTcpBanner(
  ip: string,
  port: number,
  timeoutMs = 2000
): Promise<{ reachable: boolean; banner: string; error?: string }> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    let banner = '';

    const finish = (res: { reachable: boolean; banner: string; error?: string }) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(res);
    };

    socket.setTimeout(timeoutMs);
    socket.on('connect', () => {
      setTimeout(() => {
        finish({ reachable: true, banner: banner.trim() });
      }, 350);
    });
    socket.on('data', (chunk) => {
      banner += chunk.toString('utf8');
      if (banner.includes('\n')) {
        finish({ reachable: true, banner: banner.trim() });
      }
    });
    socket.on('timeout', () => {
      finish({ reachable: false, banner: '', error: `Zeitüberschreitung nach ${timeoutMs} ms` });
    });
    socket.on('error', (err) => {
      finish({ reachable: false, banner: '', error: err.message });
    });
    socket.connect(port, ip);
  });
}

function findPython3Binary(): string | null {
  for (const candidate of ['/usr/bin/python3', '/usr/local/bin/python3', '/bin/python3']) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

// Self-contained POSIX PTY bridge via Python stdlib (no native C++ build needed).
// fd 0 -> PTY master stdin, fd 1 <- PTY master stdout, fd 3 -> resize control ("cols rows\n").
const PYTHON_PTY_BRIDGE = `
import os, sys, pty, select, fcntl, termios, struct, signal, errno

cols = int(sys.argv[1])
rows = int(sys.argv[2])
cmd = sys.argv[3:]

def set_winsize(fd, r, c):
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", r, c, 0, 0))
    except OSError:
        pass

pid, master_fd = pty.fork()
if pid == 0:
    os.execv(cmd[0], cmd)

set_winsize(master_fd, rows, cols)

stdin_fd = 0
stdout_fd = 1
ctrl_fd = 3
ctrl_buf = b""

def handle_term(signum, frame):
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass

signal.signal(signal.SIGTERM, handle_term)
signal.signal(signal.SIGHUP, handle_term)

exit_code = 0
watch_fds = [master_fd, stdin_fd, ctrl_fd]

try:
    while True:
        try:
            rlist, _, _ = select.select(watch_fds, [], [], 0.5)
        except InterruptedError:
            continue
        except ValueError:
            break

        if master_fd in rlist:
            try:
                data = os.read(master_fd, 4096)
                if not data:
                    break
                os.write(stdout_fd, data)
            except OSError as e:
                if e.errno in (errno.EIO, errno.EBADF):
                    break
                raise

        if stdin_fd in rlist:
            try:
                data = os.read(stdin_fd, 4096)
                if not data:
                    watch_fds.remove(stdin_fd)
                    try:
                        os.kill(pid, signal.SIGHUP)
                    except OSError:
                        pass
                else:
                    os.write(master_fd, data)
            except OSError:
                if stdin_fd in watch_fds:
                    watch_fds.remove(stdin_fd)

        if ctrl_fd in rlist:
            try:
                chunk = os.read(ctrl_fd, 1024)
                if not chunk:
                    watch_fds.remove(ctrl_fd)
                else:
                    ctrl_buf += chunk
                    while b"\\n" in ctrl_buf:
                        line, ctrl_buf = ctrl_buf.split(b"\\n", 1)
                        parts = line.decode("ascii", "ignore").strip().split()
                        if len(parts) == 2:
                            try:
                                nc = max(20, min(400, int(parts[0])))
                                nr = max(8, min(200, int(parts[1])))
                                set_winsize(master_fd, nr, nc)
                                os.kill(pid, signal.SIGWINCH)
                            except Exception:
                                pass
            except OSError:
                if ctrl_fd in watch_fds:
                    watch_fds.remove(ctrl_fd)

        wpid, status = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            if os.WIFEXITED(status):
                exit_code = os.WEXITSTATUS(status)
            elif os.WIFSIGNALED(status):
                exit_code = 128 + os.WTERMSIG(status)
            break
finally:
    try:
        while True:
            rlist, _, _ = select.select([master_fd], [], [], 0.05)
            if not rlist:
                break
            data = os.read(master_fd, 4096)
            if not data:
                break
            os.write(stdout_fd, data)
    except OSError:
        pass
    try:
        os.close(master_fd)
    except OSError:
        pass
    try:
        wpid, status = os.waitpid(pid, os.WNOHANG)
        if wpid == 0:
            os.kill(pid, signal.SIGTERM)
            _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status):
            exit_code = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            exit_code = 128 + os.WTERMSIG(status)
    except ChildProcessError:
        pass
    except OSError:
        pass

sys.exit(exit_code)
`;

function sendJson(ws: WebSocket, payload: Record<string, unknown>) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(payload));
  }
}

function isOriginAllowed(req: http.IncomingMessage): boolean {
  const origin = req.headers.origin;
  if (!origin) return true;
  const expectedHost = String(req.headers['x-forwarded-host'] || req.headers.host || '')
    .split(',')[0]
    .trim()
    .toLowerCase();
  if (!expectedHost) return true;
  try {
    const parsed = new URL(origin);
    return parsed.host.toLowerCase() === expectedHost;
  } catch {
    return false;
  }
}

async function runSandboxPreviewShell(
  ws: WebSocket,
  ticket: ShellTicketPayload,
  certificate: UserCertificateBundle,
  startedAt: number
) {
  const hasCert = Boolean(certificate.certContent && certificate.certContent.trim());
  const meta = certificate.metadata;
  const principalAllowed =
    !hasCert || meta.principals.length === 0 || meta.principals.includes(ticket.sshUser);

  const hostKeyArgs = ticket.ignoreHostKey
    ? ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null']
    : ['-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=<known_hosts>'];

  const displayInvocation = [
    'ssh',
    '-tt',
    '-i',
    '/tmp/trixiessh-shell-XXXXXX/zertifikat',
    ...(hasCert ? ['-o', 'CertificateFile=/tmp/trixiessh-shell-XXXXXX/zertifikat-cert.pub'] : []),
    '-o',
    'IdentitiesOnly=yes',
    '-o',
    'PasswordAuthentication=no',
    '-o',
    'KbdInteractiveAuthentication=no',
    ...hostKeyArgs,
    '-o',
    'ConnectTimeout=10',
    '-p',
    String(ticket.port),
    `${ticket.sshUser}@${ticket.ipAddress}`,
  ].join(' ');

  sendJson(ws, {
    type: 'ready',
    mode: 'sandbox-preview',
    target: `${ticket.sshUser}@${ticket.ipAddress}:${ticket.port}`,
    certificateName: certificate.name,
  });

  const probe = await probeTcpBanner(ticket.ipAddress, ticket.port, 1800);

  const lines = [
    `\x1b[1;36m=== SSH-Shell Vorschau-Modus (kein /usr/bin/ssh in dieser Sandbox) ===\x1b[0m`,
    `Ziel:          \x1b[1m${ticket.sshUser}@${ticket.ipAddress}:${ticket.port}\x1b[0m${ticket.serverLabel ? ` (${ticket.serverLabel})` : ''}`,
    `Zertifikat:    ${certificate.name} (${hasCert ? '3-Dateien-Verbund' : '2-Dateien-Schlüsselpaar'})`,
    `Fingerabdruck: ${meta.pubKeyFingerprint || '—'}`,
    ...(hasCert
      ? [
          `Principals:    ${meta.principals.length > 0 ? meta.principals.join(', ') : '(alle)'} -> ${
            principalAllowed ? '\x1b[32mOK\x1b[0m' : '\x1b[31mNICHT ERLAUBT\x1b[0m'
          }`,
          `Gültigkeit:    ${
            meta.isExpired
              ? '\x1b[31mABGELAUFEN\x1b[0m'
              : meta.isNotYetValid
                ? '\x1b[33mNOCH NICHT GÜLTIG\x1b[0m'
                : '\x1b[32mGültig\x1b[0m'
          }`,
        ]
      : []),
    `TCP-Prüfung:   ${
      probe.reachable
        ? `\x1b[32mErreichbar\x1b[0m${probe.banner ? ` (${probe.banner})` : ''}`
        : `\x1b[33mNicht erreichbar\x1b[0m (${probe.error ?? 'keine Antwort'})`
    }`,
    ``,
    `\x1b[90mOpenSSH-Aufruf auf Debian 13 (Trixie):\x1b[0m`,
    `\x1b[37m$ ${displayInvocation}\x1b[0m`,
    ``,
    `\x1b[33mHinweis:\x1b[0m In dieser Vorschau-Umgebung ist kein OpenSSH-Client (/usr/bin/ssh) installiert.`,
    `Auf Ihrem Debian-13-Server mit installiertem .deb-Paket öffnet sich hier direkt die echte interaktive SSH-Shell (PTY).`,
  ];

  sendJson(ws, { type: 'output', data: lines.join('\r\n') + '\r\n' });
  const exitCode = hasCert && (meta.isExpired || meta.isNotYetValid || !principalAllowed) ? 255 : 0;

  store.addLog({
    userId: ticket.userId,
    username: ticket.username,
    commandId: 'interactive-shell',
    commandName: 'SSH-Shell (Interaktiv)',
    commandText: 'interactive-shell',
    targetIp: ticket.ipAddress,
    targetPort: ticket.port,
    sshUser: ticket.sshUser,
    serverLabel: ticket.serverLabel || ticket.ipAddress,
    certificateId: certificate.id,
    certificateKeyId: certificate.metadata.keyId || certificate.name,
    mode: 'sandbox-dry-run',
    sshInvocation: displayInvocation,
    exitCode,
    stdout: 'Interaktive SSH-Shell (Vorschau-Modus ohne /usr/bin/ssh)',
    stderr: '',
    durationMs: Date.now() - startedAt,
  });

  sendJson(ws, {
    type: 'exit',
    code: exitCode,
    reason: 'Vorschau-Prüfung abgeschlossen (kein /usr/bin/ssh in Sandbox).',
  });
}

function startLiveOpenSshShell(
  ws: WebSocket,
  ticket: ShellTicketPayload,
  certificate: UserCertificateBundle,
  sshBinary: string,
  startedAt: number
) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trixiessh-shell-'));
  let cleanedUp = false;
  let child: ChildProcess | null = null;
  let resizePipe: Writable | null = null;
  let logged = false;

  const hasCert = Boolean(certificate.certContent && certificate.certContent.trim());
  const displayHostKeyArgs = ticket.ignoreHostKey
    ? ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null']
    : ['-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=<known_hosts>'];
  const displayInvocation = [
    'ssh',
    '-tt',
    '-i',
    '/tmp/trixiessh-shell-XXXXXX/zertifikat',
    ...(hasCert ? ['-o', 'CertificateFile=/tmp/trixiessh-shell-XXXXXX/zertifikat-cert.pub'] : []),
    '-o',
    'IdentitiesOnly=yes',
    '-o',
    'PasswordAuthentication=no',
    '-o',
    'KbdInteractiveAuthentication=no',
    ...displayHostKeyArgs,
    '-o',
    'ConnectTimeout=10',
    '-p',
    String(ticket.port),
    `${ticket.sshUser}@${ticket.ipAddress}`,
  ].join(' ');

  const cleanup = () => {
    if (cleanedUp) return;
    cleanedUp = true;
    try {
      if (child && !child.killed) {
        child.kill('SIGTERM');
      }
    } catch {
      // ignore
    }
    wipeAndRemoveDir(tempDir);
  };

  const recordLog = (exitCode: number, note: string) => {
    if (logged) return;
    logged = true;
    store.addLog({
      userId: ticket.userId,
      username: ticket.username,
      commandId: 'interactive-shell',
      commandName: 'SSH-Shell (Interaktiv)',
      commandText: 'interactive-shell',
      targetIp: ticket.ipAddress,
      targetPort: ticket.port,
      sshUser: ticket.sshUser,
      serverLabel: ticket.serverLabel || ticket.ipAddress,
      certificateId: certificate.id,
      certificateKeyId: certificate.metadata.keyId || certificate.name,
      mode: 'openssh-live',
      sshInvocation: displayInvocation,
      exitCode,
      stdout: note,
      stderr: '',
      durationMs: Date.now() - startedAt,
    });
  };

  try {
    fs.chmodSync(tempDir, 0o700);
    const privKeyPath = path.join(tempDir, 'zertifikat');
    const pubKeyPath = path.join(tempDir, 'zertifikat.pub');
    const certPath = path.join(tempDir, 'zertifikat-cert.pub');

    const privateKeyPlain = decryptSecret(certificate.privateKeyEncrypted);
    fs.writeFileSync(
      privKeyPath,
      privateKeyPlain.endsWith('\n') ? privateKeyPlain : `${privateKeyPlain}\n`,
      { mode: 0o600 }
    );
    fs.writeFileSync(pubKeyPath, certificate.publicKeyContent, { mode: 0o644 });
    if (hasCert) {
      fs.writeFileSync(certPath, certificate.certContent, { mode: 0o644 });
    }

    const liveHostKeyArgs = ticket.ignoreHostKey
      ? ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null']
      : [
          '-o',
          'StrictHostKeyChecking=accept-new',
          '-o',
          `UserKnownHostsFile=${getUserKnownHostsPath(ticket.userId)}`,
          '-o',
          'HashKnownHosts=no',
        ];

    const sshArgs = [
      '-tt',
      '-i',
      privKeyPath,
      ...(hasCert ? ['-o', `CertificateFile=${certPath}`] : []),
      '-o',
      'IdentitiesOnly=yes',
      '-o',
      'PasswordAuthentication=no',
      '-o',
      'KbdInteractiveAuthentication=no',
      ...liveHostKeyArgs,
      '-o',
      'ConnectTimeout=10',
      '-o',
      'ServerAliveInterval=30',
      '-o',
      'ServerAliveCountMax=3',
      '-p',
      String(ticket.port),
      `${ticket.sshUser}@${ticket.ipAddress}`,
    ];

    const effectivePassphrase =
      typeof ticket.passphrase === 'string' && ticket.passphrase.length > 0
        ? ticket.passphrase
        : certificate.passphraseEncrypted
          ? decryptSecret(certificate.passphraseEncrypted)
          : '';

    const python3 = findPython3Binary();
    const spawnEnv: Record<string, string> = {
      PATH: '/usr/bin:/bin',
      HOME: tempDir,
      TERM: 'xterm-256color',
      LANG: 'C.UTF-8',
    };

    if (effectivePassphrase) {
      const passPath = path.join(tempDir, 'passphrase');
      const askpassPath = path.join(tempDir, 'askpass.sh');
      fs.writeFileSync(passPath, `${effectivePassphrase}\n`, { mode: 0o600 });
      fs.writeFileSync(
        askpassPath,
        '#!/bin/sh\nif [ -f "$TRIXIESSH_PASS_FILE" ]; then\n  cat "$TRIXIESSH_PASS_FILE"\n  rm -f "$TRIXIESSH_PASS_FILE"\nfi\n',
        { mode: 0o700 }
      );
      spawnEnv.SSH_ASKPASS = askpassPath;
      spawnEnv.SSH_ASKPASS_REQUIRE = 'force';
      spawnEnv.DISPLAY = 'none:0';
      spawnEnv.TRIXIESSH_PASS_FILE = passPath;
    }

    if (python3) {
      child = spawn(
        python3,
        ['-u', '-c', PYTHON_PTY_BRIDGE, String(ticket.cols), String(ticket.rows), sshBinary, ...sshArgs],
        {
          stdio: ['pipe', 'pipe', 'pipe', 'pipe'],
          env: spawnEnv,
        }
      );
      resizePipe = (child.stdio[3] as Writable | null) ?? null;
    } else {
      // Fallback without PTY wrapper if python3 is unavailable
      child = spawn(sshBinary, sshArgs, {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: spawnEnv,
      });
    }

    sendJson(ws, {
      type: 'ready',
      mode: 'openssh-live',
      target: `${ticket.sshUser}@${ticket.ipAddress}:${ticket.port}`,
      certificateName: certificate.name,
    });

    child.stdout?.on('data', (chunk: Buffer) => {
      sendJson(ws, { type: 'output', data: chunk.toString('utf8') });
    });

    child.stderr?.on('data', (chunk: Buffer) => {
      sendJson(ws, { type: 'output', data: chunk.toString('utf8') });
    });

    child.on('error', (err) => {
      sendJson(ws, { type: 'error', message: `SSH-Prozessfehler: ${err.message}` });
      recordLog(255, `SSH-Prozessfehler: ${err.message}`);
      cleanup();
      if (ws.readyState === WebSocket.OPEN) ws.close();
    });

    child.on('exit', (code, signal) => {
      const exitCode = typeof code === 'number' ? code : signal ? 128 : 0;
      const reason = signal ? `Beendet durch Signal ${signal}` : `Verbindung beendet (Exit-Code ${exitCode})`;
      sendJson(ws, { type: 'exit', code: exitCode, reason });
      recordLog(exitCode, `Interaktive SSH-Sitzung beendet (${reason})`);
      cleanup();
      if (ws.readyState === WebSocket.OPEN) ws.close(1000, 'SSH exited');
    });

    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString('utf8')) as {
          type?: string;
          data?: string;
          cols?: number;
          rows?: number;
        };
        if (msg.type === 'input' && typeof msg.data === 'string') {
          if (child?.stdin && !child.stdin.destroyed) {
            child.stdin.write(msg.data);
          }
        } else if (msg.type === 'resize') {
          const cols = Math.min(400, Math.max(20, Math.floor(Number(msg.cols) || 100)));
          const rows = Math.min(200, Math.max(8, Math.floor(Number(msg.rows) || 30)));
          if (resizePipe && !resizePipe.destroyed) {
            resizePipe.write(`${cols} ${rows}\n`);
          }
        } else if (msg.type === 'ping') {
          sendJson(ws, { type: 'pong' });
        }
      } catch {
        // ignore malformed frames
      }
    });

    ws.on('close', () => {
      recordLog(0, 'Interaktive SSH-Sitzung vom Browser getrennt');
      cleanup();
    });

    ws.on('error', () => {
      recordLog(255, 'WebSocket-Verbindungsfehler');
      cleanup();
    });
  } catch (err) {
    cleanup();
    const message = err instanceof Error ? err.message : 'SSH-Shell konnte nicht gestartet werden.';
    sendJson(ws, { type: 'error', message });
    recordLog(255, message);
    if (ws.readyState === WebSocket.OPEN) ws.close(1011, 'Shell start error');
  }
}

export function attachSshShellWebSocket(server: http.Server) {
  const wss = new WebSocketServer({ noServer: true, maxPayload: 128 * 1024 });

  server.on('upgrade', (req, socket, head) => {
    const rawUrl = req.url || '';
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(rawUrl, 'http://localhost');
    } catch {
      return;
    }
    if (parsedUrl.pathname !== '/api/ws/shell') {
      return;
    }

    if (!isOriginAllowed(req)) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }

    const ticketToken = parsedUrl.searchParams.get('ticket') || '';
    const ticket = consumeShellTicket(ticketToken);
    if (!ticket) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      const startedAt = Date.now();
      const certificate = store.getAccessibleCertificate(ticket.certificateId, ticket.userId);
      if (!certificate) {
        sendJson(ws, {
          type: 'error',
          message: 'Zertifikatspaket nicht gefunden oder keine Berechtigung.',
        });
        ws.close(1008, 'Forbidden');
        return;
      }

      const sshBinary = findOpenSshBinary();
      if (!sshBinary) {
        void runSandboxPreviewShell(ws, ticket, certificate, startedAt);
        return;
      }

      startLiveOpenSshShell(ws, ticket, certificate, sshBinary, startedAt);
    });
  });
}
