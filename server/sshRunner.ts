import { execFile } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { decryptSecret, type SshCommand, type UserCertificateBundle } from './store.ts';

let cachedSshBinary: string | null | undefined;

export function findOpenSshBinary(): string | null {
  if (cachedSshBinary !== undefined) return cachedSshBinary;
  const candidates = ['/usr/bin/ssh', '/bin/ssh', '/usr/local/bin/ssh'];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      cachedSshBinary = candidate;
      return candidate;
    }
  }
  cachedSshBinary = null;
  return null;
}

export function validateTargetIp(ip: string): boolean {
  return net.isIP(ip.trim()) !== 0;
}

export function validateSshUsername(sshUser: string): boolean {
  return /^[a-z_][a-z0-9_.-]{0,31}$/i.test(sshUser.trim());
}

function probeTcpPort(ip: string, port: number, timeoutMs = 2000): Promise<{ reachable: boolean; banner: string; error?: string }> {
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
      // Wait briefly for SSH-2.0 banner if remote sshd responds immediately
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

function wipeAndRemoveDir(dir: string) {
  try {
    const keyFile = path.join(dir, 'zertifikat');
    if (fs.existsSync(keyFile)) {
      const size = fs.statSync(keyFile).size;
      fs.writeFileSync(keyFile, Buffer.alloc(size, 0));
    }
  } catch {
    // ignore cleanup error
  }
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    // ignore cleanup error
  }
}

export interface SshExecutionResult {
  mode: 'openssh-live' | 'sandbox-dry-run';
  sshInvocation: string;
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
}

export async function executeSshCommand(params: {
  ipAddress: string;
  port: number;
  sshUser: string;
  command: SshCommand;
  certificate: UserCertificateBundle;
  forceDryRun?: boolean;
}): Promise<SshExecutionResult> {
  const started = Date.now();
  const sshBinary = findOpenSshBinary();
  const displayInvocation = [
    'ssh',
    '-i',
    '/tmp/trixiessh-XXXXXX/zertifikat',
    '-o',
    'CertificateFile=/tmp/trixiessh-XXXXXX/zertifikat-cert.pub',
    '-o',
    'IdentitiesOnly=yes',
    '-o',
    'BatchMode=yes',
    '-o',
    'PasswordAuthentication=no',
    '-o',
    'KbdInteractiveAuthentication=no',
    '-o',
    'StrictHostKeyChecking=accept-new',
    '-o',
    'ConnectTimeout=10',
    '-p',
    String(params.port),
    `${params.sshUser}@${params.ipAddress}`,
    '--',
    params.command.command,
  ].join(' ');

  // Live OpenSSH execution when running on Debian Trixie / Linux host with openssh-client
  if (sshBinary && !params.forceDryRun) {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trixiessh-'));
    try {
      fs.chmodSync(tempDir, 0o700);
      const privKeyPath = path.join(tempDir, 'zertifikat');
      const pubKeyPath = path.join(tempDir, 'zertifikat.pub');
      const certPath = path.join(tempDir, 'zertifikat-cert.pub');

      const privateKeyPlain = decryptSecret(params.certificate.privateKeyEncrypted);
      fs.writeFileSync(privKeyPath, privateKeyPlain.endsWith('\n') ? privateKeyPlain : privateKeyPlain + '\n', {
        mode: 0o600,
      });
      fs.writeFileSync(pubKeyPath, params.certificate.publicKeyContent, { mode: 0o644 });
      fs.writeFileSync(certPath, params.certificate.certContent, { mode: 0o644 });

      const args = [
        '-i',
        privKeyPath,
        '-o',
        `CertificateFile=${certPath}`,
        '-o',
        'IdentitiesOnly=yes',
        '-o',
        'BatchMode=yes',
        '-o',
        'PasswordAuthentication=no',
        '-o',
        'KbdInteractiveAuthentication=no',
        '-o',
        'StrictHostKeyChecking=accept-new',
        '-o',
        'ConnectTimeout=10',
        '-p',
        String(params.port),
        `${params.sshUser}@${params.ipAddress}`,
        '--',
        params.command.command,
      ];

      const execResult = await new Promise<{ exitCode: number; stdout: string; stderr: string }>((resolve) => {
        execFile(
          sshBinary,
          args,
          {
            timeout: params.command.timeoutSec * 1000,
            maxBuffer: 4 * 1024 * 1024,
            env: {
              PATH: '/usr/bin:/bin',
              HOME: tempDir,
            },
          },
          (error, stdout, stderr) => {
            if (!error) {
              resolve({ exitCode: 0, stdout: stdout.toString(), stderr: stderr.toString() });
            } else {
              const code = typeof error.code === 'number' ? error.code : 255;
              resolve({
                exitCode: code,
                stdout: stdout.toString(),
                stderr: stderr.toString() || error.message,
              });
            }
          }
        );
      });

      return {
        mode: 'openssh-live',
        sshInvocation: displayInvocation,
        exitCode: execResult.exitCode,
        stdout: execResult.stdout,
        stderr: execResult.stderr,
        durationMs: Date.now() - started,
      };
    } finally {
      wipeAndRemoveDir(tempDir);
    }
  }

  // Sandbox / Dry-Run verification when /usr/bin/ssh is not present in preview container
  const meta = params.certificate.metadata;
  const principalAllowed =
    meta.principals.length === 0 || meta.principals.includes(params.sshUser);
  const probe = await probeTcpPort(params.ipAddress, params.port, 1800);

  const checks: string[] = [
    `[Prüfung] OpenSSH-Zertifikatspaket: ${params.certificate.name}`,
    `  · Privatschlüssel (0600): ${params.certificate.privateKeyFileName} (${meta.privateKeyFormat})`,
    `  · Öffentlicher Schlüssel (0644): ${params.certificate.publicKeyFileName} (${meta.pubKeyFingerprint})`,
    `  · Signiertes Zertifikat (0644): ${params.certificate.certFileName} (Key-ID: ${meta.keyId}, Serial: ${meta.serial})`,
    `  · Signierende CA: ${meta.caFingerprint}`,
    `  · Zertifizierte Principals: ${meta.principals.length ? meta.principals.join(', ') : '(alle)'}`,
    `  · Ziel-Benutzer "${params.sshUser}": ${principalAllowed ? 'OK (in Principals enthalten)' : 'FEHLER (nicht in Principals zugelassen)'}`,
    `  · Gültigkeit: ${meta.isExpired ? 'ABGELAUFEN' : meta.isNotYetValid ? 'NOCH NICHT GÜLTIG' : 'Gültig'}`,
    `  · TCP-Verbindungstest ${params.ipAddress}:${params.port}: ${
      probe.reachable
        ? `Erreichbar${probe.banner ? ` (${probe.banner})` : ''}`
        : `Nicht erreichbar (${probe.error ?? 'keine Antwort'})`
    }`,
    ...(params.command.kind === 'chain' && params.command.steps.length > 0
      ? [
          '',
          `[Befehlskette (${params.command.steps.length} Schritte · ${
            params.command.stopOnError ? 'Abbruch bei Fehler &&' : 'Fortfahren bei Fehler ;'
          } · als ein SSH-Befehl)]`,
          ...params.command.steps.flatMap((s, idx) => {
            const lines = [`  ${idx + 1}. ${s.command}`];
            if (idx < params.command.steps.length - 1 && s.sleepAfterSec > 0) {
              lines.push(`     ↳ sleep ${s.sleepAfterSec}s`);
            }
            return lines;
          }),
        ]
      : []),
    '',
    `[OpenSSH-Aufruf auf Debian Trixie]`,
    `  $ ${displayInvocation}`,
  ];

  const errLines: string[] = [];
  if (!sshBinary) {
    errLines.push(
      'Hinweis: In dieser Vorschau-Sandbox ist kein /usr/bin/ssh-Binary installiert. Die produktive Ausführung erfolgt über das Rust-Binary unter Debian Trixie (mit openssh-client).'
    );
  }
  if (meta.isExpired) {
    errLines.push('Zertifikatsprüfung fehlgeschlagen: zertifikat-cert.pub ist abgelaufen.');
  }
  if (!principalAllowed) {
    errLines.push(
      `Zertifikatsprüfung fehlgeschlagen: SSH-Benutzer "${params.sshUser}" ist nicht in den erlaubten Principals (${meta.principals.join(', ')}) enthalten.`
    );
  }

  const failedValidation = meta.isExpired || meta.isNotYetValid || !principalAllowed;

  return {
    mode: 'sandbox-dry-run',
    sshInvocation: displayInvocation,
    exitCode: failedValidation ? 255 : 0,
    stdout: checks.join('\n'),
    stderr: errLines.join('\n'),
    durationMs: Date.now() - started,
  };
}
