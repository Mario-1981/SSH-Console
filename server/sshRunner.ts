import { execFile } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { decryptSecret, type SshCommand, type UserCertificateBundle } from './store.ts';
import { getUserKnownHostsPath } from './knownHosts.ts';
import {
  executeWorkflowEngine,
  parseAndValidateWorkflow,
  resolveWorkflowRuntimeVars,
  type WorkflowStep,
} from '../src/workflowEngine.ts';

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

export interface SshExecutionResult {
  mode: 'openssh-live' | 'sandbox-dry-run';
  sshInvocation: string;
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
}

function summarizeWorkflowSteps(steps: WorkflowStep[], indent = '  '): string[] {
  const lines: string[] = [];
  steps.forEach((s, idx) => {
    const num = `${indent}${idx + 1}.`;
    if (s.type === 'run') {
      const idTag = s.id ? `[${s.id}] ` : '';
      const filterTag = s.filter ? ' (+filter)' : '';
      lines.push(`${num} RUN ${idTag}${s.command}${filterTag}`);
      if (s.sleepAfterSec && s.sleepAfterSec > 0) {
        lines.push(`${indent}   ↳ sleep ${s.sleepAfterSec}s`);
      }
    } else if (s.type === 'sleep') {
      lines.push(`${num} SLEEP ${s.seconds}s`);
    } else if (s.type === 'if') {
      lines.push(`${num} IF ${JSON.stringify(s.when)}`);
      lines.push(`${indent}   THEN:`);
      lines.push(...summarizeWorkflowSteps(s.then, `${indent}     `));
      if (s.else && s.else.length > 0) {
        lines.push(`${indent}   ELSE:`);
        lines.push(...summarizeWorkflowSteps(s.else, `${indent}     `));
      }
    } else if (s.type === 'loop') {
      const iv = s.intervalSec ? `, alle ${s.intervalSec}s` : '';
      lines.push(
        `${num} LOOP (max ${s.maxIterations}x${iv}${s.until ? `, bis ${JSON.stringify(s.until)}` : ''})`
      );
      lines.push(...summarizeWorkflowSteps(s.steps, `${indent}   `));
    } else if (s.type === 'set') {
      lines.push(`${num} SET ${s.name} = ${s.value}${s.filter ? ' (+filter)' : ''}`);
    } else if (s.type === 'log') {
      lines.push(`${num} LOG ${s.message}`);
    } else if (s.type === 'stop' || s.type === 'fail') {
      lines.push(`${num} ${s.type.toUpperCase()} (exit ${s.exitCode ?? (s.type === 'fail' ? 1 : 0)})${s.message ? `: ${s.message}` : ''}`);
    }
  });
  return lines;
}

export async function executeSshCommand(params: {
  userId: string;
  ipAddress: string;
  port: number;
  sshUser: string;
  serverLabel?: string;
  command: SshCommand;
  certificate: UserCertificateBundle;
  passphrase?: string;
  workflowVars?: Record<string, string>;
  ignoreHostKey?: boolean;
  forceDryRun?: boolean;
}): Promise<SshExecutionResult> {
  const started = Date.now();
  const sshBinary = findOpenSshBinary();
  const hasCert = Boolean(params.certificate.certContent && params.certificate.certContent.trim());
  const isWorkflow = params.command.kind === 'workflow';
  const displayHostKeyArgs = params.ignoreHostKey
    ? ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null']
    : ['-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=<known_hosts>'];

  const hasPassphraseConfigured = Boolean(
    (typeof params.passphrase === 'string' && params.passphrase.length > 0) ||
      params.certificate.passphraseEncrypted
  );

  const displayInvocation = [
    'ssh',
    '-i',
    '/tmp/trixiessh-XXXXXX/zertifikat',
    ...(hasCert ? ['-o', 'CertificateFile=/tmp/trixiessh-XXXXXX/zertifikat-cert.pub'] : []),
    '-o',
    'IdentitiesOnly=yes',
    '-o',
    hasPassphraseConfigured ? 'NumberOfPasswordPrompts=1' : 'BatchMode=yes',
    '-o',
    'PasswordAuthentication=no',
    '-o',
    'KbdInteractiveAuthentication=no',
    ...displayHostKeyArgs,
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
      if (hasCert) {
        fs.writeFileSync(certPath, params.certificate.certContent, { mode: 0o644 });
      }

      const effectivePassphrase =
        typeof params.passphrase === 'string' && params.passphrase.length > 0
          ? params.passphrase
          : params.certificate.passphraseEncrypted
            ? decryptSecret(params.certificate.passphraseEncrypted)
            : '';

      const useAskPass = Boolean(effectivePassphrase);
      const childEnv: Record<string, string> = {
        PATH: '/usr/bin:/bin',
        HOME: tempDir,
      };

      if (useAskPass) {
        const passPath = path.join(tempDir, 'passphrase');
        const askpassPath = path.join(tempDir, 'askpass.sh');
        fs.writeFileSync(passPath, `${effectivePassphrase}\n`, { mode: 0o600 });
        // Keep passfile until wipeAndRemoveDir() zeros and removes it in finally
        const askpassBody =
          '#!/bin/sh\nif [ -f "$TRIXIESSH_PASS_FILE" ]; then\n  cat "$TRIXIESSH_PASS_FILE"\nfi\n';
        fs.writeFileSync(askpassPath, askpassBody, { mode: 0o700 });
        childEnv.SSH_ASKPASS = askpassPath;
        childEnv.SSH_ASKPASS_REQUIRE = 'force';
        childEnv.DISPLAY = 'none:0';
        childEnv.TRIXIESSH_PASS_FILE = passPath;
      }

      const liveHostKeyArgs = params.ignoreHostKey
        ? ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null']
        : [
            '-o',
            'StrictHostKeyChecking=accept-new',
            '-o',
            `UserKnownHostsFile=${getUserKnownHostsPath(params.userId)}`,
            '-o',
            'HashKnownHosts=no',
          ];

      const baseArgs = [
        '-i',
        privKeyPath,
        ...(hasCert ? ['-o', `CertificateFile=${certPath}`] : []),
        '-o',
        'IdentitiesOnly=yes',
        // BatchMode=yes disables SSH_ASKPASS and NumberOfPasswordPrompts=0 skips the key passphrase loop;
        // use NumberOfPasswordPrompts=1 with PasswordAuthentication=no so SSH_ASKPASS unlocks the key once.
        ...(useAskPass ? ['-o', 'NumberOfPasswordPrompts=1'] : ['-o', 'BatchMode=yes']),
        '-o',
        'PasswordAuthentication=no',
        '-o',
        'KbdInteractiveAuthentication=no',
        ...liveHostKeyArgs,
        '-o',
        'ConnectTimeout=10',
        '-p',
        String(params.port),
        `${params.sshUser}@${params.ipAddress}`,
        '--',
      ];

      const runSingleRemote = (remoteCommand: string, timeoutMs: number) =>
        new Promise<{ exitCode: number; stdout: string; stderr: string }>((resolve) => {
          execFile(
            sshBinary,
            [...baseArgs, remoteCommand],
            {
              timeout: Math.max(1000, timeoutMs),
              maxBuffer: 4 * 1024 * 1024,
              env: childEnv,
            },
            (error, stdout, stderr) => {
              const cleanedStderr = filterBenignSshStderr(stderr.toString());
              if (!error) {
                resolve({ exitCode: 0, stdout: stdout.toString(), stderr: cleanedStderr });
              } else {
                const code = typeof error.code === 'number' ? error.code : 255;
                resolve({
                  exitCode: code,
                  stdout: stdout.toString(),
                  stderr: cleanedStderr || error.message,
                });
              }
            }
          );
        });

      if (isWorkflow) {
        const parsed = parseAndValidateWorkflow(params.command.workflowJson || '');
        if (!parsed.ok) {
          return {
            mode: 'openssh-live',
            sshInvocation: displayInvocation,
            exitCode: 2,
            stdout: '',
            stderr: `Ungültiger JSON-Workflow: ${parsed.error}`,
            durationMs: Date.now() - started,
          };
        }
        const wfRes = await executeWorkflowEngine({
          workflow: parsed.workflow,
          target: {
            ip: params.ipAddress,
            port: params.port,
            user: params.sshUser,
            label: params.serverLabel || params.ipAddress,
          },
          timeoutSec: params.command.timeoutSec,
          runtimeVars: params.workflowVars,
          runRemoteCommand: runSingleRemote,
        });

        const wfInvocation =
          wfRes.commandsRun.length > 0
            ? `[JSON-Workflow · ${wfRes.executedSteps} Schritte · ${wfRes.commandsRun.length} SSH-Befehle]\n${wfRes.commandsRun
                .map((c, i) => `  ${i + 1}. ssh ... ${params.sshUser}@${params.ipAddress} -- ${c}`)
                .join('\n')}`
            : displayInvocation;

        return {
          mode: 'openssh-live',
          sshInvocation: wfInvocation,
          exitCode: wfRes.exitCode,
          stdout: wfRes.stdout,
          stderr: wfRes.stderr,
          durationMs: Date.now() - started,
        };
      }

      const execResult = await runSingleRemote(params.command.command, params.command.timeoutSec * 1000);

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
    !hasCert || meta.principals.length === 0 || meta.principals.includes(params.sshUser);
  const probe = await probeTcpPort(params.ipAddress, params.port, 1800);

  const hasEffectivePassphrase = Boolean(
    (typeof params.passphrase === 'string' && params.passphrase.length > 0) ||
      params.certificate.passphraseEncrypted
  );

  const checks: string[] = [
    hasCert
      ? `[Prüfung] OpenSSH-Zertifikatspaket (3 Dateien): ${params.certificate.name}`
      : `[Prüfung] OpenSSH-Schlüsselpaar (2 Dateien, ohne CA-Zertifikat): ${params.certificate.name}`,
    `  · Privatschlüssel (0600): ${params.certificate.privateKeyFileName} (${meta.privateKeyFormat}${
      meta.privateKeyEncrypted
        ? hasEffectivePassphrase
          ? ' · passwortgeschützt, Entsperrung per SSH_ASKPASS bereit'
          : ' · passwortgeschützt, KEIN Passwort übergeben'
        : ''
    })`,
    `  · Öffentlicher Schlüssel (0644): ${params.certificate.publicKeyFileName} (${meta.pubKeyFingerprint})`,
    ...(hasCert
      ? [
          `  · Signiertes Zertifikat (0644): ${params.certificate.certFileName} (Key-ID: ${meta.keyId}, Serial: ${meta.serial})`,
          `  · Signierende CA: ${meta.caFingerprint}`,
          `  · Zertifizierte Principals: ${meta.principals.length ? meta.principals.join(', ') : '(alle)'}`,
          `  · Ziel-Benutzer "${params.sshUser}": ${principalAllowed ? 'OK (in Principals enthalten)' : 'FEHLER (nicht in Principals zugelassen)'}`,
          `  · Gültigkeit: ${meta.isExpired ? 'ABGELAUFEN' : meta.isNotYetValid ? 'NOCH NICHT GÜLTIG' : 'Gültig'}`,
        ]
      : [
          `  · Anmeldemodus: Klassische Public-Key-Authentifizierung (authorized_keys, ohne zertifikat-cert.pub)`,
        ]),
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
    ...(isWorkflow
      ? (() => {
          const parsed = parseAndValidateWorkflow(params.command.workflowJson || '');
          if (!parsed.ok) {
            return ['', `[JSON-Workflow ungültig: ${parsed.error}]`];
          }
          const resolvedVars = resolveWorkflowRuntimeVars(parsed.workflow, params.workflowVars);
          const varLines: string[] = [];
          if (!resolvedVars.ok) {
            varLines.push(`  · Variablen-Fehler: ${resolvedVars.error}`);
          } else {
            const entries = Object.entries(resolvedVars.vars);
            if (entries.length > 0) {
              const formattedVars = entries
                .map(([k, v]) => `${k}=${resolvedVars.secretKeys.has(k) ? '********' : v}`)
                .join(', ');
              varLines.push(`  · Variablen: ${formattedVars}`);
            }
          }
          return [
            '',
            `[Komplexe Befehlskette / ${parsed.summary.previewLine}]`,
            ...varLines,
            ...summarizeWorkflowSteps(parsed.workflow.steps),
            ...(parsed.workflow.output
              ? [`  ↳ Ausgabeformat: ${parsed.workflow.output.format ?? 'text'}`]
              : []),
          ];
        })()
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
  if (hasCert && meta.isExpired) {
    errLines.push('Zertifikatsprüfung fehlgeschlagen: zertifikat-cert.pub ist abgelaufen.');
  }
  if (hasCert && !principalAllowed) {
    errLines.push(
      `Zertifikatsprüfung fehlgeschlagen: SSH-Benutzer "${params.sshUser}" ist nicht in den erlaubten Principals (${meta.principals.join(', ')}) enthalten.`
    );
  }

  const failedValidation = hasCert && (meta.isExpired || meta.isNotYetValid || !principalAllowed);

  return {
    mode: 'sandbox-dry-run',
    sshInvocation: displayInvocation,
    exitCode: failedValidation ? 255 : 0,
    stdout: checks.join('\n'),
    stderr: errLines.join('\n'),
    durationMs: Date.now() - started,
  };
}
