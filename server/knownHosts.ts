import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const KNOWN_HOSTS_DIR = path.join(DATA_DIR, 'known_hosts');

function ensureKnownHostsDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  }
  if (!fs.existsSync(KNOWN_HOSTS_DIR)) {
    fs.mkdirSync(KNOWN_HOSTS_DIR, { recursive: true, mode: 0o700 });
  }
}

function sanitizeUserId(userId: string): string {
  const clean = userId.replace(/[^a-zA-Z0-9_-]/g, '_');
  if (!clean) {
    throw new Error('Ungültige Benutzer-ID für known_hosts.');
  }
  return clean;
}

export function getUserKnownHostsPath(userId: string): string {
  ensureKnownHostsDir();
  const filePath = path.join(KNOWN_HOSTS_DIR, `${sanitizeUserId(userId)}.known_hosts`);
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, '', { mode: 0o600 });
  }
  return filePath;
}

function findSshKeygenBinary(): string | null {
  for (const candidate of ['/usr/bin/ssh-keygen', '/bin/ssh-keygen', '/usr/local/bin/ssh-keygen']) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

export function countKnownHostEntriesInFile(filePath: string): number {
  if (!fs.existsSync(filePath)) return 0;
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    let count = 0;
    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      count += 1;
    }
    return count;
  } catch {
    return 0;
  }
}

function matchesHostToken(token: string, ipLower: string, port?: number): boolean {
  const clean = token.trim().toLowerCase();
  if (!clean) return false;

  if (port === undefined) {
    if (clean === ipLower) return true;
    if (clean.startsWith(`[${ipLower}]:`)) return true;
    return false;
  }

  if (port === 22) {
    return clean === ipLower || clean === `[${ipLower}]:22`;
  }
  return clean === `[${ipLower}]:${port}`;
}

function removeMatchingEntriesFromFile(
  filePath: string,
  ipAddress: string,
  port?: number
): { removedCount: number; remainingCount: number } {
  const cleanIp = ipAddress.trim();
  if (net.isIP(cleanIp) === 0) {
    throw new Error(`Ungültige IP-Adresse: "${ipAddress}"`);
  }
  if (!fs.existsSync(filePath)) {
    return { removedCount: 0, remainingCount: 0 };
  }

  const beforeCount = countKnownHostEntriesInFile(filePath);

  // Use OpenSSH ssh-keygen -R first when available (also removes hashed |1|... entries)
  const keygen = findSshKeygenBinary();
  if (keygen) {
    const targets: string[] = [];
    if (port === undefined || port === 22) {
      targets.push(cleanIp);
      targets.push(`[${cleanIp}]:22`);
    } else {
      targets.push(`[${cleanIp}]:${port}`);
    }
    for (const target of targets) {
      try {
        execFileSync(keygen, ['-R', target, '-f', filePath], {
          stdio: 'ignore',
          timeout: 5000,
        });
      } catch {
        // ignore if host wasn't present
      }
    }
    try {
      const oldBackup = `${filePath}.old`;
      if (fs.existsSync(oldBackup)) {
        fs.unlinkSync(oldBackup);
      }
    } catch {
      // ignore cleanup error
    }
  }

  // Also filter plain-text entries directly (handles custom ports, IPv6, comma-lists, and sandboxes without ssh-keygen)
  const ipLower = cleanIp.toLowerCase();
  const content = fs.readFileSync(filePath, 'utf8');
  const nextLines: string[] = [];

  for (const rawLine of content.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('#')) {
      nextLines.push(rawLine);
      continue;
    }

    // Handle optional @cert-authority / @revoked marker
    const parts = trimmed.split(/\s+/);
    let hostIdx = 0;
    if (parts[0]?.startsWith('@') && parts.length >= 4) {
      hostIdx = 1;
    }
    if (parts.length < hostIdx + 3) {
      nextLines.push(rawLine);
      continue;
    }

    const hostTokens = parts[hostIdx].split(',');
    const remainingTokens = hostTokens.filter((tok) => !matchesHostToken(tok, ipLower, port));

    if (remainingTokens.length === 0) {
      // Entire entry matched -> drop it
      continue;
    }
    if (remainingTokens.length !== hostTokens.length) {
      const rebuilt = [...parts];
      rebuilt[hostIdx] = remainingTokens.join(',');
      nextLines.push(rebuilt.join(' '));
    } else {
      nextLines.push(rawLine);
    }
  }

  const nextContent = nextLines.length > 0 ? `${nextLines.join('\n')}\n` : '';
  fs.writeFileSync(filePath, nextContent, { mode: 0o600 });

  const remainingCount = countKnownHostEntriesInFile(filePath);
  const removedCount = Math.max(0, beforeCount - remainingCount);
  return { removedCount, remainingCount };
}

export function removeUserHostKey(
  userId: string,
  ipAddress: string,
  port?: number
): { removedCount: number; remainingCount: number } {
  const filePath = getUserKnownHostsPath(userId);
  return removeMatchingEntriesFromFile(filePath, ipAddress, port);
}

function listKnownHostsFiles(): string[] {
  ensureKnownHostsDir();
  const files: string[] = [];
  try {
    for (const entry of fs.readdirSync(KNOWN_HOSTS_DIR)) {
      if (entry.endsWith('.known_hosts')) {
        files.push(path.join(KNOWN_HOSTS_DIR, entry));
      }
    }
  } catch {
    // ignore
  }
  const legacyFile = path.join(DATA_DIR, 'known_hosts.txt');
  if (fs.existsSync(legacyFile)) {
    files.push(legacyFile);
  }
  return files;
}

export function getGlobalKnownHostsStats(): { totalEntries: number; userFiles: number } {
  const files = listKnownHostsFiles();
  let totalEntries = 0;
  let userFiles = 0;
  for (const filePath of files) {
    const count = countKnownHostEntriesInFile(filePath);
    if (count > 0) {
      totalEntries += count;
      userFiles += 1;
    }
  }
  return { totalEntries, userFiles };
}

export function clearGlobalHostKeys(filter?: {
  ipAddress?: string;
  port?: number;
}): { removedCount: number; totalEntries: number; affectedFiles: number } {
  const files = listKnownHostsFiles();
  let removedCount = 0;
  let affectedFiles = 0;

  if (filter?.ipAddress) {
    for (const filePath of files) {
      const res = removeMatchingEntriesFromFile(filePath, filter.ipAddress, filter.port);
      if (res.removedCount > 0) {
        removedCount += res.removedCount;
        affectedFiles += 1;
      }
    }
    const stats = getGlobalKnownHostsStats();
    return { removedCount, totalEntries: stats.totalEntries, affectedFiles };
  }

  for (const filePath of files) {
    const count = countKnownHostEntriesInFile(filePath);
    if (count > 0) {
      removedCount += count;
      affectedFiles += 1;
    }
    try {
      fs.writeFileSync(filePath, '', { mode: 0o600 });
    } catch {
      // ignore
    }
  }
  return { removedCount, totalEntries: 0, affectedFiles };
}
