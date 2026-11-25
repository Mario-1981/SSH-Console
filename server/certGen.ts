import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';

const require = createRequire(import.meta.url);
const bcryptPbkdf = require('bcrypt-pbkdf') as {
  pbkdf: (
    pass: Uint8Array,
    passlen: number,
    salt: Uint8Array,
    saltlen: number,
    key: Uint8Array,
    keylen: number,
    rounds: number
  ) => number;
};

function writeUInt32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

function writeUInt64(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(n & 0xffffffffffffffffn, 0);
  return b;
}

function writeSshString(data: Buffer | string): Buffer {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return Buffer.concat([writeUInt32(buf.length), buf]);
}

function writeSshMpint(raw: Buffer): Buffer {
  let start = 0;
  while (start < raw.length && raw[start] === 0) {
    start++;
  }
  const trimmed = raw.subarray(start);
  if (trimmed.length === 0) {
    return writeSshString(Buffer.alloc(0));
  }
  if ((trimmed[0] & 0x80) !== 0) {
    return writeSshString(Buffer.concat([Buffer.from([0x00]), trimmed]));
  }
  return writeSshString(trimmed);
}

class WireReader {
  private offset = 0;
  constructor(private readonly buf: Buffer) {}

  remaining(): number {
    return this.buf.length - this.offset;
  }

  readUInt32(): number {
    if (this.offset + 4 > this.buf.length) {
      throw new Error('Unerwartetes Ende im OpenSSH-Schlüsselformat.');
    }
    const v = this.buf.readUInt32BE(this.offset);
    this.offset += 4;
    return v;
  }

  readString(): Buffer {
    const len = this.readUInt32();
    if (this.offset + len > this.buf.length) {
      throw new Error('Unerwartetes Ende beim Lesen eines OpenSSH-Feldes.');
    }
    const slice = this.buf.subarray(this.offset, this.offset + len);
    this.offset += len;
    return slice;
  }

  readUtf8(): string {
    return this.readString().toString('utf8');
  }
}

function extractEd25519Raw(keypair: crypto.KeyPairKeyObjectResult): {
  pub32: Buffer;
  priv32: Buffer;
} {
  // SPKI DER for Ed25519 ends with the 32-byte public key
  const spki = keypair.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const pub32 = spki.subarray(spki.length - 32);

  // PKCS8 DER for Ed25519 ends with the 32-byte private seed
  const pkcs8 = keypair.privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
  const priv32 = pkcs8.subarray(pkcs8.length - 32);

  return { pub32, priv32 };
}

function buildEd25519PubBlob(pub32: Buffer): Buffer {
  return Buffer.concat([writeSshString('ssh-ed25519'), writeSshString(pub32)]);
}

function buildOpenSshPrivateKey(
  pub32: Buffer,
  priv32: Buffer,
  comment: string,
  passphrase?: string
): string {
  const pubBlob = buildEd25519PubBlob(pub32);
  const checkInt = crypto.randomBytes(4).readUInt32BE(0);
  const priv64 = Buffer.concat([priv32, pub32]);

  const unpaddedPrivate = Buffer.concat([
    writeUInt32(checkInt),
    writeUInt32(checkInt),
    writeSshString('ssh-ed25519'),
    writeSshString(pub32),
    writeSshString(priv64),
    writeSshString(comment),
  ]);

  const useEncryption = typeof passphrase === 'string' && passphrase.length > 0;
  // OpenSSH block padding: 8-byte block for "none", 16-byte block for "aes256-ctr"
  const blockSize = useEncryption ? 16 : 8;
  const padLen = (blockSize - (unpaddedPrivate.length % blockSize)) % blockSize;
  const padBytes = Buffer.alloc(padLen);
  for (let i = 0; i < padLen; i++) {
    padBytes[i] = i + 1;
  }
  const plainPrivateSection = Buffer.concat([unpaddedPrivate, padBytes]);

  let cipherName = 'none';
  let kdfName = 'none';
  let kdfOptions: Buffer = Buffer.alloc(0);
  let privateSection: Buffer = plainPrivateSection;

  if (useEncryption) {
    const rounds = 16;
    const salt = crypto.randomBytes(16);
    const passBytes = Buffer.from(passphrase, 'utf8');
    const keyAndIv = new Uint8Array(48); // 32-byte AES-256 key + 16-byte CTR IV
    const rc = bcryptPbkdf.pbkdf(
      passBytes,
      passBytes.length,
      salt,
      salt.length,
      keyAndIv,
      keyAndIv.length,
      rounds
    );
    if (rc !== 0) {
      passBytes.fill(0);
      keyAndIv.fill(0);
      throw new Error('Schlüsselableitung (bcrypt-pbkdf) für OpenSSH-Passwort fehlgeschlagen.');
    }

    const key = Buffer.from(keyAndIv.subarray(0, 32));
    const iv = Buffer.from(keyAndIv.subarray(32, 48));
    try {
      const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
      privateSection = Buffer.concat([cipher.update(plainPrivateSection), cipher.final()]);
      cipherName = 'aes256-ctr';
      kdfName = 'bcrypt';
      kdfOptions = Buffer.concat([writeSshString(salt), writeUInt32(rounds)]);
    } finally {
      passBytes.fill(0);
      keyAndIv.fill(0);
      key.fill(0);
      iv.fill(0);
    }
  }

  const fullBlob = Buffer.concat([
    Buffer.from('openssh-key-v1\0', 'utf8'),
    writeSshString(cipherName),
    writeSshString(kdfName),
    writeSshString(kdfOptions),
    writeUInt32(1), // number of keys
    writeSshString(pubBlob),
    writeSshString(privateSection),
  ]);

  const b64 = fullBlob.toString('base64');
  const wrapped = b64.match(/.{1,70}/g)?.join('\n') ?? b64;
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${wrapped}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

export interface GeneratedOpenSshKeypair {
  privateKey: string;
  publicKey: string;
}

/**
 * Generates an OpenSSH Ed25519 keypair (zertifikat + zertifikat.pub) without a CA certificate.
 * If a non-empty passphrase is provided, the private key is encrypted using standard
 * OpenSSH v1 format (aes256-ctr + bcrypt KDF, 16 rounds).
 */
export function generateOpenSshKeypair(params: {
  keyId: string;
  passphrase?: string;
}): GeneratedOpenSshKeypair {
  const userKp = crypto.generateKeyPairSync('ed25519');
  const userRaw = extractEd25519Raw(userKp);
  const userPubBlob = buildEd25519PubBlob(userRaw.pub32);

  const comment = `${params.keyId}@trixiessh`;
  const privateKey = buildOpenSshPrivateKey(
    userRaw.pub32,
    userRaw.priv32,
    comment,
    params.passphrase
  );
  const publicKey = `ssh-ed25519 ${userPubBlob.toString('base64')} ${comment}\n`;

  return {
    privateKey,
    publicKey,
  };
}

const PRINCIPAL_RE = /^[a-zA-Z0-9_@.-]{1,64}$/;

export function parseAndValidatePrincipals(input: unknown): string[] {
  let rawItems: string[] = [];
  if (Array.isArray(input)) {
    rawItems = input.map((v) => String(v ?? ''));
  } else if (typeof input === 'string') {
    rawItems = input.split(/[,;\n\r]+/);
  } else {
    throw new Error('Bitte mindestens einen Principal (-n) angeben (z. B. root oder admin).');
  }

  const seen = new Set<string>();
  const principals: string[] = [];
  for (const raw of rawItems) {
    const trimmed = raw.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('-') || !PRINCIPAL_RE.test(trimmed)) {
      throw new Error(
        `Ungültiger Principal (-n): „${trimmed}“. Erlaubt sind Buchstaben, Ziffern, Punkt, Unterstrich, Bindestrich (nicht am Anfang) und @ (max. 64 Zeichen).`
      );
    }
    if (!seen.has(trimmed)) {
      seen.add(trimmed);
      principals.push(trimmed);
    }
  }

  if (principals.length === 0) {
    throw new Error('Bitte mindestens einen Principal (-n) angeben (z. B. root oder admin).');
  }
  if (principals.length > 32) {
    throw new Error('Maximal 32 Principals (-n) pro Zertifikat sind zulässig.');
  }
  return principals;
}

export function isValidPrincipalToken(value: string): boolean {
  const trimmed = value.trim();
  return trimmed.length > 0 && !trimmed.startsWith('-') && PRINCIPAL_RE.test(trimmed);
}

const UNIT_SECONDS: Record<string, number> = {
  s: 1,
  m: 60,
  h: 3600,
  d: 86400,
  w: 604800,
};

export interface ParsedValidity {
  normalizedSpec: string;
  validAfterSec: bigint;
  validBeforeSec: bigint;
}

export function parseValidityDuration(rawInput: unknown): ParsedValidity {
  const raw = typeof rawInput === 'string' && rawInput.trim() ? rawInput.trim() : '+30d';
  const lower = raw.toLowerCase();

  if (lower === 'forever' || lower === 'always' || lower === 'always:forever') {
    return {
      normalizedSpec: 'always:forever',
      validAfterSec: 0n,
      validBeforeSec: 0xffffffffffffffffn,
    };
  }

  const nowSec = BigInt(Math.floor(Date.now() / 1000));
  const maxDurationSec = 100 * 365 * 86400; // 100 years

  const simpleMatch = /^\+(\d+)([smhdw])$/i.exec(raw);
  if (simpleMatch) {
    const amount = Number(simpleMatch[1]);
    const unit = simpleMatch[2].toLowerCase();
    const durationSec = amount * UNIT_SECONDS[unit];
    if (!Number.isFinite(durationSec) || durationSec < 60 || durationSec > maxDurationSec) {
      throw new Error(
        'Ungültige Gültigkeitsdauer (-V): Bitte einen Wert zwischen +60s und +36500d angeben.'
      );
    }
    return {
      normalizedSpec: `+${amount}${unit}`,
      validAfterSec: nowSec > 300n ? nowSec - 300n : 0n,
      validBeforeSec: nowSec + BigInt(durationSec),
    };
  }

  const rangeMatch = /^-(\d+)([smhdw]):\+(\d+)([smhdw])$/i.exec(raw);
  if (rangeMatch) {
    const backAmt = Number(rangeMatch[1]);
    const backUnit = rangeMatch[2].toLowerCase();
    const fwdAmt = Number(rangeMatch[3]);
    const fwdUnit = rangeMatch[4].toLowerCase();
    const backSec = backAmt * UNIT_SECONDS[backUnit];
    const fwdSec = fwdAmt * UNIT_SECONDS[fwdUnit];
    if (
      !Number.isFinite(backSec) ||
      !Number.isFinite(fwdSec) ||
      backSec > maxDurationSec ||
      fwdSec < 60 ||
      fwdSec > maxDurationSec
    ) {
      throw new Error('Ungültige Gültigkeitsdauer (-V).');
    }
    return {
      normalizedSpec: `-${backAmt}${backUnit}:+${fwdAmt}${fwdUnit}`,
      validAfterSec: nowSec > BigInt(backSec) ? nowSec - BigInt(backSec) : 0n,
      validBeforeSec: nowSec + BigInt(fwdSec),
    };
  }

  throw new Error(
    `Ungültige Gültigkeitsdauer (-V): „${raw}“. Erlaubt sind z. B. +8h, +24h, +7d, +30d, +52w oder forever.`
  );
}

export function sanitizeKeyId(raw: string, fallback = 'ssh-cert'): string {
  const cleaned = raw
    .trim()
    .replace(/[^a-zA-Z0-9_@.:/ -]+/g, '-')
    .replace(/^-+/, '')
    .trim()
    .slice(0, 128);
  return cleaned || fallback;
}

export function deriveCertFileName(
  existingCertFileName: string | undefined,
  publicKeyFileName: string | undefined,
  privateKeyFileName: string | undefined
): string {
  if (existingCertFileName && existingCertFileName.trim()) {
    return existingCertFileName.trim();
  }
  const pub = (publicKeyFileName || '').trim();
  if (pub.toLowerCase().endsWith('.pub') && pub.length > 4) {
    return `${pub.slice(0, -4)}-cert.pub`;
  }
  const priv = (privateKeyFileName || 'zertifikat').trim();
  return `${priv || 'zertifikat'}-cert.pub`;
}

export function extractFingerprintToken(raw: string | undefined | null): string {
  if (!raw) return '';
  const shaMatch = /SHA256:[A-Za-z0-9+/=]+/i.exec(raw);
  if (shaMatch) {
    const body = shaMatch[0].slice('SHA256:'.length).replace(/=+$/, '');
    return `SHA256:${body}`;
  }
  const md5Match = /MD5:[0-9a-f:]+/i.exec(raw);
  if (md5Match) {
    return md5Match[0].toLowerCase();
  }
  return raw.trim();
}

export function isSignedBySameCa(
  existingCertCaFingerprint: string | undefined | null,
  selectedCaFingerprint: string | undefined | null
): boolean {
  const a = extractFingerprintToken(existingCertCaFingerprint);
  const b = extractFingerprintToken(selectedCaFingerprint);
  return Boolean(a && b && a === b);
}

function findSshKeygenBinary(): string | null {
  for (const candidate of ['/usr/bin/ssh-keygen', '/bin/ssh-keygen', '/usr/local/bin/ssh-keygen']) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function wipeAndRemoveSignDir(dir: string) {
  for (const name of ['ca', 'passphrase', 'askpass.sh']) {
    try {
      const target = path.join(dir, name);
      if (fs.existsSync(target)) {
        const size = fs.statSync(target).size;
        fs.writeFileSync(target, Buffer.alloc(Math.max(size, 16), 0));
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

function parseSshPubKeyLine(content: string, label: string): { type: string; blob: Buffer } {
  const line = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => l.length > 0 && !l.startsWith('#'));
  if (!line) throw new Error(`${label} ist leer.`);
  const parts = line.split(/\s+/);
  if (parts.length < 2) throw new Error(`${label} hat kein gültiges OpenSSH-Format.`);
  const type = parts[0];
  const blob = Buffer.from(parts[1], 'base64');
  if (blob.length < 16) throw new Error(`${label} enthält ungültige Base64-Daten.`);
  return { type, blob };
}

function toBase64Url(buf: Buffer): string {
  let start = 0;
  while (start < buf.length - 1 && buf[start] === 0) {
    start++;
  }
  return buf.subarray(start).toString('base64url');
}

function bigIntFromBuf(buf: Buffer): bigint {
  if (buf.length === 0) return 0n;
  return BigInt('0x' + buf.toString('hex'));
}

function bigIntToBuf(n: bigint): Buffer {
  let hex = n.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
}

interface DecryptedCaKey {
  keyObject: crypto.KeyObject;
  sshType: string;
}

function decryptCaPrivateKeyNative(caPrivateKeyPem: string, passphrase: string): DecryptedCaKey {
  const trimmed = caPrivateKeyPem.trim();

  // Standard encrypted PEM (PKCS#8 / RSA / EC)
  if (!trimmed.includes('-----BEGIN OPENSSH PRIVATE KEY-----')) {
    try {
      const keyObject = crypto.createPrivateKey({ key: trimmed, passphrase });
      const asym = keyObject.asymmetricKeyType;
      if (asym === 'ed25519') return { keyObject, sshType: 'ssh-ed25519' };
      if (asym === 'rsa') return { keyObject, sshType: 'ssh-rsa' };
      if (asym === 'ec') {
        const curve = keyObject.asymmetricKeyDetails?.namedCurve;
        if (curve === 'prime256v1' || curve === 'P-256') {
          return { keyObject, sshType: 'ecdsa-sha2-nistp256' };
        }
        if (curve === 'secp384r1' || curve === 'P-384') {
          return { keyObject, sshType: 'ecdsa-sha2-nistp384' };
        }
        if (curve === 'secp521r1' || curve === 'P-521') {
          return { keyObject, sshType: 'ecdsa-sha2-nistp521' };
        }
      }
      throw new Error(`CA-Schlüsseltyp (${asym || 'unbekannt'}) wird nicht unterstützt.`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : '';
      if (/bad decrypt|wrong final block|passphrase|unsupported/i.test(msg)) {
        throw new Error('CA-Schlüssel konnte nicht entsperrt werden (falsches CA-Passwort?).');
      }
      throw new Error(`CA-Schlüssel konnte nicht geladen werden: ${msg || 'Unbekannter Fehler'}`);
    }
  }

  // OpenSSH v1 format
  const base64Body = trimmed
    .replace(/-----BEGIN OPENSSH PRIVATE KEY-----/, '')
    .replace(/-----END OPENSSH PRIVATE KEY-----/, '')
    .replace(/\s+/g, '');
  const raw = Buffer.from(base64Body, 'base64');
  const magic = 'openssh-key-v1\0';
  if (raw.subarray(0, magic.length).toString('utf8') !== magic) {
    throw new Error('Ungültiger OpenSSH-CA-Privatschlüssel.');
  }

  const reader = new WireReader(raw.subarray(magic.length));
  const cipherName = reader.readUtf8();
  const kdfName = reader.readUtf8();
  const kdfOptions = reader.readString();
  const numKeys = reader.readUInt32();
  if (numKeys < 1) {
    throw new Error('OpenSSH-CA-Privatschlüssel enthält keinen Schlüssel.');
  }
  reader.readString(); // embedded public key blob
  const encryptedSection = reader.readString();

  let decrypted: Buffer;
  if (cipherName === 'none' && kdfName === 'none') {
    decrypted = encryptedSection;
  } else {
    if (kdfName !== 'bcrypt') {
      throw new Error(`Nicht unterstützte OpenSSH-KDF für CA-Schlüssel: ${kdfName}`);
    }
    if (!passphrase) {
      throw new Error('Für diese CA ist ein CA-Passwort zum Signieren erforderlich.');
    }

    const kdfReader = new WireReader(kdfOptions);
    const salt = kdfReader.readString();
    const rounds = kdfReader.readUInt32();

    const cipherSpec: Record<
      string,
      { nodeAlgo: string; keyLen: number; ivLen: number; isGcm?: boolean }
    > = {
      'aes256-ctr': { nodeAlgo: 'aes-256-ctr', keyLen: 32, ivLen: 16 },
      'aes192-ctr': { nodeAlgo: 'aes-192-ctr', keyLen: 24, ivLen: 16 },
      'aes128-ctr': { nodeAlgo: 'aes-128-ctr', keyLen: 16, ivLen: 16 },
      'aes256-cbc': { nodeAlgo: 'aes-256-cbc', keyLen: 32, ivLen: 16 },
      'aes128-cbc': { nodeAlgo: 'aes-128-cbc', keyLen: 16, ivLen: 16 },
      'aes256-gcm@openssh.com': { nodeAlgo: 'aes-256-gcm', keyLen: 32, ivLen: 12, isGcm: true },
    };
    const spec = cipherSpec[cipherName];
    if (!spec) {
      throw new Error(`Nicht unterstützte CA-Schlüssel-Verschlüsselung: ${cipherName}`);
    }

    const passBytes = Buffer.from(passphrase, 'utf8');
    const derived = new Uint8Array(spec.keyLen + spec.ivLen);
    const rc = bcryptPbkdf.pbkdf(
      passBytes,
      passBytes.length,
      salt,
      salt.length,
      derived,
      derived.length,
      rounds
    );
    passBytes.fill(0);
    if (rc !== 0) {
      derived.fill(0);
      throw new Error('Schlüsselableitung für CA-Passwort fehlgeschlagen.');
    }

    const key = Buffer.from(derived.subarray(0, spec.keyLen));
    const iv = Buffer.from(derived.subarray(spec.keyLen, spec.keyLen + spec.ivLen));
    derived.fill(0);

    try {
      if (spec.isGcm) {
        if (encryptedSection.length < 16) {
          throw new Error('CA-Schlüssel konnte nicht entsperrt werden (falsches CA-Passwort?).');
        }
        const ciphertext = encryptedSection.subarray(0, encryptedSection.length - 16);
        const authTag = encryptedSection.subarray(encryptedSection.length - 16);
        const decipher = crypto.createDecipheriv(
          spec.nodeAlgo as crypto.CipherGCMTypes,
          key,
          iv
        );
        decipher.setAuthTag(authTag);
        decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      } else {
        const decipher = crypto.createDecipheriv(spec.nodeAlgo, key, iv);
        decipher.setAutoPadding(false);
        decrypted = Buffer.concat([decipher.update(encryptedSection), decipher.final()]);
      }
    } catch {
      throw new Error('CA-Schlüssel konnte nicht entsperrt werden (falsches CA-Passwort?).');
    } finally {
      key.fill(0);
      iv.fill(0);
    }
  }

  const privReader = new WireReader(decrypted);
  const check1 = privReader.readUInt32();
  const check2 = privReader.readUInt32();
  if (check1 !== check2) {
    decrypted.fill(0);
    throw new Error('CA-Schlüssel konnte nicht entsperrt werden (falsches CA-Passwort?).');
  }

  const keyType = privReader.readUtf8();
  try {
    if (keyType === 'ssh-ed25519') {
      privReader.readString(); // pub32
      const priv64 = privReader.readString();
      if (priv64.length < 32) {
        throw new Error('Ungültige Ed25519-CA-Schlüsseldaten.');
      }
      const seed32 = priv64.subarray(0, 32);
      const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
      const pkcs8Der = Buffer.concat([pkcs8Prefix, seed32]);
      const keyObject = crypto.createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
      pkcs8Der.fill(0);
      return { keyObject, sshType: 'ssh-ed25519' };
    }

    if (keyType === 'ssh-rsa') {
      const nBuf = privReader.readString();
      const eBuf = privReader.readString();
      const dBuf = privReader.readString();
      const iqmpBuf = privReader.readString();
      const pBuf = privReader.readString();
      const qBuf = privReader.readString();

      const dBig = bigIntFromBuf(dBuf);
      const pBig = bigIntFromBuf(pBuf);
      const qBig = bigIntFromBuf(qBuf);
      const dpBuf = bigIntToBuf(dBig % (pBig - 1n));
      const dqBuf = bigIntToBuf(dBig % (qBig - 1n));

      const keyObject = crypto.createPrivateKey({
        key: {
          kty: 'RSA',
          n: toBase64Url(nBuf),
          e: toBase64Url(eBuf),
          d: toBase64Url(dBuf),
          p: toBase64Url(pBuf),
          q: toBase64Url(qBuf),
          dp: toBase64Url(dpBuf),
          dq: toBase64Url(dqBuf),
          qi: toBase64Url(iqmpBuf),
        },
        format: 'jwk',
      });
      return { keyObject, sshType: 'ssh-rsa' };
    }

    if (
      keyType === 'ecdsa-sha2-nistp256' ||
      keyType === 'ecdsa-sha2-nistp384' ||
      keyType === 'ecdsa-sha2-nistp521'
    ) {
      privReader.readString(); // curve name
      const qBuf = privReader.readString(); // 0x04 || X || Y
      const dBuf = privReader.readString();
      const coordLen = keyType === 'ecdsa-sha2-nistp256' ? 32 : keyType === 'ecdsa-sha2-nistp384' ? 48 : 66;
      const crv = keyType === 'ecdsa-sha2-nistp256' ? 'P-256' : keyType === 'ecdsa-sha2-nistp384' ? 'P-384' : 'P-521';
      if (qBuf.length !== 1 + coordLen * 2 || qBuf[0] !== 0x04) {
        throw new Error('Ungültiger ECDSA-CA-Schlüsselpunkt.');
      }
      const x = qBuf.subarray(1, 1 + coordLen);
      const y = qBuf.subarray(1 + coordLen, 1 + coordLen * 2);
      let dPadded = dBuf;
      while (dPadded.length > coordLen && dPadded[0] === 0) {
        dPadded = dPadded.subarray(1);
      }
      if (dPadded.length < coordLen) {
        dPadded = Buffer.concat([Buffer.alloc(coordLen - dPadded.length, 0), dPadded]);
      }
      const keyObject = crypto.createPrivateKey({
        key: {
          kty: 'EC',
          crv,
          x: x.toString('base64url'),
          y: y.toString('base64url'),
          d: dPadded.toString('base64url'),
        },
        format: 'jwk',
      });
      return { keyObject, sshType: keyType };
    }

    throw new Error(`CA-Schlüsseltyp „${keyType}“ wird nicht unterstützt.`);
  } finally {
    decrypted.fill(0);
  }
}

function mapPubAlgoToCertAlgo(pubType: string): string {
  switch (pubType) {
    case 'ssh-ed25519':
      return 'ssh-ed25519-cert-v01@openssh.com';
    case 'ssh-rsa':
      return 'ssh-rsa-cert-v01@openssh.com';
    case 'ecdsa-sha2-nistp256':
      return 'ecdsa-sha2-nistp256-cert-v01@openssh.com';
    case 'ecdsa-sha2-nistp384':
      return 'ecdsa-sha2-nistp384-cert-v01@openssh.com';
    case 'ecdsa-sha2-nistp521':
      return 'ecdsa-sha2-nistp521-cert-v01@openssh.com';
    case 'sk-ssh-ed25519@openssh.com':
      return 'sk-ssh-ed25519-cert-v01@openssh.com';
    default:
      throw new Error(`Öffentlicher Schlüsseltyp „${pubType}“ wird für die CA-Signierung nicht unterstützt.`);
  }
}

function buildDefaultUserExtensions(): Buffer {
  const names = [
    'permit-X11-forwarding',
    'permit-agent-forwarding',
    'permit-port-forwarding',
    'permit-pty',
    'permit-user-rc',
  ];
  return Buffer.concat(names.map((name) => Buffer.concat([writeSshString(name), writeSshString(Buffer.alloc(0))])));
}

function signPayloadWithCa(ca: DecryptedCaKey, toBeSigned: Buffer): Buffer {
  if (ca.sshType === 'ssh-ed25519') {
    const sig = crypto.sign(null, toBeSigned, ca.keyObject);
    return Buffer.concat([writeSshString('ssh-ed25519'), writeSshString(sig)]);
  }
  if (ca.sshType === 'ssh-rsa') {
    const sig = crypto.sign('sha512', toBeSigned, ca.keyObject);
    return Buffer.concat([writeSshString('rsa-sha2-512'), writeSshString(sig)]);
  }
  if (
    ca.sshType === 'ecdsa-sha2-nistp256' ||
    ca.sshType === 'ecdsa-sha2-nistp384' ||
    ca.sshType === 'ecdsa-sha2-nistp521'
  ) {
    const hash =
      ca.sshType === 'ecdsa-sha2-nistp256'
        ? 'sha256'
        : ca.sshType === 'ecdsa-sha2-nistp384'
          ? 'sha384'
          : 'sha512';
    const sigRaw = crypto.sign(hash, toBeSigned, {
      key: ca.keyObject,
      dsaEncoding: 'ieee-p1363',
    });
    const half = sigRaw.length / 2;
    const r = sigRaw.subarray(0, half);
    const s = sigRaw.subarray(half);
    const rsBlob = Buffer.concat([writeSshMpint(r), writeSshMpint(s)]);
    return Buffer.concat([writeSshString(ca.sshType), writeSshString(rsBlob)]);
  }
  throw new Error(`Signaturalgorithmus für CA-Typ „${ca.sshType}“ nicht unterstützt.`);
}

function signOpenSshUserCertificateNative(params: {
  caPrivateKey: string;
  caPublicKey: string;
  caPassphrase: string;
  userPublicKey: string;
  keyId: string;
  principals: string[];
  validity: ParsedValidity;
  serial: bigint;
}): string {
  const ca = decryptCaPrivateKeyNative(params.caPrivateKey, params.caPassphrase);
  const caPub = parseSshPubKeyLine(params.caPublicKey, 'Öffentlicher CA-Schlüssel (ca.pub)');
  const userPub = parseSshPubKeyLine(params.userPublicKey, 'Öffentlicher Benutzerschlüssel (zertifikat.pub)');

  const certAlgo = mapPubAlgoToCertAlgo(userPub.type);

  // Extract the raw public key fields after the leading algorithm string
  const pubReader = new WireReader(userPub.blob);
  const embeddedAlgo = pubReader.readUtf8();
  if (embeddedAlgo !== userPub.type) {
    throw new Error('Algorithmus-Abweichung im öffentlichen Benutzerschlüssel.');
  }
  const keyBodyStart = 4 + Buffer.byteLength(embeddedAlgo, 'utf8');
  const userPubKeyBody = userPub.blob.subarray(keyBodyStart);

  const principalsBuf = Buffer.concat(params.principals.map((p) => writeSshString(p)));
  const extensionsBuf = buildDefaultUserExtensions();

  const toBeSigned = Buffer.concat([
    writeSshString(certAlgo),
    writeSshString(crypto.randomBytes(32)),
    userPubKeyBody,
    writeUInt64(params.serial),
    writeUInt32(1), // SSH_CERT_TYPE_USER
    writeSshString(params.keyId),
    writeSshString(principalsBuf),
    writeUInt64(params.validity.validAfterSec),
    writeUInt64(params.validity.validBeforeSec),
    writeSshString(Buffer.alloc(0)), // critical options
    writeSshString(extensionsBuf),
    writeSshString(Buffer.alloc(0)), // reserved
    writeSshString(caPub.blob),
  ]);

  const sigBlob = signPayloadWithCa(ca, toBeSigned);
  const finalCertBlob = Buffer.concat([toBeSigned, writeSshString(sigBlob)]);
  return `${certAlgo} ${finalCertBlob.toString('base64')} ${params.keyId}\n`;
}

async function signOpenSshUserCertificateViaKeygen(
  keygenBin: string,
  params: {
    caPrivateKey: string;
    caPublicKey: string;
    caPassphrase: string;
    userPublicKey: string;
    keyId: string;
    principals: string[];
    validity: ParsedValidity;
    serial: bigint;
  }
): Promise<string> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trixiessh-sign-'));
  fs.chmodSync(tmpDir, 0o700);
  try {
    const caPath = path.join(tmpDir, 'ca');
    const caPubPath = path.join(tmpDir, 'ca.pub');
    const targetPubPath = path.join(tmpDir, 'target.pub');
    const targetCertPath = path.join(tmpDir, 'target-cert.pub');
    const passPath = path.join(tmpDir, 'passphrase');
    const askpassPath = path.join(tmpDir, 'askpass.sh');

    const caText = params.caPrivateKey.endsWith('\n')
      ? params.caPrivateKey
      : params.caPrivateKey + '\n';
    fs.writeFileSync(caPath, caText, { mode: 0o600 });
    fs.writeFileSync(caPubPath, params.caPublicKey.trim() + '\n', { mode: 0o644 });
    fs.writeFileSync(targetPubPath, params.userPublicKey.trim() + '\n', { mode: 0o644 });

    const env: NodeJS.ProcessEnv = {
      PATH: '/usr/bin:/bin:/usr/local/bin',
      HOME: tmpDir,
    };

    if (params.caPassphrase) {
      fs.writeFileSync(passPath, params.caPassphrase + '\n', { mode: 0o600 });
      fs.writeFileSync(askpassPath, '#!/bin/sh\ncat "$TRIXIESSH_PASS_FILE"\n', { mode: 0o700 });
      env.SSH_ASKPASS = askpassPath;
      env.SSH_ASKPASS_REQUIRE = 'force';
      env.DISPLAY = 'none:0';
      env.TRIXIESSH_PASS_FILE = passPath;
    }

    const args = [
      '-s',
      caPath,
      '-I',
      params.keyId,
      '-n',
      params.principals.join(','),
      '-V',
      params.validity.normalizedSpec,
      '-z',
      params.serial.toString(),
      targetPubPath,
    ];

    await new Promise<void>((resolve, reject) => {
      execFile(keygenBin, args, { env, timeout: 15000 }, (err, _stdout, stderr) => {
        if (err) {
          const text = String(stderr || err.message || '').trim();
          if (/incorrect passphrase|load key|bad passphrase|cannot decode/i.test(text)) {
            reject(new Error('CA-Schlüssel konnte nicht entsperrt werden (falsches CA-Passwort?).'));
            return;
          }
          reject(new Error(`ssh-keygen Signierung fehlgeschlagen: ${text || err.message}`));
          return;
        }
        resolve();
      });
    });

    if (!fs.existsSync(targetCertPath)) {
      throw new Error('Signiertes Zertifikat (target-cert.pub) wurde von ssh-keygen nicht erzeugt.');
    }
    return fs.readFileSync(targetCertPath, 'utf8').trim() + '\n';
  } finally {
    wipeAndRemoveSignDir(tmpDir);
  }
}

export async function signOpenSshUserCertificate(params: {
  caPrivateKey: string;
  caPublicKey: string;
  caPassphrase: string;
  userPublicKey: string;
  keyId: string;
  principals: string[];
  validity: ParsedValidity;
  serial?: bigint;
}): Promise<string> {
  const serial = params.serial ?? BigInt(Date.now());
  const keygenBin = findSshKeygenBinary();
  if (keygenBin) {
    return signOpenSshUserCertificateViaKeygen(keygenBin, { ...params, serial });
  }
  return signOpenSshUserCertificateNative({ ...params, serial });
}

