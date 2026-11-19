import crypto from 'node:crypto';

export interface ParsedCertMetadata {
  hasCertificate: boolean;
  certAlgorithm: string;
  pubKeyAlgorithm: string;
  serial: string;
  certType: 'user' | 'host' | 'keypair' | 'unknown';
  keyId: string;
  principals: string[];
  validAfter: string;
  validBefore: string;
  validAfterUnix: number;
  validBeforeUnix: number;
  isExpired: boolean;
  isNotYetValid: boolean;
  criticalOptions: string[];
  extensions: string[];
  pubKeyFingerprint: string;
  caFingerprint: string;
  privateKeyFormat: 'openssh-v1' | 'pem-rsa' | 'pem-ec' | 'pem-pkcs8' | 'unknown';
  privateKeyEncrypted: boolean;
  pubKeyMatchesCert: boolean;
  privateKeyMatchesPub: boolean | null;
  warnings: string[];
}

class SshBufferReader {
  private offset = 0;
  constructor(private readonly buf: Buffer) {}

  remaining(): number {
    return this.buf.length - this.offset;
  }

  readUInt32(): number {
    if (this.offset + 4 > this.buf.length) {
      throw new Error('Unerwartetes Ende im OpenSSH-Binärformat (uint32)');
    }
    const val = this.buf.readUInt32BE(this.offset);
    this.offset += 4;
    return val;
  }

  readUInt64(): bigint {
    if (this.offset + 8 > this.buf.length) {
      throw new Error('Unerwartetes Ende im OpenSSH-Binärformat (uint64)');
    }
    const val = this.buf.readBigUInt64BE(this.offset);
    this.offset += 8;
    return val;
  }

  readBytes(len: number): Buffer {
    if (this.offset + len > this.buf.length) {
      throw new Error('Unerwartetes Ende im OpenSSH-Binärformat (bytes)');
    }
    const slice = this.buf.subarray(this.offset, this.offset + len);
    this.offset += len;
    return slice;
  }

  readString(): Buffer {
    const len = this.readUInt32();
    return this.readBytes(len);
  }

  readUtf8(): string {
    return this.readString().toString('utf8');
  }
}

function writeSshString(data: Buffer | string): Buffer {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length, 0);
  return Buffer.concat([len, buf]);
}

function sha256Fingerprint(blob: Buffer): string {
  const hash = crypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '');
  return `SHA256:${hash}`;
}

function parseSshTextLine(content: string, label: string): { type: string; blob: Buffer; comment: string } {
  const line = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => l.length > 0 && !l.startsWith('#'));

  if (!line) {
    throw new Error(`${label} ist leer.`);
  }

  const parts = line.split(/\s+/);
  if (parts.length < 2) {
    throw new Error(`${label} hat kein gültiges OpenSSH-Format (erwartet: <Typ> <Base64> [Kommentar]).`);
  }

  const type = parts[0];
  const blob = Buffer.from(parts[1], 'base64');
  if (blob.length < 16) {
    throw new Error(`${label} enthält ungültige Base64-Schlüsseldaten.`);
  }

  const comment = parts.slice(2).join(' ');
  return { type, blob, comment };
}

function parsePackedStrings(buf: Buffer): string[] {
  const reader = new SshBufferReader(buf);
  const items: string[] = [];
  while (reader.remaining() > 0) {
    items.push(reader.readUtf8());
  }
  return items;
}

function parsePackedOptions(buf: Buffer): string[] {
  const reader = new SshBufferReader(buf);
  const items: string[] = [];
  while (reader.remaining() > 0) {
    const name = reader.readUtf8();
    const dataBuf = reader.readString();
    if (dataBuf.length > 0) {
      const inner = new SshBufferReader(dataBuf);
      try {
        const val = inner.readUtf8();
        items.push(`${name}=${val}`);
      } catch {
        items.push(name);
      }
    } else {
      items.push(name);
    }
  }
  return items;
}

function inspectPrivateKey(privateKeyPem: string): {
  format: ParsedCertMetadata['privateKeyFormat'];
  encrypted: boolean;
  embeddedPubKeyBlob: Buffer | null;
} {
  const trimmed = privateKeyPem.trim();
  if (trimmed.includes('-----BEGIN OPENSSH PRIVATE KEY-----') && trimmed.includes('-----END OPENSSH PRIVATE KEY-----')) {
    const base64Body = trimmed
      .replace(/-----BEGIN OPENSSH PRIVATE KEY-----/, '')
      .replace(/-----END OPENSSH PRIVATE KEY-----/, '')
      .replace(/\s+/g, '');
    const raw = Buffer.from(base64Body, 'base64');
    const magic = 'openssh-key-v1\0';
    if (raw.subarray(0, magic.length).toString('utf8') !== magic) {
      throw new Error('Ungültiger OpenSSH-Privatschlüssel (openssh-key-v1 Header fehlt).');
    }
    const reader = new SshBufferReader(raw.subarray(magic.length));
    const ciphername = reader.readUtf8();
    const kdfname = reader.readUtf8();
    reader.readString(); // kdfoptions
    const numKeys = reader.readUInt32();
    const embeddedPubKeyBlob = numKeys >= 1 ? reader.readString() : null;
    const encrypted = ciphername !== 'none' || kdfname !== 'none';
    return {
      format: 'openssh-v1',
      encrypted,
      embeddedPubKeyBlob,
    };
  }

  if (trimmed.includes('-----BEGIN RSA PRIVATE KEY-----')) {
    return {
      format: 'pem-rsa',
      encrypted: trimmed.includes('ENCRYPTED'),
      embeddedPubKeyBlob: null,
    };
  }
  if (trimmed.includes('-----BEGIN EC PRIVATE KEY-----')) {
    return {
      format: 'pem-ec',
      encrypted: trimmed.includes('ENCRYPTED'),
      embeddedPubKeyBlob: null,
    };
  }
  if (trimmed.includes('-----BEGIN PRIVATE KEY-----') || trimmed.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----')) {
    return {
      format: 'pem-pkcs8',
      encrypted: trimmed.includes('ENCRYPTED'),
      embeddedPubKeyBlob: null,
    };
  }

  throw new Error(
    'Privater Schlüssel (zertifikat) wurde nicht erkannt. Erwartet wird ein OpenSSH- oder PEM-Privatschlüssel.'
  );
}

export function validateAndParseCertificateBundle(
  privateKeyContent: string,
  publicKeyContent: string,
  certContent?: string
): ParsedCertMetadata {
  const warnings: string[] = [];

  // 1. Validate Private Key (zertifikat)
  const privInfo = inspectPrivateKey(privateKeyContent);
  if (privInfo.encrypted) {
    warnings.push(
      'Der private Schlüssel ist passwortgeschützt (verschlüsselt). Für vollautomatische passwortlose SSH-Ausführung im BatchMode wird ein unverschlüsselter Schlüssel empfohlen.'
    );
  }

  // 2. Validate Public Key (zertifikat.pub)
  const pubParsed = parseSshTextLine(publicKeyContent, 'Öffentlicher Schlüssel (zertifikat.pub)');
  if (pubParsed.type.endsWith('-cert-v01@openssh.com')) {
    throw new Error(
      'In zertifikat.pub wurde ein Zertifikat statt des öffentlichen Schlüssels erkannt. Bitte Dateien korrekt zuordnen.'
    );
  }
  const pubKeyReader = new SshBufferReader(pubParsed.blob);
  const pubKeyAlgoInside = pubKeyReader.readUtf8();
  if (pubKeyAlgoInside !== pubParsed.type) {
    throw new Error('Algorithmus-Abweichung in zertifikat.pub.');
  }
  const pubKeyFingerprint = sha256Fingerprint(pubParsed.blob);

  // Check if private key matches public key (for openssh-key-v1 format)
  let privateKeyMatchesPub: boolean | null = null;
  if (privInfo.embeddedPubKeyBlob) {
    privateKeyMatchesPub = privInfo.embeddedPubKeyBlob.equals(pubParsed.blob);
    if (!privateKeyMatchesPub) {
      throw new Error(
        'Der private Schlüssel (zertifikat) passt kryptografisch nicht zum öffentlichen Schlüssel (zertifikat.pub).'
      );
    }
  }

  // Optional 3rd file: if certContent is omitted, treat as standard 2-file OpenSSH keypair
  const trimmedCert = typeof certContent === 'string' ? certContent.trim() : '';
  if (!trimmedCert) {
    return {
      hasCertificate: false,
      certAlgorithm: '',
      pubKeyAlgorithm: pubParsed.type,
      serial: '—',
      certType: 'keypair',
      keyId: pubParsed.comment || '',
      principals: [],
      validAfter: 'Unbegrenzt (SSH-Schlüsselpaar)',
      validBefore: 'Unbegrenzt (kein Ablauf)',
      validAfterUnix: 0,
      validBeforeUnix: 0,
      isExpired: false,
      isNotYetValid: false,
      criticalOptions: [],
      extensions: [],
      pubKeyFingerprint,
      caFingerprint: '',
      privateKeyFormat: privInfo.format,
      privateKeyEncrypted: privInfo.encrypted,
      pubKeyMatchesCert: false,
      privateKeyMatchesPub,
      warnings,
    };
  }

  // 3. Validate & Parse OpenSSH Certificate (zertifikat-cert.pub)
  const certParsed = parseSshTextLine(trimmedCert, 'OpenSSH-Zertifikat (zertifikat-cert.pub)');
  if (!certParsed.type.endsWith('-cert-v01@openssh.com')) {
    throw new Error(
      `zertifikat-cert.pub ist kein gültiges OpenSSH-Zertifikat (Typ "${certParsed.type}", erwartet "*-cert-v01@openssh.com").`
    );
  }

  const reader = new SshBufferReader(certParsed.blob);
  const certAlgo = reader.readUtf8();
  if (certAlgo !== certParsed.type) {
    throw new Error('Zertifikatstyp im Header stimmt nicht mit dem Binärinhalt überein.');
  }

  // Nonce
  reader.readString();

  // Extract certified public key blob according to PROTOCOL.certkeys
  let certifiedPubBlob: Buffer;
  if (certAlgo === 'ssh-ed25519-cert-v01@openssh.com') {
    const pk = reader.readString();
    certifiedPubBlob = Buffer.concat([writeSshString('ssh-ed25519'), writeSshString(pk)]);
  } else if (certAlgo === 'ssh-rsa-cert-v01@openssh.com') {
    const e = reader.readString();
    const n = reader.readString();
    certifiedPubBlob = Buffer.concat([writeSshString('ssh-rsa'), writeSshString(e), writeSshString(n)]);
  } else if (certAlgo.startsWith('ecdsa-sha2-') && certAlgo.endsWith('-cert-v01@openssh.com')) {
    const curve = reader.readString();
    const q = reader.readString();
    const baseAlgo = certAlgo.replace('-cert-v01@openssh.com', '');
    certifiedPubBlob = Buffer.concat([writeSshString(baseAlgo), writeSshString(curve), writeSshString(q)]);
  } else if (certAlgo.startsWith('sk-ssh-ed25519-cert-v01@openssh.com')) {
    const pk = reader.readString();
    const app = reader.readString();
    certifiedPubBlob = Buffer.concat([
      writeSshString('sk-ssh-ed25519@openssh.com'),
      writeSshString(pk),
      writeSshString(app),
    ]);
  } else {
    throw new Error(`Zertifikatsalgorithmus "${certAlgo}" wird derzeit nicht unterstützt.`);
  }

  const serial = reader.readUInt64().toString();
  const typeCode = reader.readUInt32();
  const certType: ParsedCertMetadata['certType'] =
    typeCode === 1 ? 'user' : typeCode === 2 ? 'host' : 'unknown';

  const keyId = reader.readUtf8();
  const principalsBuf = reader.readString();
  const principals = parsePackedStrings(principalsBuf);

  const validAfterBig = reader.readUInt64();
  const validBeforeBig = reader.readUInt64();

  const criticalOptionsBuf = reader.readString();
  const criticalOptions = parsePackedOptions(criticalOptionsBuf);

  const extensionsBuf = reader.readString();
  const extensions = parsePackedOptions(extensionsBuf);

  // reserved
  reader.readString();

  const signatureKeyBlob = reader.readString();
  const caFingerprint = sha256Fingerprint(signatureKeyBlob);

  // signature
  reader.readString();

  // Verify certified public key equals zertifikat.pub
  const pubKeyMatchesCert = certifiedPubBlob.equals(pubParsed.blob);
  if (!pubKeyMatchesCert) {
    throw new Error(
      'Der in zertifikat-cert.pub zertifizierte öffentliche Schlüssel stimmt nicht mit zertifikat.pub überein.'
    );
  }

  if (certType !== 'user') {
    throw new Error(
      `zertifikat-cert.pub ist kein Benutzerzertifikat (Typ: ${certType}). Für SSH-Anmeldungen wird ein User-Zertifikat (Typ 1) benötigt.`
    );
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const maxSafeUnix = BigInt(8640000000000);
  const validAfterUnix = validAfterBig > maxSafeUnix ? 0 : Number(validAfterBig);
  const validBeforeUnix =
    validBeforeBig === BigInt('18446744073709551615') || validBeforeBig > maxSafeUnix
      ? 0
      : Number(validBeforeBig);

  const validAfter =
    validAfterUnix === 0 ? 'Unbegrenzt (sofort)' : new Date(validAfterUnix * 1000).toISOString();
  const validBefore =
    validBeforeUnix === 0 ? 'Unbegrenzt (kein Ablauf)' : new Date(validBeforeUnix * 1000).toISOString();

  const isNotYetValid = validAfterUnix > 0 && nowSec < validAfterUnix;
  const isExpired = validBeforeUnix > 0 && nowSec > validBeforeUnix;

  if (isExpired) {
    warnings.push('Das OpenSSH-Zertifikat ist abgelaufen. Zielserver werden die Anmeldung ablehnen.');
  }
  if (isNotYetValid) {
    warnings.push('Das OpenSSH-Zertifikat ist noch nicht gültig.');
  }
  if (principals.length === 0) {
    warnings.push('Keine Principals im Zertifikat hinterlegt (Wildcard-Zertifikat — ggf. serverseitig eingeschränkt).');
  }

  return {
    hasCertificate: true,
    certAlgorithm: certAlgo,
    pubKeyAlgorithm: pubParsed.type,
    serial,
    certType,
    keyId,
    principals,
    validAfter,
    validBefore,
    validAfterUnix,
    validBeforeUnix,
    isExpired,
    isNotYetValid,
    criticalOptions,
    extensions,
    pubKeyFingerprint,
    caFingerprint,
    privateKeyFormat: privInfo.format,
    privateKeyEncrypted: privInfo.encrypted,
    pubKeyMatchesCert,
    privateKeyMatchesPub,
    warnings,
  };
}
