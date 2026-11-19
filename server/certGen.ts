import crypto from 'node:crypto';

function writeUInt32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

function writeUInt64(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(n, 0);
  return b;
}

function writeSshString(data: Buffer | string): Buffer {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return Buffer.concat([writeUInt32(buf.length), buf]);
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

function buildOpenSshPrivateKey(pub32: Buffer, priv32: Buffer, comment: string): string {
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

  // OpenSSH block padding (8-byte block for cipher "none")
  const blockSize = 8;
  const padLen = blockSize - (unpaddedPrivate.length % blockSize);
  const padBytes = Buffer.alloc(padLen);
  for (let i = 0; i < padLen; i++) {
    padBytes[i] = i + 1;
  }
  const privateSection = Buffer.concat([unpaddedPrivate, padBytes]);

  const fullBlob = Buffer.concat([
    Buffer.from('openssh-key-v1\0', 'utf8'),
    writeSshString('none'), // ciphername
    writeSshString('none'), // kdfname
    writeSshString(Buffer.alloc(0)), // kdfoptions
    writeUInt32(1), // number of keys
    writeSshString(pubBlob),
    writeSshString(privateSection),
  ]);

  const b64 = fullBlob.toString('base64');
  const wrapped = b64.match(/.{1,70}/g)?.join('\n') ?? b64;
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${wrapped}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

export interface GeneratedTestCertBundle {
  privateKey: string;
  publicKey: string;
  certificate: string;
  caPublicKey: string;
}

/**
 * Generates a cryptographically authentic OpenSSH Ed25519 keypair + CA-signed
 * User Certificate (ssh-ed25519-cert-v01@openssh.com) conforming to PROTOCOL.certkeys.
 */
export function generateTestOpenSshCertBundle(params: {
  keyId: string;
  principals: string[];
  validDays?: number;
}): GeneratedTestCertBundle {
  const userKp = crypto.generateKeyPairSync('ed25519');
  const caKp = crypto.generateKeyPairSync('ed25519');

  const userRaw = extractEd25519Raw(userKp);
  const caRaw = extractEd25519Raw(caKp);

  const userPubBlob = buildEd25519PubBlob(userRaw.pub32);
  const caPubBlob = buildEd25519PubBlob(caRaw.pub32);

  const comment = `${params.keyId}@trixiessh`;
  const privateKey = buildOpenSshPrivateKey(userRaw.pub32, userRaw.priv32, comment);
  const publicKey = `ssh-ed25519 ${userPubBlob.toString('base64')} ${comment}\n`;
  const caPublicKey = `ssh-ed25519 ${caPubBlob.toString('base64')} trixiessh-test-ca\n`;

  // Construct PROTOCOL.certkeys v01 payload
  const nonce = crypto.randomBytes(32);
  const serial = BigInt(Math.floor(Date.now() / 1000));
  const certType = 1; // SSH_CERT_TYPE_USER
  const nowSec = BigInt(Math.floor(Date.now() / 1000) - 60);
  const validDays = params.validDays ?? 90;
  const validBefore = nowSec + BigInt(validDays * 86400);

  const principalsPacked = Buffer.concat(params.principals.map((p) => writeSshString(p)));

  const standardExtensions = [
    'permit-X11-forwarding',
    'permit-agent-forwarding',
    'permit-port-forwarding',
    'permit-pty',
    'permit-user-rc',
  ];
  const extensionsPacked = Buffer.concat(
    standardExtensions.map((ext) => Buffer.concat([writeSshString(ext), writeSshString(Buffer.alloc(0))]))
  );

  const toBeSigned = Buffer.concat([
    writeSshString('ssh-ed25519-cert-v01@openssh.com'),
    writeSshString(nonce),
    writeSshString(userRaw.pub32),
    writeUInt64(serial),
    writeUInt32(certType),
    writeSshString(params.keyId),
    writeSshString(principalsPacked),
    writeUInt64(nowSec),
    writeUInt64(validBefore),
    writeSshString(Buffer.alloc(0)), // critical options
    writeSshString(extensionsPacked),
    writeSshString(Buffer.alloc(0)), // reserved
    writeSshString(caPubBlob), // signature key (CA pubkey)
  ]);

  const rawSig = crypto.sign(null, toBeSigned, caKp.privateKey);
  const sigBlob = Buffer.concat([writeSshString('ssh-ed25519'), writeSshString(rawSig)]);
  const fullCertBlob = Buffer.concat([toBeSigned, writeSshString(sigBlob)]);

  const certificate = `ssh-ed25519-cert-v01@openssh.com ${fullCertBlob.toString('base64')} ${comment}\n`;

  return {
    privateKey,
    publicKey,
    certificate,
    caPublicKey,
  };
}
