---
title: Certificates, CA Signing & API
lang: en
alt_url: /de/zertifikate-api.html
---

# Certificates, CA Signing, Automatic Re-Certification & API

SSH Console supports both **CA-signed OpenSSH User Certificates** (3-file model) and **classic SSH Keypairs** (2-file model), including **in-browser key generation**, **built-in SSH Certificate Authority (CA) management**, **single & batch signing**, **policy-enforced user self-signing**, **automatic re-certification**, and an automated **`curl` upload & rotation API**.

---

## Supported Key & Certificate Formats

| Mode | Files | Target Server Configuration |
| --- | --- | --- |
| **3-File OpenSSH Certificate** | `zertifikat` (private key) + `zertifikat.pub` (public key) + `zertifikat-cert.pub` (CA-signed certificate) | `TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub` in `/etc/ssh/sshd_config` |
| **2-File SSH Keypair** | `zertifikat` (private key) + `zertifikat.pub` (public key) | Public key placed in `~/.ssh/authorized_keys` |

On every upload or update, SSH Console automatically parses and verifies:
- Private key format (`openssh-v1`, PEM RSA/EC/PKCS#8) and whether it is passphrase-encrypted
- Cryptographic match between `zertifikat.pub` and `zertifikat-cert.pub`
- Certificate Key ID, serial, principals (`-n`), extensions, CA fingerprint, and validity window (`validAfter` / `validBefore`, with expired/not-yet-valid indicators)

---

## Key Generation, Duplicate Protection & Passphrase Policies

### 1. In-App Key Generation & Passphrase Rules
- Under **SSH Keys & Certificates**, users can generate new SSH keypairs directly in the browser (if granted by their user group).
- During key generation, the user is prompted for an optional or required **passphrase**:
  - When the group permission **Require certificate passphrase** (`requireCertificatePassphrase`) is enabled, a passphrase is mandatory; otherwise leaving it blank creates an unencrypted key.
  - Every certificate passphrase must satisfy the **password complexity policy** (**min. 8 characters** and **at least 3 of 4 character classes**: uppercase, lowercase, digits, special characters).
- The group permission **Allow storing certificate passphrases** (`storeCertificatePassphrase`) controls whether passphrases may be saved AES-256-GCM encrypted in SSH Console.

### 2. Duplicate-Name Warning & Overwrite Confirmation
- While typing a certificate name (during generation or upload), SSH Console displays a live notice if a certificate with that name already exists.
- Existing certificates are **never silently overwritten**—the UI always asks for explicit confirmation before replacing an existing bundle.

### 3. Controlling User `zertifikat-cert.pub` Uploads
- Administrators can toggle **Upload own signed `zertifikat-cert.pub`** (`uploadSignedCert`) per group to decide whether users may upload externally signed certificates or must sign through managed CAs.

### 4. Passphrase-Protected Private Keys (Two Unlock Modes)
1. **Store Passphrase Encrypted** (when permitted by group policy): Encrypted at rest using **AES-256-GCM**, never returned to the browser, and removable at any time (`clear_passphrase=true`).
2. **Enter Passphrase Per Use**: Leaving the passphrase unstored displays an unlock prompt in the **Dashboard** or **SSH Shell**. The passphrase is used strictly for that execution via an ephemeral `SSH_ASKPASS` helper script (`0700`/`0600`) and wiped immediately afterwards.

### 5. Admin Cross-User Certificate Overview
- Administrators see both their own certificates and a searchable, filterable overview of all other users' certificates under **SSH Keys & Certificates**.
- Administrators can **inspect metadata, sign with a CA, and delete** other users' certificates, while **strictly blocking access to private keys** and preventing edits to other users' keypairs.

---

## Built-In SSH CA Management (`Admin → CA Certificates`)

Administrators manage OpenSSH Certificate Authorities directly under **Administration → CA Certificates**:

1. **Generate or Import a CA**:
   - Create a new OpenSSH User CA (`ca` + `ca.pub`, e.g. Ed25519/ECDSA/RSA) or import an existing CA keypair.
   - **Mandatory Strong CA Passphrase**: Every CA requires a passphrase that meets the complexity rules.
   - **Optional Server-Side Passphrase Storage**: Just like SSH certificates, a CA passphrase can optionally be stored **AES-256-GCM encrypted** on the server:
     - *Not stored:* Manual admin signing prompts for the CA passphrase on each signing operation.
     - *Stored encrypted:* Enables **user self-signing** and **automatic re-certification**.
2. **Distribute `ca.pub` to Target Servers**:
   - Download or copy `ca.pub` from the CA list, place it at `/etc/ssh/ssh_user_ca.pub` on your Linux servers, and add to `/etc/ssh/sshd_config`:
     ```text
     TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub
     ```
   - Reload OpenSSH (`sudo systemctl reload ssh`).

---

## Signing Certificates with a CA

### Admin Signing (Single & Batch)
- Administrators can sign one certificate or multiple selected certificates at once (**Batch Signing**) with any managed CA:
  - Choose the **CA**, set **Principals (`-n`)** (optionally including each certificate owner's username), **validity (`-V`)**, and an optional **Key-ID prefix**.
  - Unlock via the stored CA passphrase or a one-time passphrase prompt.

### User Self-Signing (Single & Batch Update)
- When a user's group has **Self-sign own certificates** (`selfSignCertificates`) enabled and at least one CA with a stored passphrase assigned, users can sign one or more of their own certificates via **Self-sign** / **Batch Update**.
- Users select an assigned CA and their target certificates.
- **Principals (`-n`)**, **signature validity (`-V`)**, and **auto-renewal start time** are displayed clearly and **strictly enforced from the group+CA policy** (cannot be overridden by the user).

### Foreign-CA Overwrite Warning
- If one or more selected certificates already contain a `zertifikat-cert.pub` file that was **not** signed by the currently selected CA, SSH Console displays an explicit warning listing every affected certificate and its current CA fingerprint/name.
- Signing only proceeds after checking the explicit overwrite confirmation (enforced on both frontend and backend via HTTP `409 Conflict`).

---

## Automatic Re-Certification (Until Revocation or Rights Removal)

Both **Admin Signing** and **User Self-Signing** (when the user's group has **Allow automatic re-certification** / `autoRenewCertificates`) support enabling **Automatic Re-Certification**:

- **Requirements**:
  - The chosen CA has its passphrase stored encrypted on the server.
  - Signature validity is finite (not `forever`).
  - For users: the group has both `selfSignCertificates` and `autoRenewCertificates`, and the CA is assigned to the group.
- **Renewal Timing**:
  - For **users**, the renewal lead time configured by the administrator **per group and per CA** applies strictly (e.g. *Automatic from 20% before expiry*, *From 24 hours before expiry*, or custom minutes/hours/days).
  - For **admin-initiated signing**, the administrator selects the lead time in the signing modal.
  - The background scheduler (in both Rust and Node.js backends) periodically checks due certificates, prevents renewal loops, and dynamically applies updated group+CA parameters (`-n`, `-V`, lead time) on every user renewal.
- **Revocation & Immediate Rights Removal**:
  - Every certificate with active auto-renewal displays its CA, `-V`, lead time, and last renewal timestamp directly on the card, with one-click **Revoke** (single) and **Revoke Auto-Renewal** (batch) buttons for the owner or any admin.
  - Upon **rights removal**, auto-renewal stops **immediately** (and is re-verified before every renewal run) with a recorded reason whenever:
    - `selfSignCertificates` or `autoRenewCertificates` is removed from the user's group,
    - the CA is unassigned from the group or its validity is switched to `forever`,
    - the CA is deleted or its stored passphrase is cleared,
    - the user account is deactivated/deleted or the enabling admin loses admin status,
    - the certificate is manually replaced or re-uploaded.

---

## Automated `curl` Upload & Rotation API

Generate personal API keys (`sshc_...`) under **Account & Security** or via **Upload via curl & API Key** on the **SSH Keys & Certificates** page (requires the `useApi` group permission).

### Endpoints

```text
GET    /api/v1/certificates
POST   /api/v1/certificates/upload
PATCH  /api/v1/certificates/<name-or-id>
PUT    /api/v1/certificates/<name-or-id>
```

### Authentication Headers

Use either header with your personal API key:
- `X-API-Key: sshc_<your-key>`
- `Authorization: Bearer sshc_<your-key>`

### 1. Upload or Replace a 3-File Certificate Bundle

If a bundle with the same `name` already exists for your user, it is updated in place (`HTTP 200`, `"replaced": true`); otherwise a new bundle is created (`HTTP 201`, `"replaced": false`).

```bash
curl -X POST "https://ssh.example.net/api/v1/certificates/upload" \
  -H "X-API-Key: sshc_YOUR_API_KEY" \
  -F "name=prod-ed25519" \
  -F "private_key=@./zertifikat" \
  -F "public_key=@./zertifikat.pub" \
  -F "cert=@./zertifikat-cert.pub"
```

With an optional stored passphrase for an encrypted private key (subject to group policy & complexity rules):

```bash
curl -X POST "https://ssh.example.net/api/v1/certificates/upload" \
  -H "X-API-Key: sshc_YOUR_API_KEY" \
  -F "name=prod-ed25519" \
  -F "private_key=@./zertifikat" \
  -F "public_key=@./zertifikat.pub" \
  -F "cert=@./zertifikat-cert.pub" \
  -F "passphrase=YOUR_STRONG_PASSPHRASE"
```

### 2. Upload a 2-File SSH Keypair (No CA Certificate)

```bash
curl -X POST "https://ssh.example.net/api/v1/certificates/upload" \
  -H "X-API-Key: sshc_YOUR_API_KEY" \
  -F "name=prod-keypair" \
  -F "private_key=@./zertifikat" \
  -F "public_key=@./zertifikat.pub"
```

### 3. Rotate Only `zertifikat-cert.pub` (Partial Update)

Keep the stored private and public keys untouched (along with sharing permissions and stored passphrase) and rotate only the signed certificate by bundle `name` or `id` (requires `uploadSignedCert`; automatically stops any active auto-renewal on that bundle):

```bash
curl -X PATCH "https://ssh.example.net/api/v1/certificates/prod-ed25519" \
  -H "X-API-Key: sshc_YOUR_API_KEY" \
  -F "cert=@./zertifikat-cert.pub"
```

### 4. Update or Clear a Stored Passphrase

```bash
# Set / update stored passphrase
curl -X PATCH "https://ssh.example.net/api/v1/certificates/prod-ed25519" \
  -H "X-API-Key: sshc_YOUR_API_KEY" \
  -F "passphrase=NEW_STRONG_PASSPHRASE"

# Remove stored passphrase (switch back to per-use prompt)
curl -X PATCH "https://ssh.example.net/api/v1/certificates/prod-ed25519" \
  -H "X-API-Key: sshc_YOUR_API_KEY" \
  -F "clear_passphrase=true"
```

### 5. List Your Certificates

```bash
curl -H "X-API-Key: sshc_YOUR_API_KEY" \
  "https://ssh.example.net/api/v1/certificates"
```

### Form & JSON Field Reference

All endpoints accept both `multipart/form-data` and `application/json`:

| Field | Required | Accepted Aliases | Description |
| --- | --- | --- | --- |
| `private_key` | On create | `privateKey`, `zertifikat`, `key` | Private OpenSSH/PEM key file or content |
| `public_key` | On create | `publicKey`, `zertifikat_pub`, `pub` | Matching public key (`.pub`) |
| `cert` | No | `certificate`, `cert_pub`, `zertifikat_cert` | Optional CA-signed OpenSSH certificate (`-cert.pub`, subject to `uploadSignedCert`) |
| `name` | No | `label` | Bundle label (defaults to certificate `keyId` or filename) |
| `passphrase` | No | `key_passphrase`, `keyPassphrase` | Optional passphrase for an encrypted private key (AES-256-GCM; subject to group policy & complexity rules) |
| `clear_passphrase` | No | `clearPassphrase` | Set to `true` on `PATCH`/`PUT` to delete a stored passphrase |
| `remove_cert` | No | `removeCert` | Set to `true` on `PATCH`/`PUT` to remove `cert` and convert to a 2-file keypair |

---

Next: **[Troubleshooting & FAQ](./troubleshooting.html)**
