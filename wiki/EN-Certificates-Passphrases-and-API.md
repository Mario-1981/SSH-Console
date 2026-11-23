> [🏠 Home](Home) · [🇩🇪 Deutsche Version](DE-Zertifikate-Passphrases-und-API)

# Certificates, Passphrases & `curl` Upload API

SSH Console supports both **CA-signed OpenSSH User Certificates** (3-file model) and **classic SSH Keypairs** (2-file model), including **passphrase-protected private keys** and automated certificate rotation via `curl`.

---

## Supported Key & Certificate Formats

| Mode | Files | Target Server Configuration |
| --- | --- | --- |
| **3-File OpenSSH Certificate** | `zertifikat` (private key) + `zertifikat.pub` (public key) + `zertifikat-cert.pub` (CA-signed certificate) | `TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub` in `/etc/ssh/sshd_config` |
| **2-File SSH Keypair** | `zertifikat` (private key) + `zertifikat.pub` (public key) | Public key placed in `~/.ssh/authorized_keys` |

On every upload or update, SSH Console automatically parses and verifies:
- Private key format (`openssh-v1`, PEM RSA/EC/PKCS#8) and whether it is passphrase-encrypted
- Cryptographic match between `zertifikat.pub` and `zertifikat-cert.pub`
- Certificate Key ID, serial, principals, extensions, CA fingerprint, and validity window (`validAfter` / `validBefore`, with expired/not-yet-valid indicators)

### Setting Up an OpenSSH User CA on Target Servers

1. Generate a User CA key pair once on a secure CA host:
   ```bash
   ssh-keygen -t ed25519 -f ssh_user_ca -C "SSH Console User CA"
   ```
2. Copy `ssh_user_ca.pub` to all target Linux servers and add to `/etc/ssh/sshd_config`:
   ```text
   TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub
   ```
   Reload OpenSSH:
   ```bash
   sudo systemctl reload ssh
   ```
3. Generate a user key and sign it with a short validity window (e.g. 24 hours or 90 days):
   ```bash
   ssh-keygen -t ed25519 -f zertifikat -N ""
   ssh-keygen -s ssh_user_ca -I "ops-alice" -n root,deploy -V +7d zertifikat.pub
   ```

---

## Passphrase-Protected Private Keys

If your private key (`zertifikat`) is encrypted with a passphrase, SSH Console detects this automatically and offers **two unlock modes**:

1. **Store Passphrase Encrypted (Convenient / Automated)**
   - Provide the passphrase during upload, later via the **Passphrase** action on the **SSH Keys & Certificates** page, or via the `curl` API (`-F "passphrase=..."`).
   - Stored encrypted at rest using **AES-256-GCM** (never returned to the browser).
   - Can be updated or removed (`clear_passphrase=true`) at any time.
2. **Enter Passphrase Per Use (Maximum Security)**
   - Leave the passphrase empty when uploading.
   - Whenever you select this certificate on the **Dashboard** (Batch/Quick Command) or in the **SSH Shell**, an unlock password field appears automatically.
   - The passphrase is sent only for that request/session, passed to OpenSSH via an ephemeral `SSH_ASKPASS` helper script (`0700`/`0600`), and wiped immediately after execution.

---

## Automated `curl` Upload & Rotation API

Generate personal API keys (`sshc_...`) under **Account & Security** or via **Upload via curl & API Key** on the **SSH Keys & Certificates** page.

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

With an optional stored passphrase for an encrypted private key:

```bash
curl -X POST "https://ssh.example.net/api/v1/certificates/upload" \
  -H "X-API-Key: sshc_YOUR_API_KEY" \
  -F "name=prod-ed25519" \
  -F "private_key=@./zertifikat" \
  -F "public_key=@./zertifikat.pub" \
  -F "cert=@./zertifikat-cert.pub" \
  -F "passphrase=YOUR_KEY_PASSPHRASE"
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

Keep the stored private and public keys untouched (along with sharing permissions and stored passphrase) and rotate only the signed certificate by bundle `name` or `id`:

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
  -F "passphrase=NEW_PASSPHRASE"

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
| `cert` | No | `certificate`, `cert_pub`, `zertifikat_cert` | Optional CA-signed OpenSSH certificate (`-cert.pub`) |
| `name` | No | `label` | Bundle label (defaults to certificate `keyId` or filename) |
| `passphrase` | No | `key_passphrase`, `keyPassphrase` | Optional passphrase for an encrypted private key (stored with AES-256-GCM) |
| `clear_passphrase` | No | `clearPassphrase` | Set to `true` on `PATCH`/`PUT` to delete a stored passphrase |
| `remove_cert` | No | `removeCert` | Set to `true` on `PATCH`/`PUT` to remove `cert` and convert to a 2-file keypair |
