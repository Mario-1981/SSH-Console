# SSH Console

A self-hosted web console for executing SSH commands and multi-step command chains across Linux servers using passwordless OpenSSH certificates or classic SSH keypairs, with a 60-second reachability dashboard, BMC HTTPS monitoring, role-based sharing, and a `curl`-friendly certificate upload API.

Built with a React + TypeScript frontend and a native **Rust (Axum + SQLite)** backend packaged for **Debian 13 (Trixie)**, alongside a Node.js/Express development server.

---

## Features

- **SSH Commands & Command Chains**: Define reusable single commands or multi-step chains with configurable `sleep` intervals and stop-on-error (`&&` vs `;`) execution within a single SSH session.
- **OpenSSH Certificates & Keypairs**: Supports both 3-file CA-signed OpenSSH certificate bundles (`zertifikat`, `zertifikat.pub`, `zertifikat-cert.pub`) and classic 2-file SSH keypairs (`zertifikat`, `zertifikat.pub` for `authorized_keys`). Cryptographic key-to-certificate matching and validity windows are verified on upload.
- **Automated `curl` Upload API**: Generate personal API keys (`sshc_...`) and push short-lived or rotated SSH certificates directly from scripts or cron jobs via `POST /api/v1/certificates/upload` (supports `multipart/form-data` and JSON, automatically overwriting existing entries with the same name).
- **60-Second Ping Dashboard & Batch Execution**: Monitors all target IPs every 60 seconds (ICMP ping with TCP fallback), displays live online/offline status and latency, and lets you assign commands per server or in bulk and execute them in parallel.
- **BMC Management Support**: Store an optional BMC/IPMI/iDRAC/iLO IP per server with a direct `https://` link and one-click HTTPS Port `443` TLS reachability check.
- **Privacy & Admin Sharing**: Accounts are created exclusively by administrators (no public self-registration). Commands, servers, and certificates are private to their creator by default; administrators can share their entries with all users or selected accounts without exposing encrypted private keys.
- **Bilingual UI (German & English)**: Instant `DE / EN` switcher available on every screen.
- **Audit Log**: Complete execution history with target, user, certificate key ID, OpenSSH invocation parameters, exit code, duration, `stdout`, and `stderr`.

---

## Quick Installation on Debian 13 (Trixie)

### Option 1: Install a `.deb` release package

Download the latest `ssh-console_<version>_amd64.deb` package from GitHub Releases (built automatically by `.github/workflows/release-deb.yml`) and install it:

```bash
sudo apt update
sudo apt install ./ssh-console_*_amd64.deb
```

The Debian package automatically:
1. Installs the compiled Rust binary (`/usr/local/bin/ssh-console`) and built web frontend (`/opt/ssh-console/dist`).
2. Creates a dedicated system user (`ssh-console`) and data directory (`/var/lib/ssh-console`).
3. Installs and starts the `ssh-console.service` systemd unit.

Verify the service status:

```bash
sudo systemctl status ssh-console
```

Open `http://<server-ip>:3000` in your browser and complete the one-time initial administrator setup.

### Option 2: Build the `.deb` package yourself

GitHub Actions builds the Debian 13 package automatically on version tags (`v*`) or via **Actions → Build & Release Debian Package → Run workflow**.

To build the `.deb` locally on Debian 13 (Trixie):

```bash
npm install --legacy-peer-deps
npm run build
cd rust-app
cargo build --release
./debian/build-deb.sh
```

---

## Local Development

### Prerequisites

- Node.js 20+ (22 recommended)
- OpenSSH client (`ssh`) for live SSH command execution (optional; falls back to dry-run validation if unavailable)
- Rust 1.85+ (only required when compiling the native Rust backend under `rust-app/`)

### Run the development server

```bash
npm install --legacy-peer-deps
npm run dev
```

The app runs on **http://localhost:3000**.

### Build & type-check

```bash
npm run lint
npm run build
```

---

## Certificate Upload API (`curl`)

Each user can create and revoke personal API keys (`sshc_...`) in the UI under **Account & Password** or via the **Upload via curl & API Key** button on the **SSH Keys & Certificates** page.

### Endpoint

```
POST /api/v1/certificates/upload
```

### Authentication

Provide the API key using either header:

- `X-API-Key: sshc_<your-key>`
- `Authorization: Bearer sshc_<your-key>`

### Upload a 3-file CA-signed OpenSSH certificate

```bash
curl -X POST "https://your-server/api/v1/certificates/upload" \
  -H "X-API-Key: sshc_YOUR_API_KEY" \
  -F "name=prod-ed25519" \
  -F "private_key=@./zertifikat" \
  -F "public_key=@./zertifikat.pub" \
  -F "cert=@./zertifikat-cert.pub"
```

### Upload a 2-file SSH keypair (without CA certificate)

```bash
curl -X POST "https://your-server/api/v1/certificates/upload" \
  -H "X-API-Key: sshc_YOUR_API_KEY" \
  -F "name=prod-keypair" \
  -F "private_key=@./zertifikat" \
  -F "public_key=@./zertifikat.pub"
```

### Form Fields & Behavior

| Field | Required | Aliases | Description |
| --- | --- | --- | --- |
| `private_key` | Yes | `privateKey`, `zertifikat`, `key` | Private OpenSSH/PEM key file |
| `public_key` | Yes | `publicKey`, `zertifikat_pub`, `pub` | Matching public key file (`.pub`) |
| `cert` | No | `certificate`, `cert_pub`, `zertifikat_cert` | Optional CA-signed OpenSSH certificate (`-cert.pub`) |
| `name` | No | `label` | Bundle label (defaults to certificate `keyId` or filename) |

- If the authenticated user already has a bundle with the same `name`, it is validated and overwritten in place (`HTTP 200`, `"replaced": true`). Otherwise a new entry is created (`HTTP 201`, `"replaced": false`).
- `application/json` payloads are also supported using the same field names.

---

## Configuration & Data Storage

### Production (Rust backend / Debian `.deb`)

Service configuration is stored in `/etc/default/ssh-console`:

| Variable | Default | Description |
| --- | --- | --- |
| `SSH_CONSOLE_BIND` | `0.0.0.0:3000` | Listen address and port |
| `SSH_CONSOLE_DATA_DIR` | `/var/lib/ssh-console` | Directory for SQLite database and vault master key |
| `SSH_CONSOLE_STATIC_DIR` | `/opt/ssh-console/dist` | Directory containing the built frontend assets |
| `RUST_LOG` | `info` | Log verbosity (`debug`, `info`, `warn`, `error`) |

Stored files in `/var/lib/ssh-console`:
- `ssh-console.sqlite` — SQLite (WAL mode) storing users, sessions, hashed API keys, SSH commands, servers, certificates (encrypted private keys), and execution logs.
- `vault.key` (`0600`) — 256-bit AES-256-GCM master key used to encrypt stored SSH private keys.

### Development (Node.js / Express)

- `data/trixiessh.json` — Local JSON database.
- `data/master.key` (`0600`) — Local AES-256-GCM master key (overrideable via `TRIXIESSH_MASTER_KEY`).

---

## Security Architecture

- **Private Keys at Rest**: Encrypted with **AES-256-GCM** using a dedicated server-side master key; never returned to the browser.
- **Ephemeral SSH Execution**: Private keys are decrypted into a temporary `0700`/`0600` directory strictly for the duration of an OpenSSH invocation and wiped immediately afterwards.
- **Passwords**: Hashed with Argon2id (Rust backend) / scrypt with per-user salts (Express dev backend).
- **API Keys**: Generated with 256 bits of cryptographic entropy, displayed once on creation, and stored exclusively as **SHA-256** hashes.
- **Closed Registration**: The initial setup route is permanently locked once the first administrator account exists.

---

## License

MIT
