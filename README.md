# SSH Console

A self-hosted web console for managing Linux servers with **OpenSSH certificates** and **SSH keypairs** (including passphrase-protected keys), featuring a scalable **staggered Ping & Dual-BMC Dashboard**, a **multi-tab interactive browser SSH Shell**, **single commands & multi-step command chains**, **OIDC SSO / 2FA / Passkeys**, **Docker & Debian 13 (Trixie)** packaging, and an automated **`curl` certificate upload & rotation API**.

Built with a React + TypeScript frontend and a native **Rust (Axum + SQLite)** production backend, alongside a Node.js/Express development server.

> **Documentation (GitHub Pages · English & Deutsch):** Full guides are available in [`/docs`](./docs/index.md) ([English](./docs/en/overview.md) · [Deutsch](./docs/de/ueberblick.md)) and deploy automatically via GitHub Pages (`.github/workflows/pages.yml`).

---

## Features

- **Scalable Auto-Ping Dashboard (10–1,000+ IPs), Adaptive Backoff & Pagination**:
  - Configurable auto-ping interval (`5s–3600s`, pauseable) with **evenly staggered per-IP pacing** so every host keeps its configured probe interval while spreading network load smoothly across time instead of sending burst floods.
  - **Adaptive Offline Backoff**: Hosts that stay unreachable beyond a configurable failure threshold (default: `5` consecutive misses) automatically slow down their check interval (default: `5×`, configurable by admins) to reduce network and CPU load — and **immediately reset** to the standard interval on the first successful ping.
  - **Pagination, Categories & Dual BMC**: Page-size switcher (`10`, `20`, `50`, `All`), server categories, batch command assignment & parallel execution, plus primary and secondary BMC/IPMI/iDRAC/iLO IPs with direct `https://` links and TLS port `443` reachability checks.
- **Multi-Tab Interactive Browser SSH Shell**: Open multiple simultaneous live OpenSSH PTY terminals (`xterm.js` over WebSockets) to saved servers or ad-hoc IPs directly in the browser, including terminal resize synchronization and on-demand key passphrase unlock.
- **SSH Commands, Command Chains & Host-Key Verification**:
  - Define reusable single commands or multi-step chains with configurable `sleep` intervals and stop-on-error (`&&` vs `;`) execution within a single SSH session.
  - Persistent server-side `known_hosts` tracking (`StrictHostKeyChecking=accept-new`): routine first-connect `Warning: Permanently added ...` notices are automatically filtered out, while real `REMOTE HOST IDENTIFICATION HAS CHANGED` alerts are surfaced prominently with a one-click host-key reset.
- **OpenSSH Certificates, Keypairs & Passphrase Unlock**:
  - Supports 3-file CA-signed OpenSSH certificate bundles (`zertifikat`, `zertifikat.pub`, `zertifikat-cert.pub`) and classic 2-file SSH keypairs (`zertifikat`, `zertifikat.pub` for `authorized_keys`), with cryptographic key/certificate verification and validity window checks.
  - **Encrypted Private Keys**: Automatically detects passphrase-protected keys and lets you either store the passphrase **AES-256-GCM encrypted** with the bundle or enter it on demand per execution / shell session (passed ephemerally via `SSH_ASKPASS`).
- **Automated `curl` Upload & Rotation API**: Generate personal API keys (`sshc_...`) and upload, replace, or partially rotate certificates and passphrases from scripts or cron jobs via `/api/v1/certificates/*`.
- **Privacy, SSO, 2FA & Passkeys**:
  - **OIDC / OAuth 2.0 SSO (PKCE S256)**: Connect Keycloak, Authentik, Microsoft Entra ID, Google Workspace, Okta, GitLab, etc. with auto-discovery, optional auto-provisioning, and a required connection test before disabling local login.
  - **2FA & Passkeys**: Optional or admin-enforced **TOTP Authenticator Apps** (+ recovery codes), **FIDO2 Hardware Security Keys**, and passwordless **Passkeys** (discoverable WebAuthn), with self-service management and admin reset.
  - **Role-Based Sharing**: Commands, servers, and certificates are private to their creator by default; administrators can share items with all users or specific accounts without ever exposing decrypted private keys or passphrases.
- **Bilingual UI (German & English)**: Instant `DE / EN` switcher across every screen.
- **Audit Log**: Complete execution history with target, user, certificate key ID, OpenSSH arguments, exit code, duration, `stdout`, and `stderr`.

---

## Quick Installation

### Option 1: Docker & Docker Compose (Recommended)

A multi-stage [`Dockerfile`](./Dockerfile) (Node.js frontend build → Rust release build → minimal `debian:trixie-slim` runtime) and [`docker-compose.yml`](./docker-compose.yml) are included. Prebuilt container images are published automatically to GitHub Container Registry (GHCR) by `.github/workflows/release-docker.yml`.

#### Pull from GHCR & run with Docker Compose

```bash
export SSH_CONSOLE_IMAGE="ghcr.io/<owner>/<repo>:latest"
docker compose pull
docker compose up -d
```

#### Or build and start locally

```bash
docker compose up -d --build
```

#### Or run directly with `docker run`

```bash
docker run -d \
  --name ssh-console \
  --restart unless-stopped \
  -p 3000:3000 \
  --cap-drop=ALL \
  --cap-add=NET_RAW \
  --security-opt no-new-privileges:true \
  -v ssh-console-data:/var/lib/ssh-console \
  ghcr.io/<owner>/<repo>:latest
```

> **Note:** `--cap-add=NET_RAW` enables native ICMP ping (`/bin/ping`). Without it, SSH Console automatically falls back to TCP reachability checks.

Open `http://<server-ip>:3000` in your browser to complete the one-time initial administrator setup.

---

### Option 2: Debian 13 (Trixie) `.deb` Package

Download the latest `ssh-console_<version>_amd64.deb` package from GitHub Releases (built automatically by `.github/workflows/release-deb.yml`) and install it:

```bash
sudo apt update
sudo apt install ./ssh-console_*_amd64.deb
```

The package automatically:
1. Installs the compiled Rust binary (`/usr/local/bin/ssh-console`) and built frontend (`/opt/ssh-console/dist`).
2. Creates a dedicated system user (`ssh-console`) and data directory (`/var/lib/ssh-console`).
3. Installs and starts the hardened `ssh-console.service` systemd unit.

Verify the service:

```bash
sudo systemctl status ssh-console
```

To build the `.deb` package locally on Debian 13 (Trixie):

```bash
npm install --legacy-peer-deps
npm run build
cd rust-app
cargo build --release
./debian/build-deb.sh
```

---

## GitHub Actions & GitHub Pages

| Workflow | Trigger | Purpose |
| --- | --- | --- |
| [`.github/workflows/release-docker.yml`](./.github/workflows/release-docker.yml) | Push to `main`/`master`, `v*` tags, manual | Builds & publishes multi-arch Docker images (`linux/amd64`, plus `linux/arm64` on `v*` tags or manual selection) to GHCR |
| [`.github/workflows/release-deb.yml`](./.github/workflows/release-deb.yml) | `v*` tags, manual | Builds Debian 13 (Trixie) `.deb` packages and attaches them to a GitHub Release |
| [`.github/workflows/pages.yml`](./.github/workflows/pages.yml) | Changes in `docs/`, manual | Builds & deploys the bilingual `/docs` site to **GitHub Pages** using Node 24 actions |

To enable the hosted documentation in your fork/repository, open **Settings → Pages → Build and deployment → Source** and select **GitHub Actions**.

---

## Local Development

### Prerequisites

- Node.js 20+ (22 recommended)
- OpenSSH client (`ssh`) for live SSH execution (optional; falls back to dry-run validation if unavailable)
- Rust 1.85+ (only required when compiling the native Rust backend under `rust-app/`)

### Run the development server

```bash
npm install --legacy-peer-deps
npm run dev
```

The app runs on **http://localhost:3000**.

### Type-check & build

```bash
npm run lint
npm run build
```

---

## Certificate Upload API (`curl`)

Each user can create and revoke personal API keys (`sshc_...`) under **Account & Security** or via **Upload via curl & API Key** on the **SSH Keys & Certificates** page.

### Endpoints

```text
GET    /api/v1/certificates
POST   /api/v1/certificates/upload
PATCH  /api/v1/certificates/<name-or-id>
PUT    /api/v1/certificates/<name-or-id>
```

### Authentication

Provide the API key using either header:

- `X-API-Key: sshc_<your-key>`
- `Authorization: Bearer sshc_<your-key>`

### Upload a 3-file CA-signed OpenSSH certificate (with optional passphrase)

```bash
curl -X POST "https://your-server/api/v1/certificates/upload" \
  -H "X-API-Key: sshc_YOUR_API_KEY" \
  -F "name=prod-ed25519" \
  -F "private_key=@./zertifikat" \
  -F "public_key=@./zertifikat.pub" \
  -F "cert=@./zertifikat-cert.pub" \
  -F "passphrase=OPTIONAL_KEY_PASSPHRASE"
```

### Upload a 2-file SSH keypair (without CA certificate)

```bash
curl -X POST "https://your-server/api/v1/certificates/upload" \
  -H "X-API-Key: sshc_YOUR_API_KEY" \
  -F "name=prod-keypair" \
  -F "private_key=@./zertifikat" \
  -F "public_key=@./zertifikat.pub"
```

### Rotate only `zertifikat-cert.pub` (partial update)

Keep the stored private/public keys, sharing settings, and stored passphrase untouched and rotate only the signed certificate (by bundle `name` or `id`):

```bash
curl -X PATCH "https://your-server/api/v1/certificates/prod-ed25519" \
  -H "X-API-Key: sshc_YOUR_API_KEY" \
  -F "cert=@./zertifikat-cert.pub"
```

### Update or clear a stored key passphrase

```bash
# Store or update passphrase
curl -X PATCH "https://your-server/api/v1/certificates/prod-ed25519" \
  -H "X-API-Key: sshc_YOUR_API_KEY" \
  -F "passphrase=NEW_PASSPHRASE"

# Remove stored passphrase (revert to per-use prompt)
curl -X PATCH "https://your-server/api/v1/certificates/prod-ed25519" \
  -H "X-API-Key: sshc_YOUR_API_KEY" \
  -F "clear_passphrase=true"
```

### List your certificates

```bash
curl -H "X-API-Key: sshc_YOUR_API_KEY" \
  "https://your-server/api/v1/certificates"
```

### Form & JSON Field Reference

| Field | Required | Aliases | Description |
| --- | --- | --- | --- |
| `private_key` | On create | `privateKey`, `zertifikat`, `key` | Private OpenSSH/PEM key file |
| `public_key` | On create | `publicKey`, `zertifikat_pub`, `pub` | Matching public key file (`.pub`) |
| `cert` | No | `certificate`, `cert_pub`, `zertifikat_cert` | Optional CA-signed OpenSSH certificate (`-cert.pub`) |
| `name` | No | `label` | Bundle label (defaults to certificate `keyId` or filename) |
| `passphrase` | No | `key_passphrase`, `keyPassphrase` | Optional passphrase for an encrypted private key (stored encrypted with AES-256-GCM) |
| `clear_passphrase` | No | `clearPassphrase` | Set to `true` on `PATCH`/`PUT` to delete a stored passphrase |
| `remove_cert` | No | `removeCert` | Set to `true` on `PATCH`/`PUT` to remove `cert` and convert to a 2-file keypair |

- On `POST /api/v1/certificates/upload`, an existing bundle with the same `name` for the authenticated user is updated in place (`HTTP 200`, `"replaced": true`); otherwise a new entry is created (`HTTP 201`, `"replaced": false`).
- On `PATCH` / `PUT /api/v1/certificates/<name-or-id>`, only supplied fields are updated while unchanged files, bundle ID, and sharing settings are preserved.
- `application/json` payloads are also supported using the same field names.

---

## Configuration & Data Storage

### Production (Docker & Debian `.deb` / Rust backend)

Environment variables (configured via `docker-compose.yml` or `/etc/default/ssh-console`):

| Variable | Default | Description |
| --- | --- | --- |
| `SSH_CONSOLE_BIND` | `0.0.0.0:3000` | Listen address and port |
| `SSH_CONSOLE_DATA_DIR` | `/var/lib/ssh-console` | Persistent directory for SQLite DB, vault key, and `known_hosts` |
| `SSH_CONSOLE_STATIC_DIR` | `/opt/ssh-console/dist` | Directory containing the built frontend assets |
| `RUST_LOG` | `info` | Log verbosity (`debug`, `info`, `warn`, `error`) |

Persistent files in `/var/lib/ssh-console`:
- `ssh-console.sqlite` — SQLite (WAL mode) storing users, sessions, hashed API keys, SSH commands, servers, certificates (encrypted private keys & passphrases), SSO/2FA settings, and audit logs.
- `vault.key` (`0600`) — 256-bit AES-256-GCM master key used to encrypt stored private keys, key passphrases, and OIDC client secrets.
- `known_hosts` (`0600`) — Persistent OpenSSH host-key registry for `StrictHostKeyChecking=accept-new`.

### Development (Node.js / Express)

- `data/trixiessh.json` — Local JSON store.
- `data/master.key` (`0600`) — Local AES-256-GCM master key (overrideable via `TRIXIESSH_MASTER_KEY`).
- `data/known_hosts` (`0600`) — Local OpenSSH host-key registry.

---

## Security Architecture

- **Private Keys & Passphrases at Rest**: Encrypted with **AES-256-GCM** using a dedicated server-side master key; never returned to the browser.
- **Ephemeral SSH Execution**: Private keys and optional `SSH_ASKPASS` helper scripts are written into a temporary `0700`/`0600` directory strictly for the duration of an OpenSSH invocation and wiped immediately afterwards.
- **Passwords**: Hashed with Argon2id (Rust backend) / scrypt with per-user salts (Express dev backend).
- **API Keys**: Generated with 256 bits of cryptographic entropy, displayed once on creation, and stored exclusively as **SHA-256** hashes.
- **Closed Registration**: The initial setup route is permanently locked once the first administrator account exists.

---

## License

MIT
