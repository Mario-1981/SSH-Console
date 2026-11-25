---
title: Installation & Docker
lang: en
alt_url: /de/installation.html
---

# Installation & Deployment

SSH Console is packaged for **Docker / GitHub Container Registry (GHCR)** and **Debian 13 (Trixie)** as a native Rust binary with a pre-built React frontend, and can also run with **Node.js** for local development.

---

## Option 1: Docker & Docker Compose (Recommended for Containers)

The repository includes a **self-contained 3-stage `Dockerfile`** (building both the React frontend and native Debian 13 Rust backend) and a hardened **`docker-compose.yml`**.

### Pull Pre-Built Image from GitHub Container Registry (GHCR)

GitHub Actions (`.github/workflows/release-docker.yml`) automatically builds and publishes images to `ghcr.io/<owner>/<repo>` on pushes to `main`, version tags (`v*`, multi-arch `amd64` + `arm64`), or manual dispatch:

```bash
SSH_CONSOLE_IMAGE=ghcr.io/<owner>/<repo>:latest docker compose pull
SSH_CONSOLE_IMAGE=ghcr.io/<owner>/<repo>:latest docker compose up -d
```

### Build Locally with Docker Compose

```bash
docker compose up -d --build
```

### Run Directly with Docker CLI

```bash
docker build -t ssh-console:latest .

docker run -d \
  --name ssh-console \
  --restart unless-stopped \
  -p 3000:3000 \
  --cap-drop=ALL \
  --cap-add=NET_RAW \
  --security-opt no-new-privileges:true \
  -v ssh-console-data:/var/lib/ssh-console \
  ssh-console:latest
```

> **Tip:** `--cap-add=NET_RAW` enables native ICMP `/bin/ping` inside the container. Without it, SSH Console automatically falls back to TCP connect pings on each server's SSH port.

---

## Option 2: Debian 13 (Trixie) `.deb` Package

Download the latest `.deb` package from GitHub Releases (built automatically by `.github/workflows/release-deb.yml`) and install it:

```bash
sudo apt update
sudo apt install ./ssh-console_*_amd64.deb
```

The package automatically:
1. Installs the Rust binary at `/usr/local/bin/ssh-console` and the web frontend at `/opt/ssh-console/dist`.
2. Installs required runtime packages (`openssh-client` incl. `ssh` & `ssh-keygen`, `iputils-ping`, `curl`, `ca-certificates`).
3. Creates the dedicated system user `ssh-console` and data directory `/var/lib/ssh-console` (`0700`).
4. Installs and enables `ssh-console.service`.

Check service status and logs:

```bash
sudo systemctl status ssh-console
sudo journalctl -u ssh-console -f
```

Open `http://<server-ip>:3000` (or your HTTPS reverse proxy URL) and complete the one-time administrator setup.

### Build the `.deb` Package Locally

On a Debian 13 (Trixie) machine with Node.js 20+ and Rust 1.85+:

```bash
npm install --legacy-peer-deps
npm run build
cd rust-app
cargo build --release
./debian/build-deb.sh
```

---

## Option 3: Local Development (Node.js / Express)

Prerequisites: **Node.js 20+** (22 recommended) and OpenSSH client (`ssh` & `ssh-keygen` for key/CA generation and certificate signing).

```bash
npm install --legacy-peer-deps
npm run dev
```

The development server listens on **http://localhost:3000**.  
Type-checking and production frontend build:

```bash
npm run lint
npm run build
```

---

## Configuration Reference

### Environment Variables (`/etc/default/ssh-console` or Docker `environment`)

| Variable | Default | Description |
| --- | --- | --- |
| `SSH_CONSOLE_BIND` | `0.0.0.0:3000` | Listen address and port (set to `127.0.0.1:3000` behind a reverse proxy) |
| `SSH_CONSOLE_DATA_DIR` | `/var/lib/ssh-console` | Directory for `ssh-console.sqlite` and `vault.key` |
| `SSH_CONSOLE_STATIC_DIR` | `/opt/ssh-console/dist` | Directory containing the built frontend assets |
| `SSH_CONSOLE_SRC_DIR` | `/opt/ssh-console/rust-src` | Optional Rust source bundle directory |
| `RUST_LOG` | `info` | Log level (`error`, `warn`, `info`, `debug`) |

### Systemd Hardening

The included `ssh-console.service` enforces strict systemd sandboxing:
- Dedicated unprivileged user `ssh-console`
- `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `LockPersonality=yes`
- `ReadWritePaths=/var/lib/ssh-console`
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`
- `CapabilityBoundingSet=` (empty)

---

## Reverse Proxy Configuration (HTTPS & WebSockets)

> **Important:** HTTPS is **required** in production for **WebAuthn Security Keys**, **Passkeys**, secure session cookies, and **OIDC SSO**. Because the interactive SSH Shell uses WebSockets (`/ws/shell`), ensure WebSocket upgrade headers are forwarded.

### Nginx Example

```nginx
server {
    listen 443 ssl http2;
    server_name ssh.example.net;

    ssl_certificate     /etc/letsencrypt/live/ssh.example.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ssh.example.net/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support for the interactive SSH Shell
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

### Caddy Example

```caddyfile
ssh.example.net {
    reverse_proxy 127.0.0.1:3000
}
```

After setting up HTTPS, enter your public URL (e.g. `https://ssh.example.net`) in **Admin → Authentication & SSO → Public URL**.

---

## Backup & Restore

All persistent state lives in `/var/lib/ssh-console` (or the `ssh-console-data` Docker volume):

| File | Importance | Description |
| --- | --- | --- |
| `ssh-console.sqlite` (+ `-wal`/`-shm`) | **Critical** | Users, user groups, CA assignments, servers, categories, commands & workflows, encrypted SSH certificates & managed CAs, auto-renewal configs, background jobs, audit logs, settings |
| `vault.key` (`0600`) | **Critical** | 256-bit AES-256-GCM master key. **Without this file, encrypted SSH private keys, managed CA keys, and stored passphrases cannot be decrypted!** |
| `known_hosts/` | Recommended | Per-user SSH host key trust databases |

### Consistent Online Backup (Debian Host)

```bash
sudo mkdir -p /var/backups/ssh-console
sudo sqlite3 /var/lib/ssh-console/ssh-console.sqlite \
  ".backup '/var/backups/ssh-console/ssh-console.sqlite'"
sudo cp -p /var/lib/ssh-console/vault.key /var/backups/ssh-console/vault.key
sudo chmod 0600 /var/backups/ssh-console/vault.key
```

### Restore

```bash
sudo systemctl stop ssh-console
sudo cp /var/backups/ssh-console/ssh-console.sqlite /var/lib/ssh-console/ssh-console.sqlite
sudo cp /var/backups/ssh-console/vault.key /var/lib/ssh-console/vault.key
sudo rm -f /var/lib/ssh-console/ssh-console.sqlite-wal /var/lib/ssh-console/ssh-console.sqlite-shm
sudo chown -R ssh-console:ssh-console /var/lib/ssh-console
sudo chmod 0600 /var/lib/ssh-console/vault.key
sudo systemctl start ssh-console
```

---

Next: **[Authentication, Groups, SSO & 2FA](./authentication.html)**
