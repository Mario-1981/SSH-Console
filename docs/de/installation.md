---
title: Installation & Docker
lang: de
alt_url: /en/installation.html
---

# Installation & Betrieb

SSH Console steht als **Docker-Image (inkl. GitHub Container Registry / GHCR)** sowie als natives **Debian-13-(Trixie)-Paket** bereit und lässt sich zur lokalen Entwicklung zusätzlich direkt mit **Node.js** betreiben.

---

## Option 1: Docker & Docker Compose (Empfohlen für Container)

Das Repository enthält ein **eigenständiges 3-stufiges `Dockerfile`** (baut sowohl das React-Frontend als auch das native Debian-13-Rust-Backend komplett im Container) sowie eine gehärtete **`docker-compose.yml`**.

### Fertiges Image aus der GitHub Container Registry (GHCR) ziehen

Der Workflow `.github/workflows/release-docker.yml` baut und veröffentlicht Images automatisch unter `ghcr.io/<owner>/<repo>` bei jedem Push auf `main`, bei Version-Tags (`v*`, Multi-Arch `amd64` + `arm64`) oder per manuellem Start:

```bash
SSH_CONSOLE_IMAGE=ghcr.io/<owner>/<repo>:latest docker compose pull
SSH_CONSOLE_IMAGE=ghcr.io/<owner>/<repo>:latest docker compose up -d
```

### Lokal mit Docker Compose bauen & starten

```bash
docker compose up -d --build
```

### Direkt mit der Docker CLI bauen & starten

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

> **Hinweis:** `--cap-add=NET_RAW` ermöglicht natives ICMP-Ping (`/bin/ping`) im Container. Ohne diese Capability nutzt SSH Console automatisch den TCP-Connect-Ping auf den jeweiligen SSH-Port.

---

## Option 2: Debian-13-(Trixie)-`.deb`-Paket

Laden Sie das aktuelle `.deb`-Paket aus den GitHub Releases herunter (automatisch gebaut über `.github/workflows/release-deb.yml`) und installieren Sie es:

```bash
sudo apt update
sudo apt install ./ssh-console_*_amd64.deb
```

Das Paket führt automatisch folgende Schritte aus:
1. Installiert das Rust-Binary (`/usr/local/bin/ssh-console`) und das gebaute Web-Frontend (`/opt/ssh-console/dist`).
2. Installiert die benötigten Systempakete (`openssh-client`, `iputils-ping`, `curl`, `ca-certificates`).
3. Legt den dedizierten Systembenutzer `ssh-console` sowie das Datenverzeichnis `/var/lib/ssh-console` (`0700`) an.
4. Installiert und startet die systemd-Unit `ssh-console.service`.

Status und Logs prüfen:

```bash
sudo systemctl status ssh-console
sudo journalctl -u ssh-console -f
```

Öffnen Sie anschließend `http://<server-ip>:3000` (bzw. Ihre HTTPS-Reverse-Proxy-Domain) im Browser und schließen Sie die einmalige Admin-Ersteinrichtung ab.

### `.deb`-Paket lokal bauen

Auf einem Debian-13-System (Trixie) mit Node.js 20+ und Rust 1.85+:

```bash
npm install --legacy-peer-deps
npm run build
cd rust-app
cargo build --release
./debian/build-deb.sh
```

---

## Option 3: Lokale Entwicklung (Node.js / Express)

Voraussetzungen: **Node.js 20+** (empfohlen 22) und OpenSSH-Client (`ssh`).

```bash
npm install --legacy-peer-deps
npm run dev
```

Der Entwicklungsserver läuft unter **http://localhost:3000**.  
Typprüfung und Produktions-Build des Frontends:

```bash
npm run lint
npm run build
```

---

## Konfiguration

### Umgebungsvariablen (`/etc/default/ssh-console` oder Docker `environment`)

| Variable | Standard | Beschreibung |
| --- | --- | --- |
| `SSH_CONSOLE_BIND` | `0.0.0.0:3000` | Listen-Adresse und Port (hinter einem Reverse-Proxy idealerweise `127.0.0.1:3000`) |
| `SSH_CONSOLE_DATA_DIR` | `/var/lib/ssh-console` | Verzeichnis für `ssh-console.sqlite` und `vault.key` |
| `SSH_CONSOLE_STATIC_DIR` | `/opt/ssh-console/dist` | Verzeichnis mit dem gebauten Frontend |
| `SSH_CONSOLE_SRC_DIR` | `/opt/ssh-console/rust-src` | Optionales Verzeichnis für den Rust-Quellcode-Export |
| `RUST_LOG` | `info` | Log-Level (`error`, `warn`, `info`, `debug`) |

### Systemd-Härtung

Die mitgelieferte Unit `ssh-console.service` nutzt strenge systemd-Schutzmechanismen:
- Eigener unprivilegierter Benutzer `ssh-console`
- `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `LockPersonality=yes`
- `ReadWritePaths=/var/lib/ssh-console`
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`
- `CapabilityBoundingSet=` (leer)

---

## Reverse-Proxy-Konfiguration (HTTPS & WebSockets)

> **Wichtig:** Für **WebAuthn-Sicherheitsschlüssel**, **Passkeys**, sichere Session-Cookies und **OIDC-SSO** ist im Produktivbetrieb **HTTPS zwingend erforderlich**. Da die interaktive SSH-Shell WebSockets (`/ws/shell`) verwendet, müssen die Upgrade-Header korrekt weitergeleitet werden.

### Nginx-Beispiel

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

        # WebSocket-Unterstützung für die interaktive SSH-Shell
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

### Caddy-Beispiel

```caddyfile
ssh.example.net {
    reverse_proxy 127.0.0.1:3000
}
```

Tragen Sie nach der HTTPS-Einrichtung Ihre öffentliche URL (z. B. `https://ssh.example.net`) unter **Admin → Anmeldung & SSO → Öffentliche URL** ein.

---

## Backup & Wiederherstellung

Alle persistenten Daten liegen in `/var/lib/ssh-console` (bzw. im Docker-Volume `ssh-console-data`):

| Datei | Wichtigkeit | Beschreibung |
| --- | --- | --- |
| `ssh-console.sqlite` (+ `-wal`/`-shm`) | **Kritisch** | Benutzer, Server, Kategorien, Befehle, verschlüsselte Zertifikate, Audit-Logs, Einstellungen |
| `vault.key` (`0600`) | **Kritisch** | 256-Bit AES-256-GCM-Masterschlüssel. **Ohne diese Datei können verschlüsselte SSH-Schlüssel und hinterlegte Passphrases nicht mehr entschlüsselt werden!** |
| `known_hosts/` | Empfohlen | Benutzerbezogene SSH-Host-Key-Datenbanken |

### Konsistentes Online-Backup (Debian-Host)

```bash
sudo mkdir -p /var/backups/ssh-console
sudo sqlite3 /var/lib/ssh-console/ssh-console.sqlite \
  ".backup '/var/backups/ssh-console/ssh-console.sqlite'"
sudo cp -p /var/lib/ssh-console/vault.key /var/backups/ssh-console/vault.key
sudo chmod 0600 /var/backups/ssh-console/vault.key
```

### Wiederherstellung

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

Weiter: **[Authentifizierung, SSO, 2FA & Passkeys](./authentifizierung.html)**
