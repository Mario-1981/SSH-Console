#!/usr/bin/env bash
set -euo pipefail

# Installationsskript für Debian 13 (Trixie)
echo "==> Installiere Debian Trixie Abhängigkeiten (openssh-client, Rust Toolchain, Build-Tools)..."
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  openssh-client \
  iputils-ping \
  curl \
  build-essential \
  pkg-config \
  libssl-dev \
  ca-certificates \
  cargo \
  rustc

echo "==> Kompiliere SSH Console Release-Binary..."
cargo build --release

echo "==> Lege Systembenutzer und Verzeichnisse an..."
if ! id -u ssh-console >/dev/null 2>&1; then
  sudo useradd --system --home-dir /var/lib/ssh-console --shell /usr/sbin/nologin ssh-console
fi

sudo mkdir -p /var/lib/ssh-console /opt/ssh-console/dist
sudo install -m 0755 target/release/ssh-console /usr/local/bin/ssh-console
sudo chown -R ssh-console:ssh-console /var/lib/ssh-console /opt/ssh-console
sudo chmod 0700 /var/lib/ssh-console

echo "==> Installiere und aktiviere systemd-Dienst..."
sudo install -m 0644 debian/ssh-console.service /etc/systemd/system/ssh-console.service
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-console.service

echo "==> Fertig! SSH Console läuft auf Port 3000."
echo "    Ersteinrichtung im Browser öffnen: http://<debian-trixie-ip>:3000"
