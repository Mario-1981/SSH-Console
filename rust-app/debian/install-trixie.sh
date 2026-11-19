#!/usr/bin/env bash
set -euo pipefail

# Installationsskript für Debian 13 (Trixie)
echo "==> Installiere Debian Trixie Abhängigkeiten (openssh-client, Rust Toolchain, Build-Tools)..."
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  openssh-client \
  iputils-ping \
  build-essential \
  pkg-config \
  libssl-dev \
  ca-certificates \
  cargo \
  rustc

echo "==> Kompiliere TrixieSSH Release-Binary..."
cargo build --release

echo "==> Lege Systembenutzer und Verzeichnisse an..."
if ! id -u trixiessh >/dev/null 2>&1; then
  sudo useradd --system --home-dir /var/lib/trixiessh --shell /usr/sbin/nologin trixiessh
fi

sudo mkdir -p /var/lib/trixiessh /opt/trixiessh/dist
sudo install -m 0755 target/release/trixiessh /usr/local/bin/trixiessh
sudo chown -R trixiessh:trixiessh /var/lib/trixiessh /opt/trixiessh
sudo chmod 0700 /var/lib/trixiessh

echo "==> Installiere und aktiviere systemd-Dienst..."
sudo install -m 0644 debian/trixiessh.service /etc/systemd/system/trixiessh.service
sudo systemctl daemon-reload
sudo systemctl enable --now trixiessh.service

echo "==> Fertig! TrixieSSH läuft auf Port 3000."
echo "    Ersteinrichtung im Browser öffnen: http://<debian-trixie-ip>:3000"
