#!/usr/bin/env bash
set -euo pipefail

# Baut ein natives, vorkompiliertes Debian-.deb-Paket direkt auf einem Debian-13-(Trixie)-Host.
# Nutzung: ./debian/build-deb.sh [pfad-zum-frontend-dist]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${1:-${RUST_ROOT}/../dist}"
VERSION="${DEB_VERSION:-1.0.0}"
ARCH="$(dpkg --print-architecture)"
PKG_NAME="ssh-console_${VERSION}_${ARCH}.deb"
STAGE_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "${STAGE_DIR}"
}
trap cleanup EXIT

echo "==> Kompiliere SSH Console Release-Binary (${ARCH})..."
(cd "${RUST_ROOT}" && cargo build --release)

echo "==> Bereite Debian-Paketstruktur vor..."
mkdir -p \
  "${STAGE_DIR}/DEBIAN" \
  "${STAGE_DIR}/usr/local/bin" \
  "${STAGE_DIR}/etc/systemd/system" \
  "${STAGE_DIR}/etc/default" \
  "${STAGE_DIR}/opt/ssh-console/dist" \
  "${STAGE_DIR}/usr/share/doc/ssh-console"

install -m 0755 "${RUST_ROOT}/target/release/ssh-console" "${STAGE_DIR}/usr/local/bin/ssh-console"
install -m 0644 "${RUST_ROOT}/debian/ssh-console.service" "${STAGE_DIR}/etc/systemd/system/ssh-console.service"
install -m 0644 "${RUST_ROOT}/README.md" "${STAGE_DIR}/usr/share/doc/ssh-console/README.md"

if [ -d "${DIST_DIR}" ] && [ -f "${DIST_DIR}/index.html" ]; then
  cp -a "${DIST_DIR}/." "${STAGE_DIR}/opt/ssh-console/dist/"
else
  echo "WARNUNG: Kein Frontend-Build unter ${DIST_DIR} gefunden. Bitte zuerst 'npm run build' ausführen."
fi

cat > "${STAGE_DIR}/etc/default/ssh-console" <<'EOF'
# SSH Console Dienstkonfiguration (/etc/default/ssh-console)
# Nach Änderungen: sudo systemctl restart ssh-console
SSH_CONSOLE_BIND=0.0.0.0:3000
SSH_CONSOLE_DATA_DIR=/var/lib/ssh-console
SSH_CONSOLE_STATIC_DIR=/opt/ssh-console/dist
RUST_LOG=info
EOF
chmod 0644 "${STAGE_DIR}/etc/default/ssh-console"

INSTALLED_KB="$(du -sk "${STAGE_DIR}" | awk '{print $1}')"

cat > "${STAGE_DIR}/DEBIAN/control" <<EOF
Package: ssh-console
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Installed-Size: ${INSTALLED_KB}
Maintainer: SSH Console Maintainers <admin@localhost>
Depends: openssh-client, iputils-ping, curl, ca-certificates, adduser
Description: SSH Console - SSH-Befehls-, Zertifikats- & BMC-Webkonsole
 Selbstgehostetes Webinterface fuer Debian 13 (Trixie) zur passwortlosen
 Ausfuehrung von SSH-Befehlen und Befehlsketten mit OpenSSH-Schluesselpaaren
 oder CA-signierten Benutzerzertifikaten, 60-Sekunden-Ping-Dashboard und
 BMC-HTTPS-Pruefung.
EOF

cat > "${STAGE_DIR}/DEBIAN/conffiles" <<'EOF'
/etc/default/ssh-console
EOF

cat > "${STAGE_DIR}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
  if ! id -u ssh-console >/dev/null 2>&1; then
    adduser --system --group --home /var/lib/ssh-console --no-create-home --shell /usr/sbin/nologin ssh-console
  fi
  mkdir -p /var/lib/ssh-console /opt/ssh-console/dist
  chown -R ssh-console:ssh-console /var/lib/ssh-console
  chmod 0700 /var/lib/ssh-console

  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable ssh-console.service >/dev/null 2>&1 || true
    systemctl restart ssh-console.service || true
  fi
fi

exit 0
EOF

cat > "${STAGE_DIR}/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e

if [ "$1" = "remove" ] || [ "$1" = "deconfigure" ]; then
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl stop ssh-console.service >/dev/null 2>&1 || true
    systemctl disable ssh-console.service >/dev/null 2>&1 || true
  fi
fi

exit 0
EOF

cat > "${STAGE_DIR}/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi

if [ "$1" = "purge" ]; then
  rm -rf /var/lib/ssh-console
fi

exit 0
EOF

chmod 0755 "${STAGE_DIR}/DEBIAN/postinst" "${STAGE_DIR}/DEBIAN/prerm" "${STAGE_DIR}/DEBIAN/postrm"
chmod 0644 "${STAGE_DIR}/DEBIAN/control" "${STAGE_DIR}/DEBIAN/conffiles"

OUT_FILE="${RUST_ROOT}/${PKG_NAME}"
dpkg-deb --root-owner-group --build "${STAGE_DIR}" "${OUT_FILE}"
echo "==> Fertig: ${OUT_FILE}"
echo "    Installation: sudo apt install ./${PKG_NAME}"
