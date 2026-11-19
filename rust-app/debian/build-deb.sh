#!/usr/bin/env bash
set -euo pipefail

# Baut ein natives, vorkompiliertes Debian-.deb-Paket direkt auf einem Debian-13-(Trixie)-Host.
# Nutzung: ./debian/build-deb.sh [pfad-zum-frontend-dist]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${1:-${RUST_ROOT}/../dist}"
VERSION="1.0.0"
ARCH="$(dpkg --print-architecture)"
PKG_NAME="trixiessh_${VERSION}_${ARCH}.deb"
STAGE_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "${STAGE_DIR}"
}
trap cleanup EXIT

echo "==> Kompiliere TrixieSSH Release-Binary (${ARCH})..."
(cd "${RUST_ROOT}" && cargo build --release)

echo "==> Bereite Debian-Paketstruktur vor..."
mkdir -p \
  "${STAGE_DIR}/DEBIAN" \
  "${STAGE_DIR}/usr/local/bin" \
  "${STAGE_DIR}/etc/systemd/system" \
  "${STAGE_DIR}/etc/default" \
  "${STAGE_DIR}/opt/trixiessh/dist" \
  "${STAGE_DIR}/usr/share/doc/trixiessh"

install -m 0755 "${RUST_ROOT}/target/release/trixiessh" "${STAGE_DIR}/usr/local/bin/trixiessh"
install -m 0644 "${RUST_ROOT}/debian/trixiessh.service" "${STAGE_DIR}/etc/systemd/system/trixiessh.service"
install -m 0644 "${RUST_ROOT}/README.md" "${STAGE_DIR}/usr/share/doc/trixiessh/README.md"

if [ -d "${DIST_DIR}" ] && [ -f "${DIST_DIR}/index.html" ]; then
  cp -a "${DIST_DIR}/." "${STAGE_DIR}/opt/trixiessh/dist/"
else
  echo "WARNUNG: Kein Frontend-Build unter ${DIST_DIR} gefunden. Bitte zuerst 'npm run build' ausführen."
fi

cat > "${STAGE_DIR}/etc/default/trixiessh" <<'EOF'
# TrixieSSH Dienstkonfiguration (/etc/default/trixiessh)
# Nach Änderungen: sudo systemctl restart trixiessh
TRIXIESSH_BIND=0.0.0.0:3000
TRIXIESSH_DATA_DIR=/var/lib/trixiessh
TRIXIESSH_STATIC_DIR=/opt/trixiessh/dist
RUST_LOG=info
EOF
chmod 0644 "${STAGE_DIR}/etc/default/trixiessh"

INSTALLED_KB="$(du -sk "${STAGE_DIR}" | awk '{print $1}')"

cat > "${STAGE_DIR}/DEBIAN/control" <<EOF
Package: trixiessh
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Installed-Size: ${INSTALLED_KB}
Maintainer: TrixieSSH Maintainers <admin@localhost>
Depends: openssh-client, iputils-ping, curl, ca-certificates, adduser
Description: TrixieSSH - SSH-Befehls-, Zertifikats- & BMC-Webkonsole
 Selbstgehostetes Webinterface fuer Debian 13 (Trixie) zur passwortlosen
 Ausfuehrung von SSH-Befehlen und Befehlsketten mit OpenSSH-Schluesselpaaren
 oder CA-signierten Benutzerzertifikaten, 60-Sekunden-Ping-Dashboard und
 BMC-HTTPS-Pruefung.
EOF

cat > "${STAGE_DIR}/DEBIAN/conffiles" <<'EOF'
/etc/default/trixiessh
EOF

cat > "${STAGE_DIR}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
  if ! id -u trixiessh >/dev/null 2>&1; then
    adduser --system --group --home /var/lib/trixiessh --no-create-home --shell /usr/sbin/nologin trixiessh
  fi
  mkdir -p /var/lib/trixiessh /opt/trixiessh/dist
  chown -R trixiessh:trixiessh /var/lib/trixiessh
  chmod 0700 /var/lib/trixiessh

  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable trixiessh.service >/dev/null 2>&1 || true
    systemctl restart trixiessh.service || true
  fi
fi

exit 0
EOF

cat > "${STAGE_DIR}/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e

if [ "$1" = "remove" ] || [ "$1" = "deconfigure" ]; then
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl stop trixiessh.service >/dev/null 2>&1 || true
    systemctl disable trixiessh.service >/dev/null 2>&1 || true
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
  rm -rf /var/lib/trixiessh
fi

exit 0
EOF

chmod 0755 "${STAGE_DIR}/DEBIAN/postinst" "${STAGE_DIR}/DEBIAN/prerm" "${STAGE_DIR}/DEBIAN/postrm"
chmod 0644 "${STAGE_DIR}/DEBIAN/control" "${STAGE_DIR}/DEBIAN/conffiles"

OUT_FILE="${RUST_ROOT}/${PKG_NAME}"
dpkg-deb --root-owner-group --build "${STAGE_DIR}" "${OUT_FILE}"
echo "==> Fertig: ${OUT_FILE}"
echo "    Installation: sudo apt install ./${PKG_NAME}"
