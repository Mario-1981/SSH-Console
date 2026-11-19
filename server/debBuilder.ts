import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export interface BuiltDebPackage {
  fileName: string;
  version: string;
  architecture: string;
  buffer: Buffer;
}

const PACKAGE_NAME = 'trixiessh';
const PACKAGE_VERSION = '1.0.0';
const PACKAGE_ARCH = 'all';

function copyDirRecursive(src: string, dest: string, skipNames: Set<string> = new Set()) {
  fs.mkdirSync(dest, { recursive: true, mode: 0o755 });
  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    if (skipNames.has(entry.name)) continue;
    if (entry.name.endsWith('.deb')) continue;
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDirRecursive(srcPath, destPath, skipNames);
    } else if (entry.isFile()) {
      fs.copyFileSync(srcPath, destPath);
      const isShellScript = entry.name.endsWith('.sh');
      fs.chmodSync(destPath, isShellScript ? 0o755 : 0o644);
    }
  }
}

function directorySizeKb(dir: string): number {
  let totalBytes = 0;
  function walk(current: string) {
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile()) {
        totalBytes += fs.statSync(full).size;
      }
    }
  }
  walk(dir);
  return Math.max(1, Math.ceil(totalBytes / 1024));
}

function ensureFrontendDist(projectRoot: string): string {
  const distDir = path.join(projectRoot, 'dist');
  const indexHtml = path.join(distDir, 'index.html');
  if (!fs.existsSync(indexHtml)) {
    execFileSync('npm', ['run', 'build'], {
      cwd: projectRoot,
      stdio: 'pipe',
      timeout: 120_000,
    });
  }
  if (!fs.existsSync(indexHtml)) {
    throw new Error('Frontend-Build (dist/index.html) konnte nicht erstellt werden.');
  }
  return distDir;
}

export function buildDebianPackage(projectRoot: string, rustAppDir: string): BuiltDebPackage {
  if (!fs.existsSync(rustAppDir)) {
    throw new Error('Rust-Projektverzeichnis wurde nicht gefunden.');
  }

  const distDir = ensureFrontendDist(projectRoot);
  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'trixiessh-deb-'));
  const stageDir = path.join(tmpBase, 'pkg');
  const fileName = `${PACKAGE_NAME}_${PACKAGE_VERSION}_${PACKAGE_ARCH}.deb`;
  const outDebPath = path.join(tmpBase, fileName);

  try {
    const debianDir = path.join(stageDir, 'DEBIAN');
    const systemdDir = path.join(stageDir, 'etc', 'systemd', 'system');
    const defaultsDir = path.join(stageDir, 'etc', 'default');
    const optDistDir = path.join(stageDir, 'opt', 'trixiessh', 'dist');
    const optRustDir = path.join(stageDir, 'opt', 'trixiessh', 'rust-src');
    const docDir = path.join(stageDir, 'usr', 'share', 'doc', 'trixiessh');

    for (const dir of [debianDir, systemdDir, defaultsDir, optDistDir, optRustDir, docDir]) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
    }

    // 1. Kompilierte Web-Oberfläche (React/Vite) einpacken
    copyDirRecursive(distDir, optDistDir);

    // 2. Vollständigen Rust-Quellcode einpacken (ohne target/.git)
    copyDirRecursive(rustAppDir, optRustDir, new Set(['target', '.git', 'node_modules']));

    // 3. Systemd-Unit und Dokumentation
    const serviceSrc = path.join(rustAppDir, 'debian', 'trixiessh.service');
    fs.copyFileSync(serviceSrc, path.join(systemdDir, 'trixiessh.service'));
    fs.chmodSync(path.join(systemdDir, 'trixiessh.service'), 0o644);

    const readmeSrc = path.join(rustAppDir, 'README.md');
    if (fs.existsSync(readmeSrc)) {
      fs.copyFileSync(readmeSrc, path.join(docDir, 'README.md'));
      fs.chmodSync(path.join(docDir, 'README.md'), 0o644);
    }

    // 4. Editierbare Dienstkonfiguration (/etc/default/trixiessh)
    const defaultsContent = `# TrixieSSH Dienstkonfiguration (/etc/default/trixiessh)
# Nach Aenderungen Dienst neu starten: sudo systemctl restart trixiessh
TRIXIESSH_BIND=0.0.0.0:3000
TRIXIESSH_DATA_DIR=/var/lib/trixiessh
TRIXIESSH_STATIC_DIR=/opt/trixiessh/dist
TRIXIESSH_SRC_DIR=/opt/trixiessh/rust-src
RUST_LOG=info
`;
    fs.writeFileSync(path.join(defaultsDir, 'trixiessh'), defaultsContent, { mode: 0o644 });

    // 5. DEBIAN/conffiles
    fs.writeFileSync(path.join(debianDir, 'conffiles'), '/etc/default/trixiessh\n', {
      mode: 0o644,
    });

    // 6. DEBIAN/postinst
    const postinst = `#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
  if ! id -u trixiessh >/dev/null 2>&1; then
    adduser --system --group --home /var/lib/trixiessh --no-create-home --shell /usr/sbin/nologin trixiessh
  fi

  mkdir -p /var/lib/trixiessh /opt/trixiessh/dist
  chown -R trixiessh:trixiessh /var/lib/trixiessh
  chmod 0700 /var/lib/trixiessh

  echo "TrixieSSH: Kompiliere natives Rust-Server-Binary fuer $(dpkg --print-architecture)..."
  BUILD_TMP="$(mktemp -d /tmp/trixiessh-build.XXXXXX)"
  trap 'rm -rf "$BUILD_TMP"' EXIT
  export CARGO_HOME="$BUILD_TMP/cargo-home"
  export CARGO_TARGET_DIR="$BUILD_TMP/target"

  cargo build --release --manifest-path /opt/trixiessh/rust-src/Cargo.toml
  install -m 0755 "$CARGO_TARGET_DIR/release/trixiessh" /usr/local/bin/trixiessh

  rm -rf "$BUILD_TMP"
  trap - EXIT

  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable trixiessh.service >/dev/null 2>&1 || true
    systemctl restart trixiessh.service || true
  fi

  echo ""
  echo "=============================================================="
  echo " TrixieSSH ${PACKAGE_VERSION} erfolgreich installiert!"
  echo " Web-Oberflaeche: http://<Server-IP>:3000"
  echo " Konfiguration:   /etc/default/trixiessh"
  echo " Status pruefen:  sudo systemctl status trixiessh"
  echo " Logs anzeigen:   sudo journalctl -u trixiessh -f"
  echo "=============================================================="
fi

exit 0
`;
    fs.writeFileSync(path.join(debianDir, 'postinst'), postinst, { mode: 0o755 });

    // 7. DEBIAN/prerm
    const prerm = `#!/bin/sh
set -e

if [ "$1" = "remove" ] || [ "$1" = "deconfigure" ]; then
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl stop trixiessh.service >/dev/null 2>&1 || true
    systemctl disable trixiessh.service >/dev/null 2>&1 || true
  fi
fi

exit 0
`;
    fs.writeFileSync(path.join(debianDir, 'prerm'), prerm, { mode: 0o755 });

    // 8. DEBIAN/postrm
    const postrm = `#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi

if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  rm -f /usr/local/bin/trixiessh
fi

if [ "$1" = "purge" ]; then
  rm -rf /var/lib/trixiessh
fi

exit 0
`;
    fs.writeFileSync(path.join(debianDir, 'postrm'), postrm, { mode: 0o755 });

    // 9. DEBIAN/control (nachdem alle Nutzdaten kopiert wurden, fuer korrekte Installed-Size)
    const installedSizeKb = directorySizeKb(stageDir);
    const control = `Package: ${PACKAGE_NAME}
Version: ${PACKAGE_VERSION}
Section: admin
Priority: optional
Architecture: ${PACKAGE_ARCH}
Installed-Size: ${installedSizeKb}
Maintainer: TrixieSSH Maintainers <admin@localhost>
Depends: openssh-client, iputils-ping, curl, ca-certificates, adduser, build-essential, pkg-config, libssl-dev, cargo, rustc
Description: TrixieSSH - SSH-Befehls-, Zertifikats- & BMC-Webkonsole
 Selbstgehostetes Webinterface fuer Debian 13 (Trixie) zur passwortlosen
 Ausfuehrung von SSH-Befehlen und Befehlsketten mit OpenSSH-Schluesselpaaren
 oder CA-signierten Benutzerzertifikaten, 60-Sekunden-Ping-Dashboard und
 BMC-HTTPS-Pruefung.
 .
 Enthaelt die fertig gebaute Web-Oberflaeche sowie den vollstaendigen
 Rust-Quellcode und kompiliert das native Server-Binary bei der Installation
 automatisch fuer die Architektur des Zielservers (amd64/arm64).
`;
    fs.writeFileSync(path.join(debianDir, 'control'), control, { mode: 0o644 });

    // 10. Echtes .deb-Paket via dpkg-deb erzeugen
    execFileSync('dpkg-deb', ['--root-owner-group', '--build', stageDir, outDebPath], {
      stdio: 'pipe',
      timeout: 60_000,
    });

    const buffer = fs.readFileSync(outDebPath);
    return {
      fileName,
      version: PACKAGE_VERSION,
      architecture: PACKAGE_ARCH,
      buffer,
    };
  } finally {
    fs.rmSync(tmpBase, { recursive: true, force: true });
  }
}
