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

const PACKAGE_NAME = 'ssh-console';
const PACKAGE_VERSION = (process.env.DEB_VERSION || '1.0.0').replace(/^v/, '').trim() || '1.0.0';
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
  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-console-deb-'));
  const stageDir = path.join(tmpBase, 'pkg');
  const fileName = `${PACKAGE_NAME}_${PACKAGE_VERSION}_${PACKAGE_ARCH}.deb`;
  const outDebPath = path.join(tmpBase, fileName);

  try {
    const debianDir = path.join(stageDir, 'DEBIAN');
    const systemdDir = path.join(stageDir, 'etc', 'systemd', 'system');
    const defaultsDir = path.join(stageDir, 'etc', 'default');
    const optDistDir = path.join(stageDir, 'opt', 'ssh-console', 'dist');
    const optRustDir = path.join(stageDir, 'opt', 'ssh-console', 'rust-src');
    const docDir = path.join(stageDir, 'usr', 'share', 'doc', 'ssh-console');

    for (const dir of [debianDir, systemdDir, defaultsDir, optDistDir, optRustDir, docDir]) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
    }

    // 1. Kompilierte Web-Oberfläche (React/Vite) einpacken
    copyDirRecursive(distDir, optDistDir);

    // 2. Vollständigen Rust-Quellcode einpacken (ohne target/.git)
    copyDirRecursive(rustAppDir, optRustDir, new Set(['target', '.git', 'node_modules']));

    // 3. Systemd-Unit und Dokumentation
    const serviceSrc = path.join(rustAppDir, 'debian', 'ssh-console.service');
    fs.copyFileSync(serviceSrc, path.join(systemdDir, 'ssh-console.service'));
    fs.chmodSync(path.join(systemdDir, 'ssh-console.service'), 0o644);

    const readmeSrc = path.join(rustAppDir, 'README.md');
    if (fs.existsSync(readmeSrc)) {
      fs.copyFileSync(readmeSrc, path.join(docDir, 'README.md'));
      fs.chmodSync(path.join(docDir, 'README.md'), 0o644);
    }

    // 4. Editierbare Dienstkonfiguration (/etc/default/ssh-console)
    const defaultsContent = `# SSH Console Dienstkonfiguration (/etc/default/ssh-console)
# Nach Aenderungen Dienst neu starten: sudo systemctl restart ssh-console
SSH_CONSOLE_BIND=0.0.0.0:3000
SSH_CONSOLE_DATA_DIR=/var/lib/ssh-console
SSH_CONSOLE_STATIC_DIR=/opt/ssh-console/dist
SSH_CONSOLE_SRC_DIR=/opt/ssh-console/rust-src
RUST_LOG=info
`;
    fs.writeFileSync(path.join(defaultsDir, 'ssh-console'), defaultsContent, { mode: 0o644 });

    // 5. DEBIAN/conffiles
    fs.writeFileSync(path.join(debianDir, 'conffiles'), '/etc/default/ssh-console\n', {
      mode: 0o644,
    });

    // 6. DEBIAN/postinst
    const postinst = `#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
  if ! id -u ssh-console >/dev/null 2>&1; then
    adduser --system --group --home /var/lib/ssh-console --no-create-home --shell /usr/sbin/nologin ssh-console
  fi

  mkdir -p /var/lib/ssh-console /opt/ssh-console/dist
  chown -R ssh-console:ssh-console /var/lib/ssh-console
  chmod 0700 /var/lib/ssh-console

  echo "SSH Console: Kompiliere natives Rust-Server-Binary fuer $(dpkg --print-architecture)..."
  BUILD_TMP="$(mktemp -d /tmp/ssh-console-build.XXXXXX)"
  trap 'rm -rf "$BUILD_TMP"' EXIT
  export CARGO_HOME="$BUILD_TMP/cargo-home"
  export CARGO_TARGET_DIR="$BUILD_TMP/target"

  (cd /opt/ssh-console/rust-src && cargo build --release)
  install -m 0755 "$CARGO_TARGET_DIR/release/ssh-console" /usr/local/bin/ssh-console

  rm -rf "$BUILD_TMP"
  trap - EXIT

  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable ssh-console.service >/dev/null 2>&1 || true
    systemctl restart ssh-console.service || true
  fi

  echo ""
  echo "=============================================================="
  echo " SSH Console ${PACKAGE_VERSION} erfolgreich installiert!"
  echo " Web-Oberflaeche: http://<Server-IP>:3000"
  echo " Konfiguration:   /etc/default/ssh-console"
  echo " Status pruefen:  sudo systemctl status ssh-console"
  echo " Logs anzeigen:   sudo journalctl -u ssh-console -f"
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
    systemctl stop ssh-console.service >/dev/null 2>&1 || true
    systemctl disable ssh-console.service >/dev/null 2>&1 || true
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
  rm -f /usr/local/bin/ssh-console
fi

if [ "$1" = "purge" ]; then
  rm -rf /var/lib/ssh-console
fi

exit 0
`;
    fs.writeFileSync(path.join(debianDir, 'postrm'), postrm, { mode: 0o755 });

    // 9. DEBIAN/control
    const installedSizeKb = directorySizeKb(stageDir);
    const control = `Package: ${PACKAGE_NAME}
Version: ${PACKAGE_VERSION}
Section: admin
Priority: optional
Architecture: ${PACKAGE_ARCH}
Installed-Size: ${installedSizeKb}
Maintainer: SSH Console Maintainers <admin@localhost>
Depends: openssh-client, iputils-ping, curl, ca-certificates, adduser, build-essential, pkg-config, libssl-dev, cargo, rustc
Description: SSH Console - SSH-Befehls-, Zertifikats- & BMC-Webkonsole
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
