import React, { useEffect, useState } from 'react';
import { Download, Copy, Check, FileCode2, Package, Loader2, AlertCircle } from 'lucide-react';
import { api } from '../api';
import type { RustProjectFile } from '../types';

export function RustDeployView() {
  const [files, setFiles] = useState<RustProjectFile[]>([]);
  const [selectedPath, setSelectedPath] = useState<string>('Cargo.toml');
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [downloadingDeb, setDownloadingDeb] = useState(false);
  const [downloadingTar, setDownloadingTar] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  useEffect(() => {
    api
      .listRustFiles()
      .then((res) => {
        setFiles(res.files);
        if (res.files.length > 0 && !res.files.some((f) => f.path === 'Cargo.toml')) {
          setSelectedPath(res.files[0].path);
        }
      })
      .finally(() => setLoading(false));
  }, []);

  const currentFile = files.find((f) => f.path === selectedPath) ?? files[0] ?? null;

  async function handleCopy() {
    if (!currentFile) return;
    await navigator.clipboard.writeText(currentFile.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }

  async function handleDownloadDeb() {
    setDownloadError(null);
    setDownloadingDeb(true);
    try {
      await api.downloadDebPackage();
    } catch (err) {
      setDownloadError(err instanceof Error ? err.message : 'Download des Debian-Pakets fehlgeschlagen.');
    } finally {
      setDownloadingDeb(false);
    }
  }

  async function handleDownloadTar() {
    setDownloadError(null);
    setDownloadingTar(true);
    try {
      await api.downloadRustArchive();
    } catch (err) {
      setDownloadError(err instanceof Error ? err.message : 'Download des Archivs fehlgeschlagen.');
    } finally {
      setDownloadingTar(false);
    }
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
            Debian-Paket (.deb) &amp; Rust-Quellcode
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            Installationsfertiges Debian-13-(Trixie)-Paket inkl. Web-Oberfläche, Rust-Server (Axum, Tokio, SQLite, Argon2, AES-256-GCM) und gehärtetem systemd-Dienst.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            type="button"
            disabled={downloadingDeb}
            onClick={handleDownloadDeb}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-60 rounded-md transition-colors cursor-pointer whitespace-nowrap"
          >
            {downloadingDeb ? <Loader2 className="w-4 h-4 animate-spin" /> : <Package className="w-4 h-4" />}
            {downloadingDeb ? 'Erzeuge .deb-Paket...' : 'Debian-Paket herunterladen (.deb)'}
          </button>

          <button
            type="button"
            disabled={downloadingTar}
            onClick={handleDownloadTar}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-sm font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 disabled:opacity-60 rounded-md transition-colors cursor-pointer whitespace-nowrap"
          >
            {downloadingTar ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
            Quellcode (.tar.gz)
          </button>
        </div>
      </div>

      {downloadError && (
        <div className="flex items-start gap-2.5 px-4 py-3 text-sm text-rose-800 bg-rose-50 border border-rose-200 rounded-md">
          <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
          <span>{downloadError}</span>
        </div>
      )}

      {/* Debian .deb Deployment Guide */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-3">
          <h2 className="font-display text-base font-semibold text-slate-900">
            01. Installation per Debian-Paket (.deb)
          </h2>
          <p className="text-xs text-slate-600 leading-relaxed">
            Kopieren Sie <code className="font-mono">ssh-console_1.0.0_all.deb</code> auf Ihren Debian-13-Server und installieren Sie es mit <code className="font-mono">apt</code>. Alle Abhängigkeiten (<code className="font-mono">openssh-client</code>, <code className="font-mono">iputils-ping</code>, <code className="font-mono">curl</code>, Rust-Toolchain) werden automatisch aufgelöst, das native Binary für <code className="font-mono">amd64</code>/<code className="font-mono">arm64</code> kompiliert und der <code className="font-mono">systemd</code>-Dienst direkt gestartet.
          </p>
          <pre className="p-3.5 rounded-md bg-[#0B1120] text-slate-200 font-mono text-xs overflow-x-auto leading-relaxed">
{`sudo apt update
sudo apt install ./ssh-console_1.0.0_all.deb

# Dienststatus & Logs prüfen
sudo systemctl status ssh-console
sudo journalctl -u ssh-console -f`}
          </pre>
          <p className="text-xs text-slate-500">
            Port oder Bind-Adresse lassen sich jederzeit in <code className="font-mono">/etc/default/ssh-console</code> anpassen (danach <code className="font-mono">sudo systemctl restart ssh-console</code>). Deinstallation: <code className="font-mono">sudo apt remove ssh-console</code> (oder <code className="font-mono">purge</code> inkl. Datenbank).
          </p>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-3">
          <h2 className="font-display text-base font-semibold text-slate-900">
            02. OpenSSH-Zertifikat oder Schlüsselpaar einrichten
          </h2>
          <p className="text-xs text-slate-600 leading-relaxed">
            SSH Console unterstützt sowohl klassische 2-Dateien-SSH-Schlüsselpaare (<code className="font-mono">zertifikat</code> + <code className="font-mono">zertifikat.pub</code> via <code className="font-mono">authorized_keys</code>) als auch CA-signierte 3-Dateien-Zertifikate inkl. <code className="font-mono">zertifikat-cert.pub</code>.
          </p>
          <pre className="p-3.5 rounded-md bg-[#0B1120] text-slate-200 font-mono text-xs overflow-x-auto leading-relaxed">
{`# Variante A: Klassisches Schlüsselpaar (ohne cert.pub)
ssh-keygen -t ed25519 -f zertifikat -N ""
ssh-copy-id -i zertifikat.pub root@<ziel-ip>

# Variante B: Zusätzlich mit SSH-CA signieren
ssh-keygen -s ssh_user_ca -I "benutzer-01" -n root,deploy -V +90d zertifikat.pub
# Auf Zielservern in /etc/ssh/sshd_config:
TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub`}
          </pre>
        </div>
      </section>

      {/* GitHub Releases Publishing Guide */}
      <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-3">
        <h2 className="font-display text-base font-semibold text-slate-900">
          03. Auf GitHub Releases bereitstellen &amp; direkt auf dem Server installieren
        </h2>
        <p className="text-xs text-slate-600 leading-relaxed">
          Der fertige GitHub-Actions-Workflow <code className="font-mono">.github/workflows/release-deb.yml</code> liegt bereits im Projekt. Nach dem Speichern/Pushen in dein GitHub-Repository baut ein Tag-Push (z. B. <code className="font-mono">v1.0.0</code>) automatisch sowohl ein vorkompiliertes <code className="font-mono">amd64</code>-Paket für Debian 13 als auch das universelle <code className="font-mono">all</code>-Paket und veröffentlicht beide direkt unter <strong>GitHub Releases</strong>.
        </p>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <pre className="p-3.5 rounded-md bg-[#0B1120] text-slate-200 font-mono text-xs overflow-x-auto leading-relaxed">
{`# Option A: Automatisch per GitHub Actions (Tag pushen)
git tag v1.0.0
git push origin v1.0.0

# Option B: Heruntergeladene .deb direkt als Release hochladen
gh release create v1.0.0 ./ssh-console_1.0.0_all.deb \\
  --title "SSH Console v1.0.0"`}
          </pre>
          <pre className="p-3.5 rounded-md bg-[#0B1120] text-slate-200 font-mono text-xs overflow-x-auto leading-relaxed">
{`# Danach direkt auf deinem Debian-13-Server installieren:
wget https://github.com/<DEIN-USER>/<DEIN-REPO>/releases/latest/download/ssh-console_1.0.0_amd64.deb
sudo apt update
sudo apt install ./ssh-console_1.0.0_amd64.deb`}
          </pre>
        </div>
      </section>

      {/* Interactive Source Code Browser */}
      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="grid grid-cols-1 lg:grid-cols-12 min-h-[520px]">
          <div className="lg:col-span-3 border-b lg:border-b-0 lg:border-r border-slate-200 bg-slate-50/70 p-3">
            <p className="px-2.5 py-1.5 text-xs font-medium text-slate-500">
              Projektdateien ({files.length})
            </p>
            {loading ? (
              <p className="px-2.5 py-4 text-xs text-slate-500">Lade Dateien...</p>
            ) : (
              <ul className="space-y-0.5 mt-1">
                {files.map((file) => {
                  const active = currentFile?.path === file.path;
                  return (
                    <li key={file.path}>
                      <button
                        type="button"
                        onClick={() => setSelectedPath(file.path)}
                        className={`w-full flex items-center justify-between gap-2 px-2.5 py-2 text-xs font-mono rounded-md transition-colors cursor-pointer text-left ${
                          active
                            ? 'bg-blue-50 text-blue-800 font-medium'
                            : 'text-slate-700 hover:bg-slate-200/60'
                        }`}
                      >
                        <span className="truncate flex items-center gap-1.5">
                          <FileCode2 className="w-3.5 h-3.5 shrink-0 opacity-70" />
                          {file.path}
                        </span>
                        <span className="text-[11px] text-slate-400 tabular-nums shrink-0">
                          {(file.size / 1024).toFixed(1)} KB
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          <div className="lg:col-span-9 flex flex-col bg-[#0B1120] text-slate-100">
            <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between gap-4 bg-slate-950/60">
              <span className="font-mono text-xs text-slate-200">
                {currentFile?.path ?? '—'}
              </span>
              <button
                type="button"
                onClick={handleCopy}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded transition-colors cursor-pointer whitespace-nowrap"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Kopiert' : 'Kopieren'}
              </button>
            </div>
            <pre className="flex-1 p-5 font-mono text-xs leading-relaxed text-slate-200 overflow-auto max-h-[580px]">
              {currentFile?.content ?? ''}
            </pre>
          </div>
        </div>
      </section>
    </div>
  );
}
