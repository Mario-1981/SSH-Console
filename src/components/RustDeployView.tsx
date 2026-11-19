import React, { useEffect, useState } from 'react';
import { Download, Copy, Check, FileCode2 } from 'lucide-react';
import { api } from '../api';
import type { RustProjectFile } from '../types';

export function RustDeployView() {
  const [files, setFiles] = useState<RustProjectFile[]>([]);
  const [selectedPath, setSelectedPath] = useState<string>('Cargo.toml');
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);

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

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
            Rust-Quellcode &amp; Debian Trixie Bereitstellung
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            Vollständiges Rust-Projekt (Axum, Tokio, SQLite, Argon2, AES-256-GCM) inklusive systemd-Unit, Installationsskript und Debian-13-Dockerfile.
          </p>
        </div>

        <button
          type="button"
          onClick={() => {
            void api.downloadRustArchive();
          }}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
        >
          <Download className="w-4 h-4" />
          Rust-Projekt herunterladen (.tar.gz)
        </button>
      </div>

      {/* Quick Debian Trixie Deployment Guide */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-3">
          <h2 className="font-display text-base font-semibold text-slate-900">
            01. Installation auf Debian 13 (Trixie)
          </h2>
          <p className="text-xs text-slate-600">
            Entpacken Sie das Archiv auf Ihrem Debian-Trixie-Host und führen Sie das Installationsskript aus. Es installiert <code className="font-mono">openssh-client</code>, kompiliert das Rust-Binary und richtet den gehärteten <code className="font-mono">systemd</code>-Dienst ein.
          </p>
          <pre className="p-3.5 rounded-md bg-[#0B1120] text-slate-200 font-mono text-xs overflow-x-auto leading-relaxed">
{`tar -xzf trixiessh-debian-trixie-rust.tar.gz
cd trixiessh-rust
chmod +x debian/install-trixie.sh
./debian/install-trixie.sh`}
          </pre>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-3">
          <h2 className="font-display text-base font-semibold text-slate-900">
            02. OpenSSH-Zertifikat auf Zielservern einrichten
          </h2>
          <p className="text-xs text-slate-600">
            Erzeugen Sie das 3-Dateien-Bündel (<code className="font-mono">zertifikat</code>,{' '}
            <code className="font-mono">zertifikat.pub</code>,{' '}
            <code className="font-mono">zertifikat-cert.pub</code>) mit Ihrer SSH-CA und tragen Sie{' '}
            <code className="font-mono">TrustedUserCAKeys</code> auf den Zielservern ein.
          </p>
          <pre className="p-3.5 rounded-md bg-[#0B1120] text-slate-200 font-mono text-xs overflow-x-auto leading-relaxed">
{`# Benutzerschlüssel + CA-signiertes Zertifikat erstellen
ssh-keygen -t ed25519 -f zertifikat -N ""
ssh-keygen -s ssh_user_ca -I "benutzer-01" -n root,deploy -V +90d zertifikat.pub

# Auf jedem Zielserver in /etc/ssh/sshd_config:
TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub`}
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
