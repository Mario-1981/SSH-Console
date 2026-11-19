import React, { useRef, useState } from 'react';
import {
  Upload,
  CheckCircle2,
  AlertTriangle,
  Trash2,
  Download,
  Wand2,
  KeyRound,
  FileText,
  Share2,
} from 'lucide-react';
import { api } from '../api';
import { ShareDialog, formatShareSummary } from './ShareDialog';
import type { User, UserCertificate } from '../types';

interface CertificatesViewProps {
  user: User;
  users: User[];
  certificates: UserCertificate[];
  onRefresh: () => Promise<void>;
}

function downloadTextFile(filename: string, content: string) {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function formatIsoDate(iso: string): string {
  if (!iso || iso.startsWith('Unbegrenzt')) return iso || '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString('de-DE', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function CertificatesView({ user, users, certificates, onRefresh }: CertificatesViewProps) {
  const isAdmin = user.role === 'admin';
  const [bundleName, setBundleName] = useState('');
  const [privFile, setPrivFile] = useState('zertifikat');
  const [pubFile, setPubFile] = useState('zertifikat.pub');
  const [certFile, setCertFile] = useState('zertifikat-cert.pub');

  const [privContent, setPrivContent] = useState('');
  const [pubContent, setPubContent] = useState('');
  const [certContent, setCertContent] = useState('');
  const [shareOnCreate, setShareOnCreate] = useState(false);
  const [sharingCert, setSharingCert] = useState<UserCertificate | null>(null);
  const [lastGeneratedBundle, setLastGeneratedBundle] = useState<{
    privateKey: string;
    publicKey: string;
    certificate: string;
    caPublicKey: string;
  } | null>(null);

  const [showTextEditors, setShowTextEditors] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [saving, setSaving] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const multiInputRef = useRef<HTMLInputElement | null>(null);
  const privInputRef = useRef<HTMLInputElement | null>(null);
  const pubInputRef = useRef<HTMLInputElement | null>(null);
  const certInputRef = useRef<HTMLInputElement | null>(null);

  async function classifyAndLoadFiles(fileList: FileList | File[]) {
    setError(null);
    setSuccess(null);
    const files = Array.from(fileList);
    let loaded = 0;

    for (const file of files) {
      const text = await file.text();
      const lower = file.name.toLowerCase();

      if (lower.endsWith('-cert.pub') || text.includes('-cert-v01@openssh.com')) {
        setCertFile(file.name);
        setCertContent(text);
        loaded++;
      } else if (
        lower.endsWith('.pub') ||
        /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-|sk-ssh-)/.test(text.trim())
      ) {
        setPubFile(file.name);
        setPubContent(text);
        loaded++;
      } else if (text.includes('PRIVATE KEY')) {
        setPrivFile(file.name);
        setPrivContent(text);
        if (!bundleName) {
          setBundleName(file.name.replace(/\.(pem|key)$/i, ''));
        }
        loaded++;
      }
    }

    if (loaded === 0) {
      setError(
        'Dateien konnten nicht automatisch zugeordnet werden. Bitte verwenden Sie zertifikat, zertifikat.pub und zertifikat-cert.pub.'
      );
    }
  }

  async function handleSingleFile(
    e: React.ChangeEvent<HTMLInputElement>,
    slot: 'priv' | 'pub' | 'cert'
  ) {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    if (slot === 'priv') {
      setPrivFile(file.name);
      setPrivContent(text);
    } else if (slot === 'pub') {
      setPubFile(file.name);
      setPubContent(text);
    } else {
      setCertFile(file.name);
      setCertContent(text);
    }
    e.target.value = '';
  }

  async function handleGenerateTestBundle() {
    setError(null);
    setSuccess(null);
    setGenerating(true);
    try {
      const keyId = `${user.username}-trixie-ed25519`;
      const generated = await api.generateTestCertificate({
        keyId,
        principals: [user.defaultSshUser || 'root', 'deploy', 'debian'],
      });

      const saved = await api.uploadCertificate({
        name: `${user.username}-ed25519-test`,
        privateKeyFileName: 'zertifikat',
        publicKeyFileName: 'zertifikat.pub',
        certFileName: 'zertifikat-cert.pub',
        privateKeyContent: generated.privateKey,
        publicKeyContent: generated.publicKey,
        certContent: generated.certificate,
      });

      await onRefresh();
      setLastGeneratedBundle(generated);
      setSuccess(
        saved.replaced
          ? `Bestehendes Test-Zertifikatspaket „${saved.certificate.name}“ wurde mit einem neu erzeugten Ed25519-Verbund (zertifikat, zertifikat.pub, zertifikat-cert.pub) überschrieben.`
          : `Test-Zertifikatspaket „${saved.certificate.name}“ (zertifikat, zertifikat.pub, zertifikat-cert.pub) wurde erzeugt, kryptografisch verifiziert und sofort gespeichert — es kann jetzt im Dashboard und bei der Befehlsausführung ausgewählt werden.`
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Testzertifikat konnte nicht erzeugt werden.');
    } finally {
      setGenerating(false);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (!privContent.trim() || !pubContent.trim() || !certContent.trim()) {
      setError(
        'Bitte laden Sie alle drei Dateien hoch: zertifikat (Privatschlüssel), zertifikat.pub (Öffentlicher Schlüssel) und zertifikat-cert.pub (Signiertes Zertifikat).'
      );
      return;
    }

    setSaving(true);
    try {
      const res = await api.uploadCertificate({
        name: bundleName.trim() || 'SSH-Zertifikat',
        privateKeyFileName: privFile,
        publicKeyFileName: pubFile,
        certFileName: certFile,
        privateKeyContent: privContent,
        publicKeyContent: pubContent,
        certContent,
        ...(isAdmin && shareOnCreate ? { sharedWithAll: true, sharedWithUserIds: [] } : {}),
      });
      await onRefresh();
      setBundleName('');
      setPrivContent('');
      setPubContent('');
      setCertContent('');
      setShareOnCreate(false);
      setLastGeneratedBundle(null);
      setSuccess(
        res.replaced
          ? `Bestehendes Zertifikatspaket „${res.certificate.name}“ wurde kryptografisch geprüft und erfolgreich überschrieben.`
          : `Zertifikatspaket „${res.certificate.name}“ kryptografisch geprüft und verschlüsselt gespeichert.`
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Zertifikatsprüfung fehlgeschlagen.');
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: string) {
    setDeletingId(id);
    setError(null);
    try {
      await api.deleteCertificate(id);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Zertifikat konnte nicht entfernt werden.');
    } finally {
      setDeletingId(null);
    }
  }

  const allThreeReady = Boolean(privContent.trim() && pubContent.trim() && certContent.trim());
  const normalizedTargetName = bundleName.trim().toLowerCase();
  const matchingExistingOwnCert = normalizedTargetName
    ? certificates.find(
        (c) => c.userId === user.id && c.name.trim().toLowerCase() === normalizedTargetName
      )
    : undefined;

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
            SSH-Zertifikate
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            Laden Sie für die passwortlose Anmeldung alle drei OpenSSH-Dateien hoch:{' '}
            <code className="font-mono text-xs text-slate-800">zertifikat</code>,{' '}
            <code className="font-mono text-xs text-slate-800">zertifikat.pub</code> und{' '}
            <code className="font-mono text-xs text-slate-800">zertifikat-cert.pub</code>.
          </p>
        </div>

        <button
          type="button"
          onClick={handleGenerateTestBundle}
          disabled={generating}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
        >
          <Wand2 className="w-3.5 h-3.5" />
          {generating ? 'Erzeuge Ed25519-Paket...' : 'Test-Zertifikatspaket erzeugen'}
        </button>
      </div>

      {error && (
        <div role="alert" className="px-4 py-3 rounded-md bg-red-50 border border-red-200 text-sm text-red-800">
          {error}
        </div>
      )}

      {success && (
        <div className="px-4 py-3 rounded-md bg-emerald-50 border border-emerald-200 text-sm text-emerald-900">
          {success}
        </div>
      )}

      {/* Upload Form */}
      <form onSubmit={handleSubmit} className="bg-white border border-slate-200 rounded-lg p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-200">
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900">
              Neues 3-Dateien-Zertifikatspaket hochladen
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Die Zusammengehörigkeit von Privatschlüssel, öffentlichem Schlüssel und CA-Zertifikat wird beim Speichern verifiziert.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowTextEditors((v) => !v)}
            className="text-xs font-medium text-blue-700 hover:text-blue-900 cursor-pointer whitespace-nowrap shrink-0"
          >
            {showTextEditors ? 'Textfelder ausblenden' : 'Inhalte manuell einfügen'}
          </button>
        </div>

        {/* Multi-file dropzone */}
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setIsDragging(false);
            if (e.dataTransfer.files?.length) {
              classifyAndLoadFiles(e.dataTransfer.files);
            }
          }}
          className={`border border-dashed rounded-md px-6 py-6 text-center transition-colors ${
            isDragging ? 'border-blue-600 bg-blue-50/50' : 'border-slate-300 bg-slate-50/70'
          }`}
        >
          <Upload className="w-5 h-5 text-slate-500 mx-auto mb-2" />
          <p className="text-sm font-medium text-slate-800">
            Alle 3 Dateien gemeinsam hierher ziehen oder auswählen
          </p>
          <p className="text-xs text-slate-500 mt-1 font-mono">
            zertifikat · zertifikat.pub · zertifikat-cert.pub
          </p>
          <input
            ref={multiInputRef}
            type="file"
            multiple
            className="hidden"
            onChange={(e) => {
              if (e.target.files?.length) classifyAndLoadFiles(e.target.files);
              e.target.value = '';
            }}
          />
          <button
            type="button"
            onClick={() => multiInputRef.current?.click()}
            className="mt-3 px-4 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
          >
            Dateien auswählen
          </button>
        </div>

        {/* Individual 3 slots */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Slot 1: zertifikat */}
          <div className="border border-slate-200 rounded-md p-4 flex flex-col justify-between bg-white">
            <div>
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs font-semibold text-slate-900">1. zertifikat</span>
                <span
                  className={`text-xs font-medium ${
                    privContent.trim() ? 'text-emerald-700' : 'text-slate-400'
                  }`}
                >
                  {privContent.trim() ? 'Geladen' : 'Fehlt'}
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-1">
                Privater OpenSSH-Schlüssel (AES-256-GCM verschlüsselt gespeichert, chmod 0600).
              </p>
              {privContent.trim() && (
                <p className="mt-2 text-xs font-mono text-slate-700 truncate">{privFile}</p>
              )}
            </div>
            <div className="mt-4 flex items-center gap-2">
              <input
                ref={privInputRef}
                type="file"
                className="hidden"
                onChange={(e) => handleSingleFile(e, 'priv')}
              />
              <button
                type="button"
                onClick={() => privInputRef.current?.click()}
                className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                Datei wählen
              </button>
              {privContent.trim() && (
                <button
                  type="button"
                  onClick={() => downloadTextFile(privFile || 'zertifikat', privContent)}
                  className="p-1.5 text-slate-500 hover:text-slate-900 rounded-md cursor-pointer"
                  title="zertifikat herunterladen"
                >
                  <Download className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Slot 2: zertifikat.pub */}
          <div className="border border-slate-200 rounded-md p-4 flex flex-col justify-between bg-white">
            <div>
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs font-semibold text-slate-900">2. zertifikat.pub</span>
                <span
                  className={`text-xs font-medium ${
                    pubContent.trim() ? 'text-emerald-700' : 'text-slate-400'
                  }`}
                >
                  {pubContent.trim() ? 'Geladen' : 'Fehlt'}
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-1">
                Öffentlicher Schlüssel (z. B. ssh-ed25519 AAAA...) zur Schlüsselpaar-Prüfung.
              </p>
              {pubContent.trim() && (
                <p className="mt-2 text-xs font-mono text-slate-700 truncate">{pubFile}</p>
              )}
            </div>
            <div className="mt-4 flex items-center gap-2">
              <input
                ref={pubInputRef}
                type="file"
                accept=".pub,text/plain"
                className="hidden"
                onChange={(e) => handleSingleFile(e, 'pub')}
              />
              <button
                type="button"
                onClick={() => pubInputRef.current?.click()}
                className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                Datei wählen
              </button>
              {pubContent.trim() && (
                <button
                  type="button"
                  onClick={() => downloadTextFile(pubFile || 'zertifikat.pub', pubContent)}
                  className="p-1.5 text-slate-500 hover:text-slate-900 rounded-md cursor-pointer"
                  title="zertifikat.pub herunterladen"
                >
                  <Download className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Slot 3: zertifikat-cert.pub */}
          <div className="border border-slate-200 rounded-md p-4 flex flex-col justify-between bg-white">
            <div>
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs font-semibold text-slate-900">3. zertifikat-cert.pub</span>
                <span
                  className={`text-xs font-medium ${
                    certContent.trim() ? 'text-emerald-700' : 'text-slate-400'
                  }`}
                >
                  {certContent.trim() ? 'Geladen' : 'Fehlt'}
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-1">
                Von Ihrer SSH-CA signiertes OpenSSH-Benutzerzertifikat (*-cert-v01@openssh.com).
              </p>
              {certContent.trim() && (
                <p className="mt-2 text-xs font-mono text-slate-700 truncate">{certFile}</p>
              )}
            </div>
            <div className="mt-4 flex items-center gap-2">
              <input
                ref={certInputRef}
                type="file"
                accept=".pub,text/plain"
                className="hidden"
                onChange={(e) => handleSingleFile(e, 'cert')}
              />
              <button
                type="button"
                onClick={() => certInputRef.current?.click()}
                className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                Datei wählen
              </button>
              {certContent.trim() && (
                <button
                  type="button"
                  onClick={() => downloadTextFile(certFile || 'zertifikat-cert.pub', certContent)}
                  className="p-1.5 text-slate-500 hover:text-slate-900 rounded-md cursor-pointer"
                  title="zertifikat-cert.pub herunterladen"
                >
                  <Download className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
        </div>

        {lastGeneratedBundle && (
          <div className="px-4 py-3 rounded-md bg-slate-50 border border-slate-200 text-xs text-slate-700 space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-medium text-slate-900">
                Erzeugte Dateien lokal herunterladen (optional):
              </span>
              <div className="flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  onClick={() => downloadTextFile('zertifikat', lastGeneratedBundle.privateKey)}
                  className="text-blue-700 hover:text-blue-900 font-mono font-medium cursor-pointer"
                >
                  zertifikat
                </button>
                <span aria-hidden="true" className="text-slate-300">·</span>
                <button
                  type="button"
                  onClick={() => downloadTextFile('zertifikat.pub', lastGeneratedBundle.publicKey)}
                  className="text-blue-700 hover:text-blue-900 font-mono font-medium cursor-pointer"
                >
                  zertifikat.pub
                </button>
                <span aria-hidden="true" className="text-slate-300">·</span>
                <button
                  type="button"
                  onClick={() => downloadTextFile('zertifikat-cert.pub', lastGeneratedBundle.certificate)}
                  className="text-blue-700 hover:text-blue-900 font-mono font-medium cursor-pointer"
                >
                  zertifikat-cert.pub
                </button>
                <span aria-hidden="true" className="text-slate-300">·</span>
                <button
                  type="button"
                  onClick={() => downloadTextFile('ssh_user_ca.pub', lastGeneratedBundle.caPublicKey)}
                  className="text-blue-700 hover:text-blue-900 font-mono font-medium cursor-pointer"
                >
                  ssh_user_ca.pub
                </button>
              </div>
            </div>
            <p className="text-[11px] text-slate-500 font-mono break-all">
              TrustedUserCAKeys: {lastGeneratedBundle.caPublicKey.trim()}
            </p>
          </div>
        )}

        {showTextEditors && (
          <div className="grid grid-cols-1 gap-4 pt-2 border-t border-slate-200">
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Inhalt von zertifikat (Privater Schlüssel)
              </label>
              <textarea
                rows={4}
                value={privContent}
                onChange={(e) => setPrivContent(e.target.value)}
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Inhalt von zertifikat.pub (Öffentlicher Schlüssel)
              </label>
              <textarea
                rows={2}
                value={pubContent}
                onChange={(e) => setPubContent(e.target.value)}
                placeholder="ssh-ed25519 AAAA..."
                className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Inhalt von zertifikat-cert.pub (Signiertes OpenSSH-Zertifikat)
              </label>
              <textarea
                rows={3}
                value={certContent}
                onChange={(e) => setCertContent(e.target.value)}
                placeholder="ssh-ed25519-cert-v01@openssh.com AAAA..."
                className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
          </div>
        )}

        <div className="space-y-4 pt-2 border-t border-slate-200">
          <div className="flex flex-col sm:flex-row sm:items-end gap-4">
            <div className="flex-1">
              <label htmlFor="cert-bundle-name" className="block text-xs font-medium text-slate-700 mb-1.5">
                Bezeichnung für dieses Zertifikatspaket
              </label>
              <input
                id="cert-bundle-name"
                type="text"
                value={bundleName}
                onChange={(e) => setBundleName(e.target.value)}
                placeholder="z. B. Produktion Ed25519 (Q4)"
                className="w-full px-3.5 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
            <button
              type="submit"
              disabled={saving || !allThreeReady}
              className="px-5 py-2 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
            >
              {saving
                ? 'Wird verifiziert...'
                : matchingExistingOwnCert
                  ? 'Bestehendes Paket überschreiben'
                  : 'Zertifikatspaket prüfen & speichern'}
            </button>
          </div>

          {matchingExistingOwnCert && (
            <p className="text-xs text-amber-800">
              Hinweis: Ein eigenes Zertifikatspaket mit der Bezeichnung „{matchingExistingOwnCert.name}“ existiert bereits und wird beim Speichern überschrieben.
            </p>
          )}

          {isAdmin && (
            <label className="inline-flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
              <input
                type="checkbox"
                checked={shareOnCreate}
                onChange={(e) => setShareOnCreate(e.target.checked)}
                className="rounded border-slate-300 text-blue-700 focus:ring-blue-600"
              />
              <span>Direkt mit allen Benutzern teilen (ansonsten nur für mich sichtbar)</span>
            </label>
          )}
        </div>
      </form>

      {/* Saved Bundles */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="font-display text-base font-semibold text-slate-900">
            Hinterlegte Zertifikatspakete ({certificates.length})
          </h2>
        </div>

        {certificates.length === 0 ? (
          <div className="bg-white border border-slate-200 rounded-lg px-6 py-12 text-center">
            <KeyRound className="w-7 h-7 text-slate-400 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-slate-900">Noch kein SSH-Zertifikat hinterlegt</h3>
            <p className="text-sm text-slate-500 mt-1 max-w-md mx-auto">
              Laden Sie oben Ihre drei Dateien (<code className="font-mono text-xs">zertifikat</code>,{' '}
              <code className="font-mono text-xs">zertifikat.pub</code>,{' '}
              <code className="font-mono text-xs">zertifikat-cert.pub</code>) hoch oder erzeugen Sie ein
              Test-Zertifikatspaket.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {certificates.map((cert) => {
              const m = cert.metadata;
              const isOwner = cert.userId === user.id;
              const shareLabel = isOwner
                ? formatShareSummary(cert.sharedWithAll, cert.sharedWithUserIds)
                : `Geteilt von ${cert.ownerUsername || 'admin'}`;
              return (
                <article
                  key={cert.id}
                  className="bg-white border border-slate-200 rounded-lg p-6 space-y-4"
                >
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <h3 className="font-display text-base font-semibold text-slate-900">
                          {cert.name}
                        </h3>
                        {m.isExpired ? (
                          <span className="inline-flex items-center gap-1 text-xs font-medium text-red-700">
                            <AlertTriangle className="w-3.5 h-3.5" />
                            Abgelaufen
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-700">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            3-Dateien-Verbund verifiziert
                          </span>
                        )}
                        <span aria-hidden="true" className="text-slate-300">·</span>
                        <span
                          className={`text-xs ${
                            !isOwner || cert.sharedWithAll || cert.sharedWithUserIds.length > 0
                              ? 'text-blue-800 font-medium'
                              : 'text-slate-500'
                          }`}
                        >
                          {shareLabel}
                        </span>
                      </div>
                      <p className="text-xs text-slate-500 mt-1 font-mono">
                        {cert.privateKeyFileName} · {cert.publicKeyFileName} · {cert.certFileName}
                      </p>
                    </div>

                    {isOwner ? (
                      <div className="flex items-center gap-2 shrink-0">
                        {isAdmin && (
                          <button
                            type="button"
                            onClick={() => setSharingCert(cert)}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-700 hover:bg-blue-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                          >
                            <Share2 className="w-3.5 h-3.5" />
                            Teilen
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => handleDelete(cert.id)}
                          disabled={deletingId === cert.id}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-700 hover:bg-red-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          {deletingId === cert.id ? 'Wird gelöscht...' : 'Entfernen'}
                        </button>
                      </div>
                    ) : (
                      <span className="text-xs text-slate-400 whitespace-nowrap shrink-0">
                        Nur für SSH nutzbar
                      </span>
                    )}
                  </div>

                  <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-x-6 gap-y-3 pt-4 border-t border-slate-200 text-xs">
                    <div>
                      <dt className="text-slate-500">Key-ID &amp; Seriennummer</dt>
                      <dd className="font-mono text-slate-900 mt-0.5 tabular-nums">
                        {m.keyId || '—'} · #{m.serial}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Erlaubte Principals (SSH-User)</dt>
                      <dd className="font-mono text-slate-900 mt-0.5">
                        {m.principals.length > 0 ? m.principals.join(', ') : '(alle)'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Gültig ab</dt>
                      <dd className="font-mono text-slate-900 mt-0.5 tabular-nums">
                        {formatIsoDate(m.validAfter)}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Gültig bis</dt>
                      <dd
                        className={`font-mono mt-0.5 tabular-nums ${
                          m.isExpired ? 'text-red-700 font-semibold' : 'text-slate-900'
                        }`}
                      >
                        {formatIsoDate(m.validBefore)}
                      </dd>
                    </div>
                    <div className="sm:col-span-2">
                      <dt className="text-slate-500">Schlüssel-Fingerabdruck ({m.pubKeyAlgorithm})</dt>
                      <dd className="font-mono text-slate-800 mt-0.5 truncate" title={m.pubKeyFingerprint}>
                        {m.pubKeyFingerprint}
                      </dd>
                    </div>
                    <div className="sm:col-span-2">
                      <dt className="text-slate-500">Signierende CA (TrustedUserCAKeys)</dt>
                      <dd className="font-mono text-slate-800 mt-0.5 truncate" title={m.caFingerprint}>
                        {m.caFingerprint}
                      </dd>
                    </div>
                  </dl>

                  {m.warnings.length > 0 && (
                    <div className="pt-3 border-t border-slate-200 space-y-1">
                      {m.warnings.map((w, idx) => (
                        <p key={idx} className="text-xs text-amber-800 flex items-start gap-1.5">
                          <FileText className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                          <span>{w}</span>
                        </p>
                      ))}
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        )}
      </section>

      {sharingCert && isAdmin && (
        <ShareDialog
          title="SSH-Zertifikatspaket teilen"
          itemName={`${sharingCert.name} (${sharingCert.metadata.keyId || sharingCert.certFileName})`}
          securityHint="Berechtigte Benutzer können dieses Zertifikatspaket für passwortlose SSH-Ausführungen nutzen. Der private Schlüssel bleibt AES-256-GCM-verschlüsselt auf dem Server und kann von Empfängern nicht eingesehen oder heruntergeladen werden."
          currentUserId={user.id}
          users={users}
          initialSharedWithAll={sharingCert.sharedWithAll}
          initialSharedWithUserIds={sharingCert.sharedWithUserIds}
          onClose={() => setSharingCert(null)}
          onSave={async (payload) => {
            await api.shareCertificate(sharingCert.id, payload);
            await onRefresh();
          }}
        />
      )}
    </div>
  );
}
