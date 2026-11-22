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
  Terminal,
  Pencil,
  X,
} from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { ApiKeyCurlPanel } from './ApiKeyCurlPanel';
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

export function CertificatesView({ user, users, certificates, onRefresh }: CertificatesViewProps) {
  const { locale, tr, formatDateTime } = useI18n();
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
  const [showApiPanel, setShowApiPanel] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [saving, setSaving] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Inline edit state for an existing owned certificate bundle
  const [editingCertId, setEditingCertId] = useState<string | null>(null);
  const [editName, setEditName] = useState('');
  const [editPrivFile, setEditPrivFile] = useState('');
  const [editPrivContent, setEditPrivContent] = useState('');
  const [editPubFile, setEditPubFile] = useState('');
  const [editPubContent, setEditPubContent] = useState('');
  const [editCertFile, setEditCertFile] = useState('');
  const [editCertContent, setEditCertContent] = useState('');
  const [editRemoveCert, setEditRemoveCert] = useState(false);
  const [editShowText, setEditShowText] = useState(false);
  const [editDragging, setEditDragging] = useState(false);
  const [editSaving, setEditSaving] = useState(false);

  const multiInputRef = useRef<HTMLInputElement | null>(null);
  const privInputRef = useRef<HTMLInputElement | null>(null);
  const pubInputRef = useRef<HTMLInputElement | null>(null);
  const certInputRef = useRef<HTMLInputElement | null>(null);

  const editMultiInputRef = useRef<HTMLInputElement | null>(null);
  const editPrivInputRef = useRef<HTMLInputElement | null>(null);
  const editPubInputRef = useRef<HTMLInputElement | null>(null);
  const editCertInputRef = useRef<HTMLInputElement | null>(null);

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
        tr(
          'Dateien konnten nicht automatisch zugeordnet werden. Bitte verwenden Sie zertifikat, zertifikat.pub und zertifikat-cert.pub.',
          'Could not classify files automatically. Please use zertifikat, zertifikat.pub, and optionally zertifikat-cert.pub.'
        )
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
          ? tr(
              `Bestehendes Test-Zertifikatspaket „${saved.certificate.name}“ wurde mit einem neu erzeugten Ed25519-Verbund (zertifikat, zertifikat.pub, zertifikat-cert.pub) überschrieben.`,
              `Existing test certificate bundle "${saved.certificate.name}" has been replaced with a newly generated Ed25519 bundle (zertifikat, zertifikat.pub, zertifikat-cert.pub).`
            )
          : tr(
              `Test-Zertifikatspaket „${saved.certificate.name}“ (zertifikat, zertifikat.pub, zertifikat-cert.pub) wurde erzeugt, kryptografisch verifiziert und sofort gespeichert — es kann jetzt im Dashboard und bei der Befehlsausführung ausgewählt werden.`,
              `Test certificate bundle "${saved.certificate.name}" (zertifikat, zertifikat.pub, zertifikat-cert.pub) was generated, cryptographically verified, and saved immediately — it is now available in the Dashboard and Run SSH views.`
            )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Testzertifikat konnte nicht erzeugt werden.', 'Could not generate test certificate.')
      );
    } finally {
      setGenerating(false);
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (!privContent.trim() || !pubContent.trim()) {
      setError(
        tr(
          'Bitte laden Sie mindestens den privaten Schlüssel (zertifikat) und den öffentlichen Schlüssel (zertifikat.pub) hoch. Das signierte Zertifikat (zertifikat-cert.pub) ist optional.',
          'Please upload at least the private key (zertifikat) and public key (zertifikat.pub). The signed certificate (zertifikat-cert.pub) is optional.'
        )
      );
      return;
    }

    const hasCertFile = Boolean(certContent.trim());
    setSaving(true);
    try {
      const res = await api.uploadCertificate({
        name:
          bundleName.trim() ||
          (hasCertFile
            ? tr('SSH-Zertifikat', 'SSH Certificate')
            : tr('SSH-Schlüsselpaar', 'SSH Keypair')),
        privateKeyFileName: privFile,
        publicKeyFileName: pubFile,
        certFileName: hasCertFile ? certFile : '',
        privateKeyContent: privContent,
        publicKeyContent: pubContent,
        certContent: hasCertFile ? certContent : '',
        ...(isAdmin && shareOnCreate ? { sharedWithAll: true, sharedWithUserIds: [] } : {}),
      });
      await onRefresh();
      setBundleName('');
      setPrivContent('');
      setPubContent('');
      setCertContent('');
      setShareOnCreate(false);
      setLastGeneratedBundle(null);
      const kindLabelDe = hasCertFile ? 'Zertifikatspaket (3 Dateien)' : 'SSH-Schlüsselpaar (2 Dateien)';
      const kindLabelEn = hasCertFile ? 'certificate bundle (3 files)' : 'SSH keypair (2 files)';
      setSuccess(
        res.replaced
          ? tr(
              `Bestehendes ${kindLabelDe} „${res.certificate.name}“ wurde kryptografisch geprüft und erfolgreich überschrieben.`,
              `Existing ${kindLabelEn} "${res.certificate.name}" was cryptographically verified and replaced.`
            )
          : tr(
              `${kindLabelDe} „${res.certificate.name}“ kryptografisch geprüft und verschlüsselt gespeichert.`,
              `Verified and encrypted ${kindLabelEn} "${res.certificate.name}" saved.`
            )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Zertifikatsprüfung fehlgeschlagen.', 'Certificate verification failed.')
      );
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: string) {
    setDeletingId(id);
    setError(null);
    try {
      await api.deleteCertificate(id);
      if (editingCertId === id) {
        cancelEdit();
      }
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Zertifikat konnte nicht entfernt werden.', 'Could not remove certificate.')
      );
    } finally {
      setDeletingId(null);
    }
  }

  function startEdit(cert: UserCertificate) {
    setError(null);
    setSuccess(null);
    setEditingCertId(cert.id);
    setEditName(cert.name);
    setEditPrivFile('');
    setEditPrivContent('');
    setEditPubFile('');
    setEditPubContent('');
    setEditCertFile('');
    setEditCertContent('');
    setEditRemoveCert(false);
    setEditShowText(false);
    setEditDragging(false);
  }

  function cancelEdit() {
    setEditingCertId(null);
    setEditName('');
    setEditPrivFile('');
    setEditPrivContent('');
    setEditPubFile('');
    setEditPubContent('');
    setEditCertFile('');
    setEditCertContent('');
    setEditRemoveCert(false);
    setEditShowText(false);
    setEditDragging(false);
  }

  async function classifyAndLoadEditFiles(fileList: FileList | File[]) {
    setError(null);
    const files = Array.from(fileList);
    let loaded = 0;

    for (const file of files) {
      const text = await file.text();
      const lower = file.name.toLowerCase();

      if (lower.endsWith('-cert.pub') || text.includes('-cert-v01@openssh.com')) {
        setEditCertFile(file.name);
        setEditCertContent(text);
        setEditRemoveCert(false);
        loaded++;
      } else if (
        lower.endsWith('.pub') ||
        /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-|sk-ssh-)/.test(text.trim())
      ) {
        setEditPubFile(file.name);
        setEditPubContent(text);
        loaded++;
      } else if (text.includes('PRIVATE KEY')) {
        setEditPrivFile(file.name);
        setEditPrivContent(text);
        loaded++;
      }
    }

    if (loaded === 0) {
      setError(
        tr(
          'Dateien konnten nicht automatisch zugeordnet werden. Bitte wählen Sie zertifikat, zertifikat.pub oder zertifikat-cert.pub.',
          'Could not classify files automatically. Please choose zertifikat, zertifikat.pub, or zertifikat-cert.pub.'
        )
      );
    }
  }

  async function handleEditSingleFile(
    e: React.ChangeEvent<HTMLInputElement>,
    slot: 'priv' | 'pub' | 'cert'
  ) {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    if (slot === 'priv') {
      setEditPrivFile(file.name);
      setEditPrivContent(text);
    } else if (slot === 'pub') {
      setEditPubFile(file.name);
      setEditPubContent(text);
    } else {
      setEditCertFile(file.name);
      setEditCertContent(text);
      setEditRemoveCert(false);
    }
    e.target.value = '';
  }

  async function handleSaveEdit(e: React.FormEvent, cert: UserCertificate) {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    const payload: {
      name?: string;
      privateKeyFileName?: string;
      publicKeyFileName?: string;
      certFileName?: string;
      privateKeyContent?: string;
      publicKeyContent?: string;
      certContent?: string;
      removeCert?: boolean;
    } = {};

    const trimmedName = editName.trim();
    if (!trimmedName) {
      setError(tr('Bitte eine Bezeichnung angeben.', 'Please enter a bundle label.'));
      return;
    }
    if (trimmedName !== cert.name) {
      payload.name = trimmedName;
    }
    if (editPrivContent.trim()) {
      payload.privateKeyContent = editPrivContent;
      if (editPrivFile) payload.privateKeyFileName = editPrivFile;
    }
    if (editPubContent.trim()) {
      payload.publicKeyContent = editPubContent;
      if (editPubFile) payload.publicKeyFileName = editPubFile;
    }
    if (editRemoveCert) {
      payload.removeCert = true;
    } else if (editCertContent.trim()) {
      payload.certContent = editCertContent;
      payload.certFileName = editCertFile || cert.certFileName || 'zertifikat-cert.pub';
    }

    if (Object.keys(payload).length === 0) {
      setError(
        tr(
          'Es wurden keine Änderungen vorgenommen. Ändern Sie den Namen oder wählen Sie mindestens eine auszutauschende Datei.',
          'No changes were made. Update the label or choose at least one file to replace.'
        )
      );
      return;
    }

    setEditSaving(true);
    try {
      const res = await api.updateCertificate(cert.id, payload);
      await onRefresh();
      cancelEdit();

      const updatedPartsDe: string[] = [];
      const updatedPartsEn: string[] = [];
      if (payload.name) {
        updatedPartsDe.push('Bezeichnung');
        updatedPartsEn.push('label');
      }
      if (payload.privateKeyContent) {
        updatedPartsDe.push('zertifikat');
        updatedPartsEn.push('zertifikat');
      }
      if (payload.publicKeyContent) {
        updatedPartsDe.push('zertifikat.pub');
        updatedPartsEn.push('zertifikat.pub');
      }
      if (payload.certContent) {
        updatedPartsDe.push('zertifikat-cert.pub');
        updatedPartsEn.push('zertifikat-cert.pub');
      }
      if (payload.removeCert) {
        updatedPartsDe.push('CA-Zertifikat entfernt');
        updatedPartsEn.push('CA certificate removed');
      }

      setSuccess(
        tr(
          `Paket „${res.certificate.name}“ erfolgreich aktualisiert und kryptografisch verifiziert (${updatedPartsDe.join(', ')}).`,
          `Bundle "${res.certificate.name}" updated and cryptographically verified (${updatedPartsEn.join(', ')}).`
        )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Änderungen konnten nicht gespeichert werden.', 'Could not save changes.')
      );
    } finally {
      setEditSaving(false);
    }
  }

  const requiredFilesReady = Boolean(privContent.trim() && pubContent.trim());
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
            {tr('SSH-Schlüssel & Zertifikate', 'SSH Keys & Certificates')}
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            {tr(
              'Laden Sie für die passwortlose Anmeldung entweder ein klassisches Schlüsselpaar (',
              'For passwordless login, upload either a standard SSH keypair ('
            )}
            <code className="font-mono text-xs text-slate-800">zertifikat</code> +{' '}
            <code className="font-mono text-xs text-slate-800">zertifikat.pub</code>
            {tr(
              ') oder zusätzlich ein signiertes OpenSSH-Zertifikat (',
              ') or additionally a signed OpenSSH certificate ('
            )}
            <code className="font-mono text-xs text-slate-800">zertifikat-cert.pub</code>
            {tr(') hoch.', ').')}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setShowApiPanel((v) => !v)}
            className={`inline-flex items-center gap-2 px-4 py-2 text-xs font-medium border rounded-md transition-colors cursor-pointer whitespace-nowrap ${
              showApiPanel
                ? 'text-blue-800 bg-blue-50 border-blue-300'
                : 'text-slate-700 bg-white border-slate-300 hover:bg-slate-50'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            {showApiPanel
              ? tr('curl-API ausblenden', 'Hide curl API')
              : tr('Upload per curl & API-Key', 'Upload via curl & API Key')}
          </button>

          <button
            type="button"
            onClick={handleGenerateTestBundle}
            disabled={generating}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
          >
            <Wand2 className="w-3.5 h-3.5" />
            {generating
              ? tr('Erzeuge Ed25519-Paket...', 'Generating Ed25519 bundle...')
              : tr('Test-Zertifikatspaket erzeugen', 'Generate Test Certificate Bundle')}
          </button>
        </div>
      </div>

      {showApiPanel && <ApiKeyCurlPanel defaultCertName={`${user.username}-ssh`} />}

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
              {tr(
                'SSH-Schlüsselpaar (2 Dateien) oder Zertifikatspaket (3 Dateien) hochladen',
                'Upload SSH Keypair (2 files) or Certificate Bundle (3 files)'
              )}
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              {tr(
                'Die kryptografische Zusammengehörigkeit von Privatschlüssel, öffentlichem Schlüssel und optionalem CA-Zertifikat wird beim Speichern verifiziert.',
                'Cryptographic pairing between the private key, public key, and optional CA certificate is verified upon saving.'
              )}
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowTextEditors((v) => !v)}
            className="text-xs font-medium text-blue-700 hover:text-blue-900 cursor-pointer whitespace-nowrap shrink-0"
          >
            {showTextEditors
              ? tr('Textfelder ausblenden', 'Hide text fields')
              : tr('Inhalte manuell einfügen', 'Paste contents manually')}
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
            {tr(
              '2 Dateien (Schlüsselpaar) oder 3 Dateien (mit CA-Zertifikat) hierher ziehen oder auswählen',
              'Drag and drop 2 files (keypair) or 3 files (with CA certificate) here, or browse'
            )}
          </p>
          <p className="text-xs text-slate-500 mt-1 font-mono">
            zertifikat · zertifikat.pub · [optional: zertifikat-cert.pub]
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
            {tr('Dateien auswählen', 'Select Files')}
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
                  {privContent.trim() ? tr('Geladen', 'Loaded') : tr('Fehlt', 'Missing')}
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-1">
                {tr(
                  'Privater OpenSSH-Schlüssel (AES-256-GCM verschlüsselt gespeichert, chmod 0600).',
                  'Private OpenSSH key (stored with AES-256-GCM encryption, chmod 0600).'
                )}
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
                {tr('Datei wählen', 'Choose File')}
              </button>
              {privContent.trim() && (
                <button
                  type="button"
                  onClick={() => downloadTextFile(privFile || 'zertifikat', privContent)}
                  className="p-1.5 text-slate-500 hover:text-slate-900 rounded-md cursor-pointer"
                  title={tr('zertifikat herunterladen', 'Download zertifikat')}
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
                  {pubContent.trim() ? tr('Geladen', 'Loaded') : tr('Fehlt', 'Missing')}
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-1">
                {tr(
                  'Öffentlicher Schlüssel (z. B. ssh-ed25519 AAAA...) zur Schlüsselpaar-Prüfung.',
                  'Public key (e.g. ssh-ed25519 AAAA...) used to verify keypair integrity.'
                )}
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
                {tr('Datei wählen', 'Choose File')}
              </button>
              {pubContent.trim() && (
                <button
                  type="button"
                  onClick={() => downloadTextFile(pubFile || 'zertifikat.pub', pubContent)}
                  className="p-1.5 text-slate-500 hover:text-slate-900 rounded-md cursor-pointer"
                  title={tr('zertifikat.pub herunterladen', 'Download zertifikat.pub')}
                >
                  <Download className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Slot 3: zertifikat-cert.pub (optional) */}
          <div className="border border-slate-200 rounded-md p-4 flex flex-col justify-between bg-white">
            <div>
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs font-semibold text-slate-900">
                  3. zertifikat-cert.pub
                </span>
                <span
                  className={`text-xs font-medium ${
                    certContent.trim() ? 'text-emerald-700' : 'text-slate-500'
                  }`}
                >
                  {certContent.trim() ? tr('Geladen', 'Loaded') : tr('Optional', 'Optional')}
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-1">
                {tr(
                  'Optional: Von Ihrer SSH-CA signiertes OpenSSH-Benutzerzertifikat (*-cert-v01@openssh.com). Leer lassen für klassisches Schlüsselpaar.',
                  'Optional: OpenSSH user certificate (*-cert-v01@openssh.com) signed by your SSH CA. Leave empty for a standard keypair.'
                )}
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
                {tr('Datei wählen', 'Choose File')}
              </button>
              {certContent.trim() && (
                <>
                  <button
                    type="button"
                    onClick={() => downloadTextFile(certFile || 'zertifikat-cert.pub', certContent)}
                    className="p-1.5 text-slate-500 hover:text-slate-900 rounded-md cursor-pointer"
                    title={tr('zertifikat-cert.pub herunterladen', 'Download zertifikat-cert.pub')}
                  >
                    <Download className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => setCertContent('')}
                    className="text-xs text-slate-500 hover:text-red-700 cursor-pointer"
                  >
                    {tr('Leeren', 'Clear')}
                  </button>
                </>
              )}
            </div>
          </div>
        </div>

        {lastGeneratedBundle && (
          <div className="px-4 py-3 rounded-md bg-slate-50 border border-slate-200 text-xs text-slate-700 space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-medium text-slate-900">
                {tr('Erzeugte Dateien lokal herunterladen (optional):', 'Download generated files locally (optional):')}
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
                {tr('Inhalt von zertifikat (Privater Schlüssel)', 'Contents of zertifikat (Private Key)')}
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
                {tr('Inhalt von zertifikat.pub (Öffentlicher Schlüssel)', 'Contents of zertifikat.pub (Public Key)')}
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
                {tr(
                  'Inhalt von zertifikat-cert.pub (optional · Signiertes OpenSSH-Zertifikat)',
                  'Contents of zertifikat-cert.pub (optional · Signed OpenSSH Certificate)'
                )}
              </label>
              <textarea
                rows={3}
                value={certContent}
                onChange={(e) => setCertContent(e.target.value)}
                placeholder="Optional: ssh-ed25519-cert-v01@openssh.com AAAA..."
                className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
          </div>
        )}

        <div className="space-y-4 pt-2 border-t border-slate-200">
          <div className="flex flex-col sm:flex-row sm:items-end gap-4">
            <div className="flex-1">
              <label htmlFor="cert-bundle-name" className="block text-xs font-medium text-slate-700 mb-1.5">
                {tr('Bezeichnung für dieses Schlüssel-/Zertifikatspaket', 'Label for this key / certificate bundle')}
              </label>
              <input
                id="cert-bundle-name"
                type="text"
                value={bundleName}
                onChange={(e) => setBundleName(e.target.value)}
                placeholder={tr('z. B. Produktion Ed25519 (Q4)', 'e.g. Production Ed25519 (Q4)')}
                className="w-full px-3.5 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
            <button
              type="submit"
              disabled={saving || !requiredFilesReady}
              className="px-5 py-2 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
            >
              {saving
                ? tr('Wird verifiziert...', 'Verifying...')
                : matchingExistingOwnCert
                  ? tr('Bestehendes Paket überschreiben', 'Overwrite Existing Bundle')
                  : certContent.trim()
                    ? tr('Zertifikatspaket prüfen & speichern', 'Verify & Save Certificate Bundle')
                    : tr('Schlüsselpaar prüfen & speichern', 'Verify & Save Keypair')}
            </button>
          </div>

          {matchingExistingOwnCert && (
            <p className="text-xs text-amber-800">
              {tr(
                `Hinweis: Ein eigenes Zertifikatspaket mit der Bezeichnung „${matchingExistingOwnCert.name}“ existiert bereits und wird beim Speichern überschrieben.`,
                `Note: You already have a bundle named "${matchingExistingOwnCert.name}". Saving will overwrite it.`
              )}
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
              <span>
                {tr(
                  'Direkt mit allen Benutzern teilen (ansonsten nur für mich sichtbar)',
                  'Share immediately with all users (otherwise visible only to me)'
                )}
              </span>
            </label>
          )}
        </div>
      </form>

      {/* Saved Bundles */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="font-display text-base font-semibold text-slate-900">
            {tr(
              `Hinterlegte Zertifikatspakete (${certificates.length})`,
              `Saved Key & Certificate Bundles (${certificates.length})`
            )}
          </h2>
        </div>

        {certificates.length === 0 ? (
          <div className="bg-white border border-slate-200 rounded-lg px-6 py-12 text-center">
            <KeyRound className="w-7 h-7 text-slate-400 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-slate-900">
              {tr('Noch kein SSH-Schlüssel oder Zertifikat hinterlegt', 'No SSH keys or certificates stored yet')}
            </h3>
            <p className="text-sm text-slate-500 mt-1 max-w-md mx-auto">
              {tr('Laden Sie oben ', 'Upload ')}
              <code className="font-mono text-xs">zertifikat</code> {tr('und', 'and')}{' '}
              <code className="font-mono text-xs">zertifikat.pub</code>{' '}
              {tr('(optional zusätzlich ', '(optionally with ')}
              <code className="font-mono text-xs">zertifikat-cert.pub</code>
              {tr(
                ') hoch oder erzeugen Sie ein Test-Zertifikatspaket.',
                ') above, or generate a test certificate bundle.'
              )}
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {certificates.map((cert) => {
              const m = cert.metadata;
              const hasCert = m.hasCertificate !== false && Boolean(cert.certFileName);
              const isOwner = cert.userId === user.id;
              const shareLabel = isOwner
                ? formatShareSummary(cert.sharedWithAll, cert.sharedWithUserIds, locale)
                : tr(
                    `Geteilt von ${cert.ownerUsername || 'admin'}`,
                    `Shared by ${cert.ownerUsername || 'admin'}`
                  );
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
                        {hasCert ? (
                          m.isExpired ? (
                            <span className="inline-flex items-center gap-1 text-xs font-medium text-red-700">
                              <AlertTriangle className="w-3.5 h-3.5" />
                              {tr('Abgelaufen', 'Expired')}
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-700">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              {tr('3-Dateien-Verbund verifiziert', '3-file bundle verified')}
                            </span>
                          )
                        ) : (
                          <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-700">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            {tr(
                              'Schlüsselpaar verifiziert (ohne CA-Zertifikat)',
                              'Keypair verified (without CA certificate)'
                            )}
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
                        {cert.privateKeyFileName} · {cert.publicKeyFileName}
                        {hasCert
                          ? ` · ${cert.certFileName}`
                          : tr(' · (ohne zertifikat-cert.pub)', ' · (no zertifikat-cert.pub)')}
                      </p>
                    </div>

                    {isOwner ? (
                      <div className="flex flex-wrap items-center gap-2 shrink-0">
                        <button
                          type="button"
                          onClick={() => (editingCertId === cert.id ? cancelEdit() : startEdit(cert))}
                          className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                            editingCertId === cert.id
                              ? 'text-slate-900 bg-slate-100 hover:bg-slate-200'
                              : 'text-slate-700 hover:bg-slate-100'
                          }`}
                        >
                          {editingCertId === cert.id ? (
                            <>
                              <X className="w-3.5 h-3.5" />
                              {tr('Abbrechen', 'Cancel')}
                            </>
                          ) : (
                            <>
                              <Pencil className="w-3.5 h-3.5" />
                              {tr('Bearbeiten', 'Edit')}
                            </>
                          )}
                        </button>
                        {isAdmin && (
                          <button
                            type="button"
                            onClick={() => setSharingCert(cert)}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-700 hover:bg-blue-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                          >
                            <Share2 className="w-3.5 h-3.5" />
                            {tr('Teilen', 'Share')}
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => handleDelete(cert.id)}
                          disabled={deletingId === cert.id}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-700 hover:bg-red-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          {deletingId === cert.id
                            ? tr('Wird gelöscht...', 'Deleting...')
                            : tr('Entfernen', 'Delete')}
                        </button>
                      </div>
                    ) : (
                      <span className="text-xs text-slate-400 whitespace-nowrap shrink-0">
                        {tr('Nur für SSH nutzbar', 'SSH use only')}
                      </span>
                    )}
                  </div>

                  {editingCertId === cert.id && isOwner && (
                    <form
                      onSubmit={(e) => handleSaveEdit(e, cert)}
                      className="rounded-md border border-blue-200 bg-slate-50/70 p-4 space-y-4"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-200">
                        <div>
                          <h4 className="text-xs font-semibold text-slate-900">
                            {tr(
                              'Paket bearbeiten (einzelne Dateien gezielt austauschen)',
                              'Edit Bundle (replace individual files selectively)'
                            )}
                          </h4>
                          <p className="text-[11px] text-slate-500 mt-0.5">
                            {tr(
                              'Nicht geänderte Dateien bleiben unverändert erhalten. Ideal, um z. B. nur ein neues zertifikat-cert.pub einzuspielen.',
                              'Unchanged files are kept as-is. Ideal for rotating only zertifikat-cert.pub without re-uploading your private key.'
                            )}
                          </p>
                        </div>
                        <button
                          type="button"
                          onClick={() => setEditShowText((v) => !v)}
                          className="text-xs font-medium text-blue-700 hover:text-blue-900 cursor-pointer whitespace-nowrap shrink-0 self-start sm:self-auto"
                        >
                          {editShowText
                            ? tr('Textfelder ausblenden', 'Hide text fields')
                            : tr('Inhalte manuell einfügen', 'Paste contents manually')}
                        </button>
                      </div>

                      <div>
                        <label
                          htmlFor={`edit-cert-name-${cert.id}`}
                          className="block text-xs font-medium text-slate-700 mb-1"
                        >
                          {tr('Bezeichnung', 'Bundle Label')}
                        </label>
                        <input
                          id={`edit-cert-name-${cert.id}`}
                          type="text"
                          value={editName}
                          onChange={(e) => setEditName(e.target.value)}
                          className="w-full sm:max-w-md px-3 py-1.5 text-sm bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                        />
                      </div>

                      <div
                        onDragOver={(e) => {
                          e.preventDefault();
                          setEditDragging(true);
                        }}
                        onDragLeave={() => setEditDragging(false)}
                        onDrop={(e) => {
                          e.preventDefault();
                          setEditDragging(false);
                          if (e.dataTransfer.files?.length) {
                            void classifyAndLoadEditFiles(e.dataTransfer.files);
                          }
                        }}
                        className={`border border-dashed rounded-md px-4 py-3 text-center transition-colors ${
                          editDragging
                            ? 'border-blue-600 bg-blue-50/70'
                            : 'border-slate-300 bg-white'
                        }`}
                      >
                        <div className="flex flex-col sm:flex-row items-center justify-center gap-2 text-xs text-slate-600">
                          <Upload className="w-4 h-4 text-slate-400 shrink-0" />
                          <span>
                            {tr(
                              'Neue Datei(en) hierher ziehen (z. B. nur zertifikat-cert.pub)',
                              'Drag replacement file(s) here (e.g. only zertifikat-cert.pub)'
                            )}
                          </span>
                          <input
                            ref={editMultiInputRef}
                            type="file"
                            multiple
                            className="hidden"
                            onChange={(e) => {
                              if (e.target.files?.length) {
                                void classifyAndLoadEditFiles(e.target.files);
                              }
                              e.target.value = '';
                            }}
                          />
                          <button
                            type="button"
                            onClick={() => editMultiInputRef.current?.click()}
                            className="px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded transition-colors cursor-pointer whitespace-nowrap"
                          >
                            {tr('Dateien wählen', 'Browse Files')}
                          </button>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        {/* Edit Slot 1: private key */}
                        <div className="border border-slate-200 rounded-md p-3 bg-white flex flex-col justify-between gap-2.5">
                          <div>
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-mono text-xs font-semibold text-slate-900">
                                1. zertifikat
                              </span>
                              <span
                                className={`text-[11px] font-medium ${
                                  editPrivContent.trim() ? 'text-blue-700' : 'text-slate-500'
                                }`}
                              >
                                {editPrivContent.trim()
                                  ? tr('Wird ersetzt', 'Will replace')
                                  : tr('Unverändert', 'Unchanged')}
                              </span>
                            </div>
                            <p className="mt-1 text-[11px] font-mono text-slate-600 truncate">
                              {editPrivContent.trim()
                                ? editPrivFile || 'zertifikat'
                                : tr(
                                    `Beibehalten: ${cert.privateKeyFileName}`,
                                    `Keeping: ${cert.privateKeyFileName}`
                                  )}
                            </p>
                          </div>
                          <div className="flex items-center gap-2">
                            <input
                              ref={editPrivInputRef}
                              type="file"
                              className="hidden"
                              onChange={(e) => handleEditSingleFile(e, 'priv')}
                            />
                            <button
                              type="button"
                              onClick={() => editPrivInputRef.current?.click()}
                              className="px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded cursor-pointer whitespace-nowrap"
                            >
                              {tr('Austauschen', 'Replace')}
                            </button>
                            {editPrivContent.trim() && (
                              <button
                                type="button"
                                onClick={() => {
                                  setEditPrivContent('');
                                  setEditPrivFile('');
                                }}
                                className="text-xs text-slate-500 hover:text-red-700 cursor-pointer"
                              >
                                {tr('Zurücksetzen', 'Reset')}
                              </button>
                            )}
                          </div>
                        </div>

                        {/* Edit Slot 2: public key */}
                        <div className="border border-slate-200 rounded-md p-3 bg-white flex flex-col justify-between gap-2.5">
                          <div>
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-mono text-xs font-semibold text-slate-900">
                                2. zertifikat.pub
                              </span>
                              <span
                                className={`text-[11px] font-medium ${
                                  editPubContent.trim() ? 'text-blue-700' : 'text-slate-500'
                                }`}
                              >
                                {editPubContent.trim()
                                  ? tr('Wird ersetzt', 'Will replace')
                                  : tr('Unverändert', 'Unchanged')}
                              </span>
                            </div>
                            <p className="mt-1 text-[11px] font-mono text-slate-600 truncate">
                              {editPubContent.trim()
                                ? editPubFile || 'zertifikat.pub'
                                : tr(
                                    `Beibehalten: ${cert.publicKeyFileName}`,
                                    `Keeping: ${cert.publicKeyFileName}`
                                  )}
                            </p>
                          </div>
                          <div className="flex items-center gap-2">
                            <input
                              ref={editPubInputRef}
                              type="file"
                              accept=".pub,text/plain"
                              className="hidden"
                              onChange={(e) => handleEditSingleFile(e, 'pub')}
                            />
                            <button
                              type="button"
                              onClick={() => editPubInputRef.current?.click()}
                              className="px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded cursor-pointer whitespace-nowrap"
                            >
                              {tr('Austauschen', 'Replace')}
                            </button>
                            {editPubContent.trim() && (
                              <button
                                type="button"
                                onClick={() => {
                                  setEditPubContent('');
                                  setEditPubFile('');
                                }}
                                className="text-xs text-slate-500 hover:text-red-700 cursor-pointer"
                              >
                                {tr('Zurücksetzen', 'Reset')}
                              </button>
                            )}
                          </div>
                        </div>

                        {/* Edit Slot 3: signed cert */}
                        <div className="border border-blue-200 rounded-md p-3 bg-white flex flex-col justify-between gap-2.5">
                          <div>
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-mono text-xs font-semibold text-slate-900">
                                3. zertifikat-cert.pub
                              </span>
                              <span
                                className={`text-[11px] font-medium ${
                                  editRemoveCert
                                    ? 'text-red-700'
                                    : editCertContent.trim()
                                      ? 'text-blue-700'
                                      : 'text-slate-500'
                                }`}
                              >
                                {editRemoveCert
                                  ? tr('Wird entfernt', 'Will remove')
                                  : editCertContent.trim()
                                    ? hasCert
                                      ? tr('Wird ersetzt', 'Will replace')
                                      : tr('Wird hinzugefügt', 'Will add')
                                    : hasCert
                                      ? tr('Unverändert', 'Unchanged')
                                      : tr('Nicht vorhanden', 'Not set')}
                              </span>
                            </div>
                            <p className="mt-1 text-[11px] font-mono text-slate-600 truncate">
                              {editRemoveCert
                                ? tr(
                                    'Umstellung auf 2-Dateien-Schlüsselpaar',
                                    'Switching to 2-file keypair'
                                  )
                                : editCertContent.trim()
                                  ? editCertFile || 'zertifikat-cert.pub'
                                  : hasCert
                                    ? tr(
                                        `Aktuell: ${cert.certFileName}`,
                                        `Current: ${cert.certFileName}`
                                      )
                                    : tr(
                                        'Optionales CA-Zertifikat nachreichen',
                                        'Optionally add a signed CA certificate'
                                      )}
                            </p>
                          </div>
                          <div className="flex flex-wrap items-center gap-2">
                            <input
                              ref={editCertInputRef}
                              type="file"
                              accept=".pub,text/plain"
                              className="hidden"
                              onChange={(e) => handleEditSingleFile(e, 'cert')}
                            />
                            <button
                              type="button"
                              onClick={() => editCertInputRef.current?.click()}
                              className="px-2.5 py-1 text-xs font-medium text-blue-800 bg-blue-50 hover:bg-blue-100 rounded cursor-pointer whitespace-nowrap"
                            >
                              {hasCert ? tr('cert.pub tauschen', 'Replace cert.pub') : tr('Hinzufügen', 'Add cert.pub')}
                            </button>
                            {editCertContent.trim() && (
                              <button
                                type="button"
                                onClick={() => {
                                  setEditCertContent('');
                                  setEditCertFile('');
                                }}
                                className="text-xs text-slate-500 hover:text-red-700 cursor-pointer"
                              >
                                {tr('Zurücksetzen', 'Reset')}
                              </button>
                            )}
                            {hasCert && !editCertContent.trim() && (
                              <button
                                type="button"
                                onClick={() => setEditRemoveCert((v) => !v)}
                                className={`text-xs cursor-pointer ${
                                  editRemoveCert
                                    ? 'text-slate-700 hover:text-slate-900 font-medium'
                                    : 'text-red-700 hover:text-red-900'
                                }`}
                              >
                                {editRemoveCert
                                  ? tr('Behalten', 'Keep cert')
                                  : tr('Entfernen', 'Remove')}
                              </button>
                            )}
                          </div>
                        </div>
                      </div>

                      {editShowText && (
                        <div className="grid grid-cols-1 gap-3 pt-2 border-t border-slate-200">
                          <div>
                            <label className="block text-xs font-medium text-slate-700 mb-1">
                              {tr(
                                'Neuer Inhalt für zertifikat-cert.pub (leer lassen = unverändert)',
                                'New contents for zertifikat-cert.pub (leave empty = unchanged)'
                              )}
                            </label>
                            <textarea
                              rows={3}
                              value={editCertContent}
                              onChange={(e) => {
                                setEditCertContent(e.target.value);
                                if (e.target.value.trim()) setEditRemoveCert(false);
                              }}
                              placeholder="ssh-ed25519-cert-v01@openssh.com AAAA..."
                              className="w-full px-3 py-2 text-xs font-mono bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                            />
                          </div>
                          <div>
                            <label className="block text-xs font-medium text-slate-700 mb-1">
                              {tr(
                                'Neuer Inhalt für zertifikat.pub (leer lassen = unverändert)',
                                'New contents for zertifikat.pub (leave empty = unchanged)'
                              )}
                            </label>
                            <textarea
                              rows={2}
                              value={editPubContent}
                              onChange={(e) => setEditPubContent(e.target.value)}
                              placeholder="ssh-ed25519 AAAA..."
                              className="w-full px-3 py-2 text-xs font-mono bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                            />
                          </div>
                          <div>
                            <label className="block text-xs font-medium text-slate-700 mb-1">
                              {tr(
                                'Neuer Inhalt für zertifikat (leer lassen = unverändert)',
                                'New contents for zertifikat (leave empty = unchanged)'
                              )}
                            </label>
                            <textarea
                              rows={3}
                              value={editPrivContent}
                              onChange={(e) => setEditPrivContent(e.target.value)}
                              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                              className="w-full px-3 py-2 text-xs font-mono bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                            />
                          </div>
                        </div>
                      )}

                      <div className="flex flex-wrap items-center justify-end gap-2 pt-2 border-t border-slate-200">
                        <button
                          type="button"
                          onClick={cancelEdit}
                          disabled={editSaving}
                          className="px-3.5 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer"
                        >
                          {tr('Abbrechen', 'Cancel')}
                        </button>
                        <button
                          type="submit"
                          disabled={editSaving}
                          className="px-4 py-1.5 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                        >
                          {editSaving
                            ? tr('Wird geprüft & gespeichert...', 'Verifying & saving...')
                            : tr('Änderungen prüfen & speichern', 'Verify & Save Changes')}
                        </button>
                      </div>
                    </form>
                  )}

                  {hasCert ? (
                    <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-x-6 gap-y-3 pt-4 border-t border-slate-200 text-xs">
                      <div>
                        <dt className="text-slate-500">{tr('Key-ID & Seriennummer', 'Key ID & Serial')}</dt>
                        <dd className="font-mono text-slate-900 mt-0.5 tabular-nums">
                          {m.keyId || '—'} · #{m.serial}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-slate-500">
                          {tr('Erlaubte Principals (SSH-User)', 'Allowed Principals (SSH Users)')}
                        </dt>
                        <dd className="font-mono text-slate-900 mt-0.5">
                          {m.principals.length > 0 ? m.principals.join(', ') : tr('(alle)', '(all)')}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-slate-500">{tr('Gültig ab', 'Valid From')}</dt>
                        <dd className="font-mono text-slate-900 mt-0.5 tabular-nums">
                          {formatDateTime(m.validAfter)}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-slate-500">{tr('Gültig bis', 'Valid Until')}</dt>
                        <dd
                          className={`font-mono mt-0.5 tabular-nums ${
                            m.isExpired ? 'text-red-700 font-semibold' : 'text-slate-900'
                          }`}
                        >
                          {formatDateTime(m.validBefore)}
                        </dd>
                      </div>
                      <div className="sm:col-span-2">
                        <dt className="text-slate-500">
                          {tr(
                            `Schlüssel-Fingerabdruck (${m.pubKeyAlgorithm})`,
                            `Key Fingerprint (${m.pubKeyAlgorithm})`
                          )}
                        </dt>
                        <dd className="font-mono text-slate-800 mt-0.5 truncate" title={m.pubKeyFingerprint}>
                          {m.pubKeyFingerprint}
                        </dd>
                      </div>
                      <div className="sm:col-span-2">
                        <dt className="text-slate-500">
                          {tr('Signierende CA (TrustedUserCAKeys)', 'Signing CA (TrustedUserCAKeys)')}
                        </dt>
                        <dd className="font-mono text-slate-800 mt-0.5 truncate" title={m.caFingerprint}>
                          {m.caFingerprint}
                        </dd>
                      </div>
                    </dl>
                  ) : (
                    <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-x-6 gap-y-3 pt-4 border-t border-slate-200 text-xs">
                      <div>
                        <dt className="text-slate-500">{tr('Anmeldemodus', 'Auth Mode')}</dt>
                        <dd className="font-mono text-slate-900 mt-0.5">
                          {tr('SSH-Schlüsselpaar (authorized_keys)', 'SSH Keypair (authorized_keys)')}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-slate-500">{tr('Schlüsselkommentar', 'Key Comment')}</dt>
                        <dd className="font-mono text-slate-900 mt-0.5">
                          {m.keyId || '—'}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-slate-500">{tr('Privatschlüssel-Format', 'Private Key Format')}</dt>
                        <dd className="font-mono text-slate-900 mt-0.5">
                          {m.privateKeyFormat}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-slate-500">{tr('Algorithmus', 'Algorithm')}</dt>
                        <dd className="font-mono text-slate-900 mt-0.5">
                          {m.pubKeyAlgorithm}
                        </dd>
                      </div>
                      <div className="sm:col-span-4">
                        <dt className="text-slate-500">{tr('Schlüssel-Fingerabdruck', 'Key Fingerprint')}</dt>
                        <dd className="font-mono text-slate-800 mt-0.5 truncate" title={m.pubKeyFingerprint}>
                          {m.pubKeyFingerprint}
                        </dd>
                      </div>
                    </dl>
                  )}

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
          title={tr('SSH-Zertifikatspaket teilen', 'Share SSH Certificate Bundle')}
          itemName={`${sharingCert.name} (${sharingCert.metadata.keyId || sharingCert.certFileName})`}
          securityHint={tr(
            'Berechtigte Benutzer können dieses Zertifikatspaket für passwortlose SSH-Ausführungen nutzen. Der private Schlüssel bleibt AES-256-GCM-verschlüsselt auf dem Server und kann von Empfängern nicht eingesehen oder heruntergeladen werden.',
            'Authorized users can use this certificate bundle for passwordless SSH execution. The private key remains AES-256-GCM encrypted on the server and cannot be viewed or downloaded by recipients.'
          )}
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
