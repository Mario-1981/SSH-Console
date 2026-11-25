import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  Download,
  FileKey2,
  FileText,
  Lock,
  Pencil,
  ShieldCheck,
  Trash2,
  Upload,
  Wand2,
  X,
} from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { getPasswordComplexityError } from '../passwordPolicy';
import { PasswordStrengthHint } from './PasswordStrengthHint';
import type { CertificateAuthority, User } from '../types';

interface CaAdminViewProps {
  currentUser: User;
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

export function CaAdminView({ currentUser }: CaAdminViewProps) {
  const { tr, formatDateTime } = useI18n();
  const [cas, setCas] = useState<CertificateAuthority[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Last generated CA bundle (one-time download for ca + ca.pub)
  const [lastGeneratedCa, setLastGeneratedCa] = useState<{
    name: string;
    privateKey: string;
    publicKey: string;
  } | null>(null);

  // Upload existing CA form state
  const [caName, setCaName] = useState('');
  const [caDescription, setCaDescription] = useState('');
  const [privFile, setPrivFile] = useState('ca');
  const [pubFile, setPubFile] = useState('ca.pub');
  const [privContent, setPrivContent] = useState('');
  const [pubContent, setPubContent] = useState('');
  const [uploadPassphrase, setUploadPassphrase] = useState('');
  const [showTextEditors, setShowTextEditors] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [savingUpload, setSavingUpload] = useState(false);
  const [confirmUploadOverwriteCa, setConfirmUploadOverwriteCa] =
    useState<CertificateAuthority | null>(null);

  // Generate CA modal state
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [genName, setGenName] = useState('');
  const [genDescription, setGenDescription] = useState('');
  const [genPassphrase, setGenPassphrase] = useState('');
  const [genPassphraseConfirm, setGenPassphraseConfirm] = useState('');
  const [genStorePassphrase, setGenStorePassphrase] = useState(false);
  const [genError, setGenError] = useState<string | null>(null);
  const [genConfirmOverwrite, setGenConfirmOverwrite] = useState(false);
  const [generating, setGenerating] = useState(false);

  // Inline edit state
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState('');
  const [editDescription, setEditDescription] = useState('');
  const [editPrivFile, setEditPrivFile] = useState('');
  const [editPrivContent, setEditPrivContent] = useState('');
  const [editPubFile, setEditPubFile] = useState('');
  const [editPubContent, setEditPubContent] = useState('');
  const [editPassphrase, setEditPassphrase] = useState('');
  const [editClearPassphrase, setEditClearPassphrase] = useState(false);
  const [editShowText, setEditShowText] = useState(false);
  const [editSaving, setEditSaving] = useState(false);

  // Two-step delete confirmation
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const multiInputRef = useRef<HTMLInputElement | null>(null);
  const privInputRef = useRef<HTMLInputElement | null>(null);
  const pubInputRef = useRef<HTMLInputElement | null>(null);
  const uploadNameInputRef = useRef<HTMLInputElement | null>(null);
  const genNameInputRef = useRef<HTMLInputElement | null>(null);
  const editPrivInputRef = useRef<HTMLInputElement | null>(null);
  const editPubInputRef = useRef<HTMLInputElement | null>(null);

  const loadCas = useCallback(async () => {
    try {
      const res = await api.listCertificateAuthorities();
      setCas(res.cas);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('CA-Zertifikate konnten nicht geladen werden.', 'Could not load CA certificates.')
      );
    } finally {
      setLoading(false);
    }
  }, [tr]);

  useEffect(() => {
    void loadCas();
  }, [loadCas]);

  async function classifyAndLoadFiles(fileList: FileList | File[]) {
    setError(null);
    setSuccess(null);
    const files = Array.from(fileList);
    let loaded = 0;

    for (const file of files) {
      const text = await file.text();
      const lower = file.name.toLowerCase();

      if (
        lower.endsWith('.pub') ||
        /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-|sk-ssh-)/.test(text.trim())
      ) {
        setPubFile(file.name);
        setPubContent(text);
        loaded++;
      } else if (text.includes('PRIVATE KEY')) {
        setPrivFile(file.name);
        setPrivContent(text);
        if (!caName) {
          setCaName(file.name.replace(/\.(pem|key)$/i, ''));
        }
        loaded++;
      }
    }

    if (loaded === 0) {
      setError(
        tr(
          'Dateien konnten nicht automatisch zugeordnet werden. Bitte wählen Sie den privaten CA-Schlüssel (ca) und den öffentlichen CA-Schlüssel (ca.pub).',
          'Could not classify files automatically. Please choose the CA private key (ca) and public key (ca.pub).'
        )
      );
    }
  }

  async function handleSingleFile(e: React.ChangeEvent<HTMLInputElement>, slot: 'priv' | 'pub') {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    if (slot === 'priv') {
      setPrivFile(file.name);
      setPrivContent(text);
    } else {
      setPubFile(file.name);
      setPubContent(text);
    }
    e.target.value = '';
  }

  async function handleEditSingleFile(
    e: React.ChangeEvent<HTMLInputElement>,
    slot: 'priv' | 'pub'
  ) {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    if (slot === 'priv') {
      setEditPrivFile(file.name);
      setEditPrivContent(text);
    } else {
      setEditPubFile(file.name);
      setEditPubContent(text);
    }
    e.target.value = '';
  }

  function openGenerateModal() {
    setError(null);
    setSuccess(null);
    setGenError(null);
    setGenName(`${currentUser.username}-ca`);
    setGenDescription('');
    setGenPassphrase('');
    setGenPassphraseConfirm('');
    setGenStorePassphrase(false);
    setGenConfirmOverwrite(false);
    setShowGenerateModal(true);
  }

  function closeGenerateModal() {
    if (generating) return;
    setShowGenerateModal(false);
    setGenPassphrase('');
    setGenPassphraseConfirm('');
    setGenStorePassphrase(false);
    setGenError(null);
    setGenConfirmOverwrite(false);
  }

  const effectiveGenName = genName.trim() || `${currentUser.username}-ca`;
  const matchingGenCa = cas.find(
    (c) => c.name.trim().toLowerCase() === effectiveGenName.toLowerCase()
  );

  const normalizedUploadName = caName.trim().toLowerCase();
  const matchingUploadCa = normalizedUploadName
    ? cas.find((c) => c.name.trim().toLowerCase() === normalizedUploadName)
    : undefined;

  async function handleGenerateSubmit(e: React.FormEvent) {
    e.preventDefault();
    setGenError(null);
    setError(null);
    setSuccess(null);

    if (!genPassphrase) {
      setGenError(
        tr(
          'Für ein CA-Zertifikat ist zwingend ein Passwort erforderlich.',
          'A passphrase is strictly required for a CA certificate.'
        )
      );
      return;
    }

    const passErr = getPasswordComplexityError(genPassphrase, tr);
    if (passErr) {
      setGenError(passErr);
      return;
    }

    if (genPassphrase !== genPassphraseConfirm) {
      setGenError(
        tr(
          'Die beiden Passwort-Eingaben stimmen nicht überein.',
          'The two passphrase entries do not match.'
        )
      );
      return;
    }

    if (matchingGenCa && !genConfirmOverwrite) {
      setGenConfirmOverwrite(true);
      return;
    }

    setGenerating(true);
    try {
      const res = await api.generateCertificateAuthority({
        name: effectiveGenName,
        description: genDescription.trim(),
        passphrase: genPassphrase,
        storePassphrase: genStorePassphrase,
        overwrite: Boolean(matchingGenCa && genConfirmOverwrite),
      });
      await loadCas();
      setLastGeneratedCa({
        name: res.ca.name,
        privateKey: res.generated.privateKey,
        publicKey: res.generated.publicKey,
      });

      const passNoteDe = genStorePassphrase
        ? ' (passwortgeschützt, Passwort verschlüsselt gespeichert)'
        : ' (passwortgeschützt, Passwort nicht auf dem Server gespeichert)';
      const passNoteEn = genStorePassphrase
        ? ' (passphrase-protected, passphrase stored encrypted)'
        : ' (passphrase-protected, passphrase not stored on server)';

      setSuccess(
        res.replaced
          ? tr(
              `Bestehende CA „${res.ca.name}“ wurde mit einem neu erzeugten Ed25519-CA-Schlüsselpaar (ca, ca.pub)${passNoteDe} überschrieben.`,
              `Existing CA "${res.ca.name}" was replaced with a newly generated Ed25519 CA keypair (ca, ca.pub)${passNoteEn}.`
            )
          : tr(
              `CA „${res.ca.name}“ (ca, ca.pub)${passNoteDe} wurde erzeugt, verifiziert und verschlüsselt gespeichert.`,
              `CA "${res.ca.name}" (ca, ca.pub)${passNoteEn} was generated, verified, and stored encrypted.`
            )
      );

      setShowGenerateModal(false);
      setGenPassphrase('');
      setGenPassphraseConfirm('');
      setGenStorePassphrase(false);
      setGenConfirmOverwrite(false);
    } catch (err) {
      setGenError(
        err instanceof Error
          ? err.message
          : tr('CA-Zertifikat konnte nicht erzeugt werden.', 'Could not generate CA certificate.')
      );
    } finally {
      setGenerating(false);
    }
  }

  async function performUpload(overwrite: boolean) {
    const effectiveName = caName.trim() || 'ssh-ca';
    setSavingUpload(true);
    setError(null);
    setSuccess(null);
    try {
      const res = await api.uploadCertificateAuthority({
        name: effectiveName,
        description: caDescription.trim(),
        privateKeyFileName: privFile,
        publicKeyFileName: pubFile,
        privateKeyContent: privContent,
        publicKeyContent: pubContent,
        ...(uploadPassphrase ? { passphrase: uploadPassphrase } : {}),
        overwrite,
      });
      await loadCas();
      setConfirmUploadOverwriteCa(null);
      setCaName('');
      setCaDescription('');
      setPrivContent('');
      setPubContent('');
      setUploadPassphrase('');
      setSuccess(
        res.replaced
          ? tr(
              `Bestehende CA „${res.ca.name}“ wurde kryptografisch geprüft und erfolgreich überschrieben.`,
              `Existing CA "${res.ca.name}" was cryptographically verified and replaced.`
            )
          : tr(
              `CA „${res.ca.name}“ (ca, ca.pub) kryptografisch geprüft und verschlüsselt gespeichert.`,
              `CA "${res.ca.name}" (ca, ca.pub) cryptographically verified and stored encrypted.`
            )
      );
    } catch (err) {
      setConfirmUploadOverwriteCa(null);
      setError(
        err instanceof Error
          ? err.message
          : tr('CA-Prüfung fehlgeschlagen.', 'CA verification failed.')
      );
    } finally {
      setSavingUpload(false);
    }
  }

  async function handleUploadSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (!privContent.trim() || !pubContent.trim()) {
      setError(
        tr(
          'Bitte laden Sie sowohl den passwortgeschützten privaten CA-Schlüssel (ca) als auch den öffentlichen CA-Schlüssel (ca.pub) hoch.',
          'Please upload both the passphrase-protected CA private key (ca) and the CA public key (ca.pub).'
        )
      );
      return;
    }

    if (uploadPassphrase) {
      const passErr = getPasswordComplexityError(uploadPassphrase, tr);
      if (passErr) {
        setError(passErr);
        return;
      }
    }

    const effectiveName = caName.trim() || 'ssh-ca';
    const existing = cas.find((c) => c.name.trim().toLowerCase() === effectiveName.toLowerCase());
    if (existing) {
      setConfirmUploadOverwriteCa(existing);
      return;
    }

    await performUpload(false);
  }

  function startEdit(ca: CertificateAuthority) {
    setError(null);
    setSuccess(null);
    setConfirmDeleteId(null);
    setEditingId(ca.id);
    setEditName(ca.name);
    setEditDescription(ca.description);
    setEditPrivFile(ca.privateKeyFileName);
    setEditPrivContent('');
    setEditPubFile(ca.publicKeyFileName);
    setEditPubContent('');
    setEditPassphrase('');
    setEditClearPassphrase(false);
    setEditShowText(false);
  }

  function cancelEdit() {
    setEditingId(null);
    setEditPrivContent('');
    setEditPubContent('');
    setEditPassphrase('');
    setEditClearPassphrase(false);
    setEditShowText(false);
  }

  async function handleSaveEdit(e: React.FormEvent, ca: CertificateAuthority) {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    const trimmedName = editName.trim();
    if (!trimmedName) {
      setError(tr('Bitte eine Bezeichnung für die CA angeben.', 'Please enter a label for the CA.'));
      return;
    }

    if (!editClearPassphrase && editPassphrase) {
      const passErr = getPasswordComplexityError(editPassphrase, tr);
      if (passErr) {
        setError(passErr);
        return;
      }
    }

    const payload: Parameters<typeof api.updateCertificateAuthority>[1] = {};
    if (trimmedName !== ca.name) payload.name = trimmedName;
    if (editDescription.trim() !== ca.description) payload.description = editDescription.trim();
    if (editPrivContent.trim()) {
      payload.privateKeyContent = editPrivContent;
      payload.privateKeyFileName = editPrivFile || ca.privateKeyFileName || 'ca';
    }
    if (editPubContent.trim()) {
      payload.publicKeyContent = editPubContent;
      payload.publicKeyFileName = editPubFile || ca.publicKeyFileName || 'ca.pub';
    }
    if (editClearPassphrase) {
      payload.clearPassphrase = true;
    } else if (editPassphrase) {
      payload.passphrase = editPassphrase;
    }

    if (Object.keys(payload).length === 0) {
      setError(
        tr(
          'Es wurden keine Änderungen vorgenommen.',
          'No changes were made.'
        )
      );
      return;
    }

    setEditSaving(true);
    try {
      const res = await api.updateCertificateAuthority(ca.id, payload);
      await loadCas();
      cancelEdit();
      setSuccess(
        tr(
          `CA „${res.ca.name}“ wurde erfolgreich aktualisiert.`,
          `CA "${res.ca.name}" has been updated.`
        )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('CA konnte nicht aktualisiert werden.', 'Could not update CA.')
      );
    } finally {
      setEditSaving(false);
    }
  }

  async function handleDelete(ca: CertificateAuthority) {
    setDeletingId(ca.id);
    setError(null);
    setSuccess(null);
    try {
      await api.deleteCertificateAuthority(ca.id);
      if (editingId === ca.id) cancelEdit();
      setConfirmDeleteId(null);
      await loadCas();
      setSuccess(
        tr(`CA „${ca.name}“ wurde dauerhaft entfernt.`, `CA "${ca.name}" was permanently deleted.`)
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('CA konnte nicht entfernt werden.', 'Could not delete CA.')
      );
    } finally {
      setDeletingId(null);
    }
  }

  async function handleCopyPubKey(ca: CertificateAuthority) {
    try {
      await navigator.clipboard.writeText(ca.publicKey);
      setCopiedId(ca.id);
      window.setTimeout(() => {
        setCopiedId((curr) => (curr === ca.id ? null : curr));
      }, 2000);
    } catch {
      setError(
        tr(
          'Kopieren in die Zwischenablage fehlgeschlagen.',
          'Failed to copy to clipboard.'
        )
      );
    }
  }

  const uploadFilesReady = Boolean(privContent.trim() && pubContent.trim());

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            {tr('CA-Zertifikate (ca & ca.pub)', 'CA Certificates (ca & ca.pub)')}
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            {tr(
              'Erzeugen und verwalten Sie passwortgeschützte OpenSSH Certificate Authorities (',
              'Generate and manage passphrase-protected OpenSSH Certificate Authorities ('
            )}
            <code className="font-mono text-xs text-slate-800 dark:text-slate-200">ca</code> +{' '}
            <code className="font-mono text-xs text-slate-800 dark:text-slate-200">ca.pub</code>
            {tr(
              ') für das künftige Signieren von SSH-Benutzerzertifikaten.',
              ') for signing SSH user certificates.'
            )}
          </p>
        </div>

        <button
          type="button"
          onClick={openGenerateModal}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0 self-start sm:self-auto"
        >
          <Wand2 className="w-3.5 h-3.5" />
          {tr('CA erzeugen', 'Generate CA')}
        </button>
      </div>

      {error && (
        <div
          role="alert"
          className="px-4 py-3 rounded-md bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800/70 text-sm text-red-800 dark:text-red-300 flex items-start gap-2"
        >
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-600 dark:text-red-400" />
          <span>{error}</span>
        </div>
      )}

      {success && (
        <div className="px-4 py-3 rounded-md bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/70 text-sm text-emerald-900 dark:text-emerald-200 flex items-start gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-emerald-700 dark:text-emerald-400" />
          <span>{success}</span>
        </div>
      )}

      {lastGeneratedCa && (
        <section className="bg-blue-50/70 dark:bg-blue-950/35 border border-blue-200 dark:border-blue-800/70 rounded-lg p-5 space-y-3">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="text-sm font-semibold text-blue-950 dark:text-blue-200">
                {tr(
                  `Neu erzeugte CA „${lastGeneratedCa.name}“ — Einmaliger Backup-Download`,
                  `Newly generated CA "${lastGeneratedCa.name}" — One-Time Backup Download`
                )}
              </h2>
              <p className="text-xs text-blue-900/80 dark:text-blue-300/90 mt-0.5">
                {tr(
                  'Der private CA-Schlüssel (ca) wird verschlüsselt gespeichert und steht nur jetzt direkt nach der Erzeugung als Download bereit. Der öffentliche Schlüssel (ca.pub) kann jederzeit unten kopiert oder heruntergeladen werden.',
                  'The CA private key (ca) is stored encrypted and is only available for download right now after generation. The public key (ca.pub) remains available below at any time.'
                )}
              </p>
            </div>
            <button
              type="button"
              onClick={() => setLastGeneratedCa(null)}
              aria-label={tr('Hinweis schließen', 'Dismiss notice')}
              className="p-1 text-blue-700 dark:text-blue-400 hover:text-blue-950 dark:hover:text-blue-200 rounded cursor-pointer shrink-0"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => downloadTextFile('ca', lastGeneratedCa.privateKey)}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-blue-900 dark:text-blue-200 bg-white dark:bg-slate-900 border border-blue-300 dark:border-blue-700/80 hover:bg-blue-100/60 dark:hover:bg-blue-900/50 rounded-md cursor-pointer whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              {tr('ca (Privatschlüssel, verschlüsselt) laden', 'Download ca (encrypted private key)')}
            </button>
            <button
              type="button"
              onClick={() => downloadTextFile('ca.pub', lastGeneratedCa.publicKey)}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-blue-900 dark:text-blue-200 bg-white dark:bg-slate-900 border border-blue-300 dark:border-blue-700/80 hover:bg-blue-100/60 dark:hover:bg-blue-900/50 rounded-md cursor-pointer whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              {tr('ca.pub (Öffentlicher Schlüssel) laden', 'Download ca.pub (public key)')}
            </button>
          </div>
        </section>
      )}

      {/* Upload Existing CA Form */}
      <form
        onSubmit={handleUploadSubmit}
        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 space-y-5"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-slate-200 dark:border-slate-800">
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
              {tr('Bestehende CA hochladen (ca & ca.pub)', 'Upload Existing CA (ca & ca.pub)')}
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              {tr(
                'Der private CA-Schlüssel (ca) muss zwingend passwortgeschützt sein und kryptografisch zu ca.pub passen.',
                'The CA private key (ca) must be passphrase-protected and cryptographically match ca.pub.'
              )}
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowTextEditors((v) => !v)}
            className="text-xs font-medium text-blue-700 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300 cursor-pointer whitespace-nowrap shrink-0 self-start sm:self-auto"
          >
            {showTextEditors
              ? tr('Textfelder ausblenden', 'Hide text fields')
              : tr('Inhalte manuell einfügen', 'Paste contents manually')}
          </button>
        </div>

        {/* Drag & Drop Zone */}
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
              void classifyAndLoadFiles(e.dataTransfer.files);
            }
          }}
          onClick={() => multiInputRef.current?.click()}
          className={`border-2 border-dashed rounded-lg px-6 py-7 text-center cursor-pointer transition-colors ${
            isDragging
              ? 'border-blue-600 bg-blue-50/70 dark:bg-blue-950/35'
              : 'border-slate-300 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-800/40 hover:border-slate-400 dark:hover:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-800/60'
          }`}
        >
          <input
            ref={multiInputRef}
            type="file"
            multiple
            className="hidden"
            onChange={(e) => {
              if (e.target.files?.length) {
                void classifyAndLoadFiles(e.target.files);
                e.target.value = '';
              }
            }}
          />
          <Upload className="w-6 h-6 text-slate-500 dark:text-slate-400 mx-auto mb-2" />
          <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
            {tr(
              'ca und ca.pub gemeinsam hierher ziehen oder auswählen',
              'Drag & drop or select ca and ca.pub together'
            )}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            {tr(
              'Automatische Erkennung von privatem (verschlüsseltem) und öffentlichem CA-Schlüssel.',
              'Automatically classifies the encrypted CA private key and public key.'
            )}
          </p>
        </div>

        {/* 2 File Slots */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div
            className={`rounded-md border p-4 flex items-center justify-between gap-3 ${
              privContent.trim()
                ? 'border-emerald-300 dark:border-emerald-700/80 bg-emerald-50/50 dark:bg-emerald-950/30'
                : 'border-slate-200 dark:border-slate-800 bg-slate-50/40 dark:bg-slate-800/30'
            }`}
          >
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <Lock
                  className={`w-4 h-4 shrink-0 ${
                    privContent.trim() ? 'text-emerald-700 dark:text-emerald-400' : 'text-slate-400'
                  }`}
                />
                <span className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100 truncate">
                  {privFile}
                </span>
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                {privContent.trim()
                  ? tr('Geladen (muss passwortgeschützt sein)', 'Loaded (must be encrypted)')
                  : tr('Privater CA-Schlüssel (Pflicht, verschlüsselt)', 'CA private key (required, encrypted)')}
              </p>
            </div>
            <input
              ref={privInputRef}
              type="file"
              className="hidden"
              onChange={(e) => void handleSingleFile(e, 'priv')}
            />
            <button
              type="button"
              onClick={() => privInputRef.current?.click()}
              className="px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md cursor-pointer whitespace-nowrap shrink-0"
            >
              {privContent.trim() ? tr('Ändern', 'Change') : tr('Wählen', 'Select')}
            </button>
          </div>

          <div
            className={`rounded-md border p-4 flex items-center justify-between gap-3 ${
              pubContent.trim()
                ? 'border-emerald-300 dark:border-emerald-700/80 bg-emerald-50/50 dark:bg-emerald-950/30'
                : 'border-slate-200 dark:border-slate-800 bg-slate-50/40 dark:bg-slate-800/30'
            }`}
          >
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <FileText
                  className={`w-4 h-4 shrink-0 ${
                    pubContent.trim() ? 'text-emerald-700 dark:text-emerald-400' : 'text-slate-400'
                  }`}
                />
                <span className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100 truncate">
                  {pubFile}
                </span>
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                {pubContent.trim()
                  ? tr('Geladen (Öffentlicher CA-Schlüssel)', 'Loaded (CA public key)')
                  : tr('Öffentlicher CA-Schlüssel (Pflicht)', 'CA public key (required)')}
              </p>
            </div>
            <input
              ref={pubInputRef}
              type="file"
              className="hidden"
              onChange={(e) => void handleSingleFile(e, 'pub')}
            />
            <button
              type="button"
              onClick={() => pubInputRef.current?.click()}
              className="px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md cursor-pointer whitespace-nowrap shrink-0"
            >
              {pubContent.trim() ? tr('Ändern', 'Change') : tr('Wählen', 'Select')}
            </button>
          </div>
        </div>

        {showTextEditors && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-slate-200 dark:border-slate-800">
            <div>
              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                {tr('Inhalt von ca (verschlüsselter Privatschlüssel)', 'Contents of ca (encrypted private key)')}
              </label>
              <textarea
                rows={4}
                value={privContent}
                onChange={(e) => setPrivContent(e.target.value)}
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                className="w-full px-3 py-2 text-xs font-mono border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                {tr('Inhalt von ca.pub (Öffentlicher CA-Schlüssel)', 'Contents of ca.pub (CA public key)')}
              </label>
              <textarea
                rows={4}
                value={pubContent}
                onChange={(e) => setPubContent(e.target.value)}
                placeholder="ssh-ed25519 AAAA... prod-user-ca"
                className="w-full px-3 py-2 text-xs font-mono border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
          </div>
        )}

        <div className="space-y-4 pt-2 border-t border-slate-200 dark:border-slate-800">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label htmlFor="ca-upload-name" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                {tr('Bezeichnung der CA', 'CA Label')}
              </label>
              <input
                ref={uploadNameInputRef}
                id="ca-upload-name"
                type="text"
                maxLength={64}
                value={caName}
                onChange={(e) => setCaName(e.target.value)}
                placeholder={tr('z. B. prod-user-ca', 'e.g. prod-user-ca')}
                className={`w-full px-3.5 py-2 text-sm border rounded-md focus:outline-none focus:ring-2 ${
                  matchingUploadCa
                    ? 'border-amber-400 dark:border-amber-700/80 bg-amber-50/40 dark:bg-amber-950/30 focus:ring-amber-500'
                    : 'border-slate-300 dark:border-slate-700 focus:ring-blue-600'
                }`}
              />
              {matchingUploadCa && (
                <p className="mt-1.5 flex items-start gap-1.5 text-xs text-amber-800 dark:text-amber-300">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
                  <span>
                    {tr(
                      `Der Name „${matchingUploadCa.name}“ ist bereits vergeben. Beim Speichern werden Sie gefragt, ob die bestehende CA überschrieben werden soll.`,
                      `The name "${matchingUploadCa.name}" is already taken. You will be asked whether to overwrite the existing CA when saving.`
                    )}
                  </span>
                </p>
              )}
            </div>

            <div>
              <label htmlFor="ca-upload-desc" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                {tr('Beschreibung / Zweck (optional)', 'Description / Purpose (optional)')}
              </label>
              <input
                id="ca-upload-desc"
                type="text"
                maxLength={300}
                value={caDescription}
                onChange={(e) => setCaDescription(e.target.value)}
                placeholder={tr(
                  'z. B. Benutzer-CA für Produktionsserver',
                  'e.g. User CA for production servers'
                )}
                className="w-full px-3.5 py-2 text-sm border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
          </div>

          <div>
            <label htmlFor="ca-upload-pass" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
              {tr(
                'CA-Passwort auf dem Server speichern (optional)',
                'Store CA Passphrase on Server (optional)'
              )}
            </label>
            <input
              id="ca-upload-pass"
              type="password"
              autoComplete="new-password"
              value={uploadPassphrase}
              onChange={(e) => setUploadPassphrase(e.target.value)}
              placeholder={tr(
                'Leer lassen für manuelle Eingabe beim späteren Signieren',
                'Leave blank to enter manually when signing certificates later'
              )}
              className="w-full md:w-1/2 px-3.5 py-2 text-sm border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
              {tr(
                'Der CA-Privatschlüssel muss zwingend passwortgeschützt sein. Optional können Sie das Passwort hier AES-256-GCM-verschlüsselt hinterlegen — oder leer lassen, um es später bei jeder Signierung einzugeben.',
                'The CA private key must always be passphrase-protected. Optionally store the passphrase AES-256-GCM encrypted here, or leave empty to prompt on each signing operation.'
              )}
            </p>
            {uploadPassphrase.length > 0 && (
              <div className="md:w-1/2">
                <PasswordStrengthHint password={uploadPassphrase} compact />
              </div>
            )}
          </div>

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={savingUpload || !uploadFilesReady}
              className="px-5 py-2 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
            >
              {savingUpload
                ? tr('Wird verifiziert...', 'Verifying...')
                : tr('CA prüfen & speichern', 'Verify & Save CA')}
            </button>
          </div>
        </div>
      </form>

      {/* Saved CAs List */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
            {tr(
              `Hinterlegte Certificate Authorities (${cas.length})`,
              `Stored Certificate Authorities (${cas.length})`
            )}
          </h2>
        </div>

        {loading ? (
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-6 py-10 text-center text-sm text-slate-500 dark:text-slate-400">
            {tr('Lade CA-Zertifikate...', 'Loading CA certificates...')}
          </div>
        ) : cas.length === 0 ? (
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-6 py-12 text-center">
            <FileKey2 className="w-7 h-7 text-slate-400 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {tr('Noch keine CA-Zertifikate hinterlegt', 'No CA certificates stored yet')}
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-md mx-auto">
              {tr(
                'Erzeugen Sie oben über „CA erzeugen“ eine neue passwortgeschützte Ed25519-CA oder laden Sie ein bestehendes Schlüsselpaar (ca & ca.pub) hoch.',
                'Click "Generate CA" above to create a new passphrase-protected Ed25519 CA or upload an existing keypair (ca & ca.pub).'
              )}
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {cas.map((ca) => {
              const isEditing = editingId === ca.id;
              const isConfirmingDelete = confirmDeleteId === ca.id;
              return (
                <article
                  key={ca.id}
                  className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-4"
                >
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                    <div className="min-w-0 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <ShieldCheck className="w-4 h-4 text-blue-700 dark:text-blue-400 shrink-0" />
                        <h3 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100 truncate">
                          {ca.name}
                        </h3>
                        <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-800">
                          {ca.keyType}
                        </span>
                        <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded bg-emerald-50 dark:bg-emerald-950/40 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/70">
                          <Lock className="w-3 h-3" />
                          {ca.hasStoredPassphrase
                            ? tr('Passwortgeschützt · Passwort gespeichert', 'Encrypted · Passphrase stored')
                            : tr('Passwortgeschützt · Abfrage bei Signierung', 'Encrypted · Prompt on sign')}
                        </span>
                      </div>

                      {ca.description && (
                        <p className="text-xs text-slate-600 dark:text-slate-400">{ca.description}</p>
                      )}

                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500 dark:text-slate-400 pt-0.5">
                        <span className="font-mono tabular-nums">
                          {tr('Dateien:', 'Files:')} {ca.privateKeyFileName}, {ca.publicKeyFileName}
                        </span>
                        {ca.fingerprint && (
                          <span className="font-mono text-[11px] text-slate-600 dark:text-slate-400 break-all">
                            {ca.fingerprint}
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-slate-400 tabular-nums">
                        {tr('Erstellt von', 'Created by')}{' '}
                        <span className="font-mono text-slate-600 dark:text-slate-400">{ca.createdByUsername || 'admin'}</span>{' '}
                        · {formatDateTime(ca.createdAt)}
                        {ca.updatedAt && ca.updatedAt !== ca.createdAt
                          ? ` · ${tr('Aktualisiert', 'Updated')} ${formatDateTime(ca.updatedAt)}`
                          : ''}
                      </p>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 shrink-0">
                      <button
                        type="button"
                        onClick={() => void handleCopyPubKey(ca)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md cursor-pointer whitespace-nowrap"
                      >
                        {copiedId === ca.id ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                            {tr('Kopiert', 'Copied')}
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            {tr('ca.pub kopieren', 'Copy ca.pub')}
                          </>
                        )}
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          downloadTextFile(ca.publicKeyFileName || 'ca.pub', `${ca.publicKey}\n`)
                        }
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md cursor-pointer whitespace-nowrap"
                      >
                        <Download className="w-3.5 h-3.5" />
                        ca.pub
                      </button>
                      <button
                        type="button"
                        onClick={() => (isEditing ? cancelEdit() : startEdit(ca))}
                        className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border rounded-md cursor-pointer whitespace-nowrap ${
                          isEditing
                            ? 'text-blue-800 dark:text-blue-300 bg-blue-50 dark:bg-blue-950/40 border-blue-300 dark:border-blue-700/80'
                            : 'text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60'
                        }`}
                      >
                        <Pencil className="w-3.5 h-3.5" />
                        {isEditing ? tr('Schließen', 'Close') : tr('Bearbeiten', 'Edit')}
                      </button>

                      {isConfirmingDelete ? (
                        <div className="inline-flex items-center gap-1.5 pl-1">
                          <button
                            type="button"
                            disabled={deletingId === ca.id}
                            onClick={() => void handleDelete(ca)}
                            className="px-2.5 py-1.5 text-xs font-medium text-white bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-md cursor-pointer whitespace-nowrap"
                          >
                            {deletingId === ca.id
                              ? tr('Löscht...', 'Deleting...')
                              : tr('Endgültig löschen', 'Confirm Delete')}
                          </button>
                          <button
                            type="button"
                            disabled={deletingId === ca.id}
                            onClick={() => setConfirmDeleteId(null)}
                            className="px-2.5 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md cursor-pointer"
                          >
                            {tr('Abbrechen', 'Cancel')}
                          </button>
                        </div>
                      ) : (
                        <button
                          type="button"
                          onClick={() => setConfirmDeleteId(ca.id)}
                          className="p-1.5 text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/50 rounded-md transition-colors cursor-pointer"
                          title={tr('CA löschen', 'Delete CA')}
                          aria-label={tr('CA löschen', 'Delete CA')}
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Public Key Preview for TrustedUserCAKeys */}
                  <div className="rounded-md bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 px-3.5 py-2.5 space-y-1">
                    <div className="flex items-center justify-between gap-2 text-[11px] text-slate-500 dark:text-slate-400">
                      <span className="font-medium text-slate-700 dark:text-slate-300">
                        {tr('Öffentlicher CA-Schlüssel (ca.pub)', 'CA Public Key (ca.pub)')}
                      </span>
                      <span className="font-mono text-slate-500 dark:text-slate-400">
                        sshd_config: TrustedUserCAKeys /etc/ssh/ca.pub
                      </span>
                    </div>
                    <pre className="font-mono text-[11px] text-slate-800 dark:text-slate-200 whitespace-pre-wrap break-all select-all">
                      {ca.publicKey}
                    </pre>
                  </div>

                  {/* Inline Edit Form */}
                  {isEditing && (
                    <form
                      onSubmit={(e) => void handleSaveEdit(e, ca)}
                      className="rounded-md border border-blue-200 dark:border-blue-800/70 bg-slate-50/70 dark:bg-slate-800/50 p-4 space-y-4"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-200 dark:border-slate-800">
                        <div>
                          <h4 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                            {tr('CA bearbeiten', 'Edit CA')}
                          </h4>
                          <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                            {tr(
                              'Passen Sie Bezeichnung, Beschreibung, gespeichertes CA-Passwort oder optional die Schlüsseldateien (ca / ca.pub) an.',
                              'Update label, description, stored CA passphrase, or optionally replace the key files (ca / ca.pub).'
                            )}
                          </p>
                        </div>
                        <button
                          type="button"
                          onClick={() => setEditShowText((v) => !v)}
                          className="text-xs font-medium text-blue-700 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300 cursor-pointer whitespace-nowrap self-start sm:self-auto"
                        >
                          {editShowText
                            ? tr('Schlüssel-Textfelder ausblenden', 'Hide key text fields')
                            : tr('Schlüssel manuell ersetzen', 'Replace keys manually')}
                        </button>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <label
                            htmlFor={`edit-ca-name-${ca.id}`}
                            className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1"
                          >
                            {tr('Bezeichnung', 'Label')}
                          </label>
                          {(() => {
                            const norm = editName.trim().toLowerCase();
                            const otherMatch = norm
                              ? cas.find(
                                  (c) => c.id !== ca.id && c.name.trim().toLowerCase() === norm
                                )
                              : undefined;
                            return (
                              <>
                                <input
                                  id={`edit-ca-name-${ca.id}`}
                                  type="text"
                                  maxLength={64}
                                  value={editName}
                                  onChange={(e) => setEditName(e.target.value)}
                                  className={`w-full px-3 py-1.5 text-sm bg-white dark:bg-slate-900 border rounded-md focus:outline-none focus:ring-2 ${
                                    otherMatch
                                      ? 'border-amber-400 dark:border-amber-700/80 bg-amber-50/40 dark:bg-amber-950/30 focus:ring-amber-500'
                                      : 'border-slate-300 dark:border-slate-700 focus:ring-blue-600'
                                  }`}
                                />
                                {otherMatch && (
                                  <p className="mt-1.5 flex items-start gap-1.5 text-xs text-amber-800 dark:text-amber-300">
                                    <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
                                    <span>
                                      {tr(
                                        `Der Name „${otherMatch.name}“ ist bereits an eine andere CA vergeben.`,
                                        `The name "${otherMatch.name}" is already used by another CA.`
                                      )}
                                    </span>
                                  </p>
                                )}
                              </>
                            );
                          })()}
                        </div>

                        <div>
                          <label
                            htmlFor={`edit-ca-desc-${ca.id}`}
                            className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1"
                          >
                            {tr('Beschreibung', 'Description')}
                          </label>
                          <input
                            id={`edit-ca-desc-${ca.id}`}
                            type="text"
                            maxLength={300}
                            value={editDescription}
                            onChange={(e) => setEditDescription(e.target.value)}
                            className="w-full px-3 py-1.5 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                          />
                        </div>
                      </div>

                      <div className="space-y-1.5">
                        <label
                          htmlFor={`edit-ca-pass-${ca.id}`}
                          className="block text-xs font-medium text-slate-700 dark:text-slate-300"
                        >
                          {tr('Gespeichertes CA-Passwort', 'Stored CA Passphrase')}
                        </label>
                        <input
                          id={`edit-ca-pass-${ca.id}`}
                          type="password"
                          autoComplete="new-password"
                          disabled={editClearPassphrase}
                          value={editPassphrase}
                          onChange={(e) => setEditPassphrase(e.target.value)}
                          placeholder={
                            ca.hasStoredPassphrase
                              ? tr(
                                  'Neues Passwort (leer = gespeichertes behalten)',
                                  'New passphrase (blank = keep stored)'
                                )
                              : tr(
                                  'Optional hinterlegen (leer = bei Signierung eingeben)',
                                  'Store optionally (blank = enter when signing)'
                                )
                          }
                          className="w-full md:w-1/2 px-3 py-1.5 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:bg-slate-100 dark:disabled:bg-slate-800/70 disabled:text-slate-400 dark:disabled:text-slate-600"
                        />
                        {!editClearPassphrase && editPassphrase.length > 0 && (
                          <div className="md:w-1/2">
                            <PasswordStrengthHint password={editPassphrase} compact />
                          </div>
                        )}
                        {ca.hasStoredPassphrase && (
                          <label className="inline-flex items-center gap-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer pt-1">
                            <input
                              type="checkbox"
                              checked={editClearPassphrase}
                              onChange={(e) => {
                                setEditClearPassphrase(e.target.checked);
                                if (e.target.checked) setEditPassphrase('');
                              }}
                              className="rounded border-slate-300 dark:border-slate-700 text-red-600 dark:text-red-400 focus:ring-red-600"
                            />
                            <span>
                              {tr(
                                'Gespeichertes CA-Passwort vom Server entfernen (künftig bei jeder Signierung abfragen)',
                                'Remove stored CA passphrase from server (prompt on each signing instead)'
                              )}
                            </span>
                          </label>
                        )}
                      </div>

                      {/* Optional key file replacement */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-slate-200 dark:border-slate-800">
                        <div className="flex items-center justify-between gap-2 px-3 py-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md">
                          <span className="font-mono text-xs text-slate-700 dark:text-slate-300 truncate">
                            {editPrivContent.trim()
                              ? `${editPrivFile} (${tr('neu gewählt', 'new file selected')})`
                              : `${ca.privateKeyFileName} (${tr('unverändert', 'unchanged')})`}
                          </span>
                          <input
                            ref={editPrivInputRef}
                            type="file"
                            className="hidden"
                            onChange={(e) => void handleEditSingleFile(e, 'priv')}
                          />
                          <button
                            type="button"
                            onClick={() => editPrivInputRef.current?.click()}
                            className="px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-300 bg-slate-50 dark:bg-slate-800/60 border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 rounded cursor-pointer whitespace-nowrap shrink-0"
                          >
                            {tr('ca tauschen', 'Replace ca')}
                          </button>
                        </div>

                        <div className="flex items-center justify-between gap-2 px-3 py-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md">
                          <span className="font-mono text-xs text-slate-700 dark:text-slate-300 truncate">
                            {editPubContent.trim()
                              ? `${editPubFile} (${tr('neu gewählt', 'new file selected')})`
                              : `${ca.publicKeyFileName} (${tr('unverändert', 'unchanged')})`}
                          </span>
                          <input
                            ref={editPubInputRef}
                            type="file"
                            className="hidden"
                            onChange={(e) => void handleEditSingleFile(e, 'pub')}
                          />
                          <button
                            type="button"
                            onClick={() => editPubInputRef.current?.click()}
                            className="px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-300 bg-slate-50 dark:bg-slate-800/60 border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 rounded cursor-pointer whitespace-nowrap shrink-0"
                          >
                            {tr('ca.pub tauschen', 'Replace ca.pub')}
                          </button>
                        </div>
                      </div>

                      {editShowText && (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          <textarea
                            rows={3}
                            value={editPrivContent}
                            onChange={(e) => setEditPrivContent(e.target.value)}
                            placeholder={tr(
                              'Optional neuer Inhalt für ca (verschlüsselt)...',
                              'Optional new contents for ca (encrypted)...'
                            )}
                            className="w-full px-3 py-2 text-xs font-mono bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                          />
                          <textarea
                            rows={3}
                            value={editPubContent}
                            onChange={(e) => setEditPubContent(e.target.value)}
                            placeholder={tr(
                              'Optional neuer Inhalt für ca.pub...',
                              'Optional new contents for ca.pub...'
                            )}
                            className="w-full px-3 py-2 text-xs font-mono bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                          />
                        </div>
                      )}

                      <div className="flex items-center justify-end gap-2 pt-1">
                        <button
                          type="button"
                          onClick={cancelEdit}
                          disabled={editSaving}
                          className="px-3.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md cursor-pointer"
                        >
                          {tr('Abbrechen', 'Cancel')}
                        </button>
                        <button
                          type="submit"
                          disabled={editSaving}
                          className="px-4 py-1.5 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md cursor-pointer whitespace-nowrap"
                        >
                          {editSaving
                            ? tr('Speichert...', 'Saving...')
                            : tr('Änderungen speichern', 'Save Changes')}
                        </button>
                      </div>
                    </form>
                  )}
                </article>
              );
            })}
          </div>
        )}
      </section>

      {/* Generate CA Modal */}
      {showGenerateModal && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="generate-ca-modal-title"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 dark:bg-black/70 backdrop-blur-[1px]"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeGenerateModal();
          }}
        >
          <form
            onSubmit={handleGenerateSubmit}
            className="w-full max-w-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xl overflow-hidden"
          >
            <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <Wand2 className="w-4 h-4 text-blue-700 dark:text-blue-400 shrink-0" />
                <h2
                  id="generate-ca-modal-title"
                  className="font-display text-base font-semibold text-slate-900 dark:text-slate-100"
                >
                  {tr('CA-Zertifikat erzeugen (Ed25519)', 'Generate CA Certificate (Ed25519)')}
                </h2>
              </div>
              <button
                type="button"
                onClick={closeGenerateModal}
                disabled={generating}
                aria-label={tr('Schließen', 'Close')}
                className="p-1 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 rounded cursor-pointer disabled:opacity-50"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-4">
              <p className="text-xs text-slate-600 dark:text-slate-400">
                {tr(
                  'Erzeugt ein neues passwortgeschütztes Ed25519-CA-Schlüsselpaar (ca und ca.pub) zum Signieren von SSH-Benutzerzertifikaten.',
                  'Generates a new passphrase-protected Ed25519 CA keypair (ca and ca.pub) for signing SSH user certificates.'
                )}
              </p>

              {genError && (
                <div
                  role="alert"
                  className="px-3 py-2 rounded-md bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800/70 text-xs text-red-800 dark:text-red-300"
                >
                  {genError}
                </div>
              )}

              <div>
                <label htmlFor="gen-ca-name" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  {tr('Bezeichnung', 'Label')}
                </label>
                <input
                  ref={genNameInputRef}
                  id="gen-ca-name"
                  type="text"
                  maxLength={64}
                  value={genName}
                  onChange={(e) => {
                    setGenName(e.target.value);
                    setGenConfirmOverwrite(false);
                  }}
                  placeholder={`${currentUser.username}-ca`}
                  className={`w-full px-3 py-2 text-sm border rounded-md focus:outline-none focus:ring-2 ${
                    matchingGenCa
                      ? 'border-amber-400 dark:border-amber-700/80 bg-amber-50/40 dark:bg-amber-950/30 focus:ring-amber-500'
                      : 'border-slate-300 dark:border-slate-700 focus:ring-blue-600'
                  }`}
                />
                {matchingGenCa && (
                  <p className="mt-1.5 flex items-start gap-1.5 text-xs text-amber-800 dark:text-amber-300">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
                    <span>
                      {tr(
                        `Der Name „${matchingGenCa.name}“ ist bereits vergeben.`,
                        `The name "${matchingGenCa.name}" is already taken.`
                      )}
                    </span>
                  </p>
                )}
              </div>

              <div>
                <label htmlFor="gen-ca-desc" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  {tr('Beschreibung (optional)', 'Description (optional)')}
                </label>
                <input
                  id="gen-ca-desc"
                  type="text"
                  maxLength={300}
                  value={genDescription}
                  onChange={(e) => setGenDescription(e.target.value)}
                  placeholder={tr('z. B. User-CA Produktion', 'e.g. Production User CA')}
                  className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </div>

              <div>
                <label htmlFor="gen-ca-pass" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  {tr('CA-Passwort (erforderlich)', 'CA Passphrase (required)')}
                </label>
                <input
                  id="gen-ca-pass"
                  type="password"
                  autoComplete="new-password"
                  autoFocus
                  required
                  value={genPassphrase}
                  onChange={(e) => setGenPassphrase(e.target.value)}
                  placeholder={tr('Starkes Passwort für CA-Privatschlüssel...', 'Strong passphrase for CA private key...')}
                  className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
                <PasswordStrengthHint password={genPassphrase} compact />
              </div>

              <div>
                <label htmlFor="gen-ca-pass-confirm" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  {tr('CA-Passwort bestätigen', 'Confirm CA Passphrase')}
                </label>
                <input
                  id="gen-ca-pass-confirm"
                  type="password"
                  autoComplete="new-password"
                  required
                  value={genPassphraseConfirm}
                  onChange={(e) => setGenPassphraseConfirm(e.target.value)}
                  placeholder={tr('Passwort erneut eingeben...', 'Re-enter passphrase...')}
                  className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </div>

              <label className="flex items-start gap-2.5 p-3 rounded-md bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={genStorePassphrase}
                  onChange={(e) => setGenStorePassphrase(e.target.checked)}
                  className="mt-0.5 rounded border-slate-300 dark:border-slate-700 text-blue-700 dark:text-blue-400 focus:ring-blue-600 cursor-pointer"
                />
                <div>
                  <span className="font-medium text-slate-900 dark:text-slate-100">
                    {tr(
                      'CA-Passwort verschlüsselt auf dem Server speichern',
                      'Store CA passphrase encrypted on server'
                    )}
                  </span>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                    {tr(
                      'Optional: Ermöglicht späteres Signieren ohne erneute Passworteingabe. Ohne Haken wird das Passwort bei jeder Signierung abgefragt.',
                      'Optional: Allows future signing without re-entering the passphrase. If unchecked, you will be prompted on each signing.'
                    )}
                  </p>
                </div>
              </label>

              {genConfirmOverwrite && matchingGenCa && (
                <div
                  role="alert"
                  className="px-3.5 py-3 rounded-md bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-700/80 text-xs text-amber-950 dark:text-amber-200 space-y-1"
                >
                  <div className="flex items-center gap-2 font-semibold text-amber-900 dark:text-amber-200">
                    <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
                    <span>
                      {tr(
                        `Bestehende CA „${matchingGenCa.name}“ überschreiben?`,
                        `Overwrite existing CA "${matchingGenCa.name}"?`
                      )}
                    </span>
                  </div>
                  <p className="text-amber-900/90 dark:text-amber-200/90 leading-relaxed">
                    {tr(
                      'Eine CA mit diesem Namen existiert bereits. Soll sie wirklich durch die neu erzeugte CA ersetzt werden?',
                      'A CA with this name already exists. Do you really want to replace it with the newly generated CA?'
                    )}
                  </p>
                </div>
              )}
            </div>

            <div className="px-5 py-3.5 bg-slate-50 dark:bg-slate-800/60 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end gap-2">
              {genConfirmOverwrite && matchingGenCa ? (
                <>
                  <button
                    type="button"
                    onClick={() => {
                      setGenConfirmOverwrite(false);
                      setTimeout(() => {
                        genNameInputRef.current?.focus();
                        genNameInputRef.current?.select();
                      }, 0);
                    }}
                    disabled={generating}
                    className="px-4 py-2 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md transition-colors cursor-pointer disabled:opacity-50"
                  >
                    {tr('Anderen Namen wählen', 'Choose Different Name')}
                  </button>
                  <button
                    type="submit"
                    disabled={generating}
                    className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-white bg-amber-600 hover:bg-amber-700 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                  >
                    <AlertTriangle className="w-3.5 h-3.5" />
                    {generating
                      ? tr('Überschreibe & erzeuge...', 'Overwriting & generating...')
                      : tr('Ja, überschreiben & erzeugen', 'Yes, Overwrite & Generate')}
                  </button>
                </>
              ) : (
                <>
                  <button
                    type="button"
                    onClick={closeGenerateModal}
                    disabled={generating}
                    className="px-4 py-2 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md transition-colors cursor-pointer disabled:opacity-50"
                  >
                    {tr('Abbrechen', 'Cancel')}
                  </button>
                  <button
                    type="submit"
                    disabled={generating}
                    className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                  >
                    <Wand2 className="w-3.5 h-3.5" />
                    {generating
                      ? tr('Erzeuge CA...', 'Generating CA...')
                      : tr('CA erzeugen', 'Generate CA')}
                  </button>
                </>
              )}
            </div>
          </form>
        </div>
      )}

      {/* Upload Overwrite Confirmation Modal */}
      {confirmUploadOverwriteCa && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="overwrite-upload-ca-title"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 dark:bg-black/70 backdrop-blur-[1px]"
          onClick={(e) => {
            if (e.target === e.currentTarget && !savingUpload) setConfirmUploadOverwriteCa(null);
          }}
        >
          <div className="w-full max-w-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
                <h2
                  id="overwrite-upload-ca-title"
                  className="font-display text-base font-semibold text-slate-900 dark:text-slate-100"
                >
                  {tr('Bestehende CA überschreiben?', 'Overwrite Existing CA?')}
                </h2>
              </div>
              <button
                type="button"
                onClick={() => setConfirmUploadOverwriteCa(null)}
                disabled={savingUpload}
                aria-label={tr('Schließen', 'Close')}
                className="p-1 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 rounded cursor-pointer disabled:opacity-50"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-3 text-sm text-slate-700 dark:text-slate-300">
              <p>
                {tr(
                  `Eine Certificate Authority mit dem Namen „${confirmUploadOverwriteCa.name}“ existiert bereits.`,
                  `A Certificate Authority named "${confirmUploadOverwriteCa.name}" already exists.`
                )}
              </p>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                {tr(
                  'Möchten Sie diese CA wirklich mit den neuen Schlüsseldateien überschreiben? Der bisherige CA-Schlüssel wird dauerhaft ersetzt.',
                  'Do you really want to overwrite this CA with the new key files? The previous CA key will be permanently replaced.'
                )}
              </p>
            </div>

            <div className="px-5 py-3.5 bg-slate-50 dark:bg-slate-800/60 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end gap-2">
              <button
                type="button"
                disabled={savingUpload}
                onClick={() => {
                  setConfirmUploadOverwriteCa(null);
                  setTimeout(() => {
                    uploadNameInputRef.current?.focus();
                    uploadNameInputRef.current?.select();
                  }, 0);
                }}
                className="px-4 py-2 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md transition-colors cursor-pointer disabled:opacity-50"
              >
                {tr('Anderen Namen wählen', 'Choose Different Name')}
              </button>
              <button
                type="button"
                disabled={savingUpload}
                onClick={() => void performUpload(true)}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-white bg-amber-600 hover:bg-amber-700 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                {savingUpload
                  ? tr('Wird überschrieben...', 'Overwriting...')
                  : tr('Ja, überschreiben', 'Yes, Overwrite')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
