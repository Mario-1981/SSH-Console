import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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
  Lock,
  Search,
  Shield,
  Users,
  RotateCcw,
  FileSignature,
  RefreshCw,
  Ban,
} from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { ApiKeyCurlPanel } from './ApiKeyCurlPanel';
import { PasswordStrengthHint } from './PasswordStrengthHint';
import { ShareDialog, formatShareSummary } from './ShareDialog';
import { SearchableSelect } from './SearchableSelect';
import { getPasswordComplexityError } from '../passwordPolicy';
import type {
  AppSettings,
  AssignedSigningCa,
  CertificateAuthority,
  ShareableUser,
  User,
  UserCertificate,
} from '../types';

interface CertificatesViewProps {
  user: User;
  users: ShareableUser[];
  certificates: UserCertificate[];
  publicUrl?: string;
  onUpdateSettings?: (settings: AppSettings) => void;
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

function extractFingerprintToken(raw?: string | null): string {
  if (!raw) return '';
  const shaMatch = /SHA256:[A-Za-z0-9+/=]+/i.exec(raw);
  if (shaMatch) {
    return `SHA256:${shaMatch[0].slice('SHA256:'.length).replace(/=+$/, '')}`;
  }
  const md5Match = /MD5:[0-9a-f:]+/i.exec(raw);
  if (md5Match) return md5Match[0].toLowerCase();
  return raw.trim();
}

function hasForeignCaCertificate(
  cert: UserCertificate,
  selectedCa: { fingerprint: string } | null
): boolean {
  if (!selectedCa) return false;
  const hasExistingCert = cert.metadata.hasCertificate !== false && Boolean(cert.certFileName);
  if (!hasExistingCert) return false;
  const existingFp = extractFingerprintToken(cert.metadata.caFingerprint);
  const selectedFp = extractFingerprintToken(selectedCa.fingerprint);
  return !(existingFp && selectedFp && existingFp === selectedFp);
}

export function CertificatesView({
  user,
  users,
  certificates,
  publicUrl = '',
  onUpdateSettings,
  onRefresh,
}: CertificatesViewProps) {
  const { locale, tr, formatDateTime } = useI18n();
  const isAdmin = user.role === 'admin';
  const canUpload = isAdmin || user.permissions?.uploadCertificates !== false;
  const canUploadSignedCert = isAdmin || user.permissions?.uploadSignedCert !== false;
  const canGenerateTest = isAdmin || user.permissions?.generateTestCertificates !== false;
  const requireCertPassphrase = !isAdmin && Boolean(user.permissions?.requireCertificatePassphrase);
  const canStoreCertPassphrase = isAdmin || user.permissions?.storeCertificatePassphrase !== false;
  const canSelfSign = !isAdmin && Boolean(user.permissions?.selfSignCertificates);
  const canAutoRenew = isAdmin || Boolean(user.permissions?.autoRenewCertificates);
  const canShare = isAdmin || Boolean(user.permissions?.shareResources);
  const canUseApi = isAdmin || user.permissions?.useApi !== false;
  const [bundleName, setBundleName] = useState('');
  const [privFile, setPrivFile] = useState('zertifikat');
  const [pubFile, setPubFile] = useState('zertifikat.pub');
  const [certFile, setCertFile] = useState('zertifikat-cert.pub');

  const [privContent, setPrivContent] = useState('');
  const [pubContent, setPubContent] = useState('');
  const [certContent, setCertContent] = useState('');
  const [keyPassphrase, setKeyPassphrase] = useState('');
  const [shareOnCreate, setShareOnCreate] = useState(false);
  const [sharingCert, setSharingCert] = useState<UserCertificate | null>(null);
  const [lastGeneratedBundle, setLastGeneratedBundle] = useState<{
    privateKey: string;
    publicKey: string;
  } | null>(null);

  // Generate certificate modal state
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [genName, setGenName] = useState('');
  const [genPassphrase, setGenPassphrase] = useState('');
  const [genPassphraseConfirm, setGenPassphraseConfirm] = useState('');
  const [genStorePassphrase, setGenStorePassphrase] = useState(false);
  const [genError, setGenError] = useState<string | null>(null);
  const [genConfirmOverwrite, setGenConfirmOverwrite] = useState(false);
  const [confirmUploadOverwriteCert, setConfirmUploadOverwriteCert] =
    useState<UserCertificate | null>(null);

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
  const [editPassphrase, setEditPassphrase] = useState('');
  const [editClearPassphrase, setEditClearPassphrase] = useState(false);
  const [editShowText, setEditShowText] = useState(false);
  const [editDragging, setEditDragging] = useState(false);
  const [editSaving, setEditSaving] = useState(false);

  // Admin oversight state: inspect, search, filter, and delete any user's certificates (read-only metadata, no private keys)
  const [activeViewTab, setActiveViewTab] = useState<'mine' | 'all'>('mine');
  const [adminCertificates, setAdminCertificates] = useState<UserCertificate[]>([]);
  const [adminLoading, setAdminLoading] = useState(false);
  const [adminLoadError, setAdminLoadError] = useState<string | null>(null);
  const [adminSearch, setAdminSearch] = useState('');
  const [adminOwnerFilter, setAdminOwnerFilter] = useState<string>('all');
  const [adminTypeFilter, setAdminTypeFilter] = useState<
    'all' | 'cert' | 'keypair' | 'expired' | 'encrypted' | 'shared'
  >('all');
  const [confirmAdminDeleteId, setConfirmAdminDeleteId] = useState<string | null>(null);
  const [adminDeletingId, setAdminDeletingId] = useState<string | null>(null);

  // Admin CA signing state (single + batch)
  const [cas, setCas] = useState<CertificateAuthority[]>([]);
  const [casLoading, setCasLoading] = useState(false);
  const [selectedMineIds, setSelectedMineIds] = useState<string[]>([]);
  const [selectedAdminIds, setSelectedAdminIds] = useState<string[]>([]);
  const [signingTargets, setSigningTargets] = useState<UserCertificate[] | null>(null);
  const [signCaId, setSignCaId] = useState('');
  const [signCaPassphrase, setSignCaPassphrase] = useState('');
  const [signPrincipals, setSignPrincipals] = useState('');
  const [signIncludeOwnerPrincipal, setSignIncludeOwnerPrincipal] = useState(false);
  const [signValidityPreset, setSignValidityPreset] = useState('+30d');
  const [signValidityCustom, setSignValidityCustom] = useState('+30d');
  const [signKeyId, setSignKeyId] = useState('');
  const [signSubmitting, setSignSubmitting] = useState(false);
  const [signConfirmForeignCa, setSignConfirmForeignCa] = useState(false);
  const [signAutoRenew, setSignAutoRenew] = useState(false);
  const [signAutoRenewBeforeSec, setSignAutoRenewBeforeSec] = useState<number>(0);
  const [signError, setSignError] = useState<string | null>(null);
  const [signPartialErrors, setSignPartialErrors] = useState<
    Array<{ certificateId: string; certificateName?: string; error: string }>
  >([]);

  const selectedSignCa = useMemo(
    () => cas.find((c) => c.id === signCaId) ?? null,
    [cas, signCaId]
  );

  const foreignCaConflicts = useMemo(() => {
    if (!signingTargets || !selectedSignCa) return [];
    return signingTargets
      .filter((t) => hasForeignCaCertificate(t, selectedSignCa))
      .map((t) => {
        const existingFp = extractFingerprintToken(t.metadata.caFingerprint);
        const matchedCa = existingFp
          ? cas.find((c) => extractFingerprintToken(c.fingerprint) === existingFp) ?? null
          : null;
        return {
          cert: t,
          existingFingerprint: existingFp || null,
          matchedCaName: matchedCa?.name || null,
        };
      });
  }, [signingTargets, selectedSignCa, cas]);

  useEffect(() => {
    setSignConfirmForeignCa(false);
  }, [signCaId, signingTargets]);

  // User self-signing state (single + batch Sammelupdate with group-assigned CAs)
  const [assignedCas, setAssignedCas] = useState<AssignedSigningCa[]>([]);
  const [assignedCasLoading, setAssignedCasLoading] = useState(false);
  const [selfSignTargets, setSelfSignTargets] = useState<UserCertificate[] | null>(null);
  const [selfSignCaId, setSelfSignCaId] = useState('');
  const [selfSignSubmitting, setSelfSignSubmitting] = useState(false);
  const [selfSignConfirmForeignCa, setSelfSignConfirmForeignCa] = useState(false);
  const [selfSignAutoRenew, setSelfSignAutoRenew] = useState(false);
  const [selfSignError, setSelfSignError] = useState<string | null>(null);
  const [selfSignPartialErrors, setSelfSignPartialErrors] = useState<
    Array<{ certificateId: string; certificateName?: string; error: string }>
  >([]);
  const [revokingAutoRenewId, setRevokingAutoRenewId] = useState<string | null>(null);
  const [batchRevokingAutoRenew, setBatchRevokingAutoRenew] = useState(false);

  const ownCertificates = useMemo(
    () => certificates.filter((c) => c.userId === user.id),
    [certificates, user.id]
  );

  const selectedSelfSignCa = useMemo(
    () => assignedCas.find((c) => c.id === selfSignCaId) ?? null,
    [assignedCas, selfSignCaId]
  );

  const selfForeignCaConflicts = useMemo(() => {
    if (!selfSignTargets || !selectedSelfSignCa) return [];
    return selfSignTargets
      .filter((t) => hasForeignCaCertificate(t, selectedSelfSignCa))
      .map((t) => {
        const existingFp = extractFingerprintToken(t.metadata.caFingerprint);
        const matchedCa = existingFp
          ? assignedCas.find((c) => extractFingerprintToken(c.fingerprint) === existingFp) ?? null
          : null;
        return {
          cert: t,
          existingFingerprint: existingFp || null,
          matchedCaName: matchedCa?.name || null,
        };
      });
  }, [selfSignTargets, selectedSelfSignCa, assignedCas]);

  useEffect(() => {
    setSelfSignConfirmForeignCa(false);
  }, [selfSignCaId, selfSignTargets]);

  const loadCas = useCallback(async () => {
    if (!isAdmin) return;
    setCasLoading(true);
    try {
      const res = await api.listCertificateAuthorities();
      setCas(res.cas);
      setSignCaId((prev) => {
        if (prev && res.cas.some((c) => c.id === prev)) return prev;
        return res.cas[0]?.id ?? '';
      });
    } catch {
      // ignore background CA list errors; shown when opening modal
    } finally {
      setCasLoading(false);
    }
  }, [isAdmin]);

  const loadAssignedCas = useCallback(async () => {
    if (!canSelfSign) {
      setAssignedCas([]);
      return;
    }
    setAssignedCasLoading(true);
    try {
      const res = await api.listAssignedSigningCas();
      setAssignedCas(res.cas);
      setSelfSignCaId((prev) => {
        if (prev && res.cas.some((c) => c.id === prev)) return prev;
        const readyFirst = res.cas.find((c) => c.hasStoredPassphrase);
        return readyFirst?.id ?? res.cas[0]?.id ?? '';
      });
    } catch {
      // ignore background load errors
    } finally {
      setAssignedCasLoading(false);
    }
  }, [canSelfSign]);

  const loadAdminCertificates = useCallback(async () => {
    if (!isAdmin) return;
    setAdminLoading(true);
    setAdminLoadError(null);
    try {
      const res = await api.listAdminCertificates();
      setAdminCertificates(res.certificates);
    } catch (err) {
      setAdminLoadError(
        err instanceof Error
          ? err.message
          : tr(
              'Benutzer-Zertifikate konnten nicht geladen werden.',
              'Could not load user certificates.'
            )
      );
    } finally {
      setAdminLoading(false);
    }
  }, [isAdmin, tr]);

  useEffect(() => {
    if (isAdmin) {
      void loadAdminCertificates();
      void loadCas();
    } else if (canSelfSign) {
      void loadAssignedCas();
    }
  }, [isAdmin, canSelfSign, certificates, loadAdminCertificates, loadCas, loadAssignedCas]);

  // Keep selections pruned when lists change
  useEffect(() => {
    const selectableIds = isAdmin
      ? certificates.map((c) => c.id)
      : ownCertificates.map((c) => c.id);
    const mineSet = new Set(selectableIds);
    setSelectedMineIds((prev) => prev.filter((id) => mineSet.has(id)));
  }, [certificates]);

  useEffect(() => {
    const adminSet = new Set(adminCertificates.map((c) => c.id));
    setSelectedAdminIds((prev) => prev.filter((id) => adminSet.has(id)));
  }, [adminCertificates]);

  const multiInputRef = useRef<HTMLInputElement | null>(null);
  const privInputRef = useRef<HTMLInputElement | null>(null);
  const pubInputRef = useRef<HTMLInputElement | null>(null);
  const certInputRef = useRef<HTMLInputElement | null>(null);
  const bundleNameInputRef = useRef<HTMLInputElement | null>(null);
  const genNameInputRef = useRef<HTMLInputElement | null>(null);

  const editMultiInputRef = useRef<HTMLInputElement | null>(null);
  const editPrivInputRef = useRef<HTMLInputElement | null>(null);
  const editPubInputRef = useRef<HTMLInputElement | null>(null);
  const editCertInputRef = useRef<HTMLInputElement | null>(null);

  async function classifyAndLoadFiles(fileList: FileList | File[]) {
    setError(null);
    setSuccess(null);
    const files = Array.from(fileList);
    let loaded = 0;

    let blockedSignedCert = false;

    for (const file of files) {
      const text = await file.text();
      const lower = file.name.toLowerCase();

      if (lower.endsWith('-cert.pub') || text.includes('-cert-v01@openssh.com')) {
        if (!canUploadSignedCert) {
          blockedSignedCert = true;
          continue;
        }
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

    if (blockedSignedCert) {
      setError(
        tr(
          'Ihre Benutzergruppe darf keine eigenen signierten Zertifikate (zertifikat-cert.pub) hochladen.',
          'Your user group is not permitted to upload own signed certificates (zertifikat-cert.pub).'
        )
      );
    } else if (loaded === 0) {
      setError(
        canUploadSignedCert
          ? tr(
              'Dateien konnten nicht automatisch zugeordnet werden. Bitte verwenden Sie zertifikat, zertifikat.pub und zertifikat-cert.pub.',
              'Could not classify files automatically. Please use zertifikat, zertifikat.pub, and optionally zertifikat-cert.pub.'
            )
          : tr(
              'Dateien konnten nicht automatisch zugeordnet werden. Bitte verwenden Sie zertifikat und zertifikat.pub.',
              'Could not classify files automatically. Please use zertifikat and zertifikat.pub.'
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
    if (slot === 'cert' && !canUploadSignedCert) {
      e.target.value = '';
      setError(
        tr(
          'Ihre Benutzergruppe darf keine eigenen signierten Zertifikate (zertifikat-cert.pub) hochladen.',
          'Your user group is not permitted to upload own signed certificates (zertifikat-cert.pub).'
        )
      );
      return;
    }
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

  function openGenerateModal() {
    setError(null);
    setSuccess(null);
    setGenError(null);
    setGenName(`${user.username}-ed25519`);
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

  async function handleGenerateCertificateSubmit(e: React.FormEvent) {
    e.preventDefault();
    setGenError(null);
    setError(null);
    setSuccess(null);

    if (requireCertPassphrase && !genPassphrase) {
      setGenError(
        tr(
          'Ihre Benutzergruppe erfordert ein Passwort für neu erzeugte Zertifikate.',
          'Your user group requires a passphrase for newly generated certificates.'
        )
      );
      return;
    }

    if (genPassphrase) {
      const passErr = getPasswordComplexityError(genPassphrase, tr);
      if (passErr) {
        setGenError(passErr);
        return;
      }
    }

    if (genPassphrase && genPassphrase !== genPassphraseConfirm) {
      setGenError(
        tr(
          'Die beiden Passwort-Eingaben stimmen nicht überein.',
          'The two passphrase entries do not match.'
        )
      );
      return;
    }

    const cleanName = genName.trim() || `${user.username}-ed25519`;
    const existingOwnCert = canUpload
      ? certificates.find(
          (c) => c.userId === user.id && c.name.trim().toLowerCase() === cleanName.toLowerCase()
        )
      : undefined;

    if (existingOwnCert && !genConfirmOverwrite) {
      setGenConfirmOverwrite(true);
      return;
    }

    const passToUse = genPassphrase;
    const shouldStorePass = Boolean(passToUse && canStoreCertPassphrase && genStorePassphrase);

    setGenerating(true);
    try {
      const generated = await api.generateTestCertificate({
        keyId: cleanName,
        ...(passToUse ? { passphrase: passToUse } : {}),
      });

      setLastGeneratedBundle(generated);

      if (canUpload) {
        const saved = await api.uploadCertificate({
          name: cleanName,
          privateKeyFileName: 'zertifikat',
          publicKeyFileName: 'zertifikat.pub',
          certFileName: '',
          privateKeyContent: generated.privateKey,
          publicKeyContent: generated.publicKey,
          certContent: '',
          overwrite: Boolean(existingOwnCert && genConfirmOverwrite),
          ...(shouldStorePass ? { passphrase: passToUse } : {}),
        });

        await onRefresh();
        const passNoteDe = passToUse
          ? shouldStorePass
            ? ' (passwortgeschützt, Passwort verschlüsselt gespeichert)'
            : ' (passwortgeschützt, Passwort wird bei jeder Nutzung abgefragt)'
          : ' (ohne Passwort)';
        const passNoteEn = passToUse
          ? shouldStorePass
            ? ' (passphrase-protected, passphrase stored encrypted)'
            : ' (passphrase-protected, passphrase prompted on each use)'
          : ' (without passphrase)';

        setSuccess(
          saved.replaced
            ? tr(
                `Bestehendes Zertifikat „${saved.certificate.name}“ wurde mit einem neu erzeugten Ed25519-Schlüsselpaar (zertifikat, zertifikat.pub)${passNoteDe} überschrieben.`,
                `Existing certificate "${saved.certificate.name}" has been replaced with a newly generated Ed25519 keypair (zertifikat, zertifikat.pub)${passNoteEn}.`
              )
            : tr(
                `Zertifikat „${saved.certificate.name}“ (zertifikat, zertifikat.pub)${passNoteDe} wurde erzeugt, kryptografisch verifiziert und sofort gespeichert — es kann jetzt im Dashboard und in der SSH-Shell ausgewählt werden.`,
                `Certificate "${saved.certificate.name}" (zertifikat, zertifikat.pub)${passNoteEn} was generated, cryptographically verified, and saved immediately — it is now available in the Dashboard and SSH Shell.`
              )
        );
      } else {
        setSuccess(
          tr(
            passToUse
              ? 'Passwortgeschütztes Zertifikat (zertifikat, zertifikat.pub) wurde erzeugt und steht unten zum lokalen Download bereit. Das Speichern auf dem Server ist für Ihre Benutzergruppe deaktiviert.'
              : 'Zertifikat (zertifikat, zertifikat.pub) wurde ohne Passwort erzeugt und steht unten zum lokalen Download bereit. Das Speichern auf dem Server ist für Ihre Benutzergruppe deaktiviert.',
            passToUse
              ? 'Passphrase-protected certificate (zertifikat, zertifikat.pub) was generated and is ready for local download below. Saving certificates on the server is disabled for your user group.'
              : 'Certificate (zertifikat, zertifikat.pub) was generated without a passphrase and is ready for local download below. Saving certificates on the server is disabled for your user group.'
          )
        );
      }

      setShowGenerateModal(false);
      setGenPassphrase('');
      setGenPassphraseConfirm('');
      setGenStorePassphrase(false);
      setGenConfirmOverwrite(false);
    } catch (err) {
      setGenError(
        err instanceof Error
          ? err.message
          : tr('Zertifikat konnte nicht erzeugt werden.', 'Could not generate certificate.')
      );
    } finally {
      setGenerating(false);
    }
  }

  async function performUpload(overwrite: boolean) {
    const hasCertFile = canUploadSignedCert && Boolean(certContent.trim());
    const effectiveName =
      bundleName.trim() ||
      (hasCertFile
        ? tr('SSH-Zertifikat', 'SSH Certificate')
        : tr('SSH-Schlüsselpaar', 'SSH Keypair'));

    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      const res = await api.uploadCertificate({
        name: effectiveName,
        privateKeyFileName: privFile,
        publicKeyFileName: pubFile,
        certFileName: hasCertFile ? certFile : '',
        privateKeyContent: privContent,
        publicKeyContent: pubContent,
        certContent: hasCertFile ? certContent : '',
        overwrite,
        ...(canStoreCertPassphrase && keyPassphrase ? { passphrase: keyPassphrase } : {}),
        ...(canShare && shareOnCreate ? { sharedWithAll: true, sharedWithUserIds: [] } : {}),
      });
      await onRefresh();
      setConfirmUploadOverwriteCert(null);
      setBundleName('');
      setPrivContent('');
      setPubContent('');
      setCertContent('');
      setKeyPassphrase('');
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
      setConfirmUploadOverwriteCert(null);
      setError(
        err instanceof Error
          ? err.message
          : tr('Zertifikatsprüfung fehlgeschlagen.', 'Certificate verification failed.')
      );
    } finally {
      setSaving(false);
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

    if (canStoreCertPassphrase && keyPassphrase) {
      const passErr = getPasswordComplexityError(keyPassphrase, tr);
      if (passErr) {
        setError(passErr);
        return;
      }
    }

    const hasCertFile = Boolean(certContent.trim());
    const effectiveName =
      bundleName.trim() ||
      (hasCertFile
        ? tr('SSH-Zertifikat', 'SSH Certificate')
        : tr('SSH-Schlüsselpaar', 'SSH Keypair'));
    const existingOwn = certificates.find(
      (c) => c.userId === user.id && c.name.trim().toLowerCase() === effectiveName.toLowerCase()
    );

    if (existingOwn) {
      setConfirmUploadOverwriteCert(existingOwn);
      return;
    }

    await performUpload(false);
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

  async function handleAdminDelete(cert: UserCertificate) {
    setAdminDeletingId(cert.id);
    setError(null);
    setSuccess(null);
    try {
      await api.deleteAdminCertificate(cert.id);
      setConfirmAdminDeleteId(null);
      if (editingCertId === cert.id) {
        cancelEdit();
      }
      setAdminCertificates((prev) => prev.filter((c) => c.id !== cert.id));
      await onRefresh();
      setSuccess(
        tr(
          `Zertifikat „${cert.name}“ (${cert.ownerUsername || 'Benutzer'}) wurde entfernt.`,
          `Certificate "${cert.name}" (${cert.ownerUsername || 'user'}) has been deleted.`
        )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Zertifikat konnte nicht entfernt werden.', 'Could not remove certificate.')
      );
    } finally {
      setAdminDeletingId(null);
    }
  }

  function openSignModal(targets: UserCertificate[]) {
    if (!isAdmin || targets.length === 0) return;
    setError(null);
    setSuccess(null);
    setSignError(null);
    setSignPartialErrors([]);
    setSignConfirmForeignCa(false);
    setSigningTargets(targets);
    setSignCaPassphrase('');
    setSignIncludeOwnerPrincipal(false);
    setSignValidityPreset('+30d');
    setSignValidityCustom('+30d');
    if (targets.length === 1) {
      const only = targets[0];
      setSignPrincipals((only.metadata.principals || []).join(', '));
      setSignKeyId(`${only.ownerUsername || user.username}-${only.name}`);
      setSignAutoRenew(Boolean(only.autoRenew?.enabled));
      setSignAutoRenewBeforeSec(only.autoRenew?.renewBeforeSeconds || 0);
    } else {
      setSignPrincipals('');
      setSignKeyId('');
      setSignAutoRenew(false);
      setSignAutoRenewBeforeSec(0);
    }
    void loadCas();
  }

  function closeSignModal() {
    if (signSubmitting) return;
    setSigningTargets(null);
    setSignCaPassphrase('');
    setSignConfirmForeignCa(false);
    setSignAutoRenew(false);
    setSignAutoRenewBeforeSec(0);
    setSignError(null);
    setSignPartialErrors([]);
  }

  function addPrincipalSuggestion(token: string) {
    const clean = token.trim();
    if (!clean) return;
    const current = signPrincipals
      .split(/[,;\n\r]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (!current.includes(clean)) {
      setSignPrincipals([...current, clean].join(', '));
    }
  }

  function toggleMineSelection(id: string) {
    setSelectedMineIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  }

  function toggleAdminSelection(id: string) {
    setSelectedAdminIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  }

  async function handleSignSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!signingTargets || signingTargets.length === 0) return;
    setSignError(null);
    setSignPartialErrors([]);

    const selectedCa = cas.find((c) => c.id === signCaId);
    if (!selectedCa) {
      setSignError(tr('Bitte wählen Sie eine CA aus.', 'Please select a Certificate Authority.'));
      return;
    }
    if (!selectedCa.hasStoredPassphrase && !signCaPassphrase) {
      setSignError(
        tr(
          'Für diese CA ist kein Passwort hinterlegt. Bitte geben Sie das CA-Passwort ein.',
          'No passphrase is stored for this CA. Please enter the CA passphrase.'
        )
      );
      return;
    }
    if (!signPrincipals.trim()) {
      setSignError(
        tr(
          'Bitte geben Sie mindestens einen Principal (-n) an (z. B. root oder admin).',
          'Please enter at least one principal (-n), e.g. root or admin.'
        )
      );
      return;
    }

    const effectiveValidity =
      signValidityPreset === 'custom' ? signValidityCustom.trim() : signValidityPreset;
    if (!effectiveValidity) {
      setSignError(tr('Bitte eine Gültigkeitsdauer (-V) angeben.', 'Please enter a validity period (-V).'));
      return;
    }

    if (foreignCaConflicts.length > 0 && !signConfirmForeignCa) {
      setSignError(
        tr(
          'Mindestens ein ausgewähltes Zertifikat besitzt bereits eine zertifikat-cert.pub-Datei, die nicht von der gewählten CA stammt. Bitte bestätigen Sie das Überschreiben in der Warnmeldung.',
          'At least one selected certificate already has a zertifikat-cert.pub file not signed by the selected CA. Please confirm the overwrite in the warning box.'
        )
      );
      return;
    }

    const wantsAdminAutoRenew =
      signAutoRenew && selectedCa.hasStoredPassphrase && effectiveValidity !== 'forever';

    setSignSubmitting(true);
    try {
      const res = await api.signCertificatesWithCa({
        caId: selectedCa.id,
        caPassphrase: signCaPassphrase || undefined,
        certificateIds: signingTargets.map((c) => c.id),
        principals: signPrincipals.trim(),
        includeOwnerPrincipal: signIncludeOwnerPrincipal,
        validity: effectiveValidity,
        keyId: signKeyId.trim() || undefined,
        confirmOverwriteForeignCa: foreignCaConflicts.length > 0 ? signConfirmForeignCa : undefined,
        autoRenew: wantsAdminAutoRenew,
        autoRenewBeforeSeconds: wantsAdminAutoRenew ? signAutoRenewBeforeSec : undefined,
      });

      const signedIdSet = new Set(res.certificates.map((c) => c.id));
      setSelectedMineIds((prev) => prev.filter((id) => !signedIdSet.has(id)));
      setSelectedAdminIds((prev) => prev.filter((id) => !signedIdSet.has(id)));

      await Promise.all([onRefresh(), loadAdminCertificates()]);

      if (res.failedCount > 0) {
        setSignPartialErrors(res.errors);
        setSigningTargets((prev) => (prev ? prev.filter((c) => !signedIdSet.has(c.id)) : null));
        setSignError(
          tr(
            `${res.signedCount} Zertifikat(e) signiert, ${res.failedCount} fehlgeschlagen.`,
            `${res.signedCount} certificate(s) signed, ${res.failedCount} failed.`
          )
        );
      } else {
        setSigningTargets(null);
        setSignCaPassphrase('');
        setSignConfirmForeignCa(false);
        const principalsLabel = res.principals.join(', ');
        setSuccess(
          res.signedCount === 1
            ? tr(
                `Zertifikat „${res.certificates[0]?.name || ''}“ erfolgreich mit CA „${res.caName}“ signiert (-n ${principalsLabel}, -V ${res.validity})${wantsAdminAutoRenew ? ' · Automatische Neuzertifizierung aktiviert' : ''}.`,
                `Certificate "${res.certificates[0]?.name || ''}" signed with CA "${res.caName}" (-n ${principalsLabel}, -V ${res.validity})${wantsAdminAutoRenew ? ' · Auto-renewal enabled' : ''}.`
              )
            : tr(
                `${res.signedCount} Zertifikate erfolgreich per Sammelsignierung mit CA „${res.caName}“ signiert (-n ${principalsLabel}, -V ${res.validity})${wantsAdminAutoRenew ? ' · Automatische Neuzertifizierung aktiviert' : ''}.`,
                `${res.signedCount} certificates batch-signed with CA "${res.caName}" (-n ${principalsLabel}, -V ${res.validity})${wantsAdminAutoRenew ? ' · Auto-renewal enabled' : ''}.`
              )
        );
      }
    } catch (err) {
      setSignError(
        err instanceof Error
          ? err.message
          : tr('Signierung fehlgeschlagen.', 'Certificate signing failed.')
      );
    } finally {
      setSignSubmitting(false);
    }
  }

  function openSelfSignModal(targets: UserCertificate[]) {
    if (!canSelfSign) return;
    const ownedOnly = targets.filter((t) => t.userId === user.id);
    if (ownedOnly.length === 0) return;
    setError(null);
    setSuccess(null);
    setSelfSignError(null);
    setSelfSignPartialErrors([]);
    setSelfSignConfirmForeignCa(false);
    if (ownedOnly.length === 1 && canAutoRenew) {
      setSelfSignAutoRenew(Boolean(ownedOnly[0].autoRenew?.enabled));
    } else {
      setSelfSignAutoRenew(false);
    }
    setSelfSignTargets(ownedOnly);
    void loadAssignedCas();
  }

  function closeSelfSignModal() {
    if (selfSignSubmitting) return;
    setSelfSignTargets(null);
    setSelfSignConfirmForeignCa(false);
    setSelfSignAutoRenew(false);
    setSelfSignError(null);
    setSelfSignPartialErrors([]);
  }

  async function handleSelfSignSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!selfSignTargets || selfSignTargets.length === 0) return;
    setSelfSignError(null);
    setSelfSignPartialErrors([]);

    const selectedCa = selectedSelfSignCa;
    if (!selectedCa) {
      setSelfSignError(
        tr('Bitte wählen Sie eine zugewiesene CA aus.', 'Please select an assigned CA.')
      );
      return;
    }
    if (!selectedCa.hasStoredPassphrase) {
      setSelfSignError(
        tr(
          `Für die CA „${selectedCa.name}“ ist noch kein Passwort auf dem Server hinterlegt. Bitte wenden Sie sich an einen Administrator.`,
          `No passphrase is stored on the server for CA "${selectedCa.name}". Please contact an administrator.`
        )
      );
      return;
    }
    if (selfForeignCaConflicts.length > 0 && !selfSignConfirmForeignCa) {
      setSelfSignError(
        tr(
          'Mindestens eines Ihrer ausgewählten Zertifikate besitzt bereits eine zertifikat-cert.pub-Datei, die nicht von der gewählten CA stammt. Bitte bestätigen Sie das Überschreiben in der Warnmeldung.',
          'At least one selected certificate already has a zertifikat-cert.pub file not signed by the selected CA. Please confirm the overwrite in the warning box.'
        )
      );
      return;
    }

    const selectedValidityLower = (selectedCa.validity || '').trim().toLowerCase();
    const isForeverCa =
      selectedValidityLower === 'forever' ||
      selectedValidityLower === 'always' ||
      selectedValidityLower === 'always:forever';
    const wantsUserAutoRenew =
      canAutoRenew &&
      selfSignAutoRenew &&
      selectedCa.hasStoredPassphrase &&
      !isForeverCa;

    setSelfSignSubmitting(true);
    try {
      const res = await api.selfSignCertificatesWithCa({
        caId: selectedCa.id,
        certificateIds: selfSignTargets.map((c) => c.id),
        confirmOverwriteForeignCa:
          selfForeignCaConflicts.length > 0 ? selfSignConfirmForeignCa : undefined,
        autoRenew: wantsUserAutoRenew,
      });

      const signedIdSet = new Set(res.certificates.map((c) => c.id));
      setSelectedMineIds((prev) => prev.filter((id) => !signedIdSet.has(id)));

      await onRefresh();

      if (res.failedCount > 0) {
        setSelfSignPartialErrors(res.errors);
        setSelfSignTargets((prev) =>
          prev ? prev.filter((c) => !signedIdSet.has(c.id)) : null
        );
        setSelfSignError(
          tr(
            `${res.signedCount} Zertifikat(e) signiert, ${res.failedCount} fehlgeschlagen.`,
            `${res.signedCount} certificate(s) signed, ${res.failedCount} failed.`
          )
        );
      } else {
        setSelfSignTargets(null);
        setSelfSignConfirmForeignCa(false);
        setSelfSignAutoRenew(false);
        const principalsLabel = res.principals.join(', ');
        setSuccess(
          res.signedCount === 1
            ? tr(
                `Zertifikat „${res.certificates[0]?.name || ''}“ erfolgreich mit CA „${res.caName}“ signiert (-n ${principalsLabel}, -V ${res.validity})${wantsUserAutoRenew ? ' · Automatische Neuzertifizierung aktiviert' : ''}.`,
                `Certificate "${res.certificates[0]?.name || ''}" signed with CA "${res.caName}" (-n ${principalsLabel}, -V ${res.validity})${wantsUserAutoRenew ? ' · Auto-renewal enabled' : ''}.`
              )
            : tr(
                `${res.signedCount} Zertifikate erfolgreich per Sammelupdate mit CA „${res.caName}“ signiert (-n ${principalsLabel}, -V ${res.validity})${wantsUserAutoRenew ? ' · Automatische Neuzertifizierung aktiviert' : ''}.`,
                `${res.signedCount} certificates batch-signed with CA "${res.caName}" (-n ${principalsLabel}, -V ${res.validity})${wantsUserAutoRenew ? ' · Auto-renewal enabled' : ''}.`
              )
        );
      }
    } catch (err) {
      setSelfSignError(
        err instanceof Error
          ? err.message
          : tr('Signierung fehlgeschlagen.', 'Certificate signing failed.')
      );
    } finally {
      setSelfSignSubmitting(false);
    }
  }

  async function handleRevokeAutoRenew(cert: UserCertificate) {
    setError(null);
    setSuccess(null);
    setRevokingAutoRenewId(cert.id);
    try {
      await api.revokeCertificateAutoRenew(cert.id);
      if (isAdmin) {
        await Promise.all([onRefresh(), loadAdminCertificates()]);
      } else {
        await onRefresh();
      }
      setSuccess(
        tr(
          `Automatische Neuzertifizierung für „${cert.name}“ wurde widerrufen.`,
          `Automatic re-certification for "${cert.name}" has been revoked.`
        )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr(
              'Automatische Neuzertifizierung konnte nicht widerrufen werden.',
              'Failed to revoke automatic re-certification.'
            )
      );
    } finally {
      setRevokingAutoRenewId(null);
    }
  }

  async function handleBatchRevokeAutoRenew(certsToRevoke: UserCertificate[]) {
    const activeIds = certsToRevoke.filter((c) => c.autoRenew?.enabled).map((c) => c.id);
    if (activeIds.length === 0) return;
    setError(null);
    setSuccess(null);
    setBatchRevokingAutoRenew(true);
    try {
      const res = await api.revokeCertificatesAutoRenewBatch(activeIds);
      if (isAdmin) {
        await Promise.all([onRefresh(), loadAdminCertificates()]);
      } else {
        await onRefresh();
      }
      setSuccess(
        tr(
          `Automatische Neuzertifizierung für ${res.revokedCount} Zertifikat(e) widerrufen.`,
          `Automatic re-certification revoked for ${res.revokedCount} certificate(s).`
        )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr(
              'Sammel-Widerruf der automatischen Neuzertifizierung fehlgeschlagen.',
              'Batch revocation of automatic re-certification failed.'
            )
      );
    } finally {
      setBatchRevokingAutoRenew(false);
    }
  }

  function formatAutoRenewLeadLabel(seconds: number): string {
    if (!seconds || seconds <= 0) {
      return tr('Automatisch (20 % vor Ablauf)', 'Automatic (20% before expiry)');
    }
    if (seconds >= 86400 && seconds % 86400 === 0) {
      const days = seconds / 86400;
      return days === 1
        ? tr('1 Tag vor Ablauf', '1 day before expiry')
        : tr(`${days} Tage vor Ablauf`, `${days} days before expiry`);
    }
    if (seconds >= 3600 && seconds % 3600 === 0) {
      const hours = seconds / 3600;
      return hours === 1
        ? tr('1 Stunde vor Ablauf', '1 hour before expiry')
        : tr(`${hours} Stunden vor Ablauf`, `${hours} hours before expiry`);
    }
    const mins = Math.max(1, Math.round(seconds / 60));
    return mins === 1
      ? tr('1 Minute vor Ablauf', '1 minute before expiry')
      : tr(`${mins} Minuten vor Ablauf`, `${mins} minutes before expiry`);
  }

  function renderAutoRenewBanner(cert: UserCertificate, canRevoke: boolean) {
    const ar = cert.autoRenew;
    if (!ar) return null;
    if (ar.enabled) {
      const isRevoking = revokingAutoRenewId === cert.id;
      return (
        <div className="pt-3 border-t border-slate-200 dark:border-slate-800">
          <div className="rounded-md bg-emerald-50/70 dark:bg-emerald-950/35 border border-emerald-200 dark:border-emerald-800/70 px-3.5 py-2.5 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
            <div className="flex items-start gap-2 min-w-0">
              <RefreshCw className="w-4 h-4 text-emerald-700 dark:text-emerald-400 shrink-0 mt-0.5" />
              <div className="space-y-0.5 min-w-0">
                <p className="font-semibold text-emerald-950 dark:text-emerald-200">
                  {tr(
                    'Automatische Neuzertifizierung aktiv (bis auf Widerruf oder Rechteentzug)',
                    'Automatic re-certification active (until revoked or rights removed)'
                  )}
                </p>
                <p className="text-emerald-900/90 dark:text-emerald-200/90 flex flex-wrap items-center gap-x-2 gap-y-0.5">
                  <span>
                    CA: <strong className="font-medium">{ar.caName || ar.caId}</strong>
                  </span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono">-V {ar.validity}</span>
                  <span aria-hidden="true">·</span>
                  <span>{formatAutoRenewLeadLabel(ar.renewBeforeSeconds)}</span>
                  <span aria-hidden="true">·</span>
                  <span>
                    {ar.mode === 'admin'
                      ? tr(
                          `Admin-Freigabe (${ar.enabledByUsername})`,
                          `Admin-enabled (${ar.enabledByUsername})`
                        )
                      : tr('Benutzer-Selbstsignierung', 'User self-signing')}
                  </span>
                </p>
                {ar.lastRenewedAt && (
                  <p className="text-[11px] text-emerald-800/80 dark:text-emerald-300/80">
                    {tr('Zuletzt erneuert:', 'Last renewed:')} {formatDateTime(ar.lastRenewedAt)}
                  </p>
                )}
                {ar.lastError && (
                  <p className="text-[11px] text-amber-900 dark:text-amber-200 bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/70 rounded px-2 py-1 mt-1">
                    {tr('Letzter Erneuerungshinweis:', 'Last renewal notice:')} {ar.lastError}
                  </p>
                )}
              </div>
            </div>
            {canRevoke && (
              <button
                type="button"
                onClick={() => void handleRevokeAutoRenew(cert)}
                disabled={isRevoking}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-red-700 dark:text-red-400 bg-white dark:bg-slate-900 hover:bg-red-50 dark:hover:bg-red-950/50 border border-red-200 dark:border-red-800/70 rounded-md transition-colors cursor-pointer disabled:opacity-50 whitespace-nowrap shrink-0 self-start sm:self-center"
              >
                <Ban className="w-3.5 h-3.5" />
                {isRevoking
                  ? tr('Wird widerrufen...', 'Revoking...')
                  : tr('Widerrufen', 'Revoke')}
              </button>
            )}
          </div>
        </div>
      );
    }

    if (ar.revokedReason) {
      return (
        <div className="pt-3 border-t border-slate-200 dark:border-slate-800">
          <div className="rounded-md bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 px-3 py-2 text-[11px] text-slate-600 dark:text-slate-400 flex items-start gap-2">
            <Ban className="w-3.5 h-3.5 text-slate-400 shrink-0 mt-0.5" />
            <span>
              <strong className="font-medium text-slate-700 dark:text-slate-300">
                {tr('Automatische Neuzertifizierung beendet:', 'Automatic re-certification stopped:')}
              </strong>{' '}
              {ar.revokedReason}
              {ar.revokedAt ? ` (${formatDateTime(ar.revokedAt)})` : ''}
            </span>
          </div>
        </div>
      );
    }
    return null;
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
    setEditPassphrase('');
    setEditClearPassphrase(false);
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
    setEditPassphrase('');
    setEditClearPassphrase(false);
    setEditShowText(false);
    setEditDragging(false);
  }

  async function classifyAndLoadEditFiles(fileList: FileList | File[]) {
    setError(null);
    const files = Array.from(fileList);
    let loaded = 0;

    let blockedSignedCert = false;

    for (const file of files) {
      const text = await file.text();
      const lower = file.name.toLowerCase();

      if (lower.endsWith('-cert.pub') || text.includes('-cert-v01@openssh.com')) {
        if (!canUploadSignedCert) {
          blockedSignedCert = true;
          continue;
        }
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

    if (blockedSignedCert) {
      setError(
        tr(
          'Ihre Benutzergruppe darf keine eigenen signierten Zertifikate (zertifikat-cert.pub) hochladen.',
          'Your user group is not permitted to upload own signed certificates (zertifikat-cert.pub).'
        )
      );
    } else if (loaded === 0) {
      setError(
        canUploadSignedCert
          ? tr(
              'Dateien konnten nicht automatisch zugeordnet werden. Bitte wählen Sie zertifikat, zertifikat.pub oder zertifikat-cert.pub.',
              'Could not classify files automatically. Please choose zertifikat, zertifikat.pub, or zertifikat-cert.pub.'
            )
          : tr(
              'Dateien konnten nicht automatisch zugeordnet werden. Bitte wählen Sie zertifikat oder zertifikat.pub.',
              'Could not classify files automatically. Please choose zertifikat or zertifikat.pub.'
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
    if (slot === 'cert' && !canUploadSignedCert) {
      e.target.value = '';
      setError(
        tr(
          'Ihre Benutzergruppe darf keine eigenen signierten Zertifikate (zertifikat-cert.pub) hochladen.',
          'Your user group is not permitted to upload own signed certificates (zertifikat-cert.pub).'
        )
      );
      return;
    }
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
      passphrase?: string;
      clearPassphrase?: boolean;
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
    } else if (canUploadSignedCert && editCertContent.trim()) {
      payload.certContent = editCertContent;
      payload.certFileName = editCertFile || cert.certFileName || 'zertifikat-cert.pub';
    }
    if (editClearPassphrase) {
      payload.clearPassphrase = true;
    } else if (canStoreCertPassphrase && editPassphrase) {
      const passErr = getPasswordComplexityError(editPassphrase, tr);
      if (passErr) {
        setError(passErr);
        return;
      }
      payload.passphrase = editPassphrase;
    }

    if (Object.keys(payload).length === 0) {
      setError(
        tr(
          'Es wurden keine Änderungen vorgenommen. Ändern Sie den Namen, das Schlüssel-Passwort oder wählen Sie mindestens eine auszutauschende Datei.',
          'No changes were made. Update the label, key passphrase, or choose at least one file to replace.'
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
      if (payload.passphrase) {
        updatedPartsDe.push('Schlüssel-Passwort hinterlegt');
        updatedPartsEn.push('key passphrase stored');
      }
      if (payload.clearPassphrase) {
        updatedPartsDe.push('Schlüssel-Passwort entfernt');
        updatedPartsEn.push('key passphrase removed');
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
  const effectiveGenName = genName.trim() || `${user.username}-ed25519`;
  const matchingGenCert = canUpload
    ? certificates.find(
        (c) => c.userId === user.id && c.name.trim().toLowerCase() === effectiveGenName.toLowerCase()
      )
    : undefined;

  const adminOwnerOptions = useMemo(() => {
    const map = new Map<string, { userId: string; username: string; count: number }>();
    for (const c of adminCertificates) {
      const existing = map.get(c.userId);
      if (existing) {
        existing.count += 1;
      } else {
        map.set(c.userId, {
          userId: c.userId,
          username: c.ownerUsername || c.userId,
          count: 1,
        });
      }
    }
    return Array.from(map.values()).sort((a, b) => a.username.localeCompare(b.username));
  }, [adminCertificates]);

  const ownAdminCertCount = useMemo(
    () => adminCertificates.filter((c) => c.userId === user.id).length,
    [adminCertificates, user.id]
  );

  const otherUsersCertCount = useMemo(
    () => adminCertificates.filter((c) => c.userId !== user.id).length,
    [adminCertificates, user.id]
  );

  const filteredAdminCertificates = useMemo(() => {
    const terms = adminSearch
      .trim()
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean);

    return adminCertificates.filter((c) => {
      if (adminOwnerFilter === '__others__' && c.userId === user.id) return false;
      if (adminOwnerFilter === '__mine__' && c.userId !== user.id) return false;
      if (
        adminOwnerFilter !== 'all' &&
        adminOwnerFilter !== '__others__' &&
        adminOwnerFilter !== '__mine__' &&
        c.userId !== adminOwnerFilter
      ) {
        return false;
      }

      const hasCert = c.metadata.hasCertificate !== false && Boolean(c.certFileName);
      if (adminTypeFilter === 'cert' && !hasCert) return false;
      if (adminTypeFilter === 'keypair' && hasCert) return false;
      if (adminTypeFilter === 'expired' && !c.metadata.isExpired) return false;
      if (adminTypeFilter === 'encrypted' && !c.metadata.privateKeyEncrypted) return false;
      if (
        adminTypeFilter === 'shared' &&
        !c.sharedWithAll &&
        c.sharedWithUserIds.length === 0
      ) {
        return false;
      }

      if (terms.length > 0) {
        const haystack = [
          c.name,
          c.ownerUsername || '',
          c.privateKeyFileName,
          c.publicKeyFileName,
          c.certFileName || '',
          c.metadata.keyId || '',
          c.metadata.pubKeyAlgorithm || '',
          c.metadata.pubKeyFingerprint || '',
          c.metadata.caFingerprint || '',
          c.metadata.privateKeyFormat || '',
          ...(c.metadata.principals || []),
        ]
          .join(' ')
          .toLowerCase();
        for (const term of terms) {
          if (!haystack.includes(term)) return false;
        }
      }

      return true;
    });
  }, [adminCertificates, adminOwnerFilter, adminSearch, adminTypeFilter, user.id]);

  const hasActiveAdminFilters =
    adminSearch.trim().length > 0 || adminOwnerFilter !== 'all' || adminTypeFilter !== 'all';

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            {tr('SSH-Schlüssel & Zertifikate', 'SSH Keys & Certificates')}
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            {tr(
              'Laden Sie für die passwortlose Anmeldung entweder ein klassisches Schlüsselpaar (',
              'For passwordless login, upload either a standard SSH keypair ('
            )}
            <code className="font-mono text-xs text-slate-800 dark:text-slate-200">zertifikat</code> +{' '}
            <code className="font-mono text-xs text-slate-800 dark:text-slate-200">zertifikat.pub</code>
            {tr(
              ') oder zusätzlich ein signiertes OpenSSH-Zertifikat (',
              ') or additionally a signed OpenSSH certificate ('
            )}
            <code className="font-mono text-xs text-slate-800 dark:text-slate-200">zertifikat-cert.pub</code>
            {tr(') hoch.', ').')}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {canUseApi && canUpload && (
            <button
              type="button"
              onClick={() => {
                if (isAdmin && activeViewTab !== 'mine') {
                  setActiveViewTab('mine');
                  setShowApiPanel(true);
                } else {
                  setShowApiPanel((v) => !v);
                }
              }}
              className={`inline-flex items-center gap-2 px-4 py-2 text-xs font-medium border rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                showApiPanel && (!isAdmin || activeViewTab === 'mine')
                  ? 'text-blue-800 dark:text-blue-300 bg-blue-50 dark:bg-blue-950/40 border-blue-300 dark:border-blue-700/80'
                  : 'text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              {showApiPanel && (!isAdmin || activeViewTab === 'mine')
                ? tr('curl-API ausblenden', 'Hide curl API')
                : tr('Upload per curl & API-Key', 'Upload via curl & API Key')}
            </button>
          )}

          {canGenerateTest && (
            <button
              type="button"
              onClick={openGenerateModal}
              disabled={generating}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md transition-colors cursor-pointer whitespace-nowrap"
            >
              <Wand2 className="w-3.5 h-3.5" />
              {generating
                ? tr('Erzeuge Zertifikat...', 'Generating certificate...')
                : tr('Zertifikat erzeugen', 'Generate Certificate')}
            </button>
          )}
        </div>
      </div>

      {isAdmin && (
        <div
          role="tablist"
          aria-label={tr('Zertifikatsansicht', 'Certificate View')}
          className="flex flex-wrap items-center gap-1 border-b border-slate-200 dark:border-slate-800"
        >
          <button
            type="button"
            role="tab"
            aria-selected={activeViewTab === 'mine'}
            onClick={() => setActiveViewTab('mine')}
            className={`inline-flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors cursor-pointer whitespace-nowrap ${
              activeViewTab === 'mine'
                ? 'border-blue-700 text-blue-800 dark:text-blue-300'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:border-slate-300 dark:hover:border-slate-600'
            }`}
          >
            <KeyRound className="w-4 h-4" />
            {tr('Eigene & geteilte Zertifikate', 'Own & Shared Certificates')}
            <span className="text-xs font-mono text-slate-500 dark:text-slate-400 tabular-nums">
              ({certificates.length})
            </span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeViewTab === 'all'}
            onClick={() => {
              setActiveViewTab('all');
              void loadAdminCertificates();
            }}
            className={`inline-flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors cursor-pointer whitespace-nowrap ${
              activeViewTab === 'all'
                ? 'border-blue-700 text-blue-800 dark:text-blue-300'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:border-slate-300 dark:hover:border-slate-600'
            }`}
          >
            <Users className="w-4 h-4" />
            {tr('Alle Benutzer-Zertifikate (Admin)', 'All User Certificates (Admin)')}
            <span className="text-xs font-mono text-slate-500 dark:text-slate-400 tabular-nums">
              ({adminCertificates.length})
            </span>
          </button>
        </div>
      )}

      {showApiPanel && canUseApi && canUpload && (!isAdmin || activeViewTab === 'mine') && (
        <ApiKeyCurlPanel
          defaultCertName={`${user.username}-ssh`}
          publicUrl={publicUrl}
          isAdmin={isAdmin}
          onUpdateSettings={onUpdateSettings}
        />
      )}

      {error && (
        <div role="alert" className="px-4 py-3 rounded-md bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800/70 text-sm text-red-800 dark:text-red-300">
          {error}
        </div>
      )}

      {success && (
        <div className="px-4 py-3 rounded-md bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/70 text-sm text-emerald-900 dark:text-emerald-200">
          {success}
        </div>
      )}

      {(!isAdmin || activeViewTab === 'mine') && (
        <>
      {!canUpload && lastGeneratedBundle && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 text-xs text-slate-700 dark:text-slate-300 space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-medium text-slate-900 dark:text-slate-100">
              {tr('Erzeugte Dateien lokal herunterladen:', 'Download generated files locally:')}
            </span>
            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => downloadTextFile('zertifikat', lastGeneratedBundle.privateKey)}
                className="text-blue-700 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300 font-mono font-medium cursor-pointer"
              >
                zertifikat
              </button>
              <span aria-hidden="true" className="text-slate-300">·</span>
              <button
                type="button"
                onClick={() => downloadTextFile('zertifikat.pub', lastGeneratedBundle.publicKey)}
                className="text-blue-700 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300 font-mono font-medium cursor-pointer"
              >
                zertifikat.pub
              </button>
            </div>
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono break-all">
            authorized_keys: {lastGeneratedBundle.publicKey.trim()}
          </p>
        </div>
      )}

      {!canUpload && (
        <div className="px-4 py-3 rounded-md bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-300">
          {tr(
            `Das Hochladen und Verwalten eigener SSH-Zertifikate ist für Ihre Benutzergruppe („${user.groupName || 'Benutzer'}“) deaktiviert. Freigegebene Zertifikate stehen unten weiterhin für SSH-Verbindungen bereit.`,
            `Uploading and managing own SSH certificates is disabled for your user group ("${user.groupName || 'User'}"). Shared certificates below remain available for SSH connections.`
          )}
        </div>
      )}

      {/* Upload Form */}
      {canUpload && (
      <form onSubmit={handleSubmit} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-200 dark:border-slate-800">
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
              {tr(
                'SSH-Schlüsselpaar (2 Dateien) oder Zertifikatspaket (3 Dateien) hochladen',
                'Upload SSH Keypair (2 files) or Certificate Bundle (3 files)'
              )}
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              {tr(
                'Die kryptografische Zusammengehörigkeit von Privatschlüssel, öffentlichem Schlüssel und optionalem CA-Zertifikat wird beim Speichern verifiziert.',
                'Cryptographic pairing between the private key, public key, and optional CA certificate is verified upon saving.'
              )}
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowTextEditors((v) => !v)}
            className="text-xs font-medium text-blue-700 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300 cursor-pointer whitespace-nowrap shrink-0"
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
            isDragging ? 'border-blue-600 bg-blue-50/50 dark:bg-blue-950/30' : 'border-slate-300 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-800/50'
          }`}
        >
          <Upload className="w-5 h-5 text-slate-500 dark:text-slate-400 mx-auto mb-2" />
          <p className="text-sm font-medium text-slate-800 dark:text-slate-200">
            {tr(
              '2 Dateien (Schlüsselpaar) oder 3 Dateien (mit CA-Zertifikat) hierher ziehen oder auswählen',
              'Drag and drop 2 files (keypair) or 3 files (with CA certificate) here, or browse'
            )}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono">
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
            className="mt-3 px-4 py-2 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md transition-colors cursor-pointer whitespace-nowrap"
          >
            {tr('Dateien auswählen', 'Select Files')}
          </button>
        </div>

        {/* Individual 3 slots */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Slot 1: zertifikat */}
          <div className="border border-slate-200 dark:border-slate-800 rounded-md p-4 flex flex-col justify-between bg-white dark:bg-slate-900">
            <div>
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100">1. zertifikat</span>
                <span
                  className={`text-xs font-medium ${
                    privContent.trim() ? 'text-emerald-700 dark:text-emerald-400' : 'text-slate-400'
                  }`}
                >
                  {privContent.trim() ? tr('Geladen', 'Loaded') : tr('Fehlt', 'Missing')}
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                {tr(
                  'Privater OpenSSH-Schlüssel (AES-256-GCM verschlüsselt gespeichert, chmod 0600).',
                  'Private OpenSSH key (stored with AES-256-GCM encryption, chmod 0600).'
                )}
              </p>
              {requireCertPassphrase && (
                <p className="mt-1.5 text-[11px] font-medium text-amber-800 dark:text-amber-300">
                  {tr(
                    'Pflicht: Ihre Benutzergruppe erfordert einen passwortgeschützten Privatschlüssel.',
                    'Required: Your user group requires a passphrase-protected private key.'
                  )}
                </p>
              )}
              {privContent.trim() && (
                <p className="mt-2 text-xs font-mono text-slate-700 dark:text-slate-300 truncate">{privFile}</p>
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
                className="px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                {tr('Datei wählen', 'Choose File')}
              </button>
              {privContent.trim() && (
                <button
                  type="button"
                  onClick={() => downloadTextFile(privFile || 'zertifikat', privContent)}
                  className="p-1.5 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 rounded-md cursor-pointer"
                  title={tr('zertifikat herunterladen', 'Download zertifikat')}
                >
                  <Download className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Slot 2: zertifikat.pub */}
          <div className="border border-slate-200 dark:border-slate-800 rounded-md p-4 flex flex-col justify-between bg-white dark:bg-slate-900">
            <div>
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100">2. zertifikat.pub</span>
                <span
                  className={`text-xs font-medium ${
                    pubContent.trim() ? 'text-emerald-700 dark:text-emerald-400' : 'text-slate-400'
                  }`}
                >
                  {pubContent.trim() ? tr('Geladen', 'Loaded') : tr('Fehlt', 'Missing')}
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                {tr(
                  'Öffentlicher Schlüssel (z. B. ssh-ed25519 AAAA...) zur Schlüsselpaar-Prüfung.',
                  'Public key (e.g. ssh-ed25519 AAAA...) used to verify keypair integrity.'
                )}
              </p>
              {pubContent.trim() && (
                <p className="mt-2 text-xs font-mono text-slate-700 dark:text-slate-300 truncate">{pubFile}</p>
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
                className="px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                {tr('Datei wählen', 'Choose File')}
              </button>
              {pubContent.trim() && (
                <button
                  type="button"
                  onClick={() => downloadTextFile(pubFile || 'zertifikat.pub', pubContent)}
                  className="p-1.5 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 rounded-md cursor-pointer"
                  title={tr('zertifikat.pub herunterladen', 'Download zertifikat.pub')}
                >
                  <Download className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Slot 3: zertifikat-cert.pub (optional / policy-controlled) */}
          {canUploadSignedCert ? (
            <div className="border border-slate-200 dark:border-slate-800 rounded-md p-4 flex flex-col justify-between bg-white dark:bg-slate-900">
              <div>
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100">
                    3. zertifikat-cert.pub
                  </span>
                  <span
                    className={`text-xs font-medium ${
                      certContent.trim() ? 'text-emerald-700 dark:text-emerald-400' : 'text-slate-500 dark:text-slate-400'
                    }`}
                  >
                    {certContent.trim() ? tr('Geladen', 'Loaded') : tr('Optional', 'Optional')}
                  </span>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                  {tr(
                    'Optional: Von Ihrer SSH-CA signiertes OpenSSH-Benutzerzertifikat (*-cert-v01@openssh.com). Leer lassen für klassisches Schlüsselpaar.',
                    'Optional: OpenSSH user certificate (*-cert-v01@openssh.com) signed by your SSH CA. Leave empty for a standard keypair.'
                  )}
                </p>
                {certContent.trim() && (
                  <p className="mt-2 text-xs font-mono text-slate-700 dark:text-slate-300 truncate">{certFile}</p>
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
                  className="px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                >
                  {tr('Datei wählen', 'Choose File')}
                </button>
                {certContent.trim() && (
                  <>
                    <button
                      type="button"
                      onClick={() => downloadTextFile(certFile || 'zertifikat-cert.pub', certContent)}
                      className="p-1.5 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 rounded-md cursor-pointer"
                      title={tr('zertifikat-cert.pub herunterladen', 'Download zertifikat-cert.pub')}
                    >
                      <Download className="w-3.5 h-3.5" />
                    </button>
                    <button
                      type="button"
                      onClick={() => setCertContent('')}
                      className="text-xs text-slate-500 dark:text-slate-400 hover:text-red-700 dark:hover:text-red-300 cursor-pointer"
                    >
                      {tr('Leeren', 'Clear')}
                    </button>
                  </>
                )}
              </div>
            </div>
          ) : (
            <div className="border border-slate-200 dark:border-slate-800 rounded-md p-4 flex flex-col justify-between bg-slate-50 dark:bg-slate-800/60">
              <div>
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-semibold text-slate-700 dark:text-slate-300">
                    3. zertifikat-cert.pub
                  </span>
                  <span className="inline-flex items-center gap-1 text-xs font-medium text-slate-500 dark:text-slate-400">
                    <Lock className="w-3 h-3" />
                    {tr('Gesperrt', 'Restricted')}
                  </span>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                  {canSelfSign
                    ? tr(
                        'Das Hochladen eigener zertifikat-cert.pub-Dateien ist für Ihre Benutzergruppe deaktiviert. Nach dem Speichern können Sie Ihren Schlüssel direkt über die zugewiesene CA signieren.',
                        'Uploading own zertifikat-cert.pub files is disabled for your group. After saving, you can sign your key directly with your assigned CA.'
                      )
                    : tr(
                        'Das Hochladen eigener zertifikat-cert.pub-Dateien ist für Ihre Benutzergruppe deaktiviert. Signaturen werden durch Administratoren über eine interne CA ausgestellt.',
                        'Uploading own zertifikat-cert.pub files is disabled for your group. Signatures are issued by administrators via an internal CA.'
                      )}
                </p>
              </div>
            </div>
          )}
        </div>

        {lastGeneratedBundle && (
          <div className="px-4 py-3 rounded-md bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-300 space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-medium text-slate-900 dark:text-slate-100">
                {tr('Erzeugte Dateien lokal herunterladen (optional):', 'Download generated files locally (optional):')}
              </span>
              <div className="flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  onClick={() => downloadTextFile('zertifikat', lastGeneratedBundle.privateKey)}
                  className="text-blue-700 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300 font-mono font-medium cursor-pointer"
                >
                  zertifikat
                </button>
                <span aria-hidden="true" className="text-slate-300">·</span>
                <button
                  type="button"
                  onClick={() => downloadTextFile('zertifikat.pub', lastGeneratedBundle.publicKey)}
                  className="text-blue-700 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300 font-mono font-medium cursor-pointer"
                >
                  zertifikat.pub
                </button>
              </div>
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono break-all">
              authorized_keys: {lastGeneratedBundle.publicKey.trim()}
            </p>
          </div>
        )}

        {showTextEditors && (
          <div className="grid grid-cols-1 gap-4 pt-2 border-t border-slate-200 dark:border-slate-800">
            <div>
              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                {tr('Inhalt von zertifikat (Privater Schlüssel)', 'Contents of zertifikat (Private Key)')}
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
                {tr('Inhalt von zertifikat.pub (Öffentlicher Schlüssel)', 'Contents of zertifikat.pub (Public Key)')}
              </label>
              <textarea
                rows={2}
                value={pubContent}
                onChange={(e) => setPubContent(e.target.value)}
                placeholder="ssh-ed25519 AAAA..."
                className="w-full px-3 py-2 text-xs font-mono border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
            {canUploadSignedCert && (
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
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
                  className="w-full px-3 py-2 text-xs font-mono border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </div>
            )}
          </div>
        )}

        <div className="space-y-4 pt-2 border-t border-slate-200 dark:border-slate-800">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label htmlFor="cert-bundle-name" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                {tr('Bezeichnung für dieses Schlüssel-/Zertifikatspaket', 'Label for this key / certificate bundle')}
              </label>
              <input
                ref={bundleNameInputRef}
                id="cert-bundle-name"
                type="text"
                value={bundleName}
                onChange={(e) => setBundleName(e.target.value)}
                placeholder={tr('z. B. Produktion Ed25519 (Q4)', 'e.g. Production Ed25519 (Q4)')}
                className={`w-full px-3.5 py-2 text-sm border rounded-md focus:outline-none focus:ring-2 ${
                  matchingExistingOwnCert
                    ? 'border-amber-400 dark:border-amber-700/80 bg-amber-50/40 dark:bg-amber-950/30 focus:ring-amber-500'
                    : 'border-slate-300 dark:border-slate-700 focus:ring-blue-600'
                }`}
              />
              {matchingExistingOwnCert && (
                <p className="mt-1.5 flex items-start gap-1.5 text-xs text-amber-800 dark:text-amber-300">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
                  <span>
                    {tr(
                      `Der Name „${matchingExistingOwnCert.name}“ ist bereits vergeben. Beim Speichern werden Sie gefragt, ob das bestehende Zertifikat überschrieben werden soll.`,
                      `The name "${matchingExistingOwnCert.name}" is already taken. You will be asked whether to overwrite the existing certificate when saving.`
                    )}
                  </span>
                </p>
              )}
            </div>
            <div>
              <label htmlFor="cert-key-passphrase" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                {tr('Schlüssel-Passwort (optional)', 'Key Passphrase (optional)')}
              </label>
              {canStoreCertPassphrase ? (
                <>
                  <input
                    id="cert-key-passphrase"
                    type="password"
                    autoComplete="new-password"
                    value={keyPassphrase}
                    onChange={(e) => setKeyPassphrase(e.target.value)}
                    placeholder={tr(
                      'Leer lassen für Eingabe bei jeder Nutzung',
                      'Leave empty to enter on each use'
                    )}
                    className="w-full px-3.5 py-2 text-sm border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                  />
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                    {tr(
                      'Nur nötig, falls der private Schlüssel passwortgeschützt ist. Wird optional AES-256-GCM-verschlüsselt gespeichert oder leer gelassen und jeweils manuell eingegeben.',
                      'Only needed if the private key is passphrase-protected. Optionally stored AES-256-GCM encrypted, or leave blank to prompt on each use.'
                    )}
                  </p>
                  {keyPassphrase.length > 0 && (
                    <PasswordStrengthHint password={keyPassphrase} compact />
                  )}
                </>
              ) : (
                <div className="px-3 py-2 rounded-md bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-800 text-xs text-slate-600 dark:text-slate-400">
                  {tr(
                    'Das Speichern von Zertifikats-Passwörtern auf dem Server ist für Ihre Benutzergruppe deaktiviert. Passwortgeschützte Schlüssel werden bei jeder Nutzung manuell entsperrt.',
                    'Storing certificate passphrases on the server is disabled for your user group. Passphrase-protected keys are unlocked manually on each use.'
                  )}
                </div>
              )}
            </div>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              {canShare && (
                <label className="inline-flex items-center gap-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={shareOnCreate}
                    onChange={(e) => setShareOnCreate(e.target.checked)}
                    className="rounded border-slate-300 dark:border-slate-700 text-blue-700 dark:text-blue-400 focus:ring-blue-600"
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
            <button
              type="submit"
              disabled={saving || !requiredFilesReady}
              className="px-5 py-2 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0 self-start sm:self-auto"
            >
              {saving
                ? tr('Wird verifiziert...', 'Verifying...')
                : certContent.trim()
                  ? tr('Zertifikatspaket prüfen & speichern', 'Verify & Save Certificate Bundle')
                  : tr('Schlüsselpaar prüfen & speichern', 'Verify & Save Keypair')}
            </button>
          </div>
        </div>
      </form>
      )}

      {/* Saved Bundles */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
            {tr(
              `Hinterlegte Zertifikatspakete (${certificates.length})`,
              `Saved Key & Certificate Bundles (${certificates.length})`
            )}
          </h2>
          {isAdmin && certificates.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  const allSelected =
                    certificates.length > 0 &&
                    certificates.every((c) => selectedMineIds.includes(c.id));
                  setSelectedMineIds(allSelected ? [] : certificates.map((c) => c.id));
                }}
                className="text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer whitespace-nowrap"
              >
                {certificates.length > 0 &&
                certificates.every((c) => selectedMineIds.includes(c.id))
                  ? tr('Auswahl aufheben', 'Clear selection')
                  : tr('Alle auswählen', 'Select all')}
              </button>
              {selectedMineIds.length > 0 && (() => {
                const selectedMineCerts = certificates.filter((c) =>
                  selectedMineIds.includes(c.id)
                );
                const activeAutoRenewSelected = selectedMineCerts.filter(
                  (c) => c.autoRenew?.enabled
                );
                return (
                  <>
                    <button
                      type="button"
                      onClick={() => openSignModal(selectedMineCerts)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                    >
                      <FileSignature className="w-3.5 h-3.5" />
                      {tr(
                        `Sammelsignierung mit CA (${selectedMineIds.length})`,
                        `Batch Sign with CA (${selectedMineIds.length})`
                      )}
                    </button>
                    {activeAutoRenewSelected.length > 0 && (
                      <button
                        type="button"
                        disabled={batchRevokingAutoRenew}
                        onClick={() => void handleBatchRevokeAutoRenew(activeAutoRenewSelected)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-950/40 hover:bg-red-100 dark:hover:bg-red-900/50 border border-red-200 dark:border-red-800/70 rounded-md transition-colors cursor-pointer disabled:opacity-50 whitespace-nowrap"
                      >
                        <Ban className="w-3.5 h-3.5" />
                        {tr(
                          `Auto-Erneuerung widerrufen (${activeAutoRenewSelected.length})`,
                          `Revoke Auto-Renew (${activeAutoRenewSelected.length})`
                        )}
                      </button>
                    )}
                  </>
                );
              })()}
            </div>
          )}
          {canSelfSign && ownCertificates.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  const allSelected =
                    ownCertificates.length > 0 &&
                    ownCertificates.every((c) => selectedMineIds.includes(c.id));
                  setSelectedMineIds(allSelected ? [] : ownCertificates.map((c) => c.id));
                }}
                className="text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer whitespace-nowrap"
              >
                {ownCertificates.length > 0 &&
                ownCertificates.every((c) => selectedMineIds.includes(c.id))
                  ? tr('Auswahl aufheben', 'Clear selection')
                  : tr('Alle eigenen auswählen', 'Select all own')}
              </button>
              {selectedMineIds.length > 0 ? (() => {
                const selectedOwnCerts = ownCertificates.filter((c) =>
                  selectedMineIds.includes(c.id)
                );
                const activeAutoRenewOwn = selectedOwnCerts.filter(
                  (c) => c.autoRenew?.enabled
                );
                return (
                  <>
                    <button
                      type="button"
                      onClick={() => openSelfSignModal(selectedOwnCerts)}
                      disabled={assignedCas.length === 0}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                    >
                      <FileSignature className="w-3.5 h-3.5" />
                      {tr(
                        `Sammelupdate signieren (${selectedMineIds.length})`,
                        `Batch Sign Update (${selectedMineIds.length})`
                      )}
                    </button>
                    {activeAutoRenewOwn.length > 0 && (
                      <button
                        type="button"
                        disabled={batchRevokingAutoRenew}
                        onClick={() => void handleBatchRevokeAutoRenew(activeAutoRenewOwn)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-950/40 hover:bg-red-100 dark:hover:bg-red-900/50 border border-red-200 dark:border-red-800/70 rounded-md transition-colors cursor-pointer disabled:opacity-50 whitespace-nowrap"
                      >
                        <Ban className="w-3.5 h-3.5" />
                        {tr(
                          `Auto-Erneuerung widerrufen (${activeAutoRenewOwn.length})`,
                          `Revoke Auto-Renew (${activeAutoRenewOwn.length})`
                        )}
                      </button>
                    )}
                  </>
                );
              })() : (
                ownCertificates.length > 1 &&
                assignedCas.length > 0 && (
                  <button
                    type="button"
                    onClick={() => openSelfSignModal(ownCertificates)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-800 dark:text-blue-300 bg-blue-50 dark:bg-blue-950/40 hover:bg-blue-100 dark:hover:bg-blue-900/50 border border-blue-200 dark:border-blue-800/70 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                  >
                    <FileSignature className="w-3.5 h-3.5" />
                    {tr(
                      `Alle ${ownCertificates.length} signieren (Sammelupdate)`,
                      `Sign All ${ownCertificates.length} (Batch Update)`
                    )}
                  </button>
                )
              )}
            </div>
          )}
        </div>

        {/* User Self-Signing Assigned CA summary strip */}
        {canSelfSign && (
          <div className="rounded-md bg-blue-50/60 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-800/70 px-4 py-3 text-xs text-slate-700 dark:text-slate-300 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-start gap-2 min-w-0">
              <FileSignature className="w-4 h-4 text-blue-700 dark:text-blue-400 shrink-0 mt-0.5" />
              <div className="space-y-1 min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <p className="font-medium text-slate-900 dark:text-slate-100">
                    {tr(
                      'Selbstsignierung über zugewiesene CA aktiviert',
                      'Self-signing via assigned CA enabled'
                    )}
                  </p>
                  {canAutoRenew && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/70 text-[11px] font-medium text-emerald-800 dark:text-emerald-300">
                      <RefreshCw className="w-3 h-3" />
                      {tr(
                        'Automatische Neuzertifizierung freigegeben',
                        'Auto-renewal permitted'
                      )}
                    </span>
                  )}
                </div>
                {assignedCasLoading && assignedCas.length === 0 ? (
                  <p className="text-slate-500 dark:text-slate-400">
                    {tr('Zugewiesene CAs werden geladen...', 'Loading assigned CAs...')}
                  </p>
                ) : assignedCas.length === 0 ? (
                  <p className="text-amber-900 dark:text-amber-200">
                    {tr(
                      'Ihrer Benutzergruppe ist aktuell noch keine CA zugewiesen. Bitte wenden Sie sich an einen Administrator.',
                      'No CA is currently assigned to your user group. Please contact an administrator.'
                    )}
                  </p>
                ) : (
                  <div className="flex flex-wrap items-center gap-2">
                    {assignedCas.map((ca) => (
                      <span
                        key={ca.id}
                        className="inline-flex flex-wrap items-center gap-1.5 px-2 py-0.5 rounded bg-white dark:bg-slate-900 border border-blue-200 dark:border-blue-800/70 text-[11px]"
                      >
                        <span className="font-semibold text-blue-950 dark:text-blue-200">{ca.name}</span>
                        <span className="font-mono text-slate-600 dark:text-slate-400">
                          -n {ca.effectivePrincipals.join(', ') || '—'}
                        </span>
                        <span className="font-mono text-slate-500 dark:text-slate-400">· -V {ca.validity}</span>
                        {!ca.hasStoredPassphrase && (
                          <span className="text-amber-700 dark:text-amber-400 font-medium">
                            · {tr('Passwort fehlt', 'Passphrase missing')}
                          </span>
                        )}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {certificates.length === 0 ? (
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-6 py-12 text-center">
            <KeyRound className="w-7 h-7 text-slate-400 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {tr('Noch kein SSH-Schlüssel oder Zertifikat hinterlegt', 'No SSH keys or certificates stored yet')}
            </h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1 max-w-md mx-auto">
              {tr('Laden Sie oben ', 'Upload ')}
              <code className="font-mono text-xs">zertifikat</code> {tr('und', 'and')}{' '}
              <code className="font-mono text-xs">zertifikat.pub</code>{' '}
              {tr('(optional zusätzlich ', '(optionally with ')}
              <code className="font-mono text-xs">zertifikat-cert.pub</code>
              {tr(
                ') hoch oder erzeugen Sie direkt ein Zertifikat.',
                ') above, or generate a certificate directly.'
              )}
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {certificates.map((cert) => {
              const m = cert.metadata;
              const hasCert = m.hasCertificate !== false && Boolean(cert.certFileName);
              const isOwner = cert.userId === user.id;
              const isSelectedMine = selectedMineIds.includes(cert.id);
              const shareLabel = isOwner
                ? formatShareSummary(cert.sharedWithAll, cert.sharedWithUserIds, locale)
                : tr(
                    `Geteilt von ${cert.ownerUsername || 'admin'}`,
                    `Shared by ${cert.ownerUsername || 'admin'}`
                  );
              return (
                <article
                  key={cert.id}
                  className={`bg-white dark:bg-slate-900 border rounded-lg p-6 space-y-4 transition-colors ${
                    isSelectedMine ? 'border-blue-400 ring-1 ring-blue-100 dark:ring-blue-900/40' : 'border-slate-200 dark:border-slate-800'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                    <div className="flex items-start gap-3 min-w-0">
                      {(isAdmin || (canSelfSign && isOwner)) && (
                        <input
                          type="checkbox"
                          checked={isSelectedMine}
                          onChange={() => toggleMineSelection(cert.id)}
                          aria-label={tr(
                            `Zertifikat ${cert.name} für Sammelsignierung auswählen`,
                            `Select certificate ${cert.name} for batch signing`
                          )}
                          className="mt-1 w-4 h-4 rounded border-slate-300 dark:border-slate-700 text-blue-700 dark:text-blue-400 focus:ring-blue-600 cursor-pointer shrink-0"
                        />
                      )}
                      <div className="min-w-0">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <h3 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
                          {cert.name}
                        </h3>
                        {hasCert ? (
                          m.isExpired ? (
                            <span className="inline-flex items-center gap-1 text-xs font-medium text-red-700 dark:text-red-400">
                              <AlertTriangle className="w-3.5 h-3.5" />
                              {tr('Abgelaufen', 'Expired')}
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-700 dark:text-emerald-400">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              {tr('3-Dateien-Verbund verifiziert', '3-file bundle verified')}
                            </span>
                          )
                        ) : (
                          <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-700 dark:text-emerald-400">
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
                              ? 'text-blue-800 dark:text-blue-300 font-medium'
                              : 'text-slate-500 dark:text-slate-400'
                          }`}
                        >
                          {shareLabel}
                        </span>
                        {m.privateKeyEncrypted && (
                          <>
                            <span aria-hidden="true" className="text-slate-300">·</span>
                            <span
                              className={`inline-flex items-center gap-1 text-xs font-medium ${
                                cert.hasStoredPassphrase ? 'text-emerald-700 dark:text-emerald-400' : 'text-amber-800 dark:text-amber-300'
                              }`}
                            >
                              <Lock className="w-3 h-3" />
                              {cert.hasStoredPassphrase
                                ? tr('Passwort hinterlegt', 'Passphrase stored')
                                : tr('Passwort bei Nutzung eingeben', 'Enter passphrase on use')}
                            </span>
                          </>
                        )}
                      </div>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono">
                        {cert.privateKeyFileName} · {cert.publicKeyFileName}
                        {hasCert
                          ? ` · ${cert.certFileName}`
                          : tr(' · (ohne zertifikat-cert.pub)', ' · (no zertifikat-cert.pub)')}
                      </p>
                      </div>
                    </div>

                    {isOwner && (canUpload || canShare || canSelfSign) ? (
                      <div className="flex flex-wrap items-center gap-2 shrink-0">
                        {isAdmin && (
                          <button
                            type="button"
                            onClick={() => openSignModal([cert])}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-800 dark:text-blue-300 bg-blue-50 dark:bg-blue-950/40 hover:bg-blue-100 dark:hover:bg-blue-900/50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                          >
                            <FileSignature className="w-3.5 h-3.5" />
                            {tr('Mit CA signieren', 'Sign with CA')}
                          </button>
                        )}
                        {canSelfSign && (
                          <button
                            type="button"
                            onClick={() => openSelfSignModal([cert])}
                            disabled={assignedCas.length === 0}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-800 dark:text-blue-300 bg-blue-50 dark:bg-blue-950/40 hover:bg-blue-100 dark:hover:bg-blue-900/50 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                          >
                            <FileSignature className="w-3.5 h-3.5" />
                            {hasCert
                              ? tr('Neu signieren', 'Re-sign with CA')
                              : tr('Mit CA signieren', 'Sign with CA')}
                          </button>
                        )}
                        {canUpload && (
                          <button
                            type="button"
                            onClick={() => (editingCertId === cert.id ? cancelEdit() : startEdit(cert))}
                            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                              editingCertId === cert.id
                                ? 'text-slate-900 dark:text-slate-100 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700'
                                : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
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
                        )}
                        {canShare && (
                          <button
                            type="button"
                            onClick={() => setSharingCert(cert)}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-700 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-950/50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                          >
                            <Share2 className="w-3.5 h-3.5" />
                            {tr('Teilen', 'Share')}
                          </button>
                        )}
                        {canUpload && (
                          <button
                            type="button"
                            onClick={() => handleDelete(cert.id)}
                            disabled={deletingId === cert.id}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-700 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                            {deletingId === cert.id
                              ? tr('Wird gelöscht...', 'Deleting...')
                              : tr('Entfernen', 'Delete')}
                          </button>
                        )}
                      </div>
                    ) : (
                      <div className="flex flex-wrap items-center gap-2 shrink-0">
                        {isAdmin && (
                          <button
                            type="button"
                            onClick={() => openSignModal([cert])}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-800 dark:text-blue-300 bg-blue-50 dark:bg-blue-950/40 hover:bg-blue-100 dark:hover:bg-blue-900/50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                          >
                            <FileSignature className="w-3.5 h-3.5" />
                            {tr('Mit CA signieren', 'Sign with CA')}
                          </button>
                        )}
                        <span className="text-xs text-slate-400 whitespace-nowrap shrink-0">
                          {tr('Nur für SSH nutzbar', 'SSH use only')}
                        </span>
                      </div>
                    )}
                  </div>

                  {editingCertId === cert.id && isOwner && canUpload && (
                    <form
                      onSubmit={(e) => handleSaveEdit(e, cert)}
                      className="rounded-md border border-blue-200 dark:border-blue-800/70 bg-slate-50/70 dark:bg-slate-800/50 p-4 space-y-4"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-200 dark:border-slate-800">
                        <div>
                          <h4 className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                            {tr(
                              'Paket bearbeiten (einzelne Dateien gezielt austauschen)',
                              'Edit Bundle (replace individual files selectively)'
                            )}
                          </h4>
                          <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                            {tr(
                              'Nicht geänderte Dateien bleiben unverändert erhalten. Ideal, um z. B. nur ein neues zertifikat-cert.pub einzuspielen.',
                              'Unchanged files are kept as-is. Ideal for rotating only zertifikat-cert.pub without re-uploading your private key.'
                            )}
                          </p>
                        </div>
                        <button
                          type="button"
                          onClick={() => setEditShowText((v) => !v)}
                          className="text-xs font-medium text-blue-700 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300 cursor-pointer whitespace-nowrap shrink-0 self-start sm:self-auto"
                        >
                          {editShowText
                            ? tr('Textfelder ausblenden', 'Hide text fields')
                            : tr('Inhalte manuell einfügen', 'Paste contents manually')}
                        </button>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <label
                            htmlFor={`edit-cert-name-${cert.id}`}
                            className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1"
                          >
                            {tr('Bezeichnung', 'Bundle Label')}
                          </label>
                          {(() => {
                            const editNorm = editName.trim().toLowerCase();
                            const matchingOtherEditCert = editNorm
                              ? certificates.find(
                                  (c) =>
                                    c.userId === user.id &&
                                    c.id !== cert.id &&
                                    c.name.trim().toLowerCase() === editNorm
                                )
                              : undefined;
                            return (
                              <>
                                <input
                                  id={`edit-cert-name-${cert.id}`}
                                  type="text"
                                  value={editName}
                                  onChange={(e) => setEditName(e.target.value)}
                                  className={`w-full px-3 py-1.5 text-sm bg-white dark:bg-slate-900 border rounded-md focus:outline-none focus:ring-2 ${
                                    matchingOtherEditCert
                                      ? 'border-amber-400 dark:border-amber-700/80 bg-amber-50/40 dark:bg-amber-950/30 focus:ring-amber-500'
                                      : 'border-slate-300 dark:border-slate-700 focus:ring-blue-600'
                                  }`}
                                />
                                {matchingOtherEditCert && (
                                  <p className="mt-1.5 flex items-start gap-1.5 text-xs text-amber-800 dark:text-amber-300">
                                    <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
                                    <span>
                                      {tr(
                                        `Der Name „${matchingOtherEditCert.name}“ ist bereits an ein anderes eigenes Zertifikat vergeben.`,
                                        `The name "${matchingOtherEditCert.name}" is already used by another one of your certificates.`
                                      )}
                                    </span>
                                  </p>
                                )}
                              </>
                            );
                          })()}
                        </div>

                        <div className="space-y-1.5">
                          <label
                            htmlFor={`edit-cert-pass-${cert.id}`}
                            className="block text-xs font-medium text-slate-700 dark:text-slate-300"
                          >
                            {tr('Schlüssel-Passwort', 'Key Passphrase')}
                          </label>
                          {canStoreCertPassphrase ? (
                            <>
                              <input
                                id={`edit-cert-pass-${cert.id}`}
                                type="password"
                                autoComplete="new-password"
                                disabled={editClearPassphrase}
                                value={editPassphrase}
                                onChange={(e) => setEditPassphrase(e.target.value)}
                                placeholder={
                                  cert.hasStoredPassphrase
                                    ? tr(
                                        'Neues Passwort (leer = aktuelles behalten)',
                                        'New passphrase (blank = keep stored)'
                                      )
                                    : tr(
                                        'Optional hinterlegen (leer = bei Nutzung eingeben)',
                                        'Store optionally (blank = enter on use)'
                                      )
                                }
                                className="w-full px-3 py-1.5 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:bg-slate-100 dark:disabled:bg-slate-800/70 disabled:text-slate-400 dark:disabled:text-slate-600"
                              />
                              {!editClearPassphrase && editPassphrase.length > 0 && (
                                <PasswordStrengthHint password={editPassphrase} compact />
                              )}
                            </>
                          ) : (
                            <p className="px-3 py-1.5 text-xs text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-800 rounded-md">
                              {tr(
                                'Speichern von Zertifikats-Passwörtern ist für Ihre Gruppe deaktiviert.',
                                'Storing certificate passphrases is disabled for your group.'
                              )}
                            </p>
                          )}
                          {cert.hasStoredPassphrase && (
                            <label className="inline-flex items-center gap-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
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
                                  'Hinterlegtes Passwort entfernen (künftig bei jeder Nutzung eingeben)',
                                  'Remove stored passphrase (prompt on each use instead)'
                                )}
                              </span>
                            </label>
                          )}
                        </div>
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
                            ? 'border-blue-600 bg-blue-50/70 dark:bg-blue-950/35'
                            : 'border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900'
                        }`}
                      >
                        <div className="flex flex-col sm:flex-row items-center justify-center gap-2 text-xs text-slate-600 dark:text-slate-400">
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
                            className="px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded transition-colors cursor-pointer whitespace-nowrap"
                          >
                            {tr('Dateien wählen', 'Browse Files')}
                          </button>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        {/* Edit Slot 1: private key */}
                        <div className="border border-slate-200 dark:border-slate-800 rounded-md p-3 bg-white dark:bg-slate-900 flex flex-col justify-between gap-2.5">
                          <div>
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100">
                                1. zertifikat
                              </span>
                              <span
                                className={`text-[11px] font-medium ${
                                  editPrivContent.trim() ? 'text-blue-700 dark:text-blue-400' : 'text-slate-500 dark:text-slate-400'
                                }`}
                              >
                                {editPrivContent.trim()
                                  ? tr('Wird ersetzt', 'Will replace')
                                  : tr('Unverändert', 'Unchanged')}
                              </span>
                            </div>
                            <p className="mt-1 text-[11px] font-mono text-slate-600 dark:text-slate-400 truncate">
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
                              className="px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded cursor-pointer whitespace-nowrap"
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
                                className="text-xs text-slate-500 dark:text-slate-400 hover:text-red-700 dark:hover:text-red-300 cursor-pointer"
                              >
                                {tr('Zurücksetzen', 'Reset')}
                              </button>
                            )}
                          </div>
                        </div>

                        {/* Edit Slot 2: public key */}
                        <div className="border border-slate-200 dark:border-slate-800 rounded-md p-3 bg-white dark:bg-slate-900 flex flex-col justify-between gap-2.5">
                          <div>
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100">
                                2. zertifikat.pub
                              </span>
                              <span
                                className={`text-[11px] font-medium ${
                                  editPubContent.trim() ? 'text-blue-700 dark:text-blue-400' : 'text-slate-500 dark:text-slate-400'
                                }`}
                              >
                                {editPubContent.trim()
                                  ? tr('Wird ersetzt', 'Will replace')
                                  : tr('Unverändert', 'Unchanged')}
                              </span>
                            </div>
                            <p className="mt-1 text-[11px] font-mono text-slate-600 dark:text-slate-400 truncate">
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
                              className="px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded cursor-pointer whitespace-nowrap"
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
                                className="text-xs text-slate-500 dark:text-slate-400 hover:text-red-700 dark:hover:text-red-300 cursor-pointer"
                              >
                                {tr('Zurücksetzen', 'Reset')}
                              </button>
                            )}
                          </div>
                        </div>

                        {/* Edit Slot 3: signed cert */}
                        <div
                          className={`border rounded-md p-3 flex flex-col justify-between gap-2.5 ${
                            canUploadSignedCert
                              ? 'border-blue-200 dark:border-blue-800/70 bg-white dark:bg-slate-900'
                              : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/60'
                          }`}
                        >
                          <div>
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100">
                                3. zertifikat-cert.pub
                              </span>
                              <span
                                className={`text-[11px] font-medium ${
                                  editRemoveCert
                                    ? 'text-red-700 dark:text-red-400'
                                    : editCertContent.trim()
                                      ? 'text-blue-700 dark:text-blue-400'
                                      : 'text-slate-500 dark:text-slate-400'
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
                                      : !canUploadSignedCert
                                        ? tr('Upload gesperrt', 'Upload disabled')
                                        : tr('Nicht vorhanden', 'Not set')}
                              </span>
                            </div>
                            <p className="mt-1 text-[11px] font-mono text-slate-600 dark:text-slate-400 truncate">
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
                                    : canUploadSignedCert
                                      ? tr(
                                          'Optionales CA-Zertifikat nachreichen',
                                          'Optionally add a signed CA certificate'
                                        )
                                      : tr(
                                          'Upload eigener cert.pub durch Gruppenrichtlinie gesperrt',
                                          'Uploading own cert.pub disabled by group policy'
                                        )}
                            </p>
                          </div>
                          <div className="flex flex-wrap items-center gap-2">
                            {canUploadSignedCert ? (
                              <>
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
                                  className="px-2.5 py-1 text-xs font-medium text-blue-800 dark:text-blue-300 bg-blue-50 dark:bg-blue-950/40 hover:bg-blue-100 dark:hover:bg-blue-900/50 rounded cursor-pointer whitespace-nowrap"
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
                                    className="text-xs text-slate-500 dark:text-slate-400 hover:text-red-700 dark:hover:text-red-300 cursor-pointer"
                                  >
                                    {tr('Zurücksetzen', 'Reset')}
                                  </button>
                                )}
                              </>
                            ) : (
                              <span className="inline-flex items-center gap-1 text-[11px] text-slate-500 dark:text-slate-400">
                                <Lock className="w-3 h-3" />
                                {tr('Nur über CA-Signierung', 'Via CA signing only')}
                              </span>
                            )}
                            {hasCert && !editCertContent.trim() && (
                              <button
                                type="button"
                                onClick={() => setEditRemoveCert((v) => !v)}
                                className={`text-xs cursor-pointer ${
                                  editRemoveCert
                                    ? 'text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-slate-100 font-medium'
                                    : 'text-red-700 dark:text-red-400 hover:text-red-900 dark:hover:text-red-300'
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
                        <div className="grid grid-cols-1 gap-3 pt-2 border-t border-slate-200 dark:border-slate-800">
                          {canUploadSignedCert && (
                            <div>
                              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
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
                                className="w-full px-3 py-2 text-xs font-mono bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                              />
                            </div>
                          )}
                          <div>
                            <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
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
                              className="w-full px-3 py-2 text-xs font-mono bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                            />
                          </div>
                          <div>
                            <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
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
                              className="w-full px-3 py-2 text-xs font-mono bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                            />
                          </div>
                        </div>
                      )}

                      <div className="flex flex-wrap items-center justify-end gap-2 pt-2 border-t border-slate-200 dark:border-slate-800">
                        <button
                          type="button"
                          onClick={cancelEdit}
                          disabled={editSaving}
                          className="px-3.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md transition-colors cursor-pointer"
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
                    <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-x-6 gap-y-3 pt-4 border-t border-slate-200 dark:border-slate-800 text-xs">
                      <div>
                        <dt className="text-slate-500 dark:text-slate-400">{tr('Key-ID & Seriennummer', 'Key ID & Serial')}</dt>
                        <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 tabular-nums">
                          {m.keyId || '—'} · #{m.serial}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-slate-500 dark:text-slate-400">
                          {tr('Erlaubte Principals (SSH-User)', 'Allowed Principals (SSH Users)')}
                        </dt>
                        <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5">
                          {m.principals.length > 0 ? m.principals.join(', ') : tr('(alle)', '(all)')}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-slate-500 dark:text-slate-400">{tr('Gültig ab', 'Valid From')}</dt>
                        <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 tabular-nums">
                          {formatDateTime(m.validAfter)}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-slate-500 dark:text-slate-400">{tr('Gültig bis', 'Valid Until')}</dt>
                        <dd
                          className={`font-mono mt-0.5 tabular-nums ${
                            m.isExpired ? 'text-red-700 dark:text-red-400 font-semibold' : 'text-slate-900 dark:text-slate-100'
                          }`}
                        >
                          {formatDateTime(m.validBefore)}
                        </dd>
                      </div>
                      <div className="sm:col-span-2">
                        <dt className="text-slate-500 dark:text-slate-400">
                          {tr(
                            `Schlüssel-Fingerabdruck (${m.pubKeyAlgorithm})`,
                            `Key Fingerprint (${m.pubKeyAlgorithm})`
                          )}
                        </dt>
                        <dd className="font-mono text-slate-800 dark:text-slate-200 mt-0.5 truncate" title={m.pubKeyFingerprint}>
                          {m.pubKeyFingerprint}
                        </dd>
                      </div>
                      <div className="sm:col-span-2">
                        <dt className="text-slate-500 dark:text-slate-400">
                          {tr('Signierende CA (TrustedUserCAKeys)', 'Signing CA (TrustedUserCAKeys)')}
                        </dt>
                        <dd className="font-mono text-slate-800 dark:text-slate-200 mt-0.5 truncate" title={m.caFingerprint}>
                          {m.caFingerprint}
                        </dd>
                      </div>
                    </dl>
                  ) : (
                    <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-x-6 gap-y-3 pt-4 border-t border-slate-200 dark:border-slate-800 text-xs">
                      <div>
                        <dt className="text-slate-500 dark:text-slate-400">{tr('Anmeldemodus', 'Auth Mode')}</dt>
                        <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5">
                          {tr('SSH-Schlüsselpaar (authorized_keys)', 'SSH Keypair (authorized_keys)')}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-slate-500 dark:text-slate-400">{tr('Schlüsselkommentar', 'Key Comment')}</dt>
                        <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5">
                          {m.keyId || '—'}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-slate-500 dark:text-slate-400">{tr('Privatschlüssel-Format', 'Private Key Format')}</dt>
                        <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5">
                          {m.privateKeyFormat}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-slate-500 dark:text-slate-400">{tr('Algorithmus', 'Algorithm')}</dt>
                        <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5">
                          {m.pubKeyAlgorithm}
                        </dd>
                      </div>
                      <div className="sm:col-span-4">
                        <dt className="text-slate-500 dark:text-slate-400">{tr('Schlüssel-Fingerabdruck', 'Key Fingerprint')}</dt>
                        <dd className="font-mono text-slate-800 dark:text-slate-200 mt-0.5 truncate" title={m.pubKeyFingerprint}>
                          {m.pubKeyFingerprint}
                        </dd>
                      </div>
                    </dl>
                  )}

                  {renderAutoRenewBanner(cert, isOwner || isAdmin)}

                  {m.warnings.length > 0 && (
                    <div className="pt-3 border-t border-slate-200 dark:border-slate-800 space-y-1">
                      {m.warnings.map((w, idx) => (
                        <p key={idx} className="text-xs text-amber-800 dark:text-amber-300 flex items-start gap-1.5">
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
        </>
      )}

      {isAdmin && activeViewTab === 'all' && (
        <section className="space-y-5">
          {/* Security Notice */}
          <div className="flex items-start gap-3 px-4 py-3 rounded-md bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-300">
            <Shield className="w-4 h-4 text-blue-700 dark:text-blue-400 shrink-0 mt-0.5" />
            <div className="space-y-0.5">
              <p className="font-medium text-slate-900 dark:text-slate-100">
                {tr(
                  'Administrationsübersicht aller Benutzer-Zertifikate (Privatschlüssel geschützt)',
                  'Administrator Overview of All User Certificates (Private Keys Protected)'
                )}
              </p>
              <p className="text-slate-600 dark:text-slate-400">
                {tr(
                  'Private Schlüssel und Passwörter anderer Benutzer werden niemals angezeigt oder übertragen. Fremde Zertifikate können hier eingesehen, durchsucht, gefiltert und bei Bedarf gelöscht werden — eine Bearbeitung oder SSH-Nutzung fremder, nicht geteilter Schlüssel ist gesperrt.',
                  'Private keys and passphrases of other users are never exposed or transmitted. Other users’ certificates can be inspected, searched, filtered, and deleted here — editing or using unshared keys for SSH is blocked.'
                )}
              </p>
            </div>
          </div>

          {/* Search & Filter Controls */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4 space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
              <div className="md:col-span-6 relative">
                <label htmlFor="admin-cert-search" className="sr-only">
                  {tr('Zertifikate durchsuchen', 'Search certificates')}
                </label>
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  id="admin-cert-search"
                  type="text"
                  value={adminSearch}
                  onChange={(e) => setAdminSearch(e.target.value)}
                  placeholder={tr(
                    'Suchen nach Name, Benutzer, Key-ID, Principal, Fingerabdruck, Algorithmus...',
                    'Search by name, user, Key ID, principal, fingerprint, algorithm...'
                  )}
                  className="w-full pl-9 pr-8 py-2 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
                {adminSearch && (
                  <button
                    type="button"
                    onClick={() => setAdminSearch('')}
                    aria-label={tr('Suche leeren', 'Clear search')}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>

              <div className="md:col-span-3">
                <label htmlFor="admin-cert-owner-filter" className="sr-only">
                  {tr('Nach Benutzer filtern', 'Filter by owner')}
                </label>
                <SearchableSelect
                  id="admin-cert-owner-filter"
                  value={adminOwnerFilter}
                  onChange={setAdminOwnerFilter}
                  ariaLabel={tr('Nach Benutzer filtern', 'Filter by owner')}
                  searchPlaceholder={tr('Benutzer filtern...', 'Filter user...')}
                  options={[
                    {
                      value: 'all',
                      label: tr(
                        `Alle Benutzer (${adminCertificates.length})`,
                        `All Users (${adminCertificates.length})`
                      ),
                    },
                    {
                      value: '__others__',
                      label: tr(
                        `Nur fremde Benutzer (${otherUsersCertCount})`,
                        `Other Users Only (${otherUsersCertCount})`
                      ),
                    },
                    {
                      value: '__mine__',
                      label: tr(
                        `Nur eigene (${ownAdminCertCount})`,
                        `Own Only (${ownAdminCertCount})`
                      ),
                    },
                    ...adminOwnerOptions.map((o) => ({
                      value: o.userId,
                      label: `${o.username}${o.userId === user.id ? tr(' (ich)', ' (me)') : ''} (${o.count})`,
                      group: tr('Einzelner Benutzer', 'Specific User'),
                      searchText: o.username,
                    })),
                  ]}
                />
              </div>

              <div className="md:col-span-3">
                <label htmlFor="admin-cert-type-filter" className="sr-only">
                  {tr('Nach Typ oder Status filtern', 'Filter by type or status')}
                </label>
                <SearchableSelect
                  id="admin-cert-type-filter"
                  value={adminTypeFilter}
                  ariaLabel={tr('Nach Typ oder Status filtern', 'Filter by type or status')}
                  searchPlaceholder={tr('Typ oder Status filtern...', 'Filter type or status...')}
                  onChange={(val) =>
                    setAdminTypeFilter(
                      val as
                        | 'all'
                        | 'cert'
                        | 'keypair'
                        | 'expired'
                        | 'encrypted'
                        | 'shared'
                    )
                  }
                  options={[
                    { value: 'all', label: tr('Alle Typen & Status', 'All Types & Statuses') },
                    {
                      value: 'cert',
                      label: tr('3-Dateien-Zertifikat (mit CA)', '3-File Certificate (with CA)'),
                    },
                    {
                      value: 'keypair',
                      label: tr('Schlüsselpaar (2 Dateien)', 'Keypair (2 Files)'),
                    },
                    { value: 'expired', label: tr('Abgelaufen', 'Expired') },
                    { value: 'encrypted', label: tr('Passwortgeschützt', 'Passphrase-protected') },
                    { value: 'shared', label: tr('Geteilt', 'Shared') },
                  ]}
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-100 dark:border-slate-800/70 text-xs text-slate-600 dark:text-slate-400">
              <div className="flex flex-wrap items-center gap-3">
                <span className="tabular-nums">
                  {tr(
                    `${filteredAdminCertificates.length} von ${adminCertificates.length} Zertifikaten angezeigt (${otherUsersCertCount} von anderen Benutzern)`,
                    `Showing ${filteredAdminCertificates.length} of ${adminCertificates.length} certificates (${otherUsersCertCount} owned by other users)`
                  )}
                </span>
                {filteredAdminCertificates.length > 0 && (
                  <>
                    <span aria-hidden="true" className="text-slate-300">·</span>
                    <button
                      type="button"
                      onClick={() => {
                        const visibleIds = filteredAdminCertificates.map((c) => c.id);
                        const allVisibleSelected = visibleIds.every((id) =>
                          selectedAdminIds.includes(id)
                        );
                        if (allVisibleSelected) {
                          setSelectedAdminIds((prev) =>
                            prev.filter((id) => !visibleIds.includes(id))
                          );
                        } else {
                          setSelectedAdminIds((prev) =>
                            Array.from(new Set([...prev, ...visibleIds]))
                          );
                        }
                      }}
                      className="text-xs font-medium text-blue-700 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300 cursor-pointer whitespace-nowrap"
                    >
                      {filteredAdminCertificates.every((c) => selectedAdminIds.includes(c.id))
                        ? tr('Sichtbare abwählen', 'Deselect visible')
                        : tr(
                            `Alle sichtbaren auswählen (${filteredAdminCertificates.length})`,
                            `Select all visible (${filteredAdminCertificates.length})`
                          )}
                    </button>
                  </>
                )}
              </div>
              <div className="flex items-center gap-3">
                {hasActiveAdminFilters && (
                  <button
                    type="button"
                    onClick={() => {
                      setAdminSearch('');
                      setAdminOwnerFilter('all');
                      setAdminTypeFilter('all');
                    }}
                    className="inline-flex items-center gap-1 text-xs font-medium text-blue-700 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300 cursor-pointer"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    {tr('Filter zurücksetzen', 'Reset filters')}
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => void loadAdminCertificates()}
                  disabled={adminLoading}
                  className="text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 disabled:opacity-50 cursor-pointer"
                >
                  {adminLoading ? tr('Wird geladen...', 'Loading...') : tr('Aktualisieren', 'Refresh')}
                </button>
              </div>
            </div>
          </div>

          {/* Batch CA Signing Bar */}
          {selectedAdminIds.length > 0 && (
            <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 rounded-lg bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800/70">
              <div className="flex items-center gap-2 text-xs text-blue-950 dark:text-blue-200 font-medium">
                <FileSignature className="w-4 h-4 text-blue-700 dark:text-blue-400 shrink-0" />
                <span>
                  {tr(
                    `${selectedAdminIds.length} Zertifikat(e) für CA-Sammelsignierung ausgewählt`,
                    `${selectedAdminIds.length} certificate(s) selected for CA batch signing`
                  )}
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => setSelectedAdminIds([])}
                  className="px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                >
                  {tr('Auswahl aufheben', 'Clear selection')}
                </button>
                {(() => {
                  const selectedAdminCerts = adminCertificates.filter((c) =>
                    selectedAdminIds.includes(c.id)
                  );
                  const activeAutoRenewAdmin = selectedAdminCerts.filter(
                    (c) => c.autoRenew?.enabled
                  );
                  return (
                    <>
                      <button
                        type="button"
                        onClick={() => openSignModal(selectedAdminCerts)}
                        className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                      >
                        <FileSignature className="w-3.5 h-3.5" />
                        {tr(
                          `Ausgewählte mit CA signieren (${selectedAdminIds.length})`,
                          `Sign Selected with CA (${selectedAdminIds.length})`
                        )}
                      </button>
                      {activeAutoRenewAdmin.length > 0 && (
                        <button
                          type="button"
                          disabled={batchRevokingAutoRenew}
                          onClick={() => void handleBatchRevokeAutoRenew(activeAutoRenewAdmin)}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-950/40 hover:bg-red-100 dark:hover:bg-red-900/50 border border-red-200 dark:border-red-800/70 rounded-md transition-colors cursor-pointer disabled:opacity-50 whitespace-nowrap"
                        >
                          <Ban className="w-3.5 h-3.5" />
                          {tr(
                            `Auto-Erneuerung widerrufen (${activeAutoRenewAdmin.length})`,
                            `Revoke Auto-Renew (${activeAutoRenewAdmin.length})`
                          )}
                        </button>
                      )}
                    </>
                  );
                })()}
              </div>
            </div>
          )}

          {adminLoadError && (
            <div role="alert" className="px-4 py-3 rounded-md bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800/70 text-sm text-red-800 dark:text-red-300">
              {adminLoadError}
            </div>
          )}

          {adminLoading && adminCertificates.length === 0 ? (
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-6 py-12 text-center text-sm text-slate-500 dark:text-slate-400">
              {tr('Benutzer-Zertifikate werden geladen...', 'Loading user certificates...')}
            </div>
          ) : filteredAdminCertificates.length === 0 ? (
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-6 py-12 text-center">
              <KeyRound className="w-7 h-7 text-slate-400 mx-auto mb-3" />
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {adminCertificates.length === 0
                  ? tr('Keine Benutzer-Zertifikate vorhanden', 'No user certificates stored')
                  : tr('Keine passenden Zertifikate gefunden', 'No matching certificates found')}
              </h3>
              <p className="text-sm text-slate-500 dark:text-slate-400 mt-1 max-w-md mx-auto">
                {adminCertificates.length === 0
                  ? tr(
                      'Es wurden bisher von keinem Benutzer SSH-Schlüssel oder Zertifikate hinterlegt.',
                      'No users have uploaded or generated SSH keys or certificates yet.'
                    )
                  : tr(
                      'Passen Sie Suchbegriff, Benutzer- oder Statusfilter an.',
                      'Try adjusting your search query, user filter, or status filter.'
                    )}
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredAdminCertificates.map((cert) => {
                const m = cert.metadata;
                const hasCert = m.hasCertificate !== false && Boolean(cert.certFileName);
                const isOwner = cert.userId === user.id;
                const isSelectedAdmin = selectedAdminIds.includes(cert.id);
                const shareLabel = formatShareSummary(
                  cert.sharedWithAll,
                  cert.sharedWithUserIds,
                  locale
                );
                const isConfirmingDelete = confirmAdminDeleteId === cert.id;
                const isDeletingThis = adminDeletingId === cert.id;

                return (
                  <article
                    key={cert.id}
                    className={`bg-white dark:bg-slate-900 border rounded-lg p-6 space-y-4 transition-colors ${
                      isSelectedAdmin ? 'border-blue-400 ring-1 ring-blue-100 dark:ring-blue-900/40' : 'border-slate-200 dark:border-slate-800'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                      <div className="flex items-start gap-3 min-w-0">
                        <input
                          type="checkbox"
                          checked={isSelectedAdmin}
                          onChange={() => toggleAdminSelection(cert.id)}
                          aria-label={tr(
                            `Zertifikat ${cert.name} für Sammelsignierung auswählen`,
                            `Select certificate ${cert.name} for batch signing`
                          )}
                          className="mt-1 w-4 h-4 rounded border-slate-300 dark:border-slate-700 text-blue-700 dark:text-blue-400 focus:ring-blue-600 cursor-pointer shrink-0"
                        />
                        <div className="min-w-0">
                          <div className="flex items-center gap-2.5 flex-wrap">
                            <h3 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
                              {cert.name}
                            </h3>
                          <span
                            className={`text-xs font-medium px-2 py-0.5 rounded border ${
                              isOwner
                                ? 'bg-blue-50 dark:bg-blue-950/40 text-blue-800 dark:text-blue-300 border-blue-200 dark:border-blue-800/70'
                                : 'bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 border-slate-200 dark:border-slate-800'
                            }`}
                          >
                            {isOwner
                              ? tr(
                                  `Eigentümer: ${cert.ownerUsername || user.username} (ich)`,
                                  `Owner: ${cert.ownerUsername || user.username} (me)`
                                )
                              : tr(
                                  `Benutzer: ${cert.ownerUsername || 'Unbekannt'}`,
                                  `User: ${cert.ownerUsername || 'Unknown'}`
                                )}
                          </span>
                          {hasCert ? (
                            m.isExpired ? (
                              <span className="inline-flex items-center gap-1 text-xs font-medium text-red-700 dark:text-red-400">
                                <AlertTriangle className="w-3.5 h-3.5" />
                                {tr('Abgelaufen', 'Expired')}
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-700 dark:text-emerald-400">
                                <CheckCircle2 className="w-3.5 h-3.5" />
                                {tr('3-Dateien-Verbund', '3-file bundle')}
                              </span>
                            )
                          ) : (
                            <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-700 dark:text-emerald-400">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              {tr('Schlüsselpaar (2 Dateien)', 'Keypair (2 files)')}
                            </span>
                          )}
                          <span aria-hidden="true" className="text-slate-300">·</span>
                          <span
                            className={`text-xs ${
                              cert.sharedWithAll || cert.sharedWithUserIds.length > 0
                                ? 'text-blue-800 dark:text-blue-300 font-medium'
                                : 'text-slate-500 dark:text-slate-400'
                            }`}
                          >
                            {shareLabel}
                          </span>
                          {m.privateKeyEncrypted && (
                            <>
                              <span aria-hidden="true" className="text-slate-300">·</span>
                              <span
                                className={`inline-flex items-center gap-1 text-xs font-medium ${
                                  cert.hasStoredPassphrase ? 'text-emerald-700 dark:text-emerald-400' : 'text-amber-800 dark:text-amber-300'
                                }`}
                              >
                                <Lock className="w-3 h-3" />
                                {cert.hasStoredPassphrase
                                  ? tr('Passwort hinterlegt', 'Passphrase stored')
                                  : tr('Passwortgeschützt', 'Passphrase protected')}
                              </span>
                            </>
                          )}
                        </div>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono">
                          {cert.privateKeyFileName} · {cert.publicKeyFileName}
                          {hasCert
                            ? ` · ${cert.certFileName}`
                            : tr(' · (ohne zertifikat-cert.pub)', ' · (no zertifikat-cert.pub)')}
                          {' · '}
                          {tr('Hinterlegt:', 'Uploaded:')} {formatDateTime(cert.uploadedAt)}
                        </p>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center gap-2 shrink-0">
                        <button
                          type="button"
                          onClick={() => openSignModal([cert])}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-800 dark:text-blue-300 bg-blue-50 dark:bg-blue-950/40 hover:bg-blue-100 dark:hover:bg-blue-900/50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                        >
                          <FileSignature className="w-3.5 h-3.5" />
                          {tr('Mit CA signieren', 'Sign with CA')}
                        </button>
                        {isOwner ? (
                          <>
                            {canUpload && (
                              <button
                                type="button"
                                onClick={() => {
                                  setActiveViewTab('mine');
                                  startEdit(cert);
                                }}
                                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                              >
                                <Pencil className="w-3.5 h-3.5" />
                                {tr('Bearbeiten', 'Edit')}
                              </button>
                            )}
                            {canShare && (
                              <button
                                type="button"
                                onClick={() => setSharingCert(cert)}
                                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-700 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-950/50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                              >
                                <Share2 className="w-3.5 h-3.5" />
                                {tr('Teilen', 'Share')}
                              </button>
                            )}
                          </>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400 mr-1 whitespace-nowrap">
                            <Lock className="w-3 h-3 text-slate-400" />
                            {tr('Schreibgeschützt', 'Read-only')}
                          </span>
                        )}

                        {isConfirmingDelete ? (
                          <div className="inline-flex items-center gap-1.5">
                            <button
                              type="button"
                              onClick={() => void handleAdminDelete(cert)}
                              disabled={isDeletingThis}
                              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-red-700 hover:bg-red-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                              {isDeletingThis
                                ? tr('Wird gelöscht...', 'Deleting...')
                                : tr('Wirklich löschen?', 'Confirm Delete')}
                            </button>
                            <button
                              type="button"
                              onClick={() => setConfirmAdminDeleteId(null)}
                              disabled={isDeletingThis}
                              className="px-2.5 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                            >
                              {tr('Abbrechen', 'Cancel')}
                            </button>
                          </div>
                        ) : (
                          <button
                            type="button"
                            onClick={() => setConfirmAdminDeleteId(cert.id)}
                            disabled={isDeletingThis}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-700 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                            {tr('Löschen', 'Delete')}
                          </button>
                        )}
                      </div>
                    </div>

                    {hasCert ? (
                      <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-x-6 gap-y-3 pt-4 border-t border-slate-200 dark:border-slate-800 text-xs">
                        <div>
                          <dt className="text-slate-500 dark:text-slate-400">{tr('Key-ID & Seriennummer', 'Key ID & Serial')}</dt>
                          <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 tabular-nums">
                            {m.keyId || '—'} · #{m.serial}
                          </dd>
                        </div>
                        <div>
                          <dt className="text-slate-500 dark:text-slate-400">
                            {tr('Erlaubte Principals (SSH-User)', 'Allowed Principals (SSH Users)')}
                          </dt>
                          <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5">
                            {m.principals.length > 0 ? m.principals.join(', ') : tr('(alle)', '(all)')}
                          </dd>
                        </div>
                        <div>
                          <dt className="text-slate-500 dark:text-slate-400">{tr('Gültig ab', 'Valid From')}</dt>
                          <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 tabular-nums">
                            {formatDateTime(m.validAfter)}
                          </dd>
                        </div>
                        <div>
                          <dt className="text-slate-500 dark:text-slate-400">{tr('Gültig bis', 'Valid Until')}</dt>
                          <dd
                            className={`font-mono mt-0.5 tabular-nums ${
                              m.isExpired ? 'text-red-700 dark:text-red-400 font-semibold' : 'text-slate-900 dark:text-slate-100'
                            }`}
                          >
                            {formatDateTime(m.validBefore)}
                          </dd>
                        </div>
                        <div className="sm:col-span-2">
                          <dt className="text-slate-500 dark:text-slate-400">
                            {tr(
                              `Schlüssel-Fingerabdruck (${m.pubKeyAlgorithm})`,
                              `Key Fingerprint (${m.pubKeyAlgorithm})`
                            )}
                          </dt>
                          <dd className="font-mono text-slate-800 dark:text-slate-200 mt-0.5 truncate" title={m.pubKeyFingerprint}>
                            {m.pubKeyFingerprint}
                          </dd>
                        </div>
                        <div className="sm:col-span-2">
                          <dt className="text-slate-500 dark:text-slate-400">
                            {tr('Signierende CA (TrustedUserCAKeys)', 'Signing CA (TrustedUserCAKeys)')}
                          </dt>
                          <dd className="font-mono text-slate-800 dark:text-slate-200 mt-0.5 truncate" title={m.caFingerprint}>
                            {m.caFingerprint}
                          </dd>
                        </div>
                      </dl>
                    ) : (
                      <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-x-6 gap-y-3 pt-4 border-t border-slate-200 dark:border-slate-800 text-xs">
                        <div>
                          <dt className="text-slate-500 dark:text-slate-400">{tr('Anmeldemodus', 'Auth Mode')}</dt>
                          <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5">
                            {tr('SSH-Schlüsselpaar (authorized_keys)', 'SSH Keypair (authorized_keys)')}
                          </dd>
                        </div>
                        <div>
                          <dt className="text-slate-500 dark:text-slate-400">{tr('Schlüsselkommentar', 'Key Comment')}</dt>
                          <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5">
                            {m.keyId || '—'}
                          </dd>
                        </div>
                        <div>
                          <dt className="text-slate-500 dark:text-slate-400">{tr('Privatschlüssel-Format', 'Private Key Format')}</dt>
                          <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5">
                            {m.privateKeyFormat}
                          </dd>
                        </div>
                        <div>
                          <dt className="text-slate-500 dark:text-slate-400">{tr('Algorithmus', 'Algorithm')}</dt>
                          <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5">
                            {m.pubKeyAlgorithm}
                          </dd>
                        </div>
                        <div className="sm:col-span-4">
                          <dt className="text-slate-500 dark:text-slate-400">{tr('Schlüssel-Fingerabdruck', 'Key Fingerprint')}</dt>
                          <dd className="font-mono text-slate-800 dark:text-slate-200 mt-0.5 truncate" title={m.pubKeyFingerprint}>
                            {m.pubKeyFingerprint}
                          </dd>
                        </div>
                      </dl>
                    )}

                    {renderAutoRenewBanner(cert, true)}

                    {m.warnings.length > 0 && (
                      <div className="pt-3 border-t border-slate-200 dark:border-slate-800 space-y-1">
                        {m.warnings.map((w, idx) => (
                          <p key={idx} className="text-xs text-amber-800 dark:text-amber-300 flex items-start gap-1.5">
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
      )}

      {showGenerateModal && canGenerateTest && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="generate-cert-modal-title"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 dark:bg-black/70 backdrop-blur-[1px]"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeGenerateModal();
          }}
        >
          <form
            onSubmit={handleGenerateCertificateSubmit}
            className="w-full max-w-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xl overflow-hidden"
          >
            <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <Wand2 className="w-4 h-4 text-blue-700 dark:text-blue-400 shrink-0" />
                <h2 id="generate-cert-modal-title" className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
                  {tr('Zertifikat erzeugen (Ed25519)', 'Generate Certificate (Ed25519)')}
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
                  'Erzeugt ein neues Ed25519-Schlüsselpaar (zertifikat und zertifikat.pub).',
                  'Generates a new Ed25519 keypair (zertifikat and zertifikat.pub).'
                )}
              </p>

              {genError && (
                <div role="alert" className="px-3 py-2 rounded-md bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800/70 text-xs text-red-800 dark:text-red-300">
                  {genError}
                </div>
              )}

              <div>
                <label htmlFor="gen-cert-name" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  {tr('Bezeichnung', 'Label')}
                </label>
                <input
                  ref={genNameInputRef}
                  id="gen-cert-name"
                  type="text"
                  value={genName}
                  onChange={(e) => {
                    setGenName(e.target.value);
                    setGenConfirmOverwrite(false);
                  }}
                  maxLength={64}
                  placeholder={`${user.username}-ed25519`}
                  className={`w-full px-3 py-2 text-sm border rounded-md focus:outline-none focus:ring-2 ${
                    matchingGenCert
                      ? 'border-amber-400 dark:border-amber-700/80 bg-amber-50/40 dark:bg-amber-950/30 focus:ring-amber-500'
                      : 'border-slate-300 dark:border-slate-700 focus:ring-blue-600'
                  }`}
                />
                {matchingGenCert && (
                  <p className="mt-1.5 flex items-start gap-1.5 text-xs text-amber-800 dark:text-amber-300">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
                    <span>
                      {tr(
                        `Der Name „${matchingGenCert.name}“ ist bereits vergeben.`,
                        `The name "${matchingGenCert.name}" is already taken.`
                      )}
                    </span>
                  </p>
                )}
              </div>

              <div>
                <label htmlFor="gen-cert-pass" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  {requireCertPassphrase
                    ? tr('Zertifikat-Passwort (erforderlich)', 'Certificate Passphrase (required)')
                    : tr('Zertifikat-Passwort (optional)', 'Certificate Passphrase (optional)')}
                </label>
                <input
                  id="gen-cert-pass"
                  type="password"
                  autoComplete="new-password"
                  autoFocus
                  required={requireCertPassphrase}
                  value={genPassphrase}
                  onChange={(e) => {
                    setGenPassphrase(e.target.value);
                    if (!e.target.value) {
                      setGenPassphraseConfirm('');
                      setGenStorePassphrase(false);
                    }
                  }}
                  placeholder={
                    requireCertPassphrase
                      ? tr('Passwort für privaten Schlüssel eingeben...', 'Enter passphrase for private key...')
                      : tr('Leer lassen für Zertifikat ohne Passwort', 'Leave empty for certificate without passphrase')
                  }
                  className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                  {requireCertPassphrase
                    ? tr(
                        'Ihre Benutzergruppe schreibt ein Passwort zum Schutz des privaten Schlüssels vor.',
                        'Your user group requires a passphrase to protect the private key.'
                      )
                    : tr(
                        'Wenn das Feld leer bleibt, wird das Zertifikat unverschlüsselt (ohne Passwort) erzeugt.',
                        'If left blank, the certificate will be generated unencrypted (without a passphrase).'
                      )}
                </p>
                {(requireCertPassphrase || genPassphrase.length > 0) && (
                  <PasswordStrengthHint password={genPassphrase} compact />
                )}
              </div>

              {genPassphrase.length > 0 && (
                <div>
                  <label htmlFor="gen-cert-pass-confirm" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    {tr('Passwort bestätigen', 'Confirm Passphrase')}
                  </label>
                  <input
                    id="gen-cert-pass-confirm"
                    type="password"
                    autoComplete="new-password"
                    required
                    value={genPassphraseConfirm}
                    onChange={(e) => setGenPassphraseConfirm(e.target.value)}
                    placeholder={tr('Passwort erneut eingeben...', 'Re-enter passphrase...')}
                    className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                  />
                </div>
              )}

              {canUpload && genPassphrase.length > 0 && (
                canStoreCertPassphrase ? (
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
                          'Zertifikat-Passwort verschlüsselt auf dem Server speichern',
                          'Store certificate passphrase encrypted on server'
                        )}
                      </span>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                        {tr(
                          'Ohne Haken wird das Passwort nicht gespeichert und bei jeder SSH-Nutzung abgefragt.',
                          'If unchecked, the passphrase is not stored and will be prompted on each SSH use.'
                        )}
                      </p>
                    </div>
                  </label>
                ) : (
                  <div className="px-3 py-2.5 rounded-md bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-800 text-xs text-slate-600 dark:text-slate-400 flex items-start gap-2">
                    <Lock className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400 shrink-0 mt-0.5" />
                    <span>
                      {tr(
                        'Das Speichern von Zertifikats-Passwörtern auf dem Server ist für Ihre Benutzergruppe deaktiviert. Das Passwort wird stattdessen bei jeder SSH-Nutzung abgefragt.',
                        'Storing certificate passphrases on the server is disabled for your user group. You will be prompted for the passphrase on each SSH use.'
                      )}
                    </span>
                  </div>
                )
              )}
              {genConfirmOverwrite && matchingGenCert && (
                <div
                  role="alert"
                  className="px-3.5 py-3 rounded-md bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-700/80 text-xs text-amber-950 dark:text-amber-200 space-y-1"
                >
                  <div className="flex items-center gap-2 font-semibold text-amber-900 dark:text-amber-200">
                    <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
                    <span>
                      {tr(
                        `Bestehendes Zertifikat „${matchingGenCert.name}“ überschreiben?`,
                        `Overwrite existing certificate "${matchingGenCert.name}"?`
                      )}
                    </span>
                  </div>
                  <p className="text-amber-900/90 dark:text-amber-200/90 leading-relaxed">
                    {tr(
                      'Ein Zertifikat mit diesem Namen existiert bereits in Ihrem Konto. Soll es wirklich durch das neu erzeugte Zertifikat überschrieben werden?',
                      'A certificate with this name already exists in your account. Do you really want to overwrite it with the newly generated certificate?'
                    )}
                  </p>
                </div>
              )}
            </div>

            <div className="px-5 py-3.5 bg-slate-50 dark:bg-slate-800/60 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end gap-2">
              {genConfirmOverwrite && matchingGenCert ? (
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
                      ? tr('Erzeuge Zertifikat...', 'Generating certificate...')
                      : tr('Zertifikat erzeugen', 'Generate Certificate')}
                  </button>
                </>
              )}
            </div>
          </form>
        </div>
      )}

      {confirmUploadOverwriteCert && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="overwrite-upload-cert-title"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 dark:bg-black/70 backdrop-blur-[1px]"
          onClick={(e) => {
            if (e.target === e.currentTarget && !saving) setConfirmUploadOverwriteCert(null);
          }}
        >
          <div className="w-full max-w-md bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
                <h2
                  id="overwrite-upload-cert-title"
                  className="font-display text-base font-semibold text-slate-900 dark:text-slate-100"
                >
                  {tr('Bestehendes Zertifikat überschreiben?', 'Overwrite Existing Certificate?')}
                </h2>
              </div>
              <button
                type="button"
                onClick={() => setConfirmUploadOverwriteCert(null)}
                disabled={saving}
                aria-label={tr('Schließen', 'Close')}
                className="p-1 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 rounded cursor-pointer disabled:opacity-50"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-3 text-sm text-slate-700 dark:text-slate-300">
              <p>
                {tr(
                  `Ein eigenes Zertifikatspaket mit dem Namen „${confirmUploadOverwriteCert.name}“ existiert bereits.`,
                  `You already have a certificate bundle named "${confirmUploadOverwriteCert.name}".`
                )}
              </p>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                {tr(
                  'Möchten Sie das bestehende Zertifikat wirklich mit den neuen Dateien überschreiben? Der bisherige Schlüssel wird dabei dauerhaft ersetzt.',
                  'Do you really want to overwrite the existing certificate with the new files? The previous key will be permanently replaced.'
                )}
              </p>
            </div>

            <div className="px-5 py-3.5 bg-slate-50 dark:bg-slate-800/60 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end gap-2">
              <button
                type="button"
                disabled={saving}
                onClick={() => {
                  setConfirmUploadOverwriteCert(null);
                  setTimeout(() => {
                    bundleNameInputRef.current?.focus();
                    bundleNameInputRef.current?.select();
                  }, 0);
                }}
                className="px-4 py-2 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md transition-colors cursor-pointer disabled:opacity-50"
              >
                {tr('Anderen Namen wählen', 'Choose Different Name')}
              </button>
              <button
                type="button"
                disabled={saving}
                onClick={() => performUpload(true)}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-white bg-amber-600 hover:bg-amber-700 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                {saving
                  ? tr('Wird überschrieben...', 'Overwriting...')
                  : tr('Ja, überschreiben', 'Yes, Overwrite')}
              </button>
            </div>
          </div>
        </div>
      )}

      {isAdmin && signingTargets && signingTargets.length > 0 && (() => {
        const selectedCa = selectedSignCa;
        const isBatch = signingTargets.length > 1;
        const singleTarget = !isBatch ? signingTargets[0] : null;
        const foreignCaConflictIdSet = new Set(foreignCaConflicts.map((c) => c.cert.id));
        return (
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="ca-sign-modal-title"
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 dark:bg-black/70 backdrop-blur-[1px]"
            onClick={(e) => {
              if (e.target === e.currentTarget) closeSignModal();
            }}
          >
            <form
              onSubmit={handleSignSubmit}
              className="w-full max-w-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xl overflow-hidden"
            >
              <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3">
                <div className="flex items-center gap-2 min-w-0">
                  <FileSignature className="w-4 h-4 text-blue-700 dark:text-blue-400 shrink-0" />
                  <h2
                    id="ca-sign-modal-title"
                    className="font-display text-base font-semibold text-slate-900 dark:text-slate-100 truncate"
                  >
                    {isBatch
                      ? tr(
                          `Sammelsignierung mit CA (${signingTargets.length} Zertifikate)`,
                          `Batch Sign with CA (${signingTargets.length} Certificates)`
                        )
                      : tr(
                          `Zertifikat mit CA signieren: ${singleTarget?.name || ''}`,
                          `Sign Certificate with CA: ${singleTarget?.name || ''}`
                        )}
                  </h2>
                </div>
                <button
                  type="button"
                  onClick={closeSignModal}
                  disabled={signSubmitting}
                  aria-label={tr('Schließen', 'Close')}
                  className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 cursor-pointer disabled:opacity-50"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-5 space-y-4 max-h-[75vh] overflow-y-auto">
                {/* Target preview */}
                <div className="rounded-md bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 p-3 space-y-1.5">
                  <p className="text-xs font-medium text-slate-800 dark:text-slate-200">
                    {isBatch
                      ? tr(
                          `Ausgewählte Ziel-Zertifikate (${signingTargets.length}):`,
                          `Selected Target Certificates (${signingTargets.length}):`
                        )
                      : tr('Ziel-Zertifikat:', 'Target Certificate:')}
                  </p>
                  <ul className="max-h-28 overflow-y-auto space-y-1 text-xs text-slate-600 dark:text-slate-400">
                    {signingTargets.map((t) => {
                      const isForeign = foreignCaConflictIdSet.has(t.id);
                      return (
                        <li key={t.id} className="flex items-center justify-between gap-2">
                          <span className="font-medium text-slate-900 dark:text-slate-100 truncate">
                            {t.name}{' '}
                            <span className="font-normal text-slate-500 dark:text-slate-400">
                              ({t.ownerUsername || user.username})
                            </span>
                          </span>
                          <span className="inline-flex items-center gap-1.5 shrink-0">
                            {isForeign && (
                              <span
                                title={tr(
                                  'Bestehende zertifikat-cert.pub stammt nicht von der gewählten CA',
                                  'Existing zertifikat-cert.pub was not signed by the selected CA'
                                )}
                                className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-900/40 border border-amber-300 dark:border-amber-700/80 text-amber-900 dark:text-amber-200 font-medium text-[10px]"
                              >
                                <AlertTriangle className="w-3 h-3 text-amber-600 dark:text-amber-400 shrink-0" />
                                {tr('Fremde CA', 'Foreign CA')}
                              </span>
                            )}
                            <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                              {t.metadata.pubKeyAlgorithm}
                            </span>
                          </span>
                        </li>
                      );
                    })}
                  </ul>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 pt-1 border-t border-slate-200 dark:border-slate-800">
                    {tr(
                      'Es wird ausschließlich der öffentliche Schlüssel signiert und das neue zertifikat-cert.pub beim jeweiligen Benutzerpaket hinterlegt. Private Benutzerschlüssel bleiben geschützt.',
                      'Only the public key is signed and the new zertifikat-cert.pub is attached to each user bundle. User private keys remain protected.'
                    )}
                  </p>
                </div>

                {signError && (
                  <div
                    role="alert"
                    className="px-3.5 py-2.5 rounded-md bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800/70 text-xs text-red-800 dark:text-red-300 space-y-1"
                  >
                    <p className="font-medium">{signError}</p>
                    {signPartialErrors.length > 0 && (
                      <ul className="list-disc pl-4 space-y-0.5">
                        {signPartialErrors.map((pe, idx) => (
                          <li key={idx}>
                            {pe.certificateName ? `${pe.certificateName}: ` : ''}
                            {pe.error}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}

                {casLoading && cas.length === 0 ? (
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {tr('Zertifizierungsstellen werden geladen...', 'Loading Certificate Authorities...')}
                  </p>
                ) : cas.length === 0 ? (
                  <div className="px-4 py-3 rounded-md bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/70 text-xs text-amber-900 dark:text-amber-200 flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                    <span>
                      {tr(
                        'Es ist noch keine SSH-CA hinterlegt. Bitte erzeugen oder laden Sie zuerst unter „Administration → CA-Zertifikate“ eine CA (ca + ca.pub) hoch.',
                        'No SSH CA is configured yet. Please create or upload a CA (ca + ca.pub) under "Administration → CA Certificates" first.'
                      )}
                    </span>
                  </div>
                ) : (
                  <>
                    {/* CA selector */}
                    <div>
                      <label
                        htmlFor="sign-ca-select"
                        className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1"
                      >
                        {tr('Zertifizierungsstelle (CA) *', 'Certificate Authority (CA) *')}
                      </label>
                      <SearchableSelect
                        id="sign-ca-select"
                        value={signCaId}
                        ariaLabel={tr('Zertifizierungsstelle (CA)', 'Certificate Authority (CA)')}
                        searchPlaceholder={tr('CA, Schlüsseltyp oder Fingerprint filtern...', 'Filter CA, key type, or fingerprint...')}
                        onChange={(val) => {
                          setSignCaId(val);
                          setSignCaPassphrase('');
                          setSignConfirmForeignCa(false);
                          setSignError(null);
                        }}
                        options={cas.map((ca) => {
                          const lockLabel = ca.hasStoredPassphrase
                            ? tr('Passwort hinterlegt', 'Passphrase stored')
                            : tr('Passwort erforderlich', 'Passphrase required');
                          return {
                            value: ca.id,
                            label: ca.name,
                            triggerLabel: `${ca.name} (${ca.keyType}) · ${lockLabel}`,
                            meta: `${ca.keyType} · ${lockLabel}`,
                            detail: ca.fingerprint,
                            searchText: `${ca.description || ''} ${ca.keyType} ${ca.fingerprint}`,
                          };
                        })}
                      />
                      {selectedCa && (
                        <p className="mt-1 text-[11px] font-mono text-slate-500 dark:text-slate-400 truncate">
                          {selectedCa.fingerprint}
                        </p>
                      )}
                    </div>

                    {/* Foreign-CA overwrite warning */}
                    {selectedCa && foreignCaConflicts.length > 0 && (
                      <div
                        role="alert"
                        className="rounded-md bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-700/80 p-3.5 text-xs text-amber-950 dark:text-amber-200 space-y-2.5"
                      >
                        <div className="flex items-start gap-2">
                          <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                          <div className="space-y-1 min-w-0">
                            <p className="font-semibold text-amber-950 dark:text-amber-200">
                              {foreignCaConflicts.length === 1
                                ? tr(
                                    'Achtung: Bestehende zertifikat-cert.pub stammt von einer anderen CA',
                                    'Warning: Existing zertifikat-cert.pub was signed by a different CA'
                                  )
                                : tr(
                                    `Achtung: ${foreignCaConflicts.length} bestehende zertifikat-cert.pub-Dateien stammen von einer anderen CA`,
                                    `Warning: ${foreignCaConflicts.length} existing zertifikat-cert.pub files were signed by a different CA`
                                  )}
                            </p>
                            <p className="text-amber-900/90 dark:text-amber-200/90 leading-relaxed">
                              {foreignCaConflicts.length === 1
                                ? tr(
                                    `Das vorhandene Zertifikat wurde nicht von der gewählten CA „${selectedCa.name}“ signiert. Durch das Signieren wird die bestehende zertifikat-cert.pub-Datei dauerhaft überschrieben.`,
                                    `The existing certificate was not signed by the selected CA "${selectedCa.name}". Signing will permanently overwrite the existing zertifikat-cert.pub file.`
                                  )
                                : tr(
                                    `Die folgenden Zertifikate wurden nicht von der gewählten CA „${selectedCa.name}“ signiert. Durch die Sammelsignierung werden deren bestehende zertifikat-cert.pub-Dateien dauerhaft überschrieben.`,
                                    `The following certificates were not signed by the selected CA "${selectedCa.name}". Batch signing will permanently overwrite their existing zertifikat-cert.pub files.`
                                  )}
                            </p>
                          </div>
                        </div>

                        <ul className="max-h-28 overflow-y-auto space-y-1 rounded bg-white/80 dark:bg-slate-900/80 border border-amber-200 dark:border-amber-800/70 px-2.5 py-2 text-[11px]">
                          {foreignCaConflicts.map(({ cert, existingFingerprint, matchedCaName }) => (
                            <li key={cert.id} className="flex flex-col gap-0.5">
                              <div className="flex items-center justify-between gap-2">
                                <span className="font-medium text-slate-900 dark:text-slate-100 truncate">
                                  {cert.name}{' '}
                                  <span className="font-normal text-slate-500 dark:text-slate-400">
                                    ({cert.ownerUsername || user.username})
                                  </span>
                                </span>
                                <span className="font-mono text-[10px] text-amber-900 dark:text-amber-200 shrink-0">
                                  {cert.certFileName || 'zertifikat-cert.pub'}
                                </span>
                              </div>
                              <span className="text-[10px] text-amber-900/80 dark:text-amber-200/80 font-mono truncate">
                                {tr('Bisherige CA: ', 'Current CA: ')}
                                {matchedCaName
                                  ? `${matchedCaName}${existingFingerprint ? ` (${existingFingerprint})` : ''}`
                                  : existingFingerprint
                                    ? `${tr('Externe CA', 'External CA')} (${existingFingerprint})`
                                    : tr('Unbekannte / externe CA', 'Unknown / external CA')}
                              </span>
                            </li>
                          ))}
                        </ul>

                        <label className="flex items-start gap-2 pt-1 cursor-pointer select-none">
                          <input
                            type="checkbox"
                            checked={signConfirmForeignCa}
                            onChange={(e) => {
                              setSignConfirmForeignCa(e.target.checked);
                              setSignError(null);
                            }}
                            className="mt-0.5 w-3.5 h-3.5 rounded border-amber-400 dark:border-amber-700/80 text-amber-700 dark:text-amber-400 focus:ring-amber-600 cursor-pointer"
                          />
                          <span className="font-medium text-amber-950 dark:text-amber-200 leading-snug">
                            {foreignCaConflicts.length === 1
                              ? tr(
                                  `Ich bestätige, dass die bestehende zertifikat-cert.pub-Datei trotz abweichender CA mit „${selectedCa.name}“ überschrieben werden soll.`,
                                  `I confirm that the existing zertifikat-cert.pub file should be overwritten using "${selectedCa.name}" despite the different CA.`
                                )
                              : tr(
                                  `Ich bestätige, dass die ${foreignCaConflicts.length} bestehenden zertifikat-cert.pub-Dateien trotz abweichender CA mit „${selectedCa.name}“ überschrieben werden sollen.`,
                                  `I confirm that the ${foreignCaConflicts.length} existing zertifikat-cert.pub files should be overwritten using "${selectedCa.name}" despite the different CA.`
                                )}
                          </span>
                        </label>
                      </div>
                    )}

                    {/* CA Passphrase */}
                    {selectedCa && (
                      <div>
                        <label
                          htmlFor="sign-ca-passphrase"
                          className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1"
                        >
                          {selectedCa.hasStoredPassphrase
                            ? tr(
                                'CA-Passwort (optional — hinterlegtes Passwort wird verwendet)',
                                'CA Passphrase (optional — stored passphrase will be used)'
                              )
                            : tr('CA-Passwort *', 'CA Passphrase *')}
                        </label>
                        {selectedCa.hasStoredPassphrase && (
                          <p className="mb-1.5 inline-flex items-center gap-1 text-[11px] font-medium text-emerald-700 dark:text-emerald-400">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            {tr(
                              'Passwort ist verschlüsselt bei dieser CA hinterlegt.',
                              'Passphrase is stored encrypted for this CA.'
                            )}
                          </p>
                        )}
                        <input
                          id="sign-ca-passphrase"
                          type="password"
                          autoComplete="off"
                          required={!selectedCa.hasStoredPassphrase}
                          value={signCaPassphrase}
                          onChange={(e) => setSignCaPassphrase(e.target.value)}
                          placeholder={
                            selectedCa.hasStoredPassphrase
                              ? tr(
                                  'Leer lassen, um das hinterlegte CA-Passwort zu nutzen',
                                  'Leave blank to use stored CA passphrase'
                                )
                              : tr('CA-Passwort eingeben...', 'Enter CA passphrase...')
                          }
                          className="w-full px-3 py-2 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                        />
                      </div>
                    )}

                    {/* Principals (-n) */}
                    <div>
                      <label
                        htmlFor="sign-principals-input"
                        className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1"
                      >
                        {tr(
                          'Principals (-n · erlaubte SSH-Benutzer, kommagetrennt) *',
                          'Principals (-n · allowed SSH usernames, comma-separated) *'
                        )}
                      </label>
                      <input
                        id="sign-principals-input"
                        type="text"
                        required
                        value={signPrincipals}
                        onChange={(e) => setSignPrincipals(e.target.value)}
                        placeholder="root, admin, debian"
                        className="w-full px-3 py-2 text-sm font-mono bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                      />
                      <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[11px]">
                        <span className="text-slate-500 dark:text-slate-400">{tr('Schnellwahl:', 'Quick add:')}</span>
                        {['root', 'admin', 'debian', 'ubuntu'].map((tok) => (
                          <button
                            key={tok}
                            type="button"
                            onClick={() => addPrincipalSuggestion(tok)}
                            className="px-2 py-0.5 font-mono text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded border border-slate-200 dark:border-slate-800 cursor-pointer"
                          >
                            + {tok}
                          </button>
                        ))}
                        {singleTarget?.ownerUsername &&
                          !['root', 'admin', 'debian', 'ubuntu'].includes(
                            singleTarget.ownerUsername
                          ) && (
                            <button
                              type="button"
                              onClick={() => addPrincipalSuggestion(singleTarget.ownerUsername!)}
                              className="px-2 py-0.5 font-mono text-blue-800 dark:text-blue-300 bg-blue-50 dark:bg-blue-950/40 hover:bg-blue-100 dark:hover:bg-blue-900/50 rounded border border-blue-200 dark:border-blue-800/70 cursor-pointer"
                            >
                              + {singleTarget.ownerUsername}
                            </button>
                          )}
                      </div>
                      {isBatch && (
                        <label className="mt-2.5 flex items-center gap-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={signIncludeOwnerPrincipal}
                            onChange={(e) => setSignIncludeOwnerPrincipal(e.target.checked)}
                            className="w-3.5 h-3.5 rounded border-slate-300 dark:border-slate-700 text-blue-700 dark:text-blue-400 focus:ring-blue-600"
                          />
                          <span>
                            {tr(
                              'Zusätzlich den jeweiligen Eigentümer-Benutzernamen automatisch zu -n hinzufügen',
                              'Also automatically append each certificate owner’s username to -n'
                            )}
                          </span>
                        </label>
                      )}
                    </div>

                    {/* Validity (-V) & Key-ID (-I) */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div>
                        <label
                          htmlFor="sign-validity-select"
                          className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1"
                        >
                          {tr('Gültigkeitsdauer (-V)', 'Validity Period (-V)')}
                        </label>
                        <SearchableSelect
                          id="sign-validity-select"
                          value={signValidityPreset}
                          onChange={setSignValidityPreset}
                          ariaLabel={tr('Gültigkeitsdauer (-V)', 'Validity Period (-V)')}
                          searchPlaceholder={tr('Gültigkeit filtern...', 'Filter validity...')}
                          options={[
                            { value: '+8h', label: tr('8 Stunden (+8h)', '8 Hours (+8h)') },
                            { value: '+24h', label: tr('24 Stunden (+24h)', '24 Hours (+24h)') },
                            { value: '+7d', label: tr('7 Tage (+7d)', '7 Days (+7d)') },
                            { value: '+30d', label: tr('30 Tage (+30d)', '30 Days (+30d)') },
                            { value: '+90d', label: tr('90 Tage (+90d)', '90 Days (+90d)') },
                            { value: '+52w', label: tr('1 Jahr (+52w)', '1 Year (+52w)') },
                            { value: 'forever', label: tr('Unbegrenzt (forever)', 'Forever (no expiry)') },
                            { value: 'custom', label: tr('Benutzerdefiniert...', 'Custom...') },
                          ]}
                        />
                        {signValidityPreset === 'custom' && (
                          <input
                            type="text"
                            value={signValidityCustom}
                            onChange={(e) => setSignValidityCustom(e.target.value)}
                            placeholder="+180d"
                            className="mt-2 w-full px-3 py-1.5 text-xs font-mono bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                          />
                        )}
                      </div>

                      <div>
                        <label
                          htmlFor="sign-keyid-input"
                          className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1"
                        >
                          {isBatch
                            ? tr('Key-ID Präfix (-I, optional)', 'Key ID Prefix (-I, optional)')
                            : tr('Key-ID (-I, optional)', 'Key ID (-I, optional)')}
                        </label>
                        <input
                          id="sign-keyid-input"
                          type="text"
                          value={signKeyId}
                          onChange={(e) => setSignKeyId(e.target.value)}
                          placeholder={
                            isBatch
                              ? tr('leer = <benutzer>-<name>', 'empty = <user>-<name>')
                              : `${singleTarget?.ownerUsername || user.username}-${singleTarget?.name || 'cert'}`
                          }
                          className="w-full px-3 py-2 text-sm font-mono bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                        />
                      </div>
                    </div>

                    {/* Automatic Re-Certification Option (Admin) */}
                    {selectedCa && (() => {
                      const effVal =
                        signValidityPreset === 'custom'
                          ? signValidityCustom.trim()
                          : signValidityPreset;
                      const canEnableAdminAutoRenew =
                        selectedCa.hasStoredPassphrase && effVal !== 'forever';
                      return (
                        <div className="rounded-md bg-emerald-50/50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800/70 p-3.5 space-y-2.5 text-xs">
                          <label
                            className={`flex items-start gap-2.5 select-none ${
                              canEnableAdminAutoRenew ? 'cursor-pointer' : 'cursor-not-allowed opacity-70'
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={canEnableAdminAutoRenew && signAutoRenew}
                              disabled={!canEnableAdminAutoRenew}
                              onChange={(e) => setSignAutoRenew(e.target.checked)}
                              className="mt-0.5 w-4 h-4 rounded border-emerald-400 text-emerald-700 dark:text-emerald-400 focus:ring-emerald-600 cursor-pointer disabled:cursor-not-allowed"
                            />
                            <div className="space-y-0.5 min-w-0">
                              <span className="font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                                <RefreshCw className="w-3.5 h-3.5 text-emerald-700 dark:text-emerald-400 shrink-0" />
                                {tr(
                                  'Automatische Neuzertifizierung aktivieren (bis auf Widerruf oder Rechteentzug)',
                                  'Enable automatic re-certification (until revoked or rights removed)'
                                )}
                              </span>
                              <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
                                {tr(
                                  'Der Server erneuert die Signatur (zertifikat-cert.pub) automatisch vor Ablauf mit dieser CA, bis sie widerrufen oder das Konto/Recht entzogen wird.',
                                  'The server automatically renews the signature (zertifikat-cert.pub) before expiry using this CA until revoked or the account/rights are removed.'
                                )}
                              </p>
                            </div>
                          </label>

                          {!selectedCa.hasStoredPassphrase && (
                            <p className="text-[11px] text-amber-900 dark:text-amber-200 bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/70 rounded px-2.5 py-1.5">
                              {tr(
                                'Für die automatische Neuzertifizierung muss das CA-Passwort unter Administration → CA-Verwaltung auf dem Server gespeichert sein.',
                                'Automatic re-certification requires the CA passphrase to be stored on the server under Administration → CA Management.'
                              )}
                            </p>
                          )}
                          {selectedCa.hasStoredPassphrase && effVal === 'forever' && (
                            <p className="text-[11px] text-slate-600 dark:text-slate-400">
                              {tr(
                                'Bei unbegrenzter Gültigkeit (forever) ist keine automatische Neuzertifizierung erforderlich.',
                                'Automatic re-certification is not needed for unlimited validity (forever).'
                              )}
                            </p>
                          )}
                          {canEnableAdminAutoRenew && signAutoRenew && (
                            <div className="pt-2 border-t border-emerald-200/80 dark:border-emerald-800/70 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                              <label
                                htmlFor="sign-autorenew-lead"
                                className="text-[11px] font-medium text-slate-700 dark:text-slate-300"
                              >
                                {tr('Erneuerungszeitpunkt:', 'Renewal lead time:')}
                              </label>
                              <SearchableSelect
                                id="sign-autorenew-lead"
                                size="xs"
                                className="w-full sm:w-56"
                                value={String(signAutoRenewBeforeSec)}
                                onChange={(val) => setSignAutoRenewBeforeSec(Number(val))}
                                ariaLabel={tr('Erneuerungszeitpunkt', 'Renewal lead time')}
                                searchPlaceholder={tr('Zeitraum filtern...', 'Filter lead time...')}
                                options={[
                                  {
                                    value: '0',
                                    label: tr('Automatisch (20 % vor Ablauf)', 'Automatic (20% before expiry)'),
                                  },
                                  {
                                    value: '3600',
                                    label: tr('1 Stunde vor Ablauf', '1 hour before expiry'),
                                  },
                                  {
                                    value: '21600',
                                    label: tr('6 Stunden vor Ablauf', '6 hours before expiry'),
                                  },
                                  {
                                    value: '86400',
                                    label: tr('24 Stunden vor Ablauf', '24 hours before expiry'),
                                  },
                                  {
                                    value: '259200',
                                    label: tr('3 Tage vor Ablauf', '3 days before expiry'),
                                  },
                                  {
                                    value: '604800',
                                    label: tr('7 Tage vor Ablauf', '7 days before expiry'),
                                  },
                                ]}
                              />
                            </div>
                          )}
                        </div>
                      );
                    })()}
                  </>
                )}
              </div>

              <div className="px-5 py-3.5 bg-slate-50 dark:bg-slate-800/60 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={closeSignModal}
                  disabled={signSubmitting}
                  className="px-4 py-2 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md transition-colors cursor-pointer disabled:opacity-50"
                >
                  {tr('Abbrechen', 'Cancel')}
                </button>
                <button
                  type="submit"
                  disabled={
                    signSubmitting ||
                    cas.length === 0 ||
                    (foreignCaConflicts.length > 0 && !signConfirmForeignCa)
                  }
                  className={`inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-white disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                    foreignCaConflicts.length > 0
                      ? 'bg-amber-600 hover:bg-amber-700'
                      : 'bg-blue-700 hover:bg-blue-800'
                  }`}
                >
                  {foreignCaConflicts.length > 0 ? (
                    <AlertTriangle className="w-3.5 h-3.5" />
                  ) : (
                    <FileSignature className="w-3.5 h-3.5" />
                  )}
                  {signSubmitting
                    ? tr('Wird signiert...', 'Signing...')
                    : foreignCaConflicts.length > 0
                      ? isBatch
                        ? tr(
                            `${signingTargets.length} Zertifikate trotzdem signieren`,
                            `Sign ${signingTargets.length} Certificates Anyway`
                          )
                        : tr('Trotzdem signieren & überschreiben', 'Sign & Overwrite Anyway')
                      : isBatch
                        ? tr(
                            `${signingTargets.length} Zertifikate signieren`,
                            `Sign ${signingTargets.length} Certificates`
                          )
                        : tr('Zertifikat signieren', 'Sign Certificate')}
                </button>
              </div>
            </form>
          </div>
        );
      })()}

      {canSelfSign && selfSignTargets && selfSignTargets.length > 0 && (() => {
        const selectedCa = selectedSelfSignCa;
        const isBatch = selfSignTargets.length > 1;
        const singleTarget = !isBatch ? selfSignTargets[0] : null;
        const conflictIdSet = new Set(selfForeignCaConflicts.map((c) => c.cert.id));
        const canSubmitSelfSign =
          !selfSignSubmitting &&
          Boolean(selectedCa) &&
          Boolean(selectedCa?.hasStoredPassphrase) &&
          (selfForeignCaConflicts.length === 0 || selfSignConfirmForeignCa);
        return (
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="self-sign-modal-title"
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 dark:bg-black/70 backdrop-blur-[1px]"
            onClick={(e) => {
              if (e.target === e.currentTarget) closeSelfSignModal();
            }}
          >
            <form
              onSubmit={handleSelfSignSubmit}
              className="w-full max-w-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xl overflow-hidden"
            >
              <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3">
                <div className="flex items-center gap-2 min-w-0">
                  <FileSignature className="w-4 h-4 text-blue-700 dark:text-blue-400 shrink-0" />
                  <h2
                    id="self-sign-modal-title"
                    className="font-display text-base font-semibold text-slate-900 dark:text-slate-100 truncate"
                  >
                    {isBatch
                      ? tr(
                          `Sammelupdate signieren (${selfSignTargets.length} Zertifikate)`,
                          `Batch Sign Update (${selfSignTargets.length} Certificates)`
                        )
                      : tr(
                          `Zertifikat mit CA signieren: ${singleTarget?.name || ''}`,
                          `Sign Certificate with CA: ${singleTarget?.name || ''}`
                        )}
                  </h2>
                </div>
                <button
                  type="button"
                  onClick={closeSelfSignModal}
                  disabled={selfSignSubmitting}
                  aria-label={tr('Schließen', 'Close')}
                  className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 cursor-pointer disabled:opacity-50"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-5 space-y-4 max-h-[75vh] overflow-y-auto">
                {/* Target preview */}
                <div className="rounded-md bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 p-3 space-y-1.5">
                  <p className="text-xs font-medium text-slate-800 dark:text-slate-200">
                    {isBatch
                      ? tr(
                          `Ausgewählte eigene Zertifikate (${selfSignTargets.length}):`,
                          `Selected Own Certificates (${selfSignTargets.length}):`
                        )
                      : tr('Ausgewähltes Zertifikat:', 'Selected Certificate:')}
                  </p>
                  <ul className="max-h-28 overflow-y-auto space-y-1 text-xs text-slate-600 dark:text-slate-400">
                    {selfSignTargets.map((t) => {
                      const isForeign = conflictIdSet.has(t.id);
                      return (
                        <li key={t.id} className="flex items-center justify-between gap-2">
                          <span className="font-medium text-slate-900 dark:text-slate-100 truncate">{t.name}</span>
                          <span className="inline-flex items-center gap-1.5 shrink-0">
                            {isForeign && (
                              <span
                                title={tr(
                                  'Bestehende zertifikat-cert.pub stammt nicht von der gewählten CA',
                                  'Existing zertifikat-cert.pub was not signed by the selected CA'
                                )}
                                className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-900/40 border border-amber-300 dark:border-amber-700/80 text-amber-900 dark:text-amber-200 font-medium text-[10px]"
                              >
                                <AlertTriangle className="w-3 h-3 text-amber-600 dark:text-amber-400 shrink-0" />
                                {tr('Fremde CA', 'Foreign CA')}
                              </span>
                            )}
                            <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                              {t.metadata.pubKeyAlgorithm}
                            </span>
                          </span>
                        </li>
                      );
                    })}
                  </ul>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 pt-1 border-t border-slate-200 dark:border-slate-800">
                    {tr(
                      'Der Server signiert Ihren öffentlichen Schlüssel mit der gewählten CA und hinterlegt die neue zertifikat-cert.pub automatisch in Ihrem Paket.',
                      'The server signs your public key with the chosen CA and attaches the new zertifikat-cert.pub automatically to your bundle.'
                    )}
                  </p>
                </div>

                {selfSignError && (
                  <div
                    role="alert"
                    className="px-3.5 py-2.5 rounded-md bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800/70 text-xs text-red-800 dark:text-red-300 space-y-1"
                  >
                    <p className="font-medium">{selfSignError}</p>
                    {selfSignPartialErrors.length > 0 && (
                      <ul className="list-disc pl-4 space-y-0.5">
                        {selfSignPartialErrors.map((pe, idx) => (
                          <li key={idx}>
                            {pe.certificateName ? `${pe.certificateName}: ` : ''}
                            {pe.error}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}

                {assignedCasLoading && assignedCas.length === 0 ? (
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {tr('Zugewiesene CAs werden geladen...', 'Loading assigned CAs...')}
                  </p>
                ) : assignedCas.length === 0 ? (
                  <div className="px-4 py-3 rounded-md bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/70 text-xs text-amber-900 dark:text-amber-200 flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                    <span>
                      {tr(
                        'Ihrer Benutzergruppe wurde noch keine CA zur Selbstsignierung zugewiesen. Bitte wenden Sie sich an einen Administrator.',
                        'No CA has been assigned to your user group for self-signing yet. Please contact an administrator.'
                      )}
                    </span>
                  </div>
                ) : (
                  <>
                    {/* Assigned CA selector */}
                    <div>
                      <label
                        htmlFor="self-sign-ca-select"
                        className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1"
                      >
                        {tr('Zugewiesene Zertifizierungsstelle (CA)', 'Assigned Certificate Authority (CA)')}
                      </label>
                      <SearchableSelect
                        id="self-sign-ca-select"
                        value={selfSignCaId}
                        ariaLabel={tr('Zugewiesene Zertifizierungsstelle (CA)', 'Assigned Certificate Authority (CA)')}
                        searchPlaceholder={tr('CA, Schlüsseltyp oder Fingerprint filtern...', 'Filter CA, key type, or fingerprint...')}
                        onChange={(val) => {
                          setSelfSignCaId(val);
                          setSelfSignConfirmForeignCa(false);
                          setSelfSignError(null);
                        }}
                        options={assignedCas.map((ca) => {
                          const missingHint = ca.hasStoredPassphrase
                            ? ''
                            : tr('Passwort fehlt', 'Passphrase missing');
                          return {
                            value: ca.id,
                            label: ca.name,
                            triggerLabel: `${ca.name} (${ca.keyType})${missingHint ? ` · ${missingHint}` : ''}`,
                            meta: [ca.keyType, missingHint].filter(Boolean).join(' · '),
                            detail: ca.fingerprint,
                            searchText: `${ca.description || ''} ${ca.keyType} ${ca.fingerprint}`,
                          };
                        })}
                      />
                      {selectedCa && (
                        <p className="mt-1 text-[11px] font-mono text-slate-500 dark:text-slate-400 truncate">
                          {selectedCa.fingerprint}
                        </p>
                      )}
                    </div>

                    {/* Group-enforced signing policy summary */}
                    {selectedCa && (
                      <div className="rounded-md bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 p-3.5 text-xs space-y-2">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-medium text-slate-800 dark:text-slate-200">
                            {tr('Vorgegebene Gruppenparameter', 'Group-Enforced Signing Policy')}
                          </span>
                          {selectedCa.hasStoredPassphrase ? (
                            <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-700 dark:text-emerald-400">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              {tr('CA bereit', 'CA ready')}
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-[11px] font-medium text-amber-800 dark:text-amber-300">
                              <AlertTriangle className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
                              {tr('CA-Passwort nicht hinterlegt', 'CA passphrase missing')}
                            </span>
                          )}
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1 border-t border-slate-200 dark:border-slate-800">
                          <div>
                            <span className="block text-[11px] text-slate-500 dark:text-slate-400">
                              {tr('Principals (-n)', 'Principals (-n)')}
                            </span>
                            <span className="font-mono font-medium text-slate-900 dark:text-slate-100 break-all">
                              {selectedCa.effectivePrincipals.join(', ') || '—'}
                            </span>
                          </div>
                          <div>
                            <span className="block text-[11px] text-slate-500 dark:text-slate-400">
                              {tr('Gültigkeitsdauer (-V)', 'Validity (-V)')}
                            </span>
                            <span className="font-mono font-medium text-slate-900 dark:text-slate-100">
                              {selectedCa.validity}
                            </span>
                          </div>
                          <div>
                            <span className="block text-[11px] text-slate-500 dark:text-slate-400">
                              {tr('Auto-Neusignierung ab', 'Auto re-sign from')}
                            </span>
                            <span className="font-medium text-slate-900 dark:text-slate-100">
                              {['forever', 'always', 'always:forever'].includes(
                                (selectedCa.validity || '').trim().toLowerCase()
                              )
                                ? tr('Nicht möglich (forever)', 'Not applicable (forever)')
                                : formatAutoRenewLeadLabel(selectedCa.autoRenewBeforeSeconds || 0)}
                            </span>
                          </div>
                        </div>
                        {!selectedCa.hasStoredPassphrase && (
                          <p className="text-[11px] text-amber-900 dark:text-amber-200 bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/70 rounded px-2.5 py-1.5">
                            {tr(
                              'Für diese CA ist noch kein Passwort auf dem Server hinterlegt. Bitte bitten Sie einen Administrator, das CA-Passwort zu hinterlegen.',
                              'No passphrase is stored on the server for this CA yet. Please ask an administrator to store the CA passphrase.'
                            )}
                          </p>
                        )}
                      </div>
                    )}

                    {/* Foreign-CA overwrite warning */}
                    {selectedCa && selfForeignCaConflicts.length > 0 && (
                      <div
                        role="alert"
                        className="rounded-md bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-700/80 p-3.5 text-xs text-amber-950 dark:text-amber-200 space-y-2.5"
                      >
                        <div className="flex items-start gap-2">
                          <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                          <div className="space-y-1 min-w-0">
                            <p className="font-semibold text-amber-950 dark:text-amber-200">
                              {selfForeignCaConflicts.length === 1
                                ? tr(
                                    'Achtung: Bestehende zertifikat-cert.pub stammt von einer anderen CA',
                                    'Warning: Existing zertifikat-cert.pub was signed by a different CA'
                                  )
                                : tr(
                                    `Achtung: ${selfForeignCaConflicts.length} bestehende zertifikat-cert.pub-Dateien stammen von einer anderen CA`,
                                    `Warning: ${selfForeignCaConflicts.length} existing zertifikat-cert.pub files were signed by a different CA`
                                  )}
                            </p>
                            <p className="text-amber-900/90 dark:text-amber-200/90 leading-relaxed">
                              {selfForeignCaConflicts.length === 1
                                ? tr(
                                    `Das vorhandene Zertifikat wurde nicht von der gewählten CA „${selectedCa.name}“ signiert. Durch das Signieren wird die bestehende zertifikat-cert.pub-Datei dauerhaft überschrieben.`,
                                    `The existing certificate was not signed by the selected CA "${selectedCa.name}". Signing will permanently overwrite the existing zertifikat-cert.pub file.`
                                  )
                                : tr(
                                    `Die folgenden Zertifikate wurden nicht von der gewählten CA „${selectedCa.name}“ signiert. Durch das Sammelupdate werden deren bestehende zertifikat-cert.pub-Dateien dauerhaft überschrieben.`,
                                    `The following certificates were not signed by the selected CA "${selectedCa.name}". Batch signing will permanently overwrite their existing zertifikat-cert.pub files.`
                                  )}
                            </p>
                          </div>
                        </div>

                        <ul className="max-h-28 overflow-y-auto space-y-1 rounded bg-white/80 dark:bg-slate-900/80 border border-amber-200 dark:border-amber-800/70 px-2.5 py-2 text-[11px]">
                          {selfForeignCaConflicts.map(({ cert, existingFingerprint, matchedCaName }) => (
                            <li key={cert.id} className="flex flex-col gap-0.5">
                              <div className="flex items-center justify-between gap-2">
                                <span className="font-medium text-slate-900 dark:text-slate-100 truncate">
                                  {cert.name}
                                </span>
                                <span className="font-mono text-[10px] text-amber-900 dark:text-amber-200 shrink-0">
                                  {cert.certFileName || 'zertifikat-cert.pub'}
                                </span>
                              </div>
                              <span className="text-[10px] text-amber-900/80 dark:text-amber-200/80 font-mono truncate">
                                {tr('Bisherige CA: ', 'Current CA: ')}
                                {matchedCaName
                                  ? `${matchedCaName}${existingFingerprint ? ` (${existingFingerprint})` : ''}`
                                  : existingFingerprint
                                    ? `${tr('Externe CA', 'External CA')} (${existingFingerprint})`
                                    : tr('Unbekannte / externe CA', 'Unknown / external CA')}
                              </span>
                            </li>
                          ))}
                        </ul>

                        <label className="flex items-start gap-2 pt-1 cursor-pointer select-none">
                          <input
                            type="checkbox"
                            checked={selfSignConfirmForeignCa}
                            onChange={(e) => {
                              setSelfSignConfirmForeignCa(e.target.checked);
                              setSelfSignError(null);
                            }}
                            className="mt-0.5 w-3.5 h-3.5 rounded border-amber-400 dark:border-amber-700/80 text-amber-700 dark:text-amber-400 focus:ring-amber-600 cursor-pointer"
                          />
                          <span className="font-medium text-amber-950 dark:text-amber-200 leading-snug">
                            {selfForeignCaConflicts.length === 1
                              ? tr(
                                  `Ich bestätige, dass die bestehende zertifikat-cert.pub-Datei trotz abweichender CA mit „${selectedCa.name}“ überschrieben werden soll.`,
                                  `I confirm that the existing zertifikat-cert.pub file should be overwritten using "${selectedCa.name}" despite the different CA.`
                                )
                              : tr(
                                  `Ich bestätige, dass die ${selfForeignCaConflicts.length} bestehenden zertifikat-cert.pub-Dateien trotz abweichender CA mit „${selectedCa.name}“ überschrieben werden sollen.`,
                                  `I confirm that the ${selfForeignCaConflicts.length} existing zertifikat-cert.pub files should be overwritten using "${selectedCa.name}" despite the different CA.`
                                )}
                          </span>
                        </label>
                      </div>
                    )}

                    {/* Automatic Re-Certification Option (User Self-Signing) */}
                    {selectedCa && (
                      canAutoRenew ? (() => {
                        const isForeverValidity = ['forever', 'always', 'always:forever'].includes(
                          (selectedCa.validity || '').trim().toLowerCase()
                        );
                        const canEnableUserAutoRenew =
                          selectedCa.hasStoredPassphrase && !isForeverValidity;
                        return (
                          <div className="rounded-md bg-emerald-50/50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800/70 p-3.5 space-y-2.5 text-xs">
                            <label
                              className={`flex items-start gap-2.5 select-none ${
                                canEnableUserAutoRenew ? 'cursor-pointer' : 'cursor-not-allowed opacity-70'
                              }`}
                            >
                              <input
                                type="checkbox"
                                checked={canEnableUserAutoRenew && selfSignAutoRenew}
                                disabled={!canEnableUserAutoRenew}
                                onChange={(e) => setSelfSignAutoRenew(e.target.checked)}
                                className="mt-0.5 w-4 h-4 rounded border-emerald-400 text-emerald-700 dark:text-emerald-400 focus:ring-emerald-600 cursor-pointer disabled:cursor-not-allowed"
                              />
                              <div className="space-y-0.5 min-w-0">
                                <span className="font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                                  <RefreshCw className="w-3.5 h-3.5 text-emerald-700 dark:text-emerald-400 shrink-0" />
                                  {tr(
                                    'Automatische Neuzertifizierung aktivieren (bis auf Widerruf oder Rechteentzug)',
                                    'Enable automatic re-certification (until revoked or rights removed)'
                                  )}
                                </span>
                                <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
                                  {isForeverValidity
                                    ? tr(
                                        'Für diese CA ist eine unbegrenzte Gültigkeit (forever) vorgegeben – eine automatische Neuzertifizierung ist daher nicht erforderlich.',
                                        'Unlimited validity (forever) is configured for this CA — automatic re-certification is not required.'
                                      )
                                    : tr(
                                        'Ihre Zertifikate werden automatisch im Rahmen Ihrer Gruppen- und CA-Vorgaben (-n, -V und Erneuerungszeitpunkt) neu signiert. Bei Widerruf oder Rechteentzug wird die Erneuerung sofort gestoppt.',
                                        'Your certificates will be automatically re-signed under your group & CA policy (-n, -V, and renewal lead time). Renewal stops immediately upon revocation or rights removal.'
                                      )}
                                </p>
                              </div>
                            </label>

                            {canEnableUserAutoRenew && selfSignAutoRenew && (
                              <div className="pt-2 border-t border-emerald-200/80 dark:border-emerald-800/70 flex flex-wrap items-center justify-between gap-2 text-[11px]">
                                <span className="font-medium text-slate-700 dark:text-slate-300">
                                  {tr(
                                    'Erneuerungszeitpunkt (Gruppen-/CA-Vorgabe):',
                                    'Renewal start time (group/CA policy):'
                                  )}
                                </span>
                                <span className="px-2 py-0.5 rounded bg-white dark:bg-slate-900 border border-emerald-200 dark:border-emerald-800/70 font-medium text-emerald-900 dark:text-emerald-200">
                                  {formatAutoRenewLeadLabel(selectedCa.autoRenewBeforeSeconds || 0)}
                                </span>
                              </div>
                            )}
                          </div>
                        );
                      })() : (
                        <div className="rounded-md bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 px-3 py-2.5 text-[11px] text-slate-600 dark:text-slate-400 flex items-start gap-2">
                          <Lock className="w-3.5 h-3.5 text-slate-400 shrink-0 mt-0.5" />
                          <span>
                            {tr(
                              'Automatische Neuzertifizierung ist für Ihre Benutzergruppe aktuell nicht freigegeben. Ein Administrator kann dieses Recht pro Gruppe aktivieren.',
                              'Automatic re-certification is not currently enabled for your user group. An administrator can grant this permission per group.'
                            )}
                          </span>
                        </div>
                      )
                    )}
                  </>
                )}
              </div>

              <div className="px-5 py-3.5 bg-slate-50 dark:bg-slate-800/60 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={closeSelfSignModal}
                  disabled={selfSignSubmitting}
                  className="px-4 py-2 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 rounded-md transition-colors cursor-pointer disabled:opacity-50"
                >
                  {tr('Abbrechen', 'Cancel')}
                </button>
                <button
                  type="submit"
                  disabled={!canSubmitSelfSign}
                  className={`inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-white disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                    selfForeignCaConflicts.length > 0
                      ? 'bg-amber-600 hover:bg-amber-700'
                      : 'bg-blue-700 hover:bg-blue-800'
                  }`}
                >
                  {selfForeignCaConflicts.length > 0 ? (
                    <AlertTriangle className="w-3.5 h-3.5" />
                  ) : (
                    <FileSignature className="w-3.5 h-3.5" />
                  )}
                  {selfSignSubmitting
                    ? tr('Wird signiert...', 'Signing...')
                    : selfForeignCaConflicts.length > 0
                      ? isBatch
                        ? tr(
                            `${selfSignTargets.length} Zertifikate trotzdem signieren`,
                            `Sign ${selfSignTargets.length} Certificates Anyway`
                          )
                        : tr('Trotzdem signieren & überschreiben', 'Sign & Overwrite Anyway')
                      : isBatch
                        ? tr(
                            `${selfSignTargets.length} Zertifikate signieren`,
                            `Sign ${selfSignTargets.length} Certificates`
                          )
                        : tr('Zertifikat signieren', 'Sign Certificate')}
                </button>
              </div>
            </form>
          </div>
        );
      })()}

      {sharingCert && canShare && (
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
