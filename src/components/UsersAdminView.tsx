import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  UserPlus,
  Trash2,
  KeyRound,
  Check,
  X,
  ShieldOff,
  Users,
  Shield,
  Lock,
  Plus,
  Pencil,
  CheckSquare,
  SlidersHorizontal,
  FileSignature,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { getPasswordComplexityError } from '../passwordPolicy';
import { PasswordStrengthHint } from './PasswordStrengthHint';
import type {
  CertificateAuthority,
  GroupCaAssignment,
  GroupPermissions,
  User,
  UserGroup,
} from '../types';

interface UsersAdminViewProps {
  currentUser: User;
  users: User[];
  groups: UserGroup[];
  onRefresh: () => Promise<void>;
  onRefreshGroups: () => Promise<void>;
}

type PermissionKey = Exclude<keyof GroupPermissions, 'caSigningAssignments'>;

interface PermissionMeta {
  key: PermissionKey;
  labelDe: string;
  labelEn: string;
  descDe: string;
  descEn: string;
  isPolicy?: boolean;
}

interface PermissionSection {
  titleDe: string;
  titleEn: string;
  items: PermissionMeta[];
}

const PERMISSION_SECTIONS: PermissionSection[] = [
  {
    titleDe: 'Server & Verbindung',
    titleEn: 'Servers & Connection',
    items: [
      {
        key: 'manageOwnServers',
        labelDe: 'Eigene Server (IPs) & Kategorien verwalten',
        labelEn: 'Manage own servers (IPs) & categories',
        descDe: 'Eigene Ziel-IPs, BMC-Adressen und Kategorien erstellen, bearbeiten und löschen.',
        descEn: 'Create, edit, and delete own target IPs, BMC addresses, and categories.',
      },
      {
        key: 'executeCommands',
        labelDe: 'SSH-Befehle & Sammelaufträge ausführen',
        labelEn: 'Execute SSH commands & batch jobs',
        descDe: 'Kurzbefehle, Ketten und Workflows im Dashboard auf Servern starten.',
        descEn: 'Run quick commands, chains, and workflows against servers from the Dashboard.',
      },
      {
        key: 'useSshShell',
        labelDe: 'Interaktive SSH-Shell nutzen',
        labelEn: 'Use interactive SSH shell',
        descDe: 'Direkte Browser-Terminalsitzungen auf Zielservern öffnen.',
        descEn: 'Open interactive browser terminal sessions to target servers.',
      },
      {
        key: 'useSshShellCustomIp',
        labelDe: 'SSH-Shell: Freie IP-Adresse eingeben',
        labelEn: 'SSH Shell: Enter custom IP address',
        descDe:
          'In der SSH-Shell beliebige Ziel-IP-Adressen und Ports statt nur gespeicherter oder freigegebener Server eingeben.',
        descEn:
          'Enter arbitrary target IP addresses and ports in the SSH shell instead of only saved or shared servers.',
      },
    ],
  },
  {
    titleDe: 'Eigene SSH-Befehle',
    titleEn: 'Own SSH Commands',
    items: [
      {
        key: 'createSingleCommands',
        labelDe: 'Einzelbefehle erstellen & verwalten',
        labelEn: 'Create & manage single commands',
        descDe: 'Eigene einzelne SSH-Befehle sowie Standardbefehle anlegen, bearbeiten und löschen.',
        descEn: 'Create, edit, and delete own single SSH commands and load presets.',
      },
      {
        key: 'createChainCommands',
        labelDe: 'Befehlsketten (Sleep) erstellen & verwalten',
        labelEn: 'Create & manage command chains (sleep)',
        descDe: 'Eigene mehrstufige Befehlsketten mit Wartezeiten anlegen und bearbeiten.',
        descEn: 'Create and edit multi-step command chains with sleep intervals.',
      },
      {
        key: 'createWorkflowCommands',
        labelDe: 'Komplexe Befehle (JSON-Workflows) erstellen & verwalten',
        labelEn: 'Create & manage complex JSON workflows',
        descDe: 'Eigene JSON-Workflows mit Bedingungen, Schleifen und Variablen anlegen.',
        descEn: 'Create and edit JSON workflows with conditions, loops, and runtime variables.',
      },
    ],
  },
  {
    titleDe: 'Zertifikate & Schlüssel',
    titleEn: 'Certificates & Keys',
    items: [
      {
        key: 'uploadCertificates',
        labelDe: 'SSH-Schlüssel & Zertifikate hochladen & verwalten',
        labelEn: 'Upload & manage SSH keys & certificates',
        descDe: 'Eigene Schlüsselpaare (zertifikat + zertifikat.pub) hochladen, ändern und entfernen.',
        descEn: 'Upload, update, and remove own SSH keypairs (zertifikat + zertifikat.pub).',
      },
      {
        key: 'uploadSignedCert',
        labelDe: 'Eigene zertifikat-cert.pub hochladen erlauben',
        labelEn: 'Allow uploading own zertifikat-cert.pub',
        descDe:
          'Erlaubt das Hochladen oder Austauschen eigener signierter Zertifikate (zertifikat-cert.pub). Deaktivieren, wenn Signaturen nur über interne CAs erfolgen dürfen.',
        descEn:
          'Allows uploading or replacing own signed certificates (zertifikat-cert.pub). Disable to restrict signatures to internal CAs.',
      },
      {
        key: 'generateTestCertificates',
        labelDe: 'Zertifikate erzeugen',
        labelEn: 'Generate certificates',
        descDe: 'Neue Ed25519-Zertifikate (zertifikat und zertifikat.pub) direkt über den Server erzeugen.',
        descEn: 'Generate new Ed25519 certificates (zertifikat and zertifikat.pub) directly on the server.',
      },
      {
        key: 'requireCertificatePassphrase',
        labelDe: 'Zertifikat-Passwort erforderlich (Pflicht)',
        labelEn: 'Certificate passphrase required (mandatory)',
        descDe:
          'Erzwingt ein Passwort beim Erzeugen neuer Zertifikate sowie passwortgeschützte Privatschlüssel beim Hochladen.',
        descEn:
          'Requires a passphrase when generating certificates and enforces encrypted private keys on upload.',
        isPolicy: true,
      },
      {
        key: 'storeCertificatePassphrase',
        labelDe: 'Zertifikat-Passwort auf dem Server speichern',
        labelEn: 'Store certificate passphrase on server',
        descDe:
          'Erlaubt es Mitgliedern, das Schlüssel-Passwort verschlüsselt beim Zertifikat zu hinterlegen (sonst Abfrage bei jeder Nutzung).',
        descEn:
          'Allows members to store the key passphrase encrypted with the certificate (otherwise prompted on each use).',
      },
      {
        key: 'selfSignCertificates',
        labelDe: 'Eigene Zertifikate selbst mit zugewiesener CA signieren',
        labelEn: 'Self-sign own certificates with assigned CA',
        descDe:
          'Erlaubt es Mitgliedern, eines oder mehrere ihrer eigenen SSH-Zertifikate (auch als Sammelupdate) mit den unten zugewiesenen CAs und Principals (-n) selbst zu signieren.',
        descEn:
          'Allows members to sign one or multiple of their own SSH certificates (including batch updates) using the assigned CAs and principals (-n) below.',
      },
      {
        key: 'autoRenewCertificates',
        labelDe: 'Automatische Neuzertifizierung erlauben',
        labelEn: 'Allow automatic re-certification',
        descDe:
          'Erlaubt es Mitgliedern, bei der Selbstsignierung eine automatische Neuzertifizierung vor Ablauf zu aktivieren. Läuft bis auf Widerruf oder Rechteentzug.',
        descEn:
          'Allows members to enable automatic certificate renewal before expiration during self-signing. Runs until revoked or permissions are removed.',
      },
    ],
  },
  {
    titleDe: 'API, Freigaben & Protokolle',
    titleEn: 'API, Sharing & Logs',
    items: [
      {
        key: 'useApi',
        labelDe: 'API-Schlüssel & REST-API nutzen',
        labelEn: 'Use API keys & REST API',
        descDe: 'Persönliche API-Keys erstellen und die REST-API (z. B. curl-Upload) verwenden.',
        descEn: 'Create personal API keys and access the REST API (e.g. curl uploads).',
      },
      {
        key: 'shareResources',
        labelDe: 'Eigene Ressourcen mit anderen teilen',
        labelEn: 'Share own resources with others',
        descDe: 'Eigene Server, Befehle und Zertifikate für ausgewählte oder alle Benutzer freigeben.',
        descEn: 'Share own servers, commands, and certificates with specific or all users.',
      },
      {
        key: 'viewOwnLogs',
        labelDe: 'Ausführungsprotokoll einsehen',
        labelEn: 'View execution logs',
        descDe: 'Eigene SSH-Ausführungen und Ausgaben im Protokoll nachverfolgen.',
        descEn: 'Inspect own SSH executions and outputs in the execution log.',
      },
    ],
  },
];

const CAPABILITY_PERMISSION_KEYS: PermissionKey[] = PERMISSION_SECTIONS.flatMap((s) =>
  s.items.filter((i) => !i.isPolicy).map((i) => i.key)
);

const DEFAULT_USER_PERMISSIONS: GroupPermissions = {
  manageOwnServers: true,
  createSingleCommands: true,
  createChainCommands: true,
  createWorkflowCommands: true,
  uploadCertificates: true,
  uploadSignedCert: true,
  generateTestCertificates: true,
  requireCertificatePassphrase: false,
  storeCertificatePassphrase: true,
  selfSignCertificates: false,
  autoRenewCertificates: false,
  useApi: true,
  shareResources: false,
  useSshShell: true,
  useSshShellCustomIp: true,
  executeCommands: true,
  viewOwnLogs: true,
  caSigningAssignments: [],
};

const ALL_PERMISSIONS: GroupPermissions = {
  manageOwnServers: true,
  createSingleCommands: true,
  createChainCommands: true,
  createWorkflowCommands: true,
  uploadCertificates: true,
  uploadSignedCert: true,
  generateTestCertificates: true,
  requireCertificatePassphrase: false,
  storeCertificatePassphrase: true,
  selfSignCertificates: true,
  autoRenewCertificates: true,
  useApi: true,
  shareResources: true,
  useSshShell: true,
  useSshShellCustomIp: true,
  executeCommands: true,
  viewOwnLogs: true,
  caSigningAssignments: [],
};

const MINIMAL_OPERATOR_PERMISSIONS: GroupPermissions = {
  manageOwnServers: false,
  createSingleCommands: false,
  createChainCommands: false,
  createWorkflowCommands: false,
  uploadCertificates: false,
  uploadSignedCert: false,
  generateTestCertificates: false,
  requireCertificatePassphrase: false,
  storeCertificatePassphrase: false,
  selfSignCertificates: false,
  autoRenewCertificates: false,
  useApi: false,
  shareResources: false,
  useSshShell: false,
  useSshShellCustomIp: false,
  executeCommands: true,
  viewOwnLogs: true,
  caSigningAssignments: [],
};

const PRINCIPAL_TOKEN_RE = /^[a-zA-Z0-9._@+-]{1,64}$/;

const CA_VALIDITY_PRESETS = [
  '+1h',
  '+8h',
  '+24h',
  '+3d',
  '+7d',
  '+14d',
  '+30d',
  '+90d',
  '+52w',
  'forever',
] as const;

const CA_AUTO_RENEW_LEAD_PRESETS = [
  0,
  900,      // 15m
  1800,     // 30m
  3600,     // 1h
  7200,     // 2h
  21600,    // 6h
  43200,    // 12h
  86400,    // 24h
  172800,   // 2d
  259200,   // 3d
  604800,   // 7d
  1209600,  // 14d
  2592000,  // 30d
] as const;

function isForeverValidity(raw: string): boolean {
  const lower = (raw || '').trim().toLowerCase();
  return lower === 'forever' || lower === 'always' || lower === 'always:forever';
}

function parseValidityForwardSecondsClient(raw: string): number | null {
  const trimmed = (raw || '').trim();
  if (!trimmed) return 30 * 86400;
  if (isForeverValidity(trimmed)) return null;
  const unitSec: Record<string, number> = {
    s: 1,
    m: 60,
    h: 3600,
    d: 86400,
    w: 604800,
  };
  const simple = /^\+(\d+)([smhdw])$/i.exec(trimmed);
  if (simple) {
    const val = Number(simple[1]) * (unitSec[simple[2].toLowerCase()] || 0);
    return val >= 60 ? val : Number.NaN;
  }
  const range = /^-(\d+)([smhdw]):\+(\d+)([smhdw])$/i.exec(trimmed);
  if (range) {
    const val = Number(range[3]) * (unitSec[range[4].toLowerCase()] || 0);
    return val >= 60 ? val : Number.NaN;
  }
  return Number.NaN;
}

function splitLeadSecondsToCustom(seconds: number): { amount: string; unit: 'm' | 'h' | 'd' } {
  if (!seconds || seconds <= 0) return { amount: '24', unit: 'h' };
  if (seconds % 86400 === 0) return { amount: String(seconds / 86400), unit: 'd' };
  if (seconds % 3600 === 0) return { amount: String(seconds / 3600), unit: 'h' };
  return { amount: String(Math.max(1, Math.round(seconds / 60))), unit: 'm' };
}

function parsePrincipalsDraft(raw: string): string[] {
  const out: string[] = [];
  for (const part of raw.split(/[,;\n\r\s]+/)) {
    const clean = part.trim();
    if (!clean || !PRINCIPAL_TOKEN_RE.test(clean)) continue;
    if (!out.includes(clean)) out.push(clean);
    if (out.length >= 32) break;
  }
  return out;
}

export function UsersAdminView({
  currentUser,
  users,
  groups,
  onRefresh,
  onRefreshGroups,
}: UsersAdminViewProps) {
  const { tr, formatDateTime } = useI18n();
  const [activeSubTab, setActiveSubTab] = useState<'users' | 'groups'>('users');

  // Create user state
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [groupId, setGroupId] = useState<string>('user');
  const [defaultSshUser, setDefaultSshUser] = useState('root');

  const [resetUserId, setResetUserId] = useState<string | null>(null);
  const [resetPasswordVal, setResetPasswordVal] = useState('');
  const [updatingGroupUserId, setUpdatingGroupUserId] = useState<string | null>(null);

  // Group editor state
  const [editingGroupId, setEditingGroupId] = useState<string | null>(null);
  const [showGroupForm, setShowGroupForm] = useState(false);
  const [grpName, setGrpName] = useState('');
  const [grpDescription, setGrpDescription] = useState('');
  const [grpPermissions, setGrpPermissions] = useState<GroupPermissions>({ ...DEFAULT_USER_PERMISSIONS });
  const [grpCaPrincipalsDrafts, setGrpCaPrincipalsDrafts] = useState<Record<string, string>>({});
  const [grpCaCustomValidity, setGrpCaCustomValidity] = useState<Record<string, boolean>>({});
  const [grpCaCustomLead, setGrpCaCustomLead] = useState<
    Record<string, { enabled: boolean; amount: string; unit: 'm' | 'h' | 'd' }>
  >({});
  const [availableCas, setAvailableCas] = useState<CertificateAuthority[]>([]);
  const [casLoading, setCasLoading] = useState(false);
  const [confirmDeleteGroupId, setConfirmDeleteGroupId] = useState<string | null>(null);
  const [deletingGroupId, setDeletingGroupId] = useState<string | null>(null);

  const [saving, setSaving] = useState(false);
  const [savingGroup, setSavingGroup] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const loadAvailableCas = useCallback(async () => {
    setCasLoading(true);
    try {
      const res = await api.listCertificateAuthorities();
      setAvailableCas(res.cas);
    } catch {
      // ignore if CA list fails transiently
    } finally {
      setCasLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAvailableCas();
  }, [loadAvailableCas]);

  const caNameById = useMemo(() => {
    const map = new Map<string, CertificateAuthority>();
    for (const ca of availableCas) {
      map.set(ca.id, ca);
    }
    return map;
  }, [availableCas]);

  const sortedGroups = useMemo(() => {
    const order = (g: UserGroup) => (g.id === 'admin' ? 0 : g.id === 'user' ? 1 : 2);
    return [...groups].sort((a, b) => {
      const diff = order(a) - order(b);
      if (diff !== 0) return diff;
      return a.name.localeCompare(b.name);
    });
  }, [groups]);

  const memberCountByGroup = useMemo(() => {
    const counts = new Map<string, number>();
    for (const u of users) {
      const gid = u.groupId || (u.role === 'admin' ? 'admin' : 'user');
      counts.set(gid, (counts.get(gid) ?? 0) + 1);
    }
    return counts;
  }, [users]);

  const editingGroupObj = useMemo(
    () => (editingGroupId ? groups.find((g) => g.id === editingGroupId) ?? null : null),
    [editingGroupId, groups]
  );

  async function handleCreateUser(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    const passwordError = getPasswordComplexityError(password, tr);
    if (passwordError) {
      setError(passwordError);
      return;
    }
    setSaving(true);
    try {
      const selectedGrp = groups.find((g) => g.id === groupId);
      const res = await api.createUser({
        username: username.trim(),
        displayName: displayName.trim() || username.trim(),
        password,
        groupId: groupId || 'user',
        role: selectedGrp?.isAdmin ? 'admin' : 'user',
        defaultSshUser: defaultSshUser.trim() || 'root',
      });
      await onRefresh();
      setUsername('');
      setDisplayName('');
      setPassword('');
      setGroupId('user');
      setDefaultSshUser('root');
      setSuccess(
        tr(
          `Benutzerkonto „${res.user.username}“ wurde in der Gruppe „${res.user.groupName}“ angelegt.`,
          `User account "${res.user.username}" has been created in group "${res.user.groupName}".`
        )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Benutzer konnte nicht angelegt werden.', 'Could not create user.')
      );
    } finally {
      setSaving(false);
    }
  }

  async function handleChangeUserGroup(u: User, nextGroupId: string) {
    if (!nextGroupId || nextGroupId === u.groupId) return;
    setError(null);
    setSuccess(null);
    setUpdatingGroupUserId(u.id);
    try {
      const res = await api.updateUser(u.id, { groupId: nextGroupId });
      await onRefresh();
      setSuccess(
        tr(
          `Benutzer „${u.username}“ wurde der Gruppe „${res.user.groupName}“ zugewiesen.`,
          `User "${u.username}" was assigned to group "${res.user.groupName}".`
        )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Benutzergruppe konnte nicht geändert werden.', 'Could not change user group.')
      );
    } finally {
      setUpdatingGroupUserId(null);
    }
  }

  async function handleToggleActive(u: User) {
    setError(null);
    setSuccess(null);
    try {
      await api.updateUser(u.id, { active: !u.active });
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Status konnte nicht aktualisiert werden.', 'Could not update status.')
      );
    }
  }

  async function handleResetPassword(userId: string) {
    setError(null);
    setSuccess(null);
    const passwordError = getPasswordComplexityError(resetPasswordVal, tr);
    if (passwordError) {
      setError(passwordError);
      return;
    }
    try {
      await api.updateUser(userId, { newPassword: resetPasswordVal });
      setResetUserId(null);
      setResetPasswordVal('');
      setSuccess(tr('Passwort wurde aktualisiert.', 'Password has been updated.'));
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Passwort konnte nicht geändert werden.', 'Could not change password.')
      );
    }
  }

  async function handleResetAuth(u: User) {
    setError(null);
    setSuccess(null);
    try {
      await api.resetUserAuth(u.id);
      await onRefresh();
      setSuccess(
        tr(
          `2FA und Passkeys für „${u.username}“ wurden zurückgesetzt.`,
          `2FA and Passkeys for "${u.username}" have been reset.`
        )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('2FA/Passkeys konnten nicht zurückgesetzt werden.', 'Could not reset 2FA/Passkeys.')
      );
    }
  }

  async function handleDeleteUser(u: User) {
    setError(null);
    setSuccess(null);
    try {
      await api.deleteUser(u.id);
      await onRefresh();
      setSuccess(
        tr(`Benutzer „${u.username}“ wurde entfernt.`, `User "${u.username}" has been deleted.`)
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Benutzer konnte nicht gelöscht werden.', 'Could not delete user.')
      );
    }
  }

  function formatLeadLabel(seconds: number): string {
    if (!seconds || seconds <= 0) {
      return tr('Automatisch (20 % vor Ablauf)', 'Automatic (20% before expiry)');
    }
    if (seconds % 86400 === 0) {
      const d = seconds / 86400;
      return d === 1
        ? tr('1 Tag vor Ablauf', '1 day before expiry')
        : tr(`${d} Tage vor Ablauf`, `${d} days before expiry`);
    }
    if (seconds % 3600 === 0) {
      const h = seconds / 3600;
      return h === 1
        ? tr('1 Stunde vor Ablauf', '1 hour before expiry')
        : tr(`${h} Stunden vor Ablauf`, `${h} hours before expiry`);
    }
    const m = Math.max(1, Math.round(seconds / 60));
    return m === 1
      ? tr('1 Minute vor Ablauf', '1 minute before expiry')
      : tr(`${m} Minuten vor Ablauf`, `${m} minutes before expiry`);
  }

  function startCreateGroup() {
    setError(null);
    setSuccess(null);
    setEditingGroupId(null);
    setGrpName('');
    setGrpDescription('');
    setGrpPermissions({ ...DEFAULT_USER_PERMISSIONS, caSigningAssignments: [] });
    setGrpCaPrincipalsDrafts({});
    setGrpCaCustomValidity({});
    setGrpCaCustomLead({});
    setShowGroupForm(true);
    void loadAvailableCas();
  }

  function startEditGroup(g: UserGroup) {
    if (g.isImmutable) return;
    setError(null);
    setSuccess(null);
    setEditingGroupId(g.id);
    setGrpName(g.name);
    setGrpDescription(g.description || '');
    const assignments: GroupCaAssignment[] = Array.isArray(g.permissions?.caSigningAssignments)
      ? g.permissions.caSigningAssignments.map((a) => ({
          caId: a.caId,
          principals: [...(a.principals || [])],
          includeOwnerPrincipal: Boolean(a.includeOwnerPrincipal),
          validity: a.validity === 'always:forever' ? 'forever' : a.validity || '+30d',
          autoRenewBeforeSeconds:
            typeof a.autoRenewBeforeSeconds === 'number' && a.autoRenewBeforeSeconds > 0
              ? a.autoRenewBeforeSeconds
              : 0,
        }))
      : [];
    const drafts: Record<string, string> = {};
    const customVal: Record<string, boolean> = {};
    const customLead: Record<string, { enabled: boolean; amount: string; unit: 'm' | 'h' | 'd' }> = {};
    for (const a of assignments) {
      drafts[a.caId] = a.principals.join(', ');
      if (!CA_VALIDITY_PRESETS.includes(a.validity as (typeof CA_VALIDITY_PRESETS)[number])) {
        customVal[a.caId] = true;
      }
      const lead = a.autoRenewBeforeSeconds || 0;
      if (!CA_AUTO_RENEW_LEAD_PRESETS.includes(lead as (typeof CA_AUTO_RENEW_LEAD_PRESETS)[number])) {
        const split = splitLeadSecondsToCustom(lead);
        customLead[a.caId] = { enabled: true, ...split };
      }
    }
    setGrpPermissions({
      ...DEFAULT_USER_PERMISSIONS,
      ...g.permissions,
      caSigningAssignments: assignments,
    });
    setGrpCaPrincipalsDrafts(drafts);
    setGrpCaCustomValidity(customVal);
    setGrpCaCustomLead(customLead);
    setShowGroupForm(true);
    void loadAvailableCas();
  }

  function cancelGroupForm() {
    setShowGroupForm(false);
    setEditingGroupId(null);
    setGrpName('');
    setGrpDescription('');
    setGrpPermissions({ ...DEFAULT_USER_PERMISSIONS, caSigningAssignments: [] });
    setGrpCaPrincipalsDrafts({});
    setGrpCaCustomValidity({});
    setGrpCaCustomLead({});
  }

  function togglePermission(key: PermissionKey) {
    setGrpPermissions((prev) => {
      const nextVal = !prev[key];
      const next: GroupPermissions = { ...prev, [key]: nextVal };
      if (key === 'useSshShell' && !nextVal) {
        next.useSshShellCustomIp = false;
      } else if (key === 'useSshShellCustomIp' && nextVal) {
        next.useSshShell = true;
      } else if (key === 'uploadCertificates' && !nextVal) {
        next.uploadSignedCert = false;
      } else if (key === 'uploadSignedCert' && nextVal) {
        next.uploadCertificates = true;
      }
      return next;
    });
  }

  function toggleGroupCaAssignment(caId: string) {
    setGrpPermissions((prev) => {
      const existing = prev.caSigningAssignments.find((a) => a.caId === caId);
      if (existing) {
        return {
          ...prev,
          caSigningAssignments: prev.caSigningAssignments.filter((a) => a.caId !== caId),
        };
      }
      const nextAssignment: GroupCaAssignment = {
        caId,
        principals: [],
        includeOwnerPrincipal: true,
        validity: '+30d',
        autoRenewBeforeSeconds: 0,
      };
      return {
        ...prev,
        caSigningAssignments: [...prev.caSigningAssignments, nextAssignment],
      };
    });
    setGrpCaPrincipalsDrafts((prev) => ({
      ...prev,
      [caId]: prev[caId] ?? '',
    }));
  }

  function updateGroupCaPrincipalsDraft(caId: string, raw: string) {
    setGrpCaPrincipalsDrafts((prev) => ({ ...prev, [caId]: raw }));
    const parsed = parsePrincipalsDraft(raw);
    setGrpPermissions((prev) => ({
      ...prev,
      caSigningAssignments: prev.caSigningAssignments.map((a) =>
        a.caId === caId ? { ...a, principals: parsed } : a
      ),
    }));
  }

  function appendGroupCaPrincipalToken(caId: string, token: string) {
    const currentDraft = grpCaPrincipalsDrafts[caId] ?? '';
    const list = parsePrincipalsDraft(currentDraft);
    if (!list.includes(token)) {
      const nextDraft = [...list, token].join(', ');
      updateGroupCaPrincipalsDraft(caId, nextDraft);
    }
  }

  function updateGroupCaAssignmentField(
    caId: string,
    patch: Partial<Pick<GroupCaAssignment, 'includeOwnerPrincipal' | 'validity' | 'autoRenewBeforeSeconds'>>
  ) {
    setGrpPermissions((prev) => ({
      ...prev,
      caSigningAssignments: prev.caSigningAssignments.map((a) =>
        a.caId === caId ? { ...a, ...patch } : a
      ),
    }));
  }

  function updateCustomLeadInput(caId: string, amountStr: string, unit: 'm' | 'h' | 'd') {
    setGrpCaCustomLead((prev) => ({
      ...prev,
      [caId]: { enabled: true, amount: amountStr, unit },
    }));
    const n = Number(amountStr);
    const mult = unit === 'd' ? 86400 : unit === 'h' ? 3600 : 60;
    const sec = Number.isFinite(n) && n > 0 ? Math.min(Math.max(Math.floor(n * mult), 60), 180 * 86400) : 0;
    updateGroupCaAssignmentField(caId, { autoRenewBeforeSeconds: sec });
  }

  async function handleSaveGroup(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    const trimmedName = grpName.trim();
    if (!trimmedName) {
      setError(tr('Bitte geben Sie einen Gruppennamen an.', 'Please enter a group name.'));
      return;
    }

    const normalizedAssignments: GroupCaAssignment[] = grpPermissions.caSigningAssignments.map((a) => {
      const val = (a.validity || '+30d').trim() || '+30d';
      const lead = isForeverValidity(val)
        ? 0
        : typeof a.autoRenewBeforeSeconds === 'number' && a.autoRenewBeforeSeconds > 0
          ? Math.floor(a.autoRenewBeforeSeconds)
          : 0;
      return {
        caId: a.caId,
        principals: parsePrincipalsDraft(grpCaPrincipalsDrafts[a.caId] ?? a.principals.join(', ')),
        includeOwnerPrincipal: Boolean(a.includeOwnerPrincipal),
        validity: val,
        autoRenewBeforeSeconds: lead,
      };
    });

    for (const a of normalizedAssignments) {
      const caLabel = caNameById.get(a.caId)?.name || a.caId;
      if (a.principals.length === 0 && !a.includeOwnerPrincipal) {
        setError(
          tr(
            `Für die zugewiesene CA „${caLabel}“ muss mindestens ein Principal (-n) angegeben oder der automatische Benutzername aktiviert sein.`,
            `For assigned CA "${caLabel}", specify at least one principal (-n) or enable automatic owner username.`
          )
        );
        return;
      }
      const fwdSec = parseValidityForwardSecondsClient(a.validity);
      if (fwdSec !== null && Number.isNaN(fwdSec)) {
        setError(
          tr(
            `Ungültige Gültigkeitsdauer (-V) für CA „${caLabel}“: „${a.validity}“. Erlaubt sind z. B. +8h, +24h, +7d, +30d, +52w oder forever.`,
            `Invalid validity (-V) for CA "${caLabel}": "${a.validity}". Examples: +8h, +24h, +7d, +30d, +52w, or forever.`
          )
        );
        return;
      }
      if (
        fwdSec !== null &&
        (a.autoRenewBeforeSeconds || 0) > 0 &&
        (a.autoRenewBeforeSeconds || 0) > Math.max(0, fwdSec - 60)
      ) {
        setError(
          tr(
            `Für die CA „${caLabel}“ muss der Zeitpunkt für die automatische Neusignierung kürzer sein als die Gültigkeitsdauer (${a.validity}).`,
            `For CA "${caLabel}", the automatic re-signing lead time must be shorter than the signature validity (${a.validity}).`
          )
        );
        return;
      }
    }

    const payloadPermissions: GroupPermissions = {
      ...grpPermissions,
      caSigningAssignments: normalizedAssignments,
    };

    setSavingGroup(true);
    try {
      if (editingGroupId) {
        const res = await api.updateGroup(editingGroupId, {
          ...(editingGroupObj?.isSystem ? {} : { name: trimmedName }),
          description: grpDescription.trim(),
          permissions: payloadPermissions,
        });
        await Promise.all([onRefreshGroups(), onRefresh()]);
        cancelGroupForm();
        setSuccess(
          tr(
            `Benutzergruppe „${res.group.name}“ und ihre Rechte wurden aktualisiert.`,
            `User group "${res.group.name}" and its permissions have been updated.`
          )
        );
      } else {
        const res = await api.createGroup({
          name: trimmedName,
          description: grpDescription.trim(),
          permissions: payloadPermissions,
        });
        await onRefreshGroups();
        cancelGroupForm();
        setSuccess(
          tr(
            `Benutzergruppe „${res.group.name}“ wurde erstellt.`,
            `User group "${res.group.name}" has been created.`
          )
        );
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Benutzergruppe konnte nicht gespeichert werden.', 'Could not save user group.')
      );
    } finally {
      setSavingGroup(false);
    }
  }

  async function handleDeleteGroup(g: UserGroup) {
    setError(null);
    setSuccess(null);
    setDeletingGroupId(g.id);
    try {
      const res = await api.deleteGroup(g.id);
      setConfirmDeleteGroupId(null);
      if (editingGroupId === g.id) {
        cancelGroupForm();
      }
      await Promise.all([onRefreshGroups(), onRefresh()]);
      setSuccess(
        res.reassignedUsers > 0
          ? tr(
              `Gruppe „${g.name}“ wurde gelöscht. ${res.reassignedUsers} Benutzer wurden automatisch der Gruppe „Benutzer“ zugewiesen.`,
              `Group "${g.name}" was deleted. ${res.reassignedUsers} user(s) were automatically reassigned to "Benutzer".`
            )
          : tr(`Gruppe „${g.name}“ wurde gelöscht.`, `Group "${g.name}" was deleted.`)
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Benutzergruppe konnte nicht gelöscht werden.', 'Could not delete user group.')
      );
    } finally {
      setDeletingGroupId(null);
    }
  }

  function countEnabledPermissions(perms: GroupPermissions): number {
    return CAPABILITY_PERMISSION_KEYS.filter((k) => Boolean(perms[k])).length;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
            {tr('Benutzer & Benutzergruppen', 'Users & User Groups')}
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            {tr(
              'Verwalten Sie Benutzerkonten, legen Sie eigene Benutzergruppen an und steuern Sie feingranulare Rechte pro Gruppe.',
              'Manage user accounts, create custom user groups, and configure granular permissions per group.'
            )}
          </p>
        </div>

        {/* Sub-tab switcher */}
        <div className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-md self-start shrink-0">
          <button
            type="button"
            onClick={() => {
              setActiveSubTab('users');
              setError(null);
            }}
            className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
              activeSubTab === 'users'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Users className="w-3.5 h-3.5" />
            {tr(`Benutzer (${users.length})`, `Users (${users.length})`)}
          </button>
          <button
            type="button"
            onClick={() => {
              setActiveSubTab('groups');
              setError(null);
            }}
            className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
              activeSubTab === 'groups'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            {tr(`Benutzergruppen & Rechte (${groups.length})`, `Groups & Permissions (${groups.length})`)}
          </button>
        </div>
      </div>

      {error && (
        <div role="alert" className="px-4 py-3 rounded-md bg-red-50 border border-red-200 text-sm text-red-800">
          {error}
        </div>
      )}

      {success && (
        <div className="px-4 py-3 rounded-md bg-emerald-50 border border-emerald-200 text-sm text-emerald-900 flex items-center justify-between gap-3">
          <span>{success}</span>
          <button
            type="button"
            onClick={() => setSuccess(null)}
            className="text-emerald-700 hover:text-emerald-950 cursor-pointer shrink-0"
            aria-label={tr('Meldung schließen', 'Dismiss')}
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {activeSubTab === 'users' ? (
        <div className="space-y-8">
          {/* Create User Form */}
          <form onSubmit={handleCreateUser} className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
            <h2 className="font-display text-base font-semibold text-slate-900">
              {tr('Neuen Benutzer anlegen', 'Create New User')}
            </h2>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-12 gap-4">
              <div className="lg:col-span-2">
                <label htmlFor="usr-name" className="block text-xs font-medium text-slate-700 mb-1.5">
                  {tr('Benutzername', 'Username')}
                </label>
                <input
                  id="usr-name"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="m.mueller"
                  className="w-full px-3 py-2 text-sm font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                  required
                />
              </div>

              <div className="lg:col-span-3">
                <label htmlFor="usr-display" className="block text-xs font-medium text-slate-700 mb-1.5">
                  {tr('Anzeigename', 'Display Name')}
                </label>
                <input
                  id="usr-display"
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder={tr('Max Müller', 'Jane Doe')}
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </div>

              <div className="lg:col-span-3">
                <label htmlFor="usr-pass" className="block text-xs font-medium text-slate-700 mb-1.5">
                  {tr('Initialpasswort (min. 8 Zeichen)', 'Initial Password (min. 8 chars)')}
                </label>
                <input
                  id="usr-pass"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  minLength={8}
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                  required
                />
              </div>

              <div className="lg:col-span-2">
                <label htmlFor="usr-group" className="block text-xs font-medium text-slate-700 mb-1.5">
                  {tr('Benutzergruppe', 'User Group')}
                </label>
                <select
                  id="usr-group"
                  value={groupId}
                  onChange={(e) => setGroupId(e.target.value)}
                  className="w-full px-3 py-2 text-sm bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                >
                  {sortedGroups.length > 0 ? (
                    sortedGroups.map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name}
                        {g.isAdmin ? ' (Admin)' : ''}
                      </option>
                    ))
                  ) : (
                    <>
                      <option value="user">{tr('Benutzer', 'User')}</option>
                      <option value="admin">{tr('Administratoren', 'Administrators')}</option>
                    </>
                  )}
                </select>
              </div>

              <div className="lg:col-span-2">
                <label htmlFor="usr-ssh" className="block text-xs font-medium text-slate-700 mb-1.5">
                  {tr('Standard-SSH-User', 'Default SSH User')}
                </label>
                <input
                  id="usr-ssh"
                  type="text"
                  value={defaultSshUser}
                  onChange={(e) => setDefaultSshUser(e.target.value)}
                  placeholder="root"
                  className="w-full px-3 py-2 text-sm font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </div>
            </div>

            <PasswordStrengthHint password={password} compact />

            <div className="flex flex-wrap items-center justify-between gap-3">
              <button
                type="button"
                onClick={() => {
                  setActiveSubTab('groups');
                  startCreateGroup();
                }}
                className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-700 hover:text-blue-900 cursor-pointer"
              >
                <SlidersHorizontal className="w-3.5 h-3.5" />
                {tr('Neue Benutzergruppe & Rechte definieren', 'Define new user group & permissions')}
              </button>
              <button
                type="submit"
                disabled={saving}
                className="inline-flex items-center gap-1.5 px-5 py-2 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                <UserPlus className="w-4 h-4" />
                {saving ? tr('Wird angelegt...', 'Creating...') : tr('Benutzer anlegen', 'Create User')}
              </button>
            </div>
          </form>

          {/* Users Table */}
          <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-200">
              <h2 className="font-display text-base font-semibold text-slate-900">
                {tr(`Angelegte Konten (${users.length})`, `Existing Accounts (${users.length})`)}
              </h2>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                    <th className="py-2.5 px-6">{tr('Benutzer', 'User')}</th>
                    <th className="py-2.5 px-4">{tr('Benutzergruppe', 'User Group')}</th>
                    <th className="py-2.5 px-4">{tr('Anmeldung & 2FA', 'Auth & 2FA')}</th>
                    <th className="py-2.5 px-4">{tr('Standard-SSH', 'Default SSH')}</th>
                    <th className="py-2.5 px-4">{tr('Letzte Anmeldung', 'Last Sign-in')}</th>
                    <th className="py-2.5 px-4">{tr('Status', 'Status')}</th>
                    <th className="py-2.5 px-6 text-right">{tr('Aktionen', 'Actions')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 text-sm">
                  {users.map((u) => {
                    const isSelf = u.id === currentUser.id;
                    const isResetting = resetUserId === u.id;
                    const hasFactors = u.totpEnabled || u.securityKeyCount > 0 || u.passkeyCount > 0;
                    const currentGid = u.groupId || (u.role === 'admin' ? 'admin' : 'user');
                    const isUpdatingGroup = updatingGroupUserId === u.id;
                    return (
                      <tr key={u.id} className="hover:bg-slate-50/80 transition-colors">
                        <td className="py-3 px-6">
                          <p className="font-medium text-slate-900">
                            {u.displayName}
                            {isSelf && (
                              <span className="text-xs text-slate-500 font-normal">
                                {' '}
                                {tr('(Sie)', '(You)')}
                              </span>
                            )}
                          </p>
                          <p className="text-xs font-mono text-slate-500">
                            {u.username}
                            {u.email ? ` · ${u.email}` : ''}
                          </p>
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          {isSelf ? (
                            <span
                              className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-800"
                              title={tr(
                                'Sie können Ihre eigene Administrator-Gruppe nicht herabstufen.',
                                'You cannot change your own administrator group.'
                              )}
                            >
                              <Lock className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                              {u.groupName || 'Administratoren'}
                            </span>
                          ) : (
                            <select
                              aria-label={tr(
                                `Benutzergruppe für ${u.username}`,
                                `User group for ${u.username}`
                              )}
                              value={currentGid}
                              disabled={isUpdatingGroup}
                              onChange={(e) => handleChangeUserGroup(u, e.target.value)}
                              className="px-2.5 py-1 text-xs bg-white border border-slate-300 rounded-md text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:opacity-50 cursor-pointer"
                            >
                              {sortedGroups.map((g) => (
                                <option key={g.id} value={g.id}>
                                  {g.name}
                                  {g.isAdmin ? ' (Admin)' : ''}
                                </option>
                              ))}
                            </select>
                          )}
                        </td>
                        <td className="py-3 px-4 text-xs text-slate-600 whitespace-nowrap">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="font-medium text-slate-800">
                              {u.authProvider === 'sso' ? 'SSO' : tr('Lokal', 'Local')}
                            </span>
                            {u.totpEnabled && <span className="text-emerald-700">· App-2FA</span>}
                            {u.securityKeyCount > 0 && (
                              <span className="text-emerald-700">· Key ({u.securityKeyCount})</span>
                            )}
                            {u.passkeyCount > 0 && (
                              <span className="text-blue-700">· Passkey ({u.passkeyCount})</span>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-4 font-mono text-xs text-slate-700 whitespace-nowrap">
                          {u.defaultSshUser}
                        </td>
                        <td className="py-3 px-4 font-mono text-xs text-slate-600 tabular-nums whitespace-nowrap">
                          {formatDateTime(u.lastLoginAt, { emptyText: tr('Noch nie', 'Never') })}
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          <button
                            type="button"
                            disabled={isSelf}
                            onClick={() => handleToggleActive(u)}
                            className={`text-xs font-medium ${
                              isSelf
                                ? 'text-emerald-700 cursor-default'
                                : u.active
                                ? 'text-emerald-700 hover:text-emerald-900 cursor-pointer'
                                : 'text-red-700 hover:text-red-900 cursor-pointer'
                            }`}
                          >
                            {u.active ? tr('Aktiv', 'Active') : tr('Gesperrt', 'Disabled')}
                          </button>
                        </td>
                        <td className="py-3 px-6 text-right whitespace-nowrap">
                          {isResetting ? (
                            <div className="inline-flex flex-col items-end gap-1.5 text-left whitespace-normal">
                              <div className="inline-flex items-center gap-2">
                                <input
                                  type="password"
                                  value={resetPasswordVal}
                                  onChange={(e) => setResetPasswordVal(e.target.value)}
                                  placeholder={tr('Neues Passwort...', 'New password...')}
                                  className="px-2.5 py-1 text-xs border border-slate-300 rounded w-44 focus:outline-none focus:ring-2 focus:ring-blue-600"
                                />
                                <button
                                  type="button"
                                  onClick={() => handleResetPassword(u.id)}
                                  className="p-1 text-emerald-700 hover:bg-emerald-50 rounded cursor-pointer"
                                  title={tr('Speichern', 'Save')}
                                >
                                  <Check className="w-4 h-4" />
                                </button>
                                <button
                                  type="button"
                                  onClick={() => {
                                    setResetUserId(null);
                                    setResetPasswordVal('');
                                  }}
                                  className="p-1 text-slate-500 hover:bg-slate-100 rounded cursor-pointer"
                                  title={tr('Abbrechen', 'Cancel')}
                                >
                                  <X className="w-4 h-4" />
                                </button>
                              </div>
                              <div className="w-72 max-w-full">
                                <PasswordStrengthHint password={resetPasswordVal} compact />
                              </div>
                            </div>
                          ) : (
                            <div className="inline-flex items-center gap-3">
                              {u.authProvider !== 'sso' && (
                                <button
                                  type="button"
                                  onClick={() => {
                                    setResetUserId(u.id);
                                    setResetPasswordVal('');
                                  }}
                                  className="inline-flex items-center gap-1 text-xs font-medium text-slate-700 hover:text-blue-700 cursor-pointer"
                                >
                                  <KeyRound className="w-3.5 h-3.5" />
                                  {tr('Passwort', 'Password')}
                                </button>
                              )}
                              {hasFactors && (
                                <button
                                  type="button"
                                  onClick={() => handleResetAuth(u)}
                                  className="inline-flex items-center gap-1 text-xs font-medium text-amber-800 hover:text-amber-950 cursor-pointer"
                                  title={tr('2FA und Passkeys zurücksetzen', 'Reset 2FA and Passkeys')}
                                >
                                  <ShieldOff className="w-3.5 h-3.5" />
                                  {tr('2FA/Passkey Reset', 'Reset 2FA/Passkey')}
                                </button>
                              )}
                              {!isSelf && (
                                <button
                                  type="button"
                                  onClick={() => handleDeleteUser(u)}
                                  className="inline-flex items-center gap-1 text-xs font-medium text-red-700 hover:text-red-900 cursor-pointer"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                  {tr('Löschen', 'Delete')}
                                </button>
                              )}
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Toolbar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <p className="text-xs text-slate-600">
              {tr(
                'Änderungen an Gruppenrechten wirken sofort für alle zugewiesenen Benutzer. Die Systemgruppe „Administratoren“ ist aus Sicherheitsgründen fest gesperrt.',
                'Permission changes take effect immediately for all assigned users. The system group "Administratoren" is permanently locked for security.'
              )}
            </p>
            {!showGroupForm && (
              <button
                type="button"
                onClick={startCreateGroup}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0 self-start sm:self-auto"
              >
                <Plus className="w-3.5 h-3.5" />
                {tr('Neue Benutzergruppe anlegen', 'Create User Group')}
              </button>
            )}
          </div>

          {/* Create / Edit Group Form */}
          {showGroupForm && (
            <form
              onSubmit={handleSaveGroup}
              className="bg-white border border-blue-200 rounded-lg p-6 space-y-6 shadow-xs"
            >
              <div className="flex items-center justify-between gap-4 pb-4 border-b border-slate-200">
                <div>
                  <h2 className="font-display text-base font-semibold text-slate-900">
                    {editingGroupId
                      ? tr(
                          `Benutzergruppe „${editingGroupObj?.name || grpName}“ bearbeiten`,
                          `Edit User Group "${editingGroupObj?.name || grpName}"`
                        )
                      : tr('Neue benutzerdefinierte Gruppe anlegen', 'Create Custom User Group')}
                  </h2>
                  <p className="text-xs text-slate-500 mt-0.5">
                    {editingGroupObj?.isSystem
                      ? tr(
                          'Sie können die Rechte und Beschreibung der Standardgruppe „Benutzer“ anpassen.',
                          'You can adjust the permissions and description of the default "Benutzer" group.'
                        )
                      : tr(
                          'Wählen Sie genau aus, welche Aktionen Mitglieder dieser Gruppe durchführen dürfen.',
                          'Select precisely which actions members of this group are allowed to perform.'
                        )}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={cancelGroupForm}
                  className="p-1.5 text-slate-500 hover:text-slate-900 hover:bg-slate-100 rounded-md cursor-pointer"
                  aria-label={tr('Schließen', 'Close')}
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="grp-name" className="block text-xs font-medium text-slate-700 mb-1.5">
                    {tr('Gruppenname', 'Group Name')}
                  </label>
                  <input
                    id="grp-name"
                    type="text"
                    value={grpName}
                    onChange={(e) => setGrpName(e.target.value)}
                    disabled={Boolean(editingGroupObj?.isSystem)}
                    maxLength={60}
                    placeholder={tr('z. B. Operatoren, Entwickler, Read-Only', 'e.g. Operators, Developers, Read-Only')}
                    className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:bg-slate-100 disabled:text-slate-500"
                    required
                  />
                </div>
                <div>
                  <label htmlFor="grp-desc" className="block text-xs font-medium text-slate-700 mb-1.5">
                    {tr('Beschreibung (optional)', 'Description (optional)')}
                  </label>
                  <input
                    id="grp-desc"
                    type="text"
                    value={grpDescription}
                    onChange={(e) => setGrpDescription(e.target.value)}
                    maxLength={240}
                    placeholder={tr(
                      'z. B. Darf Befehle ausführen und Protokolle lesen, aber keine eigenen IPs anlegen.',
                      'e.g. May run commands and view logs, but cannot add own IPs.'
                    )}
                    className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                  />
                </div>
              </div>

              {/* Quick permission presets */}
              <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                <span className="text-xs font-semibold text-slate-800 flex items-center gap-1.5">
                  <CheckSquare className="w-3.5 h-3.5 text-blue-700" />
                  {tr(
                    `Berechtigungen (${countEnabledPermissions(grpPermissions)} / ${CAPABILITY_PERMISSION_KEYS.length} Rechte aktiv)`,
                    `Permissions (${countEnabledPermissions(grpPermissions)} / ${CAPABILITY_PERMISSION_KEYS.length} rights enabled)`
                  )}
                </span>
                <div className="flex flex-wrap items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() =>
                      setGrpPermissions((prev) => ({
                        ...ALL_PERMISSIONS,
                        caSigningAssignments: prev.caSigningAssignments,
                      }))
                    }
                    className="px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded transition-colors cursor-pointer"
                  >
                    {tr('Alle Rechte', 'All Rights')}
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      setGrpPermissions((prev) => ({
                        ...DEFAULT_USER_PERMISSIONS,
                        caSigningAssignments: prev.caSigningAssignments,
                      }))
                    }
                    className="px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded transition-colors cursor-pointer"
                  >
                    {tr('Standard-Benutzer', 'Default User')}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setGrpPermissions({ ...MINIMAL_OPERATOR_PERMISSIONS, caSigningAssignments: [] });
                      setGrpCaPrincipalsDrafts({});
                    }}
                    className="px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded transition-colors cursor-pointer"
                  >
                    {tr('Minimal (Nur Ausführen)', 'Minimal (Execute Only)')}
                  </button>
                </div>
              </div>

              {/* Permission matrix */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {PERMISSION_SECTIONS.map((section) => (
                  <div
                    key={section.titleEn}
                    className="border border-slate-200 rounded-md p-4 space-y-3 bg-slate-50/40"
                  >
                    <h3 className="text-xs font-semibold text-slate-900 pb-2 border-b border-slate-200">
                      {tr(section.titleDe, section.titleEn)}
                    </h3>
                    <div className="space-y-2.5">
                      {section.items.map((item) => {
                        const checked = Boolean(grpPermissions[item.key]);
                        return (
                          <label
                            key={item.key}
                            className="flex items-start gap-2.5 cursor-pointer group"
                          >
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={() => togglePermission(item.key)}
                              className="mt-0.5 rounded border-slate-300 text-blue-700 focus:ring-blue-600 cursor-pointer"
                            />
                            <div className="min-w-0">
                              <p className="text-xs font-medium text-slate-900 group-hover:text-blue-800">
                                {tr(item.labelDe, item.labelEn)}
                              </p>
                              <p className="text-[11px] text-slate-500 mt-0.5 leading-snug">
                                {tr(item.descDe, item.descEn)}
                              </p>
                            </div>
                          </label>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>

              {/* Assigned CAs & Principals (-n) for Self-Signing */}
              <div
                className={`border rounded-md p-4 space-y-3 ${
                  grpPermissions.selfSignCertificates
                    ? 'border-blue-200 bg-blue-50/30'
                    : 'border-slate-200 bg-slate-50/40'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-slate-200">
                  <div className="flex items-center gap-2">
                    <FileSignature className="w-4 h-4 text-blue-700 shrink-0" />
                    <div>
                        <h3 className="text-xs font-semibold text-slate-900">
                        {tr(
                          `Zugewiesene CAs, Principals (-n), Gültigkeit (-V) & Auto-Neusignierung (${grpPermissions.caSigningAssignments.length})`,
                          `Assigned CAs, Principals (-n), Validity (-V) & Auto-Renewal (${grpPermissions.caSigningAssignments.length})`
                        )}
                      </h3>
                      <p className="text-[11px] text-slate-500">
                        {tr(
                          'Wählen Sie eine oder mehrere CAs und legen Sie pro CA die erlaubten Principals (-n), die Signatur-Gültigkeit (-V) und den Zeitpunkt für die automatische Neusignierung fest. Benutzer können diese Werte nicht eigenständig überschreiben.',
                          'Select one or more CAs and define allowed principals (-n), signature validity (-V), and when automatic re-signing may start per CA. Users cannot override these values.'
                        )}
                      </p>
                    </div>
                  </div>
                  {!grpPermissions.selfSignCertificates && (
                    <span className="px-2 py-0.5 text-[11px] font-medium rounded bg-slate-200 text-slate-700">
                      {tr(
                        'Selbstsignierung derzeit deaktiviert',
                        'Self-signing currently disabled'
                      )}
                    </span>
                  )}
                </div>

                {casLoading && availableCas.length === 0 ? (
                  <p className="text-xs text-slate-500">
                    {tr('CAs werden geladen...', 'Loading CAs...')}
                  </p>
                ) : availableCas.length === 0 ? (
                  <div className="px-3 py-2.5 rounded-md bg-amber-50 border border-amber-200 text-xs text-amber-900 flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                    <span>
                      {tr(
                        'Noch keine SSH-CAs vorhanden. Legen Sie zuerst unter „Administration → CA-Zertifikate“ eine CA mit hinterlegtem Passwort an.',
                        'No SSH CAs configured yet. Create a CA with a stored passphrase under "Administration → CA Certificates" first.'
                      )}
                    </span>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {availableCas.map((ca) => {
                      const assignment = grpPermissions.caSigningAssignments.find(
                        (a) => a.caId === ca.id
                      );
                      const isAssigned = Boolean(assignment);
                      const draft =
                        grpCaPrincipalsDrafts[ca.id] ??
                        (assignment ? assignment.principals.join(', ') : '');
                      const currentValidity = assignment?.validity || '+30d';
                      const isCustomVal = Boolean(
                        grpCaCustomValidity[ca.id] ||
                          !CA_VALIDITY_PRESETS.includes(
                            currentValidity as (typeof CA_VALIDITY_PRESETS)[number]
                          )
                      );
                      const currentLead = assignment?.autoRenewBeforeSeconds || 0;
                      const customLeadState = grpCaCustomLead[ca.id];
                      const isCustomLead = Boolean(
                        customLeadState?.enabled ||
                          !CA_AUTO_RENEW_LEAD_PRESETS.includes(
                            currentLead as (typeof CA_AUTO_RENEW_LEAD_PRESETS)[number]
                          )
                      );
                      const validityForever = isForeverValidity(currentValidity);
                      const validityFwdSec = parseValidityForwardSecondsClient(currentValidity);
                      const leadTooLong =
                        !validityForever &&
                        validityFwdSec !== null &&
                        !Number.isNaN(validityFwdSec) &&
                        currentLead > 0 &&
                        currentLead > Math.max(0, validityFwdSec - 60);

                      return (
                        <div
                          key={ca.id}
                          className={`rounded-md border p-3.5 space-y-3 transition-colors ${
                            isAssigned
                              ? 'bg-white border-blue-300 shadow-2xs'
                              : 'bg-white/60 border-slate-200'
                          }`}
                        >
                          <div className="flex flex-wrap items-start justify-between gap-2">
                            <label className="flex items-start gap-2.5 cursor-pointer min-w-0">
                              <input
                                type="checkbox"
                                checked={isAssigned}
                                onChange={() => toggleGroupCaAssignment(ca.id)}
                                className="mt-0.5 rounded border-slate-300 text-blue-700 focus:ring-blue-600 cursor-pointer"
                              />
                              <div className="min-w-0">
                                <p className="text-xs font-semibold text-slate-900">
                                  {ca.name}{' '}
                                  <span className="font-mono font-normal text-slate-500">
                                    ({ca.keyType})
                                  </span>
                                </p>
                                <p className="text-[11px] font-mono text-slate-500 truncate">
                                  {ca.fingerprint}
                                </p>
                              </div>
                            </label>

                            {ca.hasStoredPassphrase ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-[11px] font-medium text-emerald-800 shrink-0">
                                <CheckCircle2 className="w-3 h-3" />
                                {tr('CA-Passwort hinterlegt', 'CA passphrase stored')}
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-50 border border-amber-300 text-[11px] font-medium text-amber-900 shrink-0">
                                <AlertTriangle className="w-3 h-3 text-amber-600" />
                                {tr(
                                  'Passwort nicht hinterlegt (für Selbstsignierung nötig)',
                                  'Passphrase not stored (required for self-signing)'
                                )}
                              </span>
                            )}
                          </div>

                          {isAssigned && assignment && (
                            <div className="pt-2.5 border-t border-slate-200 space-y-3">
                              <div className="space-y-1.5">
                                <label
                                  htmlFor={`grp-ca-principals-${ca.id}`}
                                  className="block text-[11px] font-medium text-slate-700"
                                >
                                  {tr(
                                    'Principals (-n · erlaubte SSH-Benutzer, kommagetrennt)',
                                    'Principals (-n · allowed SSH usernames, comma-separated)'
                                  )}
                                </label>
                                <input
                                  id={`grp-ca-principals-${ca.id}`}
                                  type="text"
                                  value={draft}
                                  onChange={(e) =>
                                    updateGroupCaPrincipalsDraft(ca.id, e.target.value)
                                  }
                                  placeholder="deploy, admin, debian"
                                  className="w-full px-2.5 py-1.5 text-xs font-mono bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                                />
                                <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                                  <span className="text-slate-500">
                                    {tr('Schnellwahl:', 'Quick add:')}
                                  </span>
                                  {['root', 'admin', 'debian', 'ubuntu'].map((tok) => (
                                    <button
                                      key={tok}
                                      type="button"
                                      onClick={() => appendGroupCaPrincipalToken(ca.id, tok)}
                                      className="px-1.5 py-0.5 font-mono text-slate-700 bg-slate-100 hover:bg-slate-200 rounded border border-slate-200 cursor-pointer"
                                    >
                                      + {tok}
                                    </button>
                                  ))}
                                </div>
                                <label className="flex items-center gap-2 pt-1 text-[11px] text-slate-700 cursor-pointer">
                                  <input
                                    type="checkbox"
                                    checked={assignment.includeOwnerPrincipal}
                                    onChange={(e) =>
                                      updateGroupCaAssignmentField(ca.id, {
                                        includeOwnerPrincipal: e.target.checked,
                                      })
                                    }
                                    className="w-3.5 h-3.5 rounded border-slate-300 text-blue-700 focus:ring-blue-600 cursor-pointer"
                                  />
                                  <span>
                                    {tr(
                                      'Eigenen Benutzernamen des Anwenders automatisch zu -n hinzufügen',
                                      'Automatically include the signing user’s own username in -n'
                                    )}
                                  </span>
                                </label>
                              </div>

                              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-slate-100">
                                {/* Per-CA & Per-Group Signature Validity (-V) */}
                                <div className="space-y-1.5">
                                  <label
                                    htmlFor={`grp-ca-validity-${ca.id}`}
                                    className="block text-[11px] font-medium text-slate-700"
                                  >
                                    {tr(
                                      'Gültigkeit der Signatur (-V · pro CA & Gruppe)',
                                      'Signature Validity (-V · per CA & group)'
                                    )}
                                  </label>
                                  <select
                                    id={`grp-ca-validity-${ca.id}`}
                                    value={isCustomVal ? '__custom__' : currentValidity}
                                    onChange={(e) => {
                                      const val = e.target.value;
                                      if (val === '__custom__') {
                                        setGrpCaCustomValidity((prev) => ({
                                          ...prev,
                                          [ca.id]: true,
                                        }));
                                      } else {
                                        setGrpCaCustomValidity((prev) => ({
                                          ...prev,
                                          [ca.id]: false,
                                        }));
                                        updateGroupCaAssignmentField(ca.id, {
                                          validity: val,
                                          ...(isForeverValidity(val)
                                            ? { autoRenewBeforeSeconds: 0 }
                                            : {}),
                                        });
                                      }
                                    }}
                                    className="w-full px-2.5 py-1.5 text-xs bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                                  >
                                    <option value="+1h">{tr('1 Stunde (+1h)', '1 Hour (+1h)')}</option>
                                    <option value="+8h">{tr('8 Stunden (+8h)', '8 Hours (+8h)')}</option>
                                    <option value="+24h">{tr('24 Stunden (+24h)', '24 Hours (+24h)')}</option>
                                    <option value="+3d">{tr('3 Tage (+3d)', '3 Days (+3d)')}</option>
                                    <option value="+7d">{tr('7 Tage (+7d)', '7 Days (+7d)')}</option>
                                    <option value="+14d">{tr('14 Tage (+14d)', '14 Days (+14d)')}</option>
                                    <option value="+30d">{tr('30 Tage (+30d)', '30 Days (+30d)')}</option>
                                    <option value="+90d">{tr('90 Tage (+90d)', '90 Days (+90d)')}</option>
                                    <option value="+52w">{tr('1 Jahr (+52w)', '1 Year (+52w)')}</option>
                                    <option value="forever">
                                      {tr('Unbegrenzt (forever)', 'Forever (no expiry)')}
                                    </option>
                                    <option value="__custom__">
                                      {tr('Benutzerdefiniert (z. B. +12h, +45d)...', 'Custom (e.g. +12h, +45d)...')}
                                    </option>
                                  </select>
                                  {isCustomVal && (
                                    <div className="space-y-1">
                                      <input
                                        type="text"
                                        value={currentValidity}
                                        onChange={(e) =>
                                          updateGroupCaAssignmentField(ca.id, {
                                            validity: e.target.value,
                                          })
                                        }
                                        placeholder="+12h, +45d, +2w"
                                        className="w-full px-2.5 py-1.5 text-xs font-mono bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                                      />
                                      {validityFwdSec !== null && Number.isNaN(validityFwdSec) && (
                                        <p className="text-[11px] text-red-700">
                                          {tr(
                                            'Ungültiges Format. Beispiel: +30m, +12h, +14d, +4w.',
                                            'Invalid format. Example: +30m, +12h, +14d, +4w.'
                                          )}
                                        </p>
                                      )}
                                    </div>
                                  )}
                                </div>

                                {/* Per-CA & Per-Group Auto-Renewal Lead Time */}
                                <div className="space-y-1.5">
                                  <label
                                    htmlFor={`grp-ca-autorenew-${ca.id}`}
                                    className="block text-[11px] font-medium text-slate-700"
                                  >
                                    {tr(
                                      'Automatisch neusignieren ab (pro CA & Gruppe)',
                                      'Auto re-sign allowed from (per CA & group)'
                                    )}
                                  </label>
                                  <select
                                    id={`grp-ca-autorenew-${ca.id}`}
                                    disabled={validityForever}
                                    value={
                                      validityForever
                                        ? '0'
                                        : isCustomLead
                                          ? '__custom__'
                                          : String(currentLead)
                                    }
                                    onChange={(e) => {
                                      const val = e.target.value;
                                      if (val === '__custom__') {
                                        const split = splitLeadSecondsToCustom(
                                          currentLead > 0 ? currentLead : 86400
                                        );
                                        updateCustomLeadInput(ca.id, split.amount, split.unit);
                                      } else {
                                        setGrpCaCustomLead((prev) => ({
                                          ...prev,
                                          [ca.id]: {
                                            enabled: false,
                                            amount: prev[ca.id]?.amount || '24',
                                            unit: prev[ca.id]?.unit || 'h',
                                          },
                                        }));
                                        updateGroupCaAssignmentField(ca.id, {
                                          autoRenewBeforeSeconds: Number(val),
                                        });
                                      }
                                    }}
                                    className="w-full px-2.5 py-1.5 text-xs bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:bg-slate-100 disabled:text-slate-400"
                                  >
                                    <option value="0">
                                      {tr(
                                        'Automatisch (ab 20 % vor Ablauf)',
                                        'Automatic (from 20% before expiry)'
                                      )}
                                    </option>
                                    <option value="900">
                                      {tr('Ab 15 Minuten vor Ablauf', 'From 15 minutes before expiry')}
                                    </option>
                                    <option value="1800">
                                      {tr('Ab 30 Minuten vor Ablauf', 'From 30 minutes before expiry')}
                                    </option>
                                    <option value="3600">
                                      {tr('Ab 1 Stunde vor Ablauf', 'From 1 hour before expiry')}
                                    </option>
                                    <option value="7200">
                                      {tr('Ab 2 Stunden vor Ablauf', 'From 2 hours before expiry')}
                                    </option>
                                    <option value="21600">
                                      {tr('Ab 6 Stunden vor Ablauf', 'From 6 hours before expiry')}
                                    </option>
                                    <option value="43200">
                                      {tr('Ab 12 Stunden vor Ablauf', 'From 12 hours before expiry')}
                                    </option>
                                    <option value="86400">
                                      {tr('Ab 24 Stunden vor Ablauf', 'From 24 hours before expiry')}
                                    </option>
                                    <option value="172800">
                                      {tr('Ab 2 Tage vor Ablauf', 'From 2 days before expiry')}
                                    </option>
                                    <option value="259200">
                                      {tr('Ab 3 Tage vor Ablauf', 'From 3 days before expiry')}
                                    </option>
                                    <option value="604800">
                                      {tr('Ab 7 Tage vor Ablauf', 'From 7 days before expiry')}
                                    </option>
                                    <option value="1209600">
                                      {tr('Ab 14 Tage vor Ablauf', 'From 14 days before expiry')}
                                    </option>
                                    <option value="2592000">
                                      {tr('Ab 30 Tage vor Ablauf', 'From 30 days before expiry')}
                                    </option>
                                    <option value="__custom__">
                                      {tr('Benutzerdefiniert...', 'Custom...')}
                                    </option>
                                  </select>

                                  {!validityForever && isCustomLead && (
                                    <div className="flex items-center gap-2">
                                      <input
                                        type="number"
                                        min={1}
                                        max={180 * 1440}
                                        value={
                                          customLeadState?.amount ??
                                          splitLeadSecondsToCustom(currentLead).amount
                                        }
                                        onChange={(e) =>
                                          updateCustomLeadInput(
                                            ca.id,
                                            e.target.value,
                                            customLeadState?.unit ??
                                              splitLeadSecondsToCustom(currentLead).unit
                                          )
                                        }
                                        className="w-24 px-2.5 py-1.5 text-xs font-mono bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                                      />
                                      <select
                                        value={
                                          customLeadState?.unit ??
                                          splitLeadSecondsToCustom(currentLead).unit
                                        }
                                        onChange={(e) =>
                                          updateCustomLeadInput(
                                            ca.id,
                                            customLeadState?.amount ??
                                              splitLeadSecondsToCustom(currentLead).amount,
                                            e.target.value as 'm' | 'h' | 'd'
                                          )
                                        }
                                        className="flex-1 px-2.5 py-1.5 text-xs bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                                      >
                                        <option value="m">
                                          {tr('Minuten vor Ablauf', 'Minutes before expiry')}
                                        </option>
                                        <option value="h">
                                          {tr('Stunden vor Ablauf', 'Hours before expiry')}
                                        </option>
                                        <option value="d">
                                          {tr('Tage vor Ablauf', 'Days before expiry')}
                                        </option>
                                      </select>
                                    </div>
                                  )}

                                  {validityForever ? (
                                    <p className="text-[11px] text-slate-500">
                                      {tr(
                                        'Bei unbegrenzter Gültigkeit (forever) nicht erforderlich.',
                                        'Not applicable for unlimited validity (forever).'
                                      )}
                                    </p>
                                  ) : leadTooLong ? (
                                    <p className="text-[11px] text-red-700 font-medium">
                                      {tr(
                                        `Muss kürzer als die Gültigkeit (${currentValidity}) sein.`,
                                        `Must be shorter than the validity (${currentValidity}).`
                                      )}
                                    </p>
                                  ) : !grpPermissions.autoRenewCertificates ? (
                                    <p className="text-[11px] text-slate-500">
                                      {tr(
                                        'Greift, sobald „Automatische Neuzertifizierung erlauben“ aktiv ist.',
                                        'Applies once "Allow automatic re-certification" is enabled.'
                                      )}
                                    </p>
                                  ) : null}
                                </div>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-200">
                <button
                  type="button"
                  onClick={cancelGroupForm}
                  className="px-4 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer"
                >
                  {tr('Abbrechen', 'Cancel')}
                </button>
                <button
                  type="submit"
                  disabled={savingGroup}
                  className="inline-flex items-center gap-1.5 px-5 py-2 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                >
                  <Check className="w-3.5 h-3.5" />
                  {savingGroup
                    ? tr('Speichert...', 'Saving...')
                    : editingGroupId
                    ? tr('Änderungen speichern', 'Save Changes')
                    : tr('Benutzergruppe erstellen', 'Create Group')}
                </button>
              </div>
            </form>
          )}

          {/* Group List Cards */}
          <div className="space-y-4">
            {sortedGroups.map((g) => {
              const memberCount = memberCountByGroup.get(g.id) ?? 0;
              const enabledCount = countEnabledPermissions(g.permissions);
              const isConfirmingDelete = confirmDeleteGroupId === g.id;
              return (
                <article
                  key={g.id}
                  className={`bg-white border rounded-lg p-5 space-y-4 ${
                    g.isImmutable ? 'border-slate-300 bg-slate-50/30' : 'border-slate-200'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                    <div className="min-w-0 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="font-display text-base font-semibold text-slate-900 flex items-center gap-1.5">
                          {g.isImmutable && <Lock className="w-4 h-4 text-slate-600 shrink-0" />}
                          <span>{g.name}</span>
                        </h3>
                        {g.isImmutable ? (
                          <span className="px-2 py-0.5 text-[11px] font-medium rounded bg-slate-800 text-white">
                            {tr('System · Geschützt', 'System · Locked')}
                          </span>
                        ) : g.isSystem ? (
                          <span className="px-2 py-0.5 text-[11px] font-medium rounded bg-blue-50 text-blue-800 border border-blue-200">
                            {tr('Standardgruppe', 'Default Group')}
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 text-[11px] font-medium rounded bg-slate-100 text-slate-700 border border-slate-200">
                            {tr('Benutzerdefiniert', 'Custom')}
                          </span>
                        )}
                        <span className="text-xs font-mono text-slate-500 tabular-nums">
                          · {memberCount}{' '}
                          {memberCount === 1 ? tr('Mitglied', 'member') : tr('Mitglieder', 'members')}
                        </span>
                        <span className="text-xs font-mono text-slate-500 tabular-nums">
                          · {enabledCount}/{CAPABILITY_PERMISSION_KEYS.length} {tr('Rechte', 'rights')}
                        </span>
                      </div>
                      {g.description && (
                        <p className="text-xs text-slate-600">{g.description}</p>
                      )}
                      {g.isImmutable && (
                        <p className="text-xs text-slate-500">
                          {tr(
                            'Aus Sicherheitsgründen kann die Gruppe „Administratoren“ weder bearbeitet noch gelöscht werden. Mitglieder erhalten immer vollen administrativen Zugriff.',
                            'For security reasons, the "Administratoren" group cannot be edited or deleted. Members always have full administrative access.'
                          )}
                        </p>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-2 shrink-0">
                      {g.isImmutable ? (
                        <span className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-500 bg-slate-100 border border-slate-200 rounded-md">
                          <Lock className="w-3.5 h-3.5" />
                          {tr('Nicht veränderbar', 'Immutable')}
                        </span>
                      ) : (
                        <>
                          <button
                            type="button"
                            onClick={() => startEditGroup(g)}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                          >
                            <Pencil className="w-3.5 h-3.5" />
                            {tr('Rechte bearbeiten', 'Edit Permissions')}
                          </button>

                          {!g.isSystem &&
                            (isConfirmingDelete ? (
                              <div className="inline-flex items-center gap-1.5">
                                <button
                                  type="button"
                                  disabled={deletingGroupId === g.id}
                                  onClick={() => handleDeleteGroup(g)}
                                  className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-white bg-red-700 hover:bg-red-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                  {deletingGroupId === g.id
                                    ? tr('Löscht...', 'Deleting...')
                                    : memberCount > 0
                                    ? tr(
                                        `Löschen (${memberCount} → Benutzer)`,
                                        `Delete (${memberCount} → Benutzer)`
                                      )
                                    : tr('Endgültig löschen', 'Confirm Delete')}
                                </button>
                                <button
                                  type="button"
                                  disabled={deletingGroupId === g.id}
                                  onClick={() => setConfirmDeleteGroupId(null)}
                                  className="px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md cursor-pointer"
                                >
                                  {tr('Abbrechen', 'Cancel')}
                                </button>
                              </div>
                            ) : (
                              <button
                                type="button"
                                onClick={() => setConfirmDeleteGroupId(g.id)}
                                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-700 bg-red-50 hover:bg-red-100 border border-red-200 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                                {tr('Löschen', 'Delete')}
                              </button>
                            ))}
                        </>
                      )}
                    </div>
                  </div>

                  {/* Compact permissions overview grid */}
                  <div className="pt-3 border-t border-slate-200 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-4 gap-y-1.5 text-xs">
                    {PERMISSION_SECTIONS.flatMap((s) => s.items).map((item) => {
                      if (item.isPolicy) {
                        const activePolicy = !g.isAdmin && Boolean(g.permissions[item.key]);
                        return (
                          <div
                            key={item.key}
                            className={`flex items-center gap-1.5 ${
                              activePolicy ? 'text-amber-900 font-medium' : 'text-slate-400'
                            }`}
                          >
                            <Lock
                              className={`w-3.5 h-3.5 shrink-0 ${
                                activePolicy ? 'text-amber-700' : 'text-slate-300'
                              }`}
                            />
                            <span className="truncate">
                              {activePolicy
                                ? tr(item.labelDe, item.labelEn)
                                : tr('Zertifikat-Passwort optional', 'Certificate passphrase optional')}
                            </span>
                          </div>
                        );
                      }
                      const granted = g.isAdmin || Boolean(g.permissions[item.key]);
                      return (
                        <div
                          key={item.key}
                          className={`flex items-center gap-1.5 ${
                            granted ? 'text-slate-800' : 'text-slate-400 line-through'
                          }`}
                        >
                          {granted ? (
                            <Check className="w-3.5 h-3.5 text-emerald-700 shrink-0" />
                          ) : (
                            <X className="w-3.5 h-3.5 text-slate-300 shrink-0" />
                          )}
                          <span className="truncate">{tr(item.labelDe, item.labelEn)}</span>
                        </div>
                      );
                    })}
                  </div>

                  {/* Assigned CAs summary on group card */}
                  {!g.isAdmin &&
                    Array.isArray(g.permissions?.caSigningAssignments) &&
                    g.permissions.caSigningAssignments.length > 0 && (
                      <div className="pt-2.5 border-t border-slate-200 space-y-1.5">
                        <p className="text-[11px] font-semibold text-slate-700 flex items-center gap-1.5">
                          <FileSignature className="w-3.5 h-3.5 text-blue-700 shrink-0" />
                          {tr(
                            `Zugewiesene CAs für Selbstsignierung (${g.permissions.caSigningAssignments.length}):`,
                            `Assigned CAs for Self-Signing (${g.permissions.caSigningAssignments.length}):`
                          )}
                        </p>
                        <div className="flex flex-wrap gap-2">
                          {g.permissions.caSigningAssignments.map((a) => {
                            const caObj = caNameById.get(a.caId);
                            const principalParts = [
                              ...(a.principals || []),
                              ...(a.includeOwnerPrincipal
                                ? [tr('<Benutzername>', '<username>')]
                                : []),
                            ];
                            return (
                              <div
                                key={a.caId}
                                className="inline-flex flex-wrap items-center gap-1.5 px-2.5 py-1 rounded-md bg-blue-50/70 border border-blue-200 text-[11px] text-slate-800"
                              >
                                <span className="font-semibold text-blue-950">
                                  {caObj ? caObj.name : a.caId}
                                </span>
                                <span className="font-mono text-slate-600">
                                  -n {principalParts.join(', ') || '—'}
                                </span>
                                <span className="font-mono text-slate-500">
                                  · -V {a.validity || '+30d'}
                                </span>
                                {!isForeverValidity(a.validity || '+30d') && (
                                  <span className="text-emerald-800">
                                    · {tr('Auto-Erneuerung:', 'Auto-renew:')}{' '}
                                    {formatLeadLabel(a.autoRenewBeforeSeconds || 0)}
                                  </span>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}
                </article>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
