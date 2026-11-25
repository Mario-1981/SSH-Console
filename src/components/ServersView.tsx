import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Plus,
  Trash2,
  Search,
  Server,
  Share2,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Pencil,
  X,
  Activity,
  Ban,
  RotateCcw,
  Tag,
  Check,
  SlidersHorizontal,
} from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { ShareDialog, formatShareSummary } from './ShareDialog';
import { BulkServersDialog, type BulkServersPayload } from './BulkSettingsDialogs';
import type { AppSettings, BmcCheckResult, ServerCategory, ShareableUser, User, UserServer } from '../types';

interface ServersViewProps {
  user: User;
  users: ShareableUser[];
  servers: UserServer[];
  globalPingAllowed?: boolean;
  allowInsecureHostKey?: boolean;
  onUpdateSettings?: (settings: AppSettings) => void;
  onRefresh: () => Promise<void>;
}

function formatBmcUrl(ipAddress: string): string {
  const clean = ipAddress.trim();
  const host = clean.includes(':') ? `[${clean}]` : clean;
  return `https://${host}`;
}

export function ServersView({
  user,
  users,
  servers,
  globalPingAllowed = true,
  allowInsecureHostKey = false,
  onUpdateSettings,
  onRefresh,
}: ServersViewProps) {
  const { locale, tr } = useI18n();
  const isAdmin = user.role === 'admin';
  const canManageServers = isAdmin || user.permissions?.manageOwnServers !== false;
  const canShare = isAdmin || Boolean(user.permissions?.shareResources);
  const canBulkModify = canManageServers || canShare;
  const [editingId, setEditingId] = useState<string | null>(null);
  const [label, setLabel] = useState('');
  const [ipAddress, setIpAddress] = useState('');
  const [bmcIpAddress, setBmcIpAddress] = useState('');
  const [bmcIpAddress2, setBmcIpAddress2] = useState('');
  const [port, setPort] = useState('22');
  const [sshUser, setSshUser] = useState(user.defaultSshUser || 'root');
  const [notes, setNotes] = useState('');
  const [pingEnabled, setPingEnabled] = useState(true);
  const [ignoreHostKey, setIgnoreHostKey] = useState(false);
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [savedCategories, setSavedCategories] = useState<ServerCategory[]>([]);
  const [newCategoryName, setNewCategoryName] = useState('');
  const [inlineCategoryName, setInlineCategoryName] = useState('');
  const [creatingCategory, setCreatingCategory] = useState(false);
  const [deletingCategoryId, setDeletingCategoryId] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>('');
  const [shareOnCreate, setShareOnCreate] = useState(false);
  const [sharingServer, setSharingServer] = useState<UserServer | null>(null);
  const [search, setSearch] = useState('');
  const [saving, setSaving] = useState(false);
  const [togglingPingId, setTogglingPingId] = useState<string | null>(null);
  const [togglingHostKeyId, setTogglingHostKeyId] = useState<string | null>(null);
  const [resettingHostKeyId, setResettingHostKeyId] = useState<string | null>(null);
  const [togglingGlobalHostKey, setTogglingGlobalHostKey] = useState(false);
  const [confirmClearAllHostKeys, setConfirmClearAllHostKeys] = useState(false);
  const [clearingAllHostKeys, setClearingAllHostKeys] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [checkingBmcKey, setCheckingBmcKey] = useState<string | null>(null);
  const [bmcResults, setBmcResults] = useState<Record<string, BmcCheckResult>>({});
  const [selectedServerIds, setSelectedServerIds] = useState<string[]>([]);
  const [bulkDialogFocus, setBulkDialogFocus] = useState<'all' | 'categories' | 'sharing' | null>(null);
  const [bulkQuickBusy, setBulkQuickBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const loadCategories = useCallback(async () => {
    try {
      const res = await api.listServerCategories();
      setSavedCategories(res.categories);
    } catch {
      // ignore transient error
    }
  }, []);

  useEffect(() => {
    void loadCategories();
  }, [loadCategories]);

  const ownCategoryUsage = useMemo(() => {
    const counts = new Map<string, number>();
    for (const srv of servers) {
      if (srv.userId !== user.id) continue;
      for (const cat of srv.categories ?? []) {
        const key = cat.toLowerCase();
        counts.set(key, (counts.get(key) ?? 0) + 1);
      }
    }
    return counts;
  }, [servers, user.id]);

  const selectableCategories = useMemo(() => {
    const map = new Map<string, string>();
    for (const c of savedCategories) {
      const key = c.name.toLowerCase();
      if (!map.has(key)) map.set(key, c.name);
    }
    for (const srv of servers) {
      for (const cat of srv.categories ?? []) {
        const key = cat.toLowerCase();
        if (!map.has(key)) map.set(key, cat);
      }
    }
    for (const cat of selectedCategories) {
      const key = cat.toLowerCase();
      if (!map.has(key)) map.set(key, cat);
    }
    return Array.from(map.values()).sort((a, b) => a.localeCompare(b, locale));
  }, [savedCategories, servers, selectedCategories, locale]);

  const tableFilterCategories = useMemo(() => {
    const map = new Map<string, string>();
    for (const srv of servers) {
      for (const cat of srv.categories ?? []) {
        const key = cat.toLowerCase();
        if (!map.has(key)) map.set(key, cat);
      }
    }
    return Array.from(map.values()).sort((a, b) => a.localeCompare(b, locale));
  }, [servers, locale]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const catFilterLower = categoryFilter.toLowerCase();
    return servers.filter((s) => {
      const cats = s.categories ?? [];
      if (categoryFilter === '__uncategorized__') {
        if (cats.length > 0) return false;
      } else if (categoryFilter) {
        if (!cats.some((c) => c.toLowerCase() === catFilterLower)) return false;
      }
      if (!q) return true;
      return (
        s.label.toLowerCase().includes(q) ||
        s.ipAddress.toLowerCase().includes(q) ||
        (s.bmcIpAddress || '').toLowerCase().includes(q) ||
        (s.bmcIpAddress2 || '').toLowerCase().includes(q) ||
        s.sshUser.toLowerCase().includes(q) ||
        s.notes.toLowerCase().includes(q) ||
        cats.some((c) => c.toLowerCase().includes(q))
      );
    });
  }, [servers, search, categoryFilter]);

  // Keep selection synced with existing own servers
  useEffect(() => {
    const ownIdSet = new Set(servers.filter((s) => s.userId === user.id).map((s) => s.id));
    setSelectedServerIds((prev) => {
      const next = prev.filter((id) => ownIdSet.has(id));
      return next.length === prev.length ? prev : next;
    });
  }, [servers, user.id]);

  const filteredOwnServers = useMemo(
    () => filtered.filter((s) => s.userId === user.id),
    [filtered, user.id]
  );

  const selectedServers = useMemo(() => {
    const selSet = new Set(selectedServerIds);
    return servers.filter((s) => s.userId === user.id && selSet.has(s.id));
  }, [servers, user.id, selectedServerIds]);

  const allFilteredOwnSelected =
    filteredOwnServers.length > 0 &&
    filteredOwnServers.every((s) => selectedServerIds.includes(s.id));

  function toggleServerSelection(serverId: string) {
    setSelectedServerIds((prev) =>
      prev.includes(serverId) ? prev.filter((id) => id !== serverId) : [...prev, serverId]
    );
  }

  function toggleSelectAllFilteredOwn() {
    const ownIds = filteredOwnServers.map((s) => s.id);
    if (ownIds.length === 0) return;
    if (allFilteredOwnSelected) {
      const removeSet = new Set(ownIds);
      setSelectedServerIds((prev) => prev.filter((id) => !removeSet.has(id)));
    } else {
      setSelectedServerIds((prev) => Array.from(new Set([...prev, ...ownIds])));
    }
  }

  async function applyBulkServers(payload: BulkServersPayload) {
    if (selectedServerIds.length === 0) return;
    setError(null);
    setNotice(null);
    const res = await api.bulkUpdateServers({
      serverIds: selectedServerIds,
      ...payload,
    });
    await Promise.all([onRefresh(), loadCategories()]);
    setNotice(
      tr(
        `Sammeleinstellungen für ${res.updatedCount} Server (IPs) gespeichert.`,
        `Bulk settings saved for ${res.updatedCount} servers (IPs).`
      )
    );
  }

  async function handleQuickBulkServers(payload: BulkServersPayload) {
    setBulkQuickBusy(true);
    try {
      await applyBulkServers(payload);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Sammeleinstellung konnte nicht angewendet werden.', 'Could not apply bulk setting.')
      );
    } finally {
      setBulkQuickBusy(false);
    }
  }

  function toggleCategorySelection(categoryName: string) {
    const lower = categoryName.toLowerCase();
    setSelectedCategories((prev) =>
      prev.some((c) => c.toLowerCase() === lower)
        ? prev.filter((c) => c.toLowerCase() !== lower)
        : [...prev, categoryName]
    );
  }

  async function handleCreateCategory(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = newCategoryName.trim();
    if (!trimmed) return;
    setError(null);
    setCreatingCategory(true);
    try {
      await api.createServerCategory(trimmed);
      setNewCategoryName('');
      await loadCategories();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Kategorie konnte nicht angelegt werden.', 'Could not create category.')
      );
    } finally {
      setCreatingCategory(false);
    }
  }

  async function handleInlineAddCategory() {
    const trimmed = inlineCategoryName.trim();
    if (!trimmed) return;
    setError(null);
    setCreatingCategory(true);
    try {
      const res = await api.createServerCategory(trimmed);
      const canonical = res.category.name;
      setSelectedCategories((prev) =>
        prev.some((c) => c.toLowerCase() === canonical.toLowerCase()) ? prev : [...prev, canonical]
      );
      setInlineCategoryName('');
      await loadCategories();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Kategorie konnte nicht angelegt werden.', 'Could not create category.')
      );
    } finally {
      setCreatingCategory(false);
    }
  }

  async function handleDeleteCategory(cat: ServerCategory) {
    setDeletingCategoryId(cat.id);
    setError(null);
    try {
      await api.deleteServerCategory(cat.id);
      const lower = cat.name.toLowerCase();
      setSelectedCategories((prev) => prev.filter((c) => c.toLowerCase() !== lower));
      if (categoryFilter.toLowerCase() === lower) {
        setCategoryFilter('');
      }
      await Promise.all([loadCategories(), onRefresh()]);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Kategorie konnte nicht gelöscht werden.', 'Could not delete category.')
      );
    } finally {
      setDeletingCategoryId(null);
    }
  }

  function resetForm() {
    setEditingId(null);
    setLabel('');
    setIpAddress('');
    setBmcIpAddress('');
    setBmcIpAddress2('');
    setPort('22');
    setSshUser(user.defaultSshUser || 'root');
    setNotes('');
    setPingEnabled(true);
    setIgnoreHostKey(false);
    setSelectedCategories([]);
    setInlineCategoryName('');
    setShareOnCreate(false);
  }

  function startEdit(srv: UserServer) {
    setError(null);
    setEditingId(srv.id);
    setLabel(srv.label);
    setIpAddress(srv.ipAddress);
    setBmcIpAddress(srv.bmcIpAddress || '');
    setBmcIpAddress2(srv.bmcIpAddress2 || '');
    setPort(String(srv.port));
    setSshUser(srv.sshUser);
    setNotes(srv.notes || '');
    setPingEnabled(srv.pingEnabled !== false);
    setIgnoreHostKey(Boolean(srv.ignoreHostKey));
    setSelectedCategories(srv.categories ?? []);
    setInlineCategoryName('');
    setShareOnCreate(false);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSaving(true);
    try {
      if (editingId) {
        await api.updateServer(editingId, {
          label: label.trim() || ipAddress.trim(),
          ipAddress: ipAddress.trim(),
          bmcIpAddress: bmcIpAddress.trim(),
          bmcIpAddress2: bmcIpAddress2.trim(),
          port: Number(port) || 22,
          sshUser: sshUser.trim() || 'root',
          notes: notes.trim(),
          pingEnabled,
          ignoreHostKey,
          categories: selectedCategories,
        });
        // Clear stale BMC check results when IPs changed
        setBmcResults((prev) => {
          const next = { ...prev };
          delete next[`${editingId}:1`];
          delete next[`${editingId}:2`];
          return next;
        });
      } else {
        await api.createServer({
          label: label.trim() || ipAddress.trim(),
          ipAddress: ipAddress.trim(),
          bmcIpAddress: bmcIpAddress.trim(),
          bmcIpAddress2: bmcIpAddress2.trim(),
          port: Number(port) || 22,
          sshUser: sshUser.trim() || 'root',
          notes: notes.trim(),
          pingEnabled,
          ignoreHostKey: allowInsecureHostKey ? ignoreHostKey : false,
          categories: selectedCategories,
          ...(canShare && shareOnCreate ? { sharedWithAll: true, sharedWithUserIds: [] } : {}),
        });
      }
      await Promise.all([onRefresh(), loadCategories()]);
      resetForm();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Server konnte nicht gespeichert werden.', 'Could not save server.')
      );
    } finally {
      setSaving(false);
    }
  }

  async function handleCheckBmc(serverId: string, slot: 1 | 2) {
    const key = `${serverId}:${slot}`;
    setCheckingBmcKey(key);
    setError(null);
    try {
      const { result } = await api.checkServerBmc(serverId, slot);
      setBmcResults((prev) => ({ ...prev, [key]: result }));
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('BMC HTTPS-Prüfung fehlgeschlagen.', 'BMC HTTPS check failed.')
      );
    } finally {
      setCheckingBmcKey(null);
    }
  }

  async function handleTogglePing(srv: UserServer) {
    setTogglingPingId(srv.id);
    setError(null);
    try {
      await api.updateServer(srv.id, { pingEnabled: srv.pingEnabled === false });
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Ping-Einstellung konnte nicht geändert werden.', 'Could not update ping setting.')
      );
    } finally {
      setTogglingPingId(null);
    }
  }

  async function handleToggleHostKey(srv: UserServer) {
    setTogglingHostKeyId(srv.id);
    setError(null);
    try {
      await api.updateServer(srv.id, { ignoreHostKey: !srv.ignoreHostKey });
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr(
              'Host-Key-Einstellung konnte nicht geändert werden.',
              'Could not update host key setting.'
            )
      );
    } finally {
      setTogglingHostKeyId(null);
    }
  }

  async function handleToggleGlobalHostKey() {
    setTogglingGlobalHostKey(true);
    setError(null);
    try {
      const res = await api.updateAdminAuthSettings({
        allowInsecureHostKey: !allowInsecureHostKey,
      });
      onUpdateSettings?.(res.settings);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr(
              'Globale Host-Key-Richtlinie konnte nicht geändert werden.',
              'Could not update global host key policy.'
            )
      );
    } finally {
      setTogglingGlobalHostKey(false);
    }
  }

  async function handleResetServerHostKey(srv: UserServer) {
    setResettingHostKeyId(srv.id);
    setError(null);
    setNotice(null);
    try {
      const res = await api.resetHostKey({ serverId: srv.id });
      const targetLabel = res.port !== 22 ? `${res.ipAddress}:${res.port}` : res.ipAddress;
      setNotice(
        res.removedCount > 0
          ? tr(
              `Gespeicherter Host-Key für ${targetLabel} wurde gelöscht (${res.removedCount} Eintrag/Einträge entfernt). Beim nächsten Verbindungsaufbau wird der neue Host-Key akzeptiert.`,
              `Stored host key for ${targetLabel} was deleted (${res.removedCount} entry/entries removed). The new host key will be accepted on next connection.`
            )
          : tr(
              `Für ${targetLabel} war kein gespeicherter Host-Key in Ihrer known_hosts vorhanden.`,
              `No stored host key was found for ${targetLabel} in your known_hosts.`
            )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr(
              'Host-Key konnte nicht gelöscht werden.',
              'Could not delete host key.'
            )
      );
    } finally {
      setResettingHostKeyId(null);
    }
  }

  async function handleClearAllHostKeys() {
    setClearingAllHostKeys(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api.clearAllAdminHostKeys();
      setConfirmClearAllHostKeys(false);
      setNotice(
        res.removedCount > 0
          ? tr(
              `Global alle gespeicherten Host-Keys gelöscht (${res.removedCount} Einträge aus ${res.affectedFiles} Benutzer-known_hosts).`,
              `Globally cleared all stored host keys (${res.removedCount} entries across ${res.affectedFiles} user known_hosts files).`
            )
          : tr(
              'Es waren keine gespeicherten Host-Keys vorhanden.',
              'No stored host keys were present.'
            )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr(
              'Globale Host-Keys konnten nicht gelöscht werden.',
              'Could not clear global host keys.'
            )
      );
    } finally {
      setClearingAllHostKeys(false);
    }
  }

  async function handleDelete(id: string) {
    setDeletingId(id);
    setError(null);
    try {
      await api.deleteServer(id);
      if (editingId === id) resetForm();
      await onRefresh();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Server konnte nicht entfernt werden.', 'Could not delete server.')
      );
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          {tr('Meine Server (Ziel-IPs & BMC)', 'My Servers (Target IPs & BMC)')}
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
          {canShare
            ? tr(
                'Hinterlegen Sie Ziel-IPs und bis zu zwei optionale BMC-Adressen (HTTPS Port 443). Einträge sind standardmäßig privat und können mit anderen Benutzern geteilt werden.',
                'Store target server IPs and up to two optional BMC addresses (HTTPS port 443). Entries are private by default and can be shared with other users.'
              )
            : canManageServers
            ? tr(
                'Hinterlegen Sie die IP-Adressen Ihrer Zielserver sowie optional bis zu zwei BMC-IPs. Eigene Einträge sind nur für Sie sichtbar; geteilte Server stehen zusätzlich bereit.',
                'Store your target server IP addresses and up to two optional BMC IPs. Your own entries are visible only to you; shared servers are also available.'
              )
            : tr(
                'Übersicht der für Sie verfügbaren Zielserver. Das Anlegen und Bearbeiten eigener Server-IPs ist für Ihre Benutzergruppe deaktiviert.',
                'Overview of target servers available to you. Creating and editing own server IPs is disabled for your user group.'
              )}
        </p>
      </div>

      {error && (
        <div role="alert" className="px-4 py-3 rounded-md bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800/70 text-sm text-red-800 dark:text-red-300">
          {error}
        </div>
      )}

      {notice && (
        <div role="status" className="px-4 py-3 rounded-md bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/70 text-sm text-emerald-800 dark:text-emerald-300 flex items-center justify-between gap-3">
          <span>{notice}</span>
          <button
            type="button"
            onClick={() => setNotice(null)}
            className="text-emerald-700 dark:text-emerald-400 hover:text-emerald-950 dark:hover:text-emerald-200 cursor-pointer shrink-0"
            aria-label={tr('Meldung schließen', 'Dismiss notice')}
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {isAdmin && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-5 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-start gap-2.5 min-w-0">
            <ShieldAlert
              className={`w-4 h-4 shrink-0 mt-0.5 ${
                allowInsecureHostKey ? 'text-amber-600 dark:text-amber-400' : 'text-slate-500 dark:text-slate-400'
              }`}
            />
            <div className="text-xs">
              <p className="font-semibold text-slate-900 dark:text-slate-100">
                {tr(
                  'Admin-Richtlinie: Host-Key-Prüfung & known_hosts',
                  'Admin Policy: Host Key Checking & known_hosts'
                )}
              </p>
              <p className="text-slate-500 dark:text-slate-400 mt-0.5">
                {allowInsecureHostKey
                  ? tr(
                      'Zugelassen: Benutzer dürfen pro IP „StrictHostKeyChecking=no“ und „UserKnownHostsFile=/dev/null“ aktivieren.',
                      'Allowed: Users may enable StrictHostKeyChecking=no and UserKnownHostsFile=/dev/null per IP.'
                    )
                  : tr(
                      'Verboten (Standard): Die Host-Key-Prüfung wird global für alle Benutzer und IPs erzwungen.',
                      'Prohibited (default): Host key verification is globally enforced for all users and IPs.'
                    )}
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={handleToggleGlobalHostKey}
              disabled={togglingGlobalHostKey}
              className={`inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded-md border transition-colors cursor-pointer disabled:opacity-50 whitespace-nowrap shrink-0 ${
                allowInsecureHostKey
                  ? 'bg-amber-50 dark:bg-amber-950/40 text-amber-900 dark:text-amber-200 border-amber-300 dark:border-amber-700/80 hover:bg-amber-100 dark:hover:bg-amber-900/50'
                  : 'bg-slate-50 dark:bg-slate-800/60 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              {allowInsecureHostKey ? (
                <>
                  <ShieldAlert className="w-3.5 h-3.5 text-amber-700 dark:text-amber-400" />
                  {tr('Global zugelassen (Verbieten)', 'Globally Allowed (Prohibit)')}
                </>
              ) : (
                <>
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-700 dark:text-emerald-400" />
                  {tr('Global verboten (Zulassen)', 'Globally Prohibited (Allow)')}
                </>
              )}
            </button>

            {confirmClearAllHostKeys ? (
              <div className="inline-flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={handleClearAllHostKeys}
                  disabled={clearingAllHostKeys}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-red-700 hover:bg-red-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  {clearingAllHostKeys
                    ? tr('Löscht...', 'Clearing...')
                    : tr('Wirklich alle Host-Keys löschen?', 'Confirm clear all host keys?')}
                </button>
                <button
                  type="button"
                  onClick={() => setConfirmClearAllHostKeys(false)}
                  disabled={clearingAllHostKeys}
                  className="px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-md transition-colors cursor-pointer"
                >
                  {tr('Abbrechen', 'Cancel')}
                </button>
              </div>
            ) : (
              <button
                type="button"
                onClick={() => setConfirmClearAllHostKeys(true)}
                className="inline-flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-950/40 hover:bg-red-100 dark:hover:bg-red-900/50 border border-red-200 dark:border-red-800/70 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
                title={tr(
                  'Alle gespeicherten SSH-Host-Keys (known_hosts) global für sämtliche Benutzer löschen',
                  'Globally delete all stored SSH host keys (known_hosts) for all users'
                )}
              >
                <Trash2 className="w-3.5 h-3.5" />
                {tr('Alle Host-Keys löschen', 'Clear All Host Keys')}
              </button>
            )}
          </div>
        </div>
      )}

      {/* IP Categories Manager */}
      {canManageServers && (
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 space-y-3.5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-start gap-2.5 min-w-0">
            <Tag className="w-4 h-4 text-blue-700 dark:text-blue-400 shrink-0 mt-0.5" />
            <div>
              <h2 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                {tr('IP-Kategorien verwalten', 'Manage IP Categories')}
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {tr(
                  'Legen Sie Kategorien an (z. B. Produktion, Webserver, Datenbank), ordnen Sie jeder IP eine oder mehrere Kategorien zu und filtern Sie danach im Dashboard.',
                  'Define categories (e.g. Production, Web, Database), assign one or multiple categories to each IP, and filter by them on the Dashboard.'
                )}
              </p>
            </div>
          </div>

          <form onSubmit={handleCreateCategory} className="flex items-center gap-2 shrink-0">
            <input
              type="text"
              value={newCategoryName}
              onChange={(e) => setNewCategoryName(e.target.value)}
              maxLength={48}
              placeholder={tr('Neue Kategorie, z. B. Produktion', 'New category, e.g. Production')}
              className="w-52 sm:w-56 px-3 py-1.5 text-xs border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
            <button
              type="submit"
              disabled={creatingCategory || !newCategoryName.trim()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 dark:bg-slate-700 dark:hover:bg-slate-600 disabled:opacity-40 rounded-md transition-colors cursor-pointer whitespace-nowrap"
            >
              <Plus className="w-3.5 h-3.5" />
              {tr('Anlegen', 'Add')}
            </button>
          </form>
        </div>

        {savedCategories.length === 0 ? (
          <p className="text-xs text-slate-500 dark:text-slate-400">
            {tr(
              'Noch keine Kategorien angelegt. Erstellen Sie oben Ihre erste Kategorie oder direkt beim Anlegen einer IP.',
              'No categories created yet. Add your first category above or directly when adding an IP.'
            )}
          </p>
        ) : (
          <div className="flex flex-wrap items-center gap-2 pt-0.5">
            {savedCategories.map((cat) => {
              const count = ownCategoryUsage.get(cat.name.toLowerCase()) ?? 0;
              return (
                <span
                  key={cat.id}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-800 dark:text-slate-200 bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 rounded-md"
                >
                  <span>{cat.name}</span>
                  <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400 tabular-nums">
                    {count}
                  </span>
                  <button
                    type="button"
                    onClick={() => handleDeleteCategory(cat)}
                    disabled={deletingCategoryId === cat.id}
                    title={tr(
                      `Kategorie „${cat.name}“ löschen (wird auch von Ihren IPs entfernt)`,
                      `Delete category "${cat.name}" (also removed from your IPs)`
                    )}
                    className="ml-0.5 text-slate-400 hover:text-red-700 dark:hover:text-red-300 disabled:opacity-40 cursor-pointer transition-colors"
                    aria-label={tr(`Kategorie ${cat.name} löschen`, `Delete category ${cat.name}`)}
                  >
                    <X className="w-3 h-3" />
                  </button>
                </span>
              );
            })}
          </div>
        )}
      </section>
      )}

      {canManageServers && (
      <form onSubmit={handleSubmit} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 space-y-4">
        <div className="flex items-center justify-between gap-4">
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
            {editingId
              ? tr('Zielserver bearbeiten', 'Edit Target Server')
              : tr('Zielserver hinzufügen', 'Add Target Server')}
          </h2>
          {editingId && (
            <button
              type="button"
              onClick={resetForm}
              className="inline-flex items-center gap-1 text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
              {tr('Abbrechen', 'Cancel')}
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-12 gap-4">
          <div className="lg:col-span-3">
            <label htmlFor="srv-ip" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
              {tr('Server-IP (IPv4 / IPv6)', 'Server IP (IPv4 / IPv6)')}
            </label>
            <input
              id="srv-ip"
              type="text"
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              placeholder="192.168.10.24"
              className="w-full px-3 py-2 text-sm font-mono tabular-nums border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              required
            />
          </div>

          <div className="lg:col-span-3">
            <label htmlFor="srv-bmc-ip" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
              {tr('BMC-IP 1 (optional · HTTPS :443)', 'BMC IP 1 (optional · HTTPS :443)')}
            </label>
            <input
              id="srv-bmc-ip"
              type="text"
              value={bmcIpAddress}
              onChange={(e) => setBmcIpAddress(e.target.value)}
              placeholder="192.168.10.124"
              className="w-full px-3 py-2 text-sm font-mono tabular-nums border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          <div className="lg:col-span-3">
            <label htmlFor="srv-bmc-ip2" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
              {tr('BMC-IP 2 (optional · HTTPS :443)', 'BMC IP 2 (optional · HTTPS :443)')}
            </label>
            <input
              id="srv-bmc-ip2"
              type="text"
              value={bmcIpAddress2}
              onChange={(e) => setBmcIpAddress2(e.target.value)}
              placeholder="192.168.10.125"
              className="w-full px-3 py-2 text-sm font-mono tabular-nums border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          <div className="lg:col-span-3">
            <label htmlFor="srv-label" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
              {tr('Bezeichnung', 'Label')}
            </label>
            <input
              id="srv-label"
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="web-trixie-01"
              className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-12 gap-4 items-end">
          <div className="lg:col-span-2">
            <label htmlFor="srv-port" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
              {tr('SSH-Port', 'SSH Port')}
            </label>
            <input
              id="srv-port"
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(e) => setPort(e.target.value)}
              className="w-full px-3 py-2 text-sm font-mono tabular-nums border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              required
            />
          </div>

          <div className="lg:col-span-2">
            <label htmlFor="srv-sshuser" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
              {tr('SSH-Benutzer', 'SSH User')}
            </label>
            <input
              id="srv-sshuser"
              type="text"
              value={sshUser}
              onChange={(e) => setSshUser(e.target.value)}
              placeholder="root"
              className="w-full px-3 py-2 text-sm font-mono border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              required
            />
          </div>

          <div className="sm:col-span-2 lg:col-span-5">
            <label htmlFor="srv-notes" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
              {tr('Notiz (optional)', 'Notes (optional)')}
            </label>
            <input
              id="srv-notes"
              type="text"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder={tr(
                'z. B. Debian 13 Reverse-Proxy im Rechenzentrum Frankfurt · iDRAC/IPMI',
                'e.g. Debian 13 reverse proxy in Frankfurt DC · iDRAC/IPMI'
              )}
              className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          <div className="sm:col-span-2 lg:col-span-3">
            <button
              type="submit"
              disabled={saving}
              className="w-full inline-flex items-center justify-center gap-1.5 px-4 py-2 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
            >
              <Plus className="w-4 h-4" />
              {saving
                ? tr('Speichert...', 'Saving...')
                : editingId
                ? tr('Änderungen speichern', 'Save Changes')
                : tr('Hinzufügen', 'Add Server')}
            </button>
          </div>
        </div>

        {/* Multi-Category Assignment */}
        <div className="pt-2 border-t border-slate-100 dark:border-slate-800/70 space-y-2.5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <span className="text-xs font-medium text-slate-700 dark:text-slate-300">
              {tr('Kategorien zuordnen (Mehrfachauswahl)', 'Assign Categories (Multi-select)')}
              {selectedCategories.length > 0 && (
                <span className="ml-1.5 font-mono text-[11px] text-blue-700 dark:text-blue-400">
                  ({selectedCategories.length} {tr('gewählt', 'selected')})
                </span>
              )}
            </span>
            <div className="flex items-center gap-1.5">
              <input
                type="text"
                value={inlineCategoryName}
                onChange={(e) => setInlineCategoryName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    void handleInlineAddCategory();
                  }
                }}
                maxLength={48}
                placeholder={tr('Schnell neue Kategorie hinzufügen...', 'Quick add new category...')}
                className="w-48 sm:w-52 px-2.5 py-1 text-xs border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
              <button
                type="button"
                onClick={handleInlineAddCategory}
                disabled={creatingCategory || !inlineCategoryName.trim()}
                className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 disabled:opacity-40 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                <Plus className="w-3 h-3" />
                {tr('Hinzufügen', 'Add')}
              </button>
            </div>
          </div>

          {selectableCategories.length > 0 ? (
            <div className="flex flex-wrap items-center gap-1.5">
              {selectableCategories.map((catName) => {
                const isSelected = selectedCategories.some(
                  (c) => c.toLowerCase() === catName.toLowerCase()
                );
                return (
                  <button
                    key={catName}
                    type="button"
                    onClick={() => toggleCategorySelection(catName)}
                    className={`inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-md border transition-colors cursor-pointer ${
                      isSelected
                        ? 'bg-blue-50 dark:bg-blue-950/40 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-700/80'
                        : 'bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-600 hover:text-slate-900 dark:hover:text-slate-100'
                    }`}
                  >
                    {isSelected && <Check className="w-3 h-3 text-blue-700 dark:text-blue-400 shrink-0" />}
                    <span>{catName}</span>
                  </button>
                );
              })}
              {selectedCategories.length > 0 && (
                <button
                  type="button"
                  onClick={() => setSelectedCategories([])}
                  className="px-2 py-1 text-xs text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 cursor-pointer"
                >
                  {tr('Auswahl leeren', 'Clear')}
                </button>
              )}
            </div>
          ) : (
            <p className="text-xs text-slate-400">
              {tr(
                'Keine Kategorien vorhanden – geben Sie rechts einen Namen ein, um direkt eine Kategorie anzulegen und auszuwählen.',
                'No categories yet — type a name on the right to create and select one right away.'
              )}
            </p>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 pt-1">
          <label className="inline-flex items-center gap-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={pingEnabled}
              onChange={(e) => setPingEnabled(e.target.checked)}
              className="rounded border-slate-300 dark:border-slate-700 text-blue-700 dark:text-blue-400 focus:ring-blue-600"
            />
            <span>
              {tr(
                'Diese IP automatisch anpingen (Erreichbarkeitsprüfung)',
                'Auto-ping this IP (reachability check)'
              )}
              {!globalPingAllowed && (
                <span className="text-amber-700 dark:text-amber-400 ml-1.5">
                  ({tr('aktuell vom Admin global deaktiviert', 'currently disabled globally by admin')})
                </span>
              )}
            </span>
          </label>

          <label
            className={`inline-flex items-center gap-2 text-xs ${
              allowInsecureHostKey || ignoreHostKey
                ? 'text-slate-700 dark:text-slate-300 cursor-pointer'
                : 'text-slate-400 cursor-not-allowed'
            }`}
          >
            <input
              type="checkbox"
              checked={ignoreHostKey}
              disabled={!allowInsecureHostKey && !ignoreHostKey}
              onChange={(e) => setIgnoreHostKey(e.target.checked)}
              className="rounded border-slate-300 dark:border-slate-700 text-amber-600 dark:text-amber-400 focus:ring-amber-600 disabled:opacity-50"
            />
            <span>
              {tr(
                'Host-Key-Prüfung deaktivieren',
                'Disable Host Key Checking'
              )}{' '}
              <code className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                (StrictHostKeyChecking=no, UserKnownHostsFile=/dev/null)
              </code>
              {!allowInsecureHostKey && (
                <span className="text-amber-700 dark:text-amber-400 ml-1.5">
                  ({tr('vom Admin global verboten', 'globally prohibited by admin')})
                </span>
              )}
            </span>
          </label>

          {canShare && !editingId && (
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
      </form>
      )}

      {/* Server Table */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
            {tr(`Gespeicherte Zielserver (${filtered.length})`, `Saved Target Servers (${filtered.length})`)}
          </h2>
          <div className="flex flex-col sm:flex-row sm:items-center gap-2 w-full sm:w-auto">
            {tableFilterCategories.length > 0 && (
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                aria-label={tr('Nach Kategorie filtern', 'Filter by category')}
                className="w-full sm:w-48 px-3 py-1.5 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-600"
              >
                <option value="">{tr('Alle Kategorien', 'All categories')}</option>
                {tableFilterCategories.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat}
                  </option>
                ))}
                <option value="__uncategorized__">
                  {tr('Ohne Kategorie', 'Uncategorized')}
                </option>
              </select>
            )}
            <div className="relative w-full sm:w-64">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={tr('Nach IP, Kategorie oder Name filtern...', 'Filter by IP, category, or name...')}
                className="w-full pl-9 pr-3 py-1.5 text-sm border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
          </div>
        </div>

        {canBulkModify && selectedServers.length > 0 && (
          <div className="px-6 py-3 bg-blue-50/80 dark:bg-blue-950/40 border-b border-blue-200 dark:border-blue-800/70 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2.5 text-xs">
              <span className="font-semibold text-blue-950 dark:text-blue-200">
                {tr(
                  `${selectedServers.length} Server ausgewählt`,
                  `${selectedServers.length} servers selected`
                )}
              </span>
              <button
                type="button"
                onClick={() => setSelectedServerIds([])}
                className="text-blue-700 dark:text-blue-400 hover:text-blue-950 dark:hover:text-blue-200 underline cursor-pointer"
              >
                {tr('Auswahl aufheben', 'Clear selection')}
              </button>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {canManageServers && (
                <>
                  <button
                    type="button"
                    disabled={bulkQuickBusy}
                    onClick={() => handleQuickBulkServers({ pingEnabled: true })}
                    className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-emerald-900 dark:text-emerald-200 bg-white dark:bg-slate-900 border border-emerald-300 dark:border-emerald-700/80 hover:bg-emerald-50 dark:hover:bg-emerald-950/50 disabled:opacity-50 rounded-md transition-colors cursor-pointer"
                  >
                    <Activity className="w-3.5 h-3.5 text-emerald-700 dark:text-emerald-400" />
                    {tr('Ping an', 'Ping On')}
                  </button>
                  <button
                    type="button"
                    disabled={bulkQuickBusy}
                    onClick={() => handleQuickBulkServers({ pingEnabled: false })}
                    className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 disabled:opacity-50 rounded-md transition-colors cursor-pointer"
                  >
                    <Ban className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400" />
                    {tr('Ping aus', 'Ping Off')}
                  </button>
                  <button
                    type="button"
                    disabled={bulkQuickBusy}
                    onClick={() => setBulkDialogFocus('categories')}
                    className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800/60 disabled:opacity-50 rounded-md transition-colors cursor-pointer"
                  >
                    <Tag className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400" />
                    {tr('Kategorien', 'Categories')}
                  </button>
                </>
              )}
              {canShare && (
                <button
                  type="button"
                  disabled={bulkQuickBusy}
                  onClick={() => setBulkDialogFocus('sharing')}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-blue-800 dark:text-blue-300 bg-white dark:bg-slate-900 border border-blue-300 dark:border-blue-700/80 hover:bg-blue-50 dark:hover:bg-blue-950/50 disabled:opacity-50 rounded-md transition-colors cursor-pointer"
                >
                  <Share2 className="w-3.5 h-3.5 text-blue-700 dark:text-blue-400" />
                  {tr('Teilen', 'Share')}
                </button>
              )}
              {canManageServers && (
                <button
                  type="button"
                  disabled={bulkQuickBusy}
                  onClick={() => setBulkDialogFocus('all')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                >
                  <SlidersHorizontal className="w-3.5 h-3.5" />
                  {tr('Sammeleinstellungen...', 'Bulk Settings...')}
                </button>
              )}
            </div>
          </div>
        )}

        {filtered.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <Server className="w-7 h-7 text-slate-400 mx-auto mb-3" />
            <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
              {servers.length === 0
                ? tr('Noch keine Zielserver angelegt', 'No target servers added yet')
                : tr('Keine passenden Server gefunden', 'No matching servers found')}
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              {servers.length === 0
                ? tr(
                    'Fügen Sie oben eine IPv4- oder IPv6-Adresse (sowie optional eine BMC-IP) hinzu.',
                    'Add an IPv4 or IPv6 address (and an optional BMC IP) above.'
                  )
                : tr('Passen Sie Ihren Suchbegriff an.', 'Try adjusting your search query.')}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/60 text-xs font-medium text-slate-500 dark:text-slate-400">
                  {canBulkModify && (
                    <th className="py-2.5 pl-6 pr-2 w-10">
                      <input
                        type="checkbox"
                        checked={allFilteredOwnSelected}
                        disabled={filteredOwnServers.length === 0}
                        onChange={toggleSelectAllFilteredOwn}
                        aria-label={tr('Alle eigenen Server auswählen', 'Select all own servers')}
                        title={tr(
                          'Alle eigenen gefilterten Server auswählen / abwählen',
                          'Select / deselect all own filtered servers'
                        )}
                        className="rounded border-slate-300 dark:border-slate-700 text-blue-700 dark:text-blue-400 focus:ring-blue-600 disabled:opacity-40 cursor-pointer"
                      />
                    </th>
                  )}
                  <th className="py-2.5 px-4">{tr('Bezeichnung', 'Label')}</th>
                  <th className="py-2.5 px-4">{tr('Server-IP · SSH', 'Server IP · SSH')}</th>
                  <th className="py-2.5 px-4">BMC (HTTPS :443)</th>
                  <th className="py-2.5 px-4">Ping</th>
                  <th className="py-2.5 px-4">Host-Key</th>
                  <th className="py-2.5 px-4">{tr('Sichtbarkeit', 'Visibility')}</th>
                  <th className="py-2.5 px-4">{tr('Notiz', 'Notes')}</th>
                  <th className="py-2.5 px-6 text-right">{tr('Aktionen', 'Actions')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800 text-sm">
                {filtered.map((srv) => {
                  const isOwner = srv.userId === user.id;
                  const isSelected = selectedServerIds.includes(srv.id);
                  const shareLabel = isOwner
                    ? formatShareSummary(srv.sharedWithAll, srv.sharedWithUserIds, locale)
                    : tr(
                        `Geteilt von ${srv.ownerUsername || 'admin'}`,
                        `Shared by ${srv.ownerUsername || 'admin'}`
                      );
                  const bmcEntries: Array<{ slot: 1 | 2; ip: string }> = [];
                  if (srv.bmcIpAddress) bmcEntries.push({ slot: 1, ip: srv.bmcIpAddress });
                  if (srv.bmcIpAddress2) bmcEntries.push({ slot: 2, ip: srv.bmcIpAddress2 });

                  return (
                    <tr
                      key={srv.id}
                      className={`transition-colors ${
                        isSelected ? 'bg-blue-50/40 dark:bg-blue-950/30 hover:bg-blue-50/70 dark:hover:bg-blue-950/50' : 'hover:bg-slate-50/80 dark:hover:bg-slate-800/60'
                      }`}
                    >
                      {canBulkModify && (
                        <td className="py-3 pl-6 pr-2 w-10">
                          {isOwner ? (
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() => toggleServerSelection(srv.id)}
                              aria-label={tr(`${srv.label} auswählen`, `Select ${srv.label}`)}
                              className="rounded border-slate-300 dark:border-slate-700 text-blue-700 dark:text-blue-400 focus:ring-blue-600 cursor-pointer"
                            />
                          ) : (
                            <input
                              type="checkbox"
                              checked={false}
                              disabled
                              title={tr(
                                'Geteilte Server anderer Benutzer können nicht bearbeitet werden',
                                'Shared servers owned by other users cannot be modified'
                              )}
                              className="rounded border-slate-200 dark:border-slate-800 opacity-35 cursor-not-allowed"
                            />
                          )}
                        </td>
                      )}
                      <td className="py-3 px-4 font-medium text-slate-900 dark:text-slate-100">
                        <p className="whitespace-nowrap">{srv.label}</p>
                        {(srv.categories?.length ?? 0) > 0 && (
                          <div className="flex flex-wrap items-center gap-1 mt-1">
                            {(srv.categories ?? []).map((cat) => (
                              <button
                                key={cat}
                                type="button"
                                onClick={() =>
                                  setCategoryFilter((prev) =>
                                    prev.toLowerCase() === cat.toLowerCase() ? '' : cat
                                  )
                                }
                                title={tr(
                                  `Nach Kategorie „${cat}“ filtern`,
                                  `Filter by category "${cat}"`
                                )}
                                className={`px-1.5 py-0.5 text-[11px] font-medium rounded border transition-colors cursor-pointer ${
                                  categoryFilter.toLowerCase() === cat.toLowerCase()
                                    ? 'bg-blue-50 dark:bg-blue-950/40 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-700/80'
                                    : 'bg-slate-50 dark:bg-slate-800/60 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-600 hover:text-slate-900 dark:hover:text-slate-100'
                                }`}
                              >
                                {cat}
                              </button>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono text-xs text-slate-800 dark:text-slate-200 tabular-nums whitespace-nowrap">
                        <p>{srv.ipAddress}</p>
                        <p className="text-slate-500 dark:text-slate-400">
                          {srv.sshUser} · Port {srv.port}
                        </p>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        {bmcEntries.length > 0 ? (
                          <div className="space-y-2">
                            {bmcEntries.map(({ slot, ip }) => {
                              const key = `${srv.id}:${slot}`;
                              const bmcRes = bmcResults[key];
                              const isCheckingBmc = checkingBmcKey === key;
                              return (
                                <div key={slot} className="space-y-1">
                                  <div className="flex items-center gap-2.5">
                                    <span className="text-[11px] font-mono text-slate-400">
                                      BMC {slot}
                                    </span>
                                    <a
                                      href={formatBmcUrl(ip)}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      title={tr(
                                        `${formatBmcUrl(ip)} in neuem Tab öffnen`,
                                        `Open ${formatBmcUrl(ip)} in a new tab`
                                      )}
                                      className="inline-flex items-center gap-1 font-mono text-xs font-medium text-blue-700 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300 hover:underline tabular-nums"
                                    >
                                      <span>{ip}</span>
                                      <ExternalLink className="w-3 h-3 shrink-0" />
                                    </a>
                                    <button
                                      type="button"
                                      onClick={() => handleCheckBmc(srv.id, slot)}
                                      disabled={isCheckingBmc}
                                      title={tr(
                                        `BMC ${slot} über https:// Port 443 prüfen`,
                                        `Check BMC ${slot} over https:// port 443`
                                      )}
                                      className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 disabled:opacity-50 rounded transition-colors cursor-pointer"
                                    >
                                      {isCheckingBmc ? (
                                        <RefreshCw className="w-3 h-3 animate-spin" />
                                      ) : (
                                        <ShieldCheck className="w-3 h-3" />
                                      )}
                                      <span>
                                        {isCheckingBmc
                                          ? tr('Prüft...', 'Checking...')
                                          : tr('HTTPS :443 prüfen', 'Check HTTPS :443')}
                                      </span>
                                    </button>
                                  </div>
                                  {bmcRes && (
                                    <p
                                      className={`inline-flex items-center gap-1 text-[11px] font-mono tabular-nums ${
                                        bmcRes.reachable ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'
                                      }`}
                                      title={bmcRes.error || `${bmcRes.url} (${bmcRes.tlsProtocol || 'TLS'})`}
                                    >
                                      {bmcRes.reachable ? (
                                        <>
                                          <CheckCircle2 className="w-3 h-3 shrink-0" />
                                          <span>
                                            {tr('Erreichbar', 'Reachable')}
                                            {bmcRes.httpStatus ? ` · HTTP ${bmcRes.httpStatus}` : ''}
                                            {bmcRes.latencyMs !== null ? ` · ${bmcRes.latencyMs} ms` : ''}
                                          </span>
                                        </>
                                      ) : (
                                        <>
                                          <XCircle className="w-3 h-3 shrink-0" />
                                          <span>
                                            {bmcRes.error ||
                                              tr('Port 443 nicht erreichbar', 'Port 443 unreachable')}
                                          </span>
                                        </>
                                      )}
                                    </p>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        ) : (
                          <span className="text-xs text-slate-400">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-xs whitespace-nowrap">
                        {isOwner && canManageServers ? (
                          <button
                            type="button"
                            onClick={() => handleTogglePing(srv)}
                            disabled={togglingPingId === srv.id}
                            title={
                              srv.pingEnabled !== false
                                ? tr('Anpingen für diese IP deaktivieren', 'Disable pinging for this IP')
                                : tr('Anpingen für diese IP aktivieren', 'Enable pinging for this IP')
                            }
                            className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-medium transition-colors cursor-pointer disabled:opacity-50 ${
                              srv.pingEnabled !== false
                                ? 'text-emerald-800 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 hover:bg-emerald-100 dark:hover:bg-emerald-900/50'
                                : 'text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700'
                            }`}
                          >
                            {srv.pingEnabled !== false ? (
                              <>
                                <Activity className="w-3 h-3 shrink-0" />
                                <span>{tr('Aktiv', 'On')}</span>
                              </>
                            ) : (
                              <>
                                <Ban className="w-3 h-3 shrink-0" />
                                <span>{tr('Aus', 'Off')}</span>
                              </>
                            )}
                          </button>
                        ) : (
                          <span
                            className={`inline-flex items-center gap-1 font-medium ${
                              srv.pingEnabled !== false ? 'text-emerald-700 dark:text-emerald-400' : 'text-slate-500 dark:text-slate-400'
                            }`}
                          >
                            {srv.pingEnabled !== false ? (
                              <>
                                <Activity className="w-3 h-3 shrink-0" />
                                {tr('Aktiv', 'On')}
                              </>
                            ) : (
                              <>
                                <Ban className="w-3 h-3 shrink-0" />
                                {tr('Aus', 'Off')}
                              </>
                            )}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-xs whitespace-nowrap">
                        <div className="inline-flex items-center gap-1.5">
                          {isOwner && canManageServers && allowInsecureHostKey ? (
                            <button
                              type="button"
                              onClick={() => handleToggleHostKey(srv)}
                              disabled={togglingHostKeyId === srv.id}
                              title={
                                srv.ignoreHostKey
                                  ? tr(
                                      'StrictHostKeyChecking=no & UserKnownHostsFile=/dev/null aktiv – klicken zum Aktivieren der Host-Key-Prüfung',
                                      'StrictHostKeyChecking=no & UserKnownHostsFile=/dev/null active — click to re-enable host key checking'
                                    )
                                  : tr(
                                      'Host-Key-Prüfung aktiv (accept-new) – klicken für StrictHostKeyChecking=no & UserKnownHostsFile=/dev/null',
                                      'Host key checking active (accept-new) — click to set StrictHostKeyChecking=no & UserKnownHostsFile=/dev/null'
                                    )
                              }
                              className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-medium transition-colors cursor-pointer disabled:opacity-50 ${
                                srv.ignoreHostKey
                                  ? 'text-amber-900 dark:text-amber-200 bg-amber-100 dark:bg-amber-900/40 hover:bg-amber-200 dark:hover:bg-amber-900/60'
                                  : 'text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700'
                              }`}
                            >
                              {srv.ignoreHostKey ? (
                                <>
                                  <ShieldAlert className="w-3 h-3 shrink-0 text-amber-700 dark:text-amber-400" />
                                  <span>{tr('Ignorieren', 'Bypass')}</span>
                                </>
                              ) : (
                                <>
                                  <ShieldCheck className="w-3 h-3 shrink-0 text-emerald-700 dark:text-emerald-400" />
                                  <span>{tr('Prüfen', 'Verify')}</span>
                                </>
                              )}
                            </button>
                          ) : srv.ignoreHostKey && allowInsecureHostKey ? (
                            <span
                              title="StrictHostKeyChecking=no, UserKnownHostsFile=/dev/null"
                              className="inline-flex items-center gap-1 font-medium text-amber-800 dark:text-amber-300"
                            >
                              <ShieldAlert className="w-3 h-3 shrink-0 text-amber-700 dark:text-amber-400" />
                              {tr('Ignorieren', 'Bypass')}
                            </span>
                          ) : (
                            <span
                              title={
                                srv.ignoreHostKey && !allowInsecureHostKey
                                  ? tr(
                                      'Für diese IP vorgemerkt, aber global vom Admin verboten',
                                      'Configured on this IP, but globally prohibited by admin'
                                    )
                                  : 'StrictHostKeyChecking=accept-new'
                              }
                              className="inline-flex items-center gap-1 font-medium text-slate-600 dark:text-slate-400"
                            >
                              <ShieldCheck className="w-3 h-3 shrink-0 text-emerald-700 dark:text-emerald-400" />
                              {srv.ignoreHostKey && !allowInsecureHostKey
                                ? tr('Prüfen (Admin)', 'Verify (Admin)')
                                : tr('Prüfen', 'Verify')}
                            </span>
                          )}

                          {!(allowInsecureHostKey && srv.ignoreHostKey) && (
                            <button
                              type="button"
                              onClick={() => handleResetServerHostKey(srv)}
                              disabled={resettingHostKeyId === srv.id}
                              title={tr(
                                `Alten gespeicherten Host-Key für ${srv.ipAddress}${srv.port !== 22 ? `:${srv.port}` : ''} löschen`,
                                `Delete stored host key for ${srv.ipAddress}${srv.port !== 22 ? `:${srv.port}` : ''}`
                              )}
                              className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[11px] font-medium text-slate-600 dark:text-slate-400 hover:text-red-700 dark:hover:text-red-300 bg-slate-100 dark:bg-slate-800 hover:bg-red-50 dark:hover:bg-red-950/50 border border-slate-200 dark:border-slate-800 hover:border-red-200 dark:hover:border-red-800/70 rounded transition-colors cursor-pointer disabled:opacity-50"
                            >
                              <RotateCcw
                                className={`w-3 h-3 shrink-0 ${
                                  resettingHostKeyId === srv.id ? 'animate-spin' : ''
                                }`}
                              />
                              <span>{tr('Key löschen', 'Reset Key')}</span>
                            </button>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-xs whitespace-nowrap">
                        <span
                          className={
                            !isOwner || srv.sharedWithAll || srv.sharedWithUserIds.length > 0
                              ? 'text-blue-800 dark:text-blue-300 font-medium'
                              : 'text-slate-500 dark:text-slate-400'
                          }
                        >
                          {shareLabel}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-500 dark:text-slate-400 max-w-xs truncate">
                        {srv.notes || '—'}
                      </td>
                      <td className="py-3 px-6 text-right whitespace-nowrap">
                        {isOwner && (canManageServers || canShare) ? (
                          <div className="inline-flex items-center gap-3">
                            {canManageServers && (
                              <button
                                type="button"
                                onClick={() => startEdit(srv)}
                                className="inline-flex items-center gap-1 text-xs font-medium text-slate-700 dark:text-slate-300 hover:text-slate-950 dark:hover:text-slate-100 cursor-pointer"
                              >
                                <Pencil className="w-3.5 h-3.5" />
                                {tr('Bearbeiten', 'Edit')}
                              </button>
                            )}
                            {canShare && (
                              <button
                                type="button"
                                onClick={() => setSharingServer(srv)}
                                className="inline-flex items-center gap-1 text-xs font-medium text-blue-700 dark:text-blue-400 hover:text-blue-900 dark:hover:text-blue-300 cursor-pointer"
                              >
                                <Share2 className="w-3.5 h-3.5" />
                                {tr('Teilen', 'Share')}
                              </button>
                            )}
                            {canManageServers && (
                              <button
                                type="button"
                                onClick={() => handleDelete(srv.id)}
                                disabled={deletingId === srv.id}
                                className="inline-flex items-center gap-1 text-xs font-medium text-red-700 dark:text-red-400 hover:text-red-900 dark:hover:text-red-300 cursor-pointer"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                                {tr('Entfernen', 'Delete')}
                              </button>
                            )}
                          </div>
                        ) : (
                          <span className="text-xs text-slate-400">
                            {tr('Nur nutzen', 'Read-only')}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {sharingServer && canShare && (
        <ShareDialog
          title={tr('Zielserver (IP) teilen', 'Share Target Server (IP)')}
          itemName={`${sharingServer.label} (${sharingServer.sshUser}@${sharingServer.ipAddress}:${sharingServer.port})`}
          currentUserId={user.id}
          users={users}
          initialSharedWithAll={sharingServer.sharedWithAll}
          initialSharedWithUserIds={sharingServer.sharedWithUserIds}
          onClose={() => setSharingServer(null)}
          onSave={async (payload) => {
            await api.shareServer(sharingServer.id, payload);
            await onRefresh();
          }}
        />
      )}

      {bulkDialogFocus && selectedServers.length > 0 && canBulkModify && (
        <BulkServersDialog
          selectedServers={selectedServers}
          canShare={canShare}
          canManageServers={canManageServers}
          currentUserId={user.id}
          users={users}
          allowInsecureHostKey={allowInsecureHostKey}
          selectableCategories={selectableCategories}
          initialFocus={bulkDialogFocus}
          onCreateCategory={
            canManageServers
              ? async (name) => {
                  const res = await api.createServerCategory(name);
                  await loadCategories();
                  return res.category.name;
                }
              : undefined
          }
          onClose={() => setBulkDialogFocus(null)}
          onSave={applyBulkServers}
        />
      )}
    </div>
  );
}
