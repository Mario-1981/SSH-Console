import React, { useMemo, useState } from 'react';
import {
  Plus,
  Trash2,
  Search,
  Server,
  Share2,
  ExternalLink,
  ShieldCheck,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Pencil,
  X,
} from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { ShareDialog, formatShareSummary } from './ShareDialog';
import type { BmcCheckResult, User, UserServer } from '../types';

interface ServersViewProps {
  user: User;
  users: User[];
  servers: UserServer[];
  onRefresh: () => Promise<void>;
}

function formatBmcUrl(ipAddress: string): string {
  const clean = ipAddress.trim();
  const host = clean.includes(':') ? `[${clean}]` : clean;
  return `https://${host}`;
}

export function ServersView({ user, users, servers, onRefresh }: ServersViewProps) {
  const { locale, tr } = useI18n();
  const isAdmin = user.role === 'admin';
  const [editingId, setEditingId] = useState<string | null>(null);
  const [label, setLabel] = useState('');
  const [ipAddress, setIpAddress] = useState('');
  const [bmcIpAddress, setBmcIpAddress] = useState('');
  const [port, setPort] = useState('22');
  const [sshUser, setSshUser] = useState(user.defaultSshUser || 'root');
  const [notes, setNotes] = useState('');
  const [shareOnCreate, setShareOnCreate] = useState(false);
  const [sharingServer, setSharingServer] = useState<UserServer | null>(null);
  const [search, setSearch] = useState('');
  const [saving, setSaving] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [checkingBmcId, setCheckingBmcId] = useState<string | null>(null);
  const [bmcResults, setBmcResults] = useState<Record<string, BmcCheckResult>>({});
  const [error, setError] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return servers;
    return servers.filter(
      (s) =>
        s.label.toLowerCase().includes(q) ||
        s.ipAddress.toLowerCase().includes(q) ||
        (s.bmcIpAddress || '').toLowerCase().includes(q) ||
        s.sshUser.toLowerCase().includes(q) ||
        s.notes.toLowerCase().includes(q)
    );
  }, [servers, search]);

  function resetForm() {
    setEditingId(null);
    setLabel('');
    setIpAddress('');
    setBmcIpAddress('');
    setPort('22');
    setSshUser(user.defaultSshUser || 'root');
    setNotes('');
    setShareOnCreate(false);
  }

  function startEdit(srv: UserServer) {
    setError(null);
    setEditingId(srv.id);
    setLabel(srv.label);
    setIpAddress(srv.ipAddress);
    setBmcIpAddress(srv.bmcIpAddress || '');
    setPort(String(srv.port));
    setSshUser(srv.sshUser);
    setNotes(srv.notes || '');
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
          port: Number(port) || 22,
          sshUser: sshUser.trim() || 'root',
          notes: notes.trim(),
        });
        // Clear stale BMC check result when IP changed
        setBmcResults((prev) => {
          const next = { ...prev };
          delete next[editingId];
          return next;
        });
      } else {
        await api.createServer({
          label: label.trim() || ipAddress.trim(),
          ipAddress: ipAddress.trim(),
          bmcIpAddress: bmcIpAddress.trim(),
          port: Number(port) || 22,
          sshUser: sshUser.trim() || 'root',
          notes: notes.trim(),
          ...(isAdmin && shareOnCreate ? { sharedWithAll: true, sharedWithUserIds: [] } : {}),
        });
      }
      await onRefresh();
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

  async function handleCheckBmc(serverId: string) {
    setCheckingBmcId(serverId);
    setError(null);
    try {
      const { result } = await api.checkServerBmc(serverId);
      setBmcResults((prev) => ({ ...prev, [serverId]: result }));
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('BMC HTTPS-Prüfung fehlgeschlagen.', 'BMC HTTPS check failed.')
      );
    } finally {
      setCheckingBmcId(null);
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
        <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
          {tr('Meine Server (Ziel-IPs & BMC)', 'My Servers (Target IPs & BMC)')}
        </h1>
        <p className="text-sm text-slate-600 mt-1">
          {isAdmin
            ? tr(
                'Hinterlegen Sie Ziel-IPs und optionale BMC-Adressen (HTTPS Port 443). Einträge sind standardmäßig privat und können als Administrator mit anderen Benutzern geteilt werden.',
                'Store target server IPs and optional BMC addresses (HTTPS port 443). Entries are private by default and can be shared with other users as an administrator.'
              )
            : tr(
                'Hinterlegen Sie die IP-Adressen Ihrer Zielserver sowie optional eine zweite BMC-IP. Eigene Einträge sind nur für Sie sichtbar; vom Administrator geteilte Server stehen zusätzlich bereit.',
                'Store your target server IP addresses and an optional secondary BMC IP. Your own entries are visible only to you; servers shared by an administrator are also available.'
              )}
        </p>
      </div>

      {error && (
        <div role="alert" className="px-4 py-3 rounded-md bg-red-50 border border-red-200 text-sm text-red-800">
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
        <div className="flex items-center justify-between gap-4">
          <h2 className="font-display text-base font-semibold text-slate-900">
            {editingId
              ? tr('Zielserver bearbeiten', 'Edit Target Server')
              : tr('Zielserver hinzufügen', 'Add Target Server')}
          </h2>
          {editingId && (
            <button
              type="button"
              onClick={resetForm}
              className="inline-flex items-center gap-1 text-xs font-medium text-slate-600 hover:text-slate-900 cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
              {tr('Abbrechen', 'Cancel')}
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-12 gap-4">
          <div className="lg:col-span-3">
            <label htmlFor="srv-ip" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr('Server-IP (IPv4 / IPv6)', 'Server IP (IPv4 / IPv6)')}
            </label>
            <input
              id="srv-ip"
              type="text"
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              placeholder="192.168.10.24"
              className="w-full px-3 py-2 text-sm font-mono tabular-nums border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              required
            />
          </div>

          <div className="lg:col-span-3">
            <label htmlFor="srv-bmc-ip" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr('BMC-IP (optional · HTTPS :443)', 'BMC IP (optional · HTTPS :443)')}
            </label>
            <input
              id="srv-bmc-ip"
              type="text"
              value={bmcIpAddress}
              onChange={(e) => setBmcIpAddress(e.target.value)}
              placeholder="192.168.10.124"
              className="w-full px-3 py-2 text-sm font-mono tabular-nums border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          <div className="lg:col-span-2">
            <label htmlFor="srv-port" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr('SSH-Port', 'SSH Port')}
            </label>
            <input
              id="srv-port"
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(e) => setPort(e.target.value)}
              className="w-full px-3 py-2 text-sm font-mono tabular-nums border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              required
            />
          </div>

          <div className="lg:col-span-2">
            <label htmlFor="srv-sshuser" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr('SSH-Benutzer', 'SSH User')}
            </label>
            <input
              id="srv-sshuser"
              type="text"
              value={sshUser}
              onChange={(e) => setSshUser(e.target.value)}
              placeholder="root"
              className="w-full px-3 py-2 text-sm font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              required
            />
          </div>

          <div className="lg:col-span-2">
            <label htmlFor="srv-label" className="block text-xs font-medium text-slate-700 mb-1.5">
              {tr('Bezeichnung', 'Label')}
            </label>
            <input
              id="srv-label"
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="web-trixie-01"
              className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-end">
          <div className="lg:col-span-9">
            <label htmlFor="srv-notes" className="block text-xs font-medium text-slate-700 mb-1.5">
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
              className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          <div className="lg:col-span-3">
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

        {isAdmin && !editingId && (
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
      </form>

      {/* Server Table */}
      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <h2 className="font-display text-base font-semibold text-slate-900">
            {tr(`Gespeicherte Zielserver (${filtered.length})`, `Saved Target Servers (${filtered.length})`)}
          </h2>
          <div className="relative w-full sm:w-64">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={tr('Nach IP, BMC oder Name filtern...', 'Filter by IP, BMC, or name...')}
              className="w-full pl-9 pr-3 py-1.5 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <Server className="w-7 h-7 text-slate-400 mx-auto mb-3" />
            <p className="text-sm font-medium text-slate-900">
              {servers.length === 0
                ? tr('Noch keine Zielserver angelegt', 'No target servers added yet')
                : tr('Keine passenden Server gefunden', 'No matching servers found')}
            </p>
            <p className="text-xs text-slate-500 mt-1">
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
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-medium text-slate-500">
                  <th className="py-2.5 px-6">{tr('Bezeichnung', 'Label')}</th>
                  <th className="py-2.5 px-4">{tr('Server-IP · SSH', 'Server IP · SSH')}</th>
                  <th className="py-2.5 px-4">BMC (HTTPS :443)</th>
                  <th className="py-2.5 px-4">{tr('Sichtbarkeit', 'Visibility')}</th>
                  <th className="py-2.5 px-4">{tr('Notiz', 'Notes')}</th>
                  <th className="py-2.5 px-6 text-right">{tr('Aktionen', 'Actions')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 text-sm">
                {filtered.map((srv) => {
                  const isOwner = srv.userId === user.id;
                  const shareLabel = isOwner
                    ? formatShareSummary(srv.sharedWithAll, srv.sharedWithUserIds, locale)
                    : tr(
                        `Geteilt von ${srv.ownerUsername || 'admin'}`,
                        `Shared by ${srv.ownerUsername || 'admin'}`
                      );
                  const bmcRes = bmcResults[srv.id];
                  const isCheckingBmc = checkingBmcId === srv.id;

                  return (
                    <tr key={srv.id} className="hover:bg-slate-50/80 transition-colors">
                      <td className="py-3 px-6 font-medium text-slate-900 whitespace-nowrap">
                        {srv.label}
                      </td>
                      <td className="py-3 px-4 font-mono text-xs text-slate-800 tabular-nums whitespace-nowrap">
                        <p>{srv.ipAddress}</p>
                        <p className="text-slate-500">
                          {srv.sshUser} · Port {srv.port}
                        </p>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        {srv.bmcIpAddress ? (
                          <div className="space-y-1">
                            <div className="flex items-center gap-3">
                              <a
                                href={formatBmcUrl(srv.bmcIpAddress)}
                                target="_blank"
                                rel="noopener noreferrer"
                                title={tr(
                                  `${formatBmcUrl(srv.bmcIpAddress)} in neuem Tab öffnen`,
                                  `Open ${formatBmcUrl(srv.bmcIpAddress)} in a new tab`
                                )}
                                className="inline-flex items-center gap-1 font-mono text-xs font-medium text-blue-700 hover:text-blue-900 hover:underline tabular-nums"
                              >
                                <span>{srv.bmcIpAddress}</span>
                                <ExternalLink className="w-3 h-3 shrink-0" />
                              </a>
                              <button
                                type="button"
                                onClick={() => handleCheckBmc(srv.id)}
                                disabled={isCheckingBmc}
                                title={tr(
                                  'Erreichbarkeit über https:// Port 443 prüfen',
                                  'Check reachability over https:// port 443'
                                )}
                                className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 disabled:opacity-50 rounded transition-colors cursor-pointer"
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
                                  bmcRes.reachable ? 'text-emerald-700' : 'text-red-700'
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
                        ) : (
                          <span className="text-xs text-slate-400">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-xs whitespace-nowrap">
                        <span
                          className={
                            !isOwner || srv.sharedWithAll || srv.sharedWithUserIds.length > 0
                              ? 'text-blue-800 font-medium'
                              : 'text-slate-500'
                          }
                        >
                          {shareLabel}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-500 max-w-xs truncate">
                        {srv.notes || '—'}
                      </td>
                      <td className="py-3 px-6 text-right whitespace-nowrap">
                        {isOwner ? (
                          <div className="inline-flex items-center gap-3">
                            <button
                              type="button"
                              onClick={() => startEdit(srv)}
                              className="inline-flex items-center gap-1 text-xs font-medium text-slate-700 hover:text-slate-950 cursor-pointer"
                            >
                              <Pencil className="w-3.5 h-3.5" />
                              {tr('Bearbeiten', 'Edit')}
                            </button>
                            {isAdmin && (
                              <button
                                type="button"
                                onClick={() => setSharingServer(srv)}
                                className="inline-flex items-center gap-1 text-xs font-medium text-blue-700 hover:text-blue-900 cursor-pointer"
                              >
                                <Share2 className="w-3.5 h-3.5" />
                                {tr('Teilen', 'Share')}
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={() => handleDelete(srv.id)}
                              disabled={deletingId === srv.id}
                              className="inline-flex items-center gap-1 text-xs font-medium text-red-700 hover:text-red-900 cursor-pointer"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                              {tr('Entfernen', 'Delete')}
                            </button>
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

      {sharingServer && isAdmin && (
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
    </div>
  );
}
