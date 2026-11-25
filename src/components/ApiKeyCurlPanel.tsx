import React, { useEffect, useState } from 'react';
import { KeyRound, Copy, Check, Plus, Trash2, Terminal, Globe, RotateCcw, Save } from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import type { AppSettings, UserApiKey } from '../types';

const LOCAL_URL_STORAGE_KEY = 'ssh_console_curl_base_url';

function normalizeBaseUrlForCurl(raw: string, fallbackOrigin: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return fallbackOrigin;
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  return withScheme.replace(/\/+$/, '');
}

interface ApiKeyCurlPanelProps {
  defaultCertName?: string;
  publicUrl?: string;
  isAdmin?: boolean;
  onUpdateSettings?: (settings: AppSettings) => void;
}

export function ApiKeyCurlPanel({
  defaultCertName = 'my-certificate',
  publicUrl = '',
  isAdmin = false,
  onUpdateSettings,
}: ApiKeyCurlPanelProps) {
  const { tr, formatDateTime } = useI18n();
  const [apiKeys, setApiKeys] = useState<UserApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [keyName, setKeyName] = useState('');
  const [creating, setCreating] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [newlyCreatedKey, setNewlyCreatedKey] = useState<{ name: string; plainKey: string } | null>(
    null
  );
  const [curlMode, setCurlMode] = useState<'cert' | 'keypair' | 'replace-cert'>('cert');
  const [copiedTarget, setCopiedTarget] = useState<'key' | 'curl' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [domainNotice, setDomainNotice] = useState<string | null>(null);
  const [savingGlobalUrl, setSavingGlobalUrl] = useState(false);

  const browserOrigin =
    typeof window !== 'undefined' ? window.location.origin : 'https://ssh.example.net';
  const configuredGlobalUrl = (publicUrl || '').trim();

  const [domainInput, setDomainInput] = useState<string>(() => {
    if (configuredGlobalUrl) return configuredGlobalUrl;
    if (typeof window !== 'undefined') {
      try {
        const stored = window.localStorage.getItem(LOCAL_URL_STORAGE_KEY);
        if (stored && stored.trim()) return stored.trim();
      } catch {
        // ignore storage restrictions
      }
    }
    return '';
  });

  useEffect(() => {
    if (configuredGlobalUrl) {
      setDomainInput(configuredGlobalUrl);
    }
  }, [configuredGlobalUrl]);

  async function loadKeys() {
    try {
      const res = await api.listApiKeys();
      setApiKeys(res.apiKeys);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('API-Schlüssel konnten nicht geladen werden.', 'Could not load API keys.')
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadKeys();
  }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setCreating(true);
    try {
      const label = keyName.trim() || 'curl-Upload';
      const res = await api.createApiKey(label);
      setApiKeys((prev) => [res.apiKey, ...prev]);
      setNewlyCreatedKey({ name: res.apiKey.name, plainKey: res.plainKey });
      setKeyName('');
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('API-Schlüssel konnte nicht erstellt werden.', 'Could not create API key.')
      );
    } finally {
      setCreating(false);
    }
  }

  async function handleDelete(id: string) {
    setDeletingId(id);
    setError(null);
    try {
      await api.deleteApiKey(id);
      setApiKeys((prev) => prev.filter((k) => k.id !== id));
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('API-Schlüssel konnte nicht widerrufen werden.', 'Could not revoke API key.')
      );
    } finally {
      setDeletingId(null);
    }
  }

  async function copyText(text: string, target: 'key' | 'curl') {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedTarget(target);
      window.setTimeout(() => {
        setCopiedTarget((prev) => (prev === target ? null : prev));
      }, 2000);
    } catch {
      setError(tr('Kopieren in die Zwischenablage fehlgeschlagen.', 'Failed to copy to clipboard.'));
    }
  }

  function handleDomainInputChange(value: string) {
    setDomainInput(value);
    setDomainNotice(null);
    if (!isAdmin && typeof window !== 'undefined') {
      try {
        if (value.trim()) {
          window.localStorage.setItem(LOCAL_URL_STORAGE_KEY, value.trim());
        } else {
          window.localStorage.removeItem(LOCAL_URL_STORAGE_KEY);
        }
      } catch {
        // ignore storage errors
      }
    }
  }

  async function handleSaveGlobalDomain() {
    setError(null);
    setDomainNotice(null);
    setSavingGlobalUrl(true);
    try {
      const res = await api.updateAdminAuthSettings({ publicUrl: domainInput.trim() });
      const savedUrl = res.settings.publicUrl || '';
      setDomainInput(savedUrl);
      onUpdateSettings?.(res.settings);
      if (typeof window !== 'undefined') {
        try {
          window.localStorage.removeItem(LOCAL_URL_STORAGE_KEY);
        } catch {
          // ignore
        }
      }
      setDomainNotice(
        savedUrl
          ? tr(
              `Öffentliche Domain „${savedUrl}“ global für alle Benutzer gespeichert.`,
              `Public domain "${savedUrl}" saved globally for all users.`
            )
          : tr(
              'Öffentliche Domain zurückgesetzt (verwendet nun wieder die aktuelle Browser-Adresse).',
              'Public domain cleared (now using current browser address).'
            )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Öffentliche Domain konnte nicht gespeichert werden.', 'Could not save public domain.')
      );
    } finally {
      setSavingGlobalUrl(false);
    }
  }

  function handleResetLocalDomain() {
    setDomainNotice(null);
    if (typeof window !== 'undefined') {
      try {
        window.localStorage.removeItem(LOCAL_URL_STORAGE_KEY);
      } catch {
        // ignore
      }
    }
    setDomainInput(configuredGlobalUrl);
  }

  const effectiveOrigin = normalizeBaseUrlForCurl(
    domainInput || configuredGlobalUrl,
    browserOrigin
  );
  const displayedApiKey = newlyCreatedKey?.plainKey || tr('<DEIN_API_KEY>', '<YOUR_API_KEY>');

  const curlSnippet =
    curlMode === 'cert'
      ? `curl -X POST "${effectiveOrigin}/api/v1/certificates/upload" \\\n  -H "X-API-Key: ${displayedApiKey}" \\\n  -F "name=${defaultCertName}" \\\n  -F "private_key=@./zertifikat" \\\n  -F "public_key=@./zertifikat.pub" \\\n  -F "cert=@./zertifikat-cert.pub"`
      : curlMode === 'keypair'
        ? `curl -X POST "${effectiveOrigin}/api/v1/certificates/upload" \\\n  -H "X-API-Key: ${displayedApiKey}" \\\n  -F "name=${defaultCertName}" \\\n  -F "private_key=@./zertifikat" \\\n  -F "public_key=@./zertifikat.pub"`
        : `curl -X PATCH "${effectiveOrigin}/api/v1/certificates/${encodeURIComponent(defaultCertName)}" \\\n  -H "X-API-Key: ${displayedApiKey}" \\\n  -F "cert=@./zertifikat-cert.pub"`;

  return (
    <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-blue-700 dark:text-blue-400" />
            {tr('API-Schlüssel & automatischer curl-Upload', 'API Keys & Automated curl Upload')}
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            {tr(
              'Laden Sie komplette Schlüssel-/Zertifikatspakete per ',
              'Upload complete key/certificate bundles via '
            )}
            <code className="font-mono">curl</code>
            {tr(
              ' hoch oder tauschen Sie einzelne Dateien (z. B. nur ',
              ' or replace individual files (e.g. only '
            )}
            <code className="font-mono">zertifikat-cert.pub</code>
            {tr(') per ', ') via ')}
            <code className="font-mono">PATCH /api/v1/certificates/&lt;name-oder-id&gt;</code>
            {tr(' aus.', '.')}{' '}
            {tr(
              'Unveränderte Dateien bleiben erhalten.',
              'Unchanged files remain intact.'
            )}
          </p>
        </div>
      </div>

      {error && (
        <div role="alert" className="px-4 py-3 rounded-md bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800/70 text-sm text-red-800 dark:text-red-300">
          {error}
        </div>
      )}

      {domainNotice && (
        <div role="status" className="px-4 py-3 rounded-md bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/70 text-sm text-emerald-800 dark:text-emerald-300">
          {domainNotice}
        </div>
      )}

      {/* Create Key Form */}
      <form onSubmit={handleCreate} className="flex flex-col sm:flex-row gap-3">
        <input
          type="text"
          value={keyName}
          onChange={(e) => setKeyName(e.target.value)}
          placeholder={tr(
            'Bezeichnung für den API-Schlüssel (z. B. Laptop-Skript, Cronjob)',
            'Label for this API key (e.g. Laptop Script, Cronjob)'
          )}
          maxLength={64}
          className="flex-1 px-3.5 py-2 text-sm border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
        />
        <button
          type="submit"
          disabled={creating}
          className="inline-flex items-center justify-center gap-1.5 px-4 py-2 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
        >
          <Plus className="w-4 h-4" />
          {creating
            ? tr('Erzeuge...', 'Generating...')
            : tr('API-Schlüssel erzeugen', 'Generate API Key')}
        </button>
      </form>

      {/* One-time reveal of freshly generated API key */}
      {newlyCreatedKey && (
        <div className="p-4 rounded-md bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/70 space-y-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-xs font-semibold text-emerald-900 dark:text-emerald-200">
              {tr(
                `Neuer API-Schlüssel „${newlyCreatedKey.name}“ — wird nur einmalig vollständig angezeigt:`,
                `New API key "${newlyCreatedKey.name}" — displayed in full only once:`
              )}
            </span>
            <button
              type="button"
              onClick={() => copyText(newlyCreatedKey.plainKey, 'key')}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-emerald-900 dark:text-emerald-200 bg-white dark:bg-slate-900 border border-emerald-300 dark:border-emerald-700/80 hover:bg-emerald-100 dark:hover:bg-emerald-900/50 rounded-md transition-colors cursor-pointer"
            >
              {copiedTarget === 'key' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-700 dark:text-emerald-400" />
                  {tr('Kopiert', 'Copied')}
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  {tr('Key kopieren', 'Copy Key')}
                </>
              )}
            </button>
          </div>
          <code className="block px-3 py-2 text-xs font-mono text-emerald-950 dark:text-emerald-200 bg-white dark:bg-slate-900 border border-emerald-200 dark:border-emerald-800/70 rounded break-all select-all">
            {newlyCreatedKey.plainKey}
          </code>
        </div>
      )}

      {/* Configurable Public Domain / Base URL for curl */}
      <div className="p-3.5 rounded-md bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 space-y-2">
        <div className="flex flex-col sm:flex-row sm:items-center gap-2.5">
          <label
            htmlFor="curl-public-domain"
            className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 whitespace-nowrap shrink-0"
          >
            <Globe className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400" />
            {tr('Domain / Basis-URL für curl:', 'Domain / Base URL for curl:')}
          </label>
          <input
            id="curl-public-domain"
            type="text"
            value={domainInput}
            onChange={(e) => handleDomainInputChange(e.target.value)}
            placeholder="https://ssh.example.net"
            className="flex-1 px-3 py-1.5 text-xs font-mono bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
          />
          <div className="flex items-center gap-2 shrink-0">
            {isAdmin && (
              <button
                type="button"
                onClick={handleSaveGlobalDomain}
                disabled={savingGlobalUrl || domainInput.trim() === configuredGlobalUrl}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                title={tr(
                  'Diese Domain global für alle Benutzer im curl-Beispiel speichern',
                  'Save this domain globally for all users in the curl example'
                )}
              >
                <Save className="w-3.5 h-3.5" />
                {savingGlobalUrl
                  ? tr('Speichert...', 'Saving...')
                  : tr('Global speichern', 'Save Globally')}
              </button>
            )}
            {domainInput.trim() && domainInput.trim() !== configuredGlobalUrl && !isAdmin && (
              <button
                type="button"
                onClick={handleResetLocalDomain}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                {tr('Zurücksetzen', 'Reset')}
              </button>
            )}
            {isAdmin && configuredGlobalUrl && domainInput.trim() === configuredGlobalUrl && (
              <button
                type="button"
                onClick={() => {
                  setDomainInput('');
                }}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md transition-colors cursor-pointer whitespace-nowrap"
                title={tr(
                  'Feld leeren – anschließend „Global speichern“ klicken, um wieder die Browser-Adresse zu verwenden',
                  'Clear field — then click "Save Globally" to fall back to the browser address'
                )}
              >
                <RotateCcw className="w-3.5 h-3.5" />
                {tr('Leeren', 'Clear')}
              </button>
            )}
          </div>
        </div>
        <p className="text-[11px] text-slate-500 dark:text-slate-400">
          {isAdmin
            ? tr(
                'Hinterlegen Sie Ihre öffentliche Domain (z. B. https://ssh.example.net), damit bei curl nicht die interne Server-IP angezeigt wird. Mit „Global speichern“ gilt die Domain sofort für alle Benutzer.',
                'Enter your public domain (e.g. https://ssh.example.net) so curl shows your domain instead of the internal server IP. Click "Save Globally" to apply it for all users.'
              )
            : configuredGlobalUrl
              ? tr(
                  `Global konfigurierte Domain: ${configuredGlobalUrl}. Sie können die Adresse hier bei Bedarf lokal für Ihren Befehl anpassen.`,
                  `Globally configured domain: ${configuredGlobalUrl}. You can override it locally here if needed.`
                )
              : tr(
                  `Standardmäßig wird die aktuelle Browser-Adresse (${browserOrigin}) verwendet. Geben Sie hier optional eine Domain (z. B. https://ssh.example.net) ein.`,
                  `Defaults to your current browser address (${browserOrigin}). Optionally enter a domain (e.g. https://ssh.example.net) here.`
                )}
        </p>
      </div>

      {/* Ready-to-run curl command */}
      <div className="space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="inline-flex rounded-md border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/60 p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setCurlMode('cert')}
              className={`px-3 py-1 rounded font-medium transition-colors cursor-pointer ${
                curlMode === 'cert'
                  ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              {tr('3 Dateien (mit CA-Zertifikat)', '3 Files (with CA Certificate)')}
            </button>
            <button
              type="button"
              onClick={() => setCurlMode('keypair')}
              className={`px-3 py-1 rounded font-medium transition-colors cursor-pointer ${
                curlMode === 'keypair'
                  ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              {tr('2 Dateien (ohne CA-Zertifikat)', '2 Files (without CA Certificate)')}
            </button>
            <button
              type="button"
              onClick={() => setCurlMode('replace-cert')}
              className={`px-3 py-1 rounded font-medium transition-colors cursor-pointer ${
                curlMode === 'replace-cert'
                  ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              {tr('Nur cert.pub tauschen', 'Replace cert.pub only')}
            </button>
          </div>

          <button
            type="button"
            onClick={() => copyText(curlSnippet, 'curl')}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-md transition-colors cursor-pointer"
          >
            {copiedTarget === 'curl' ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-700 dark:text-emerald-400" />
                {tr('Befehl kopiert', 'Command Copied')}
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                {tr('curl-Befehl kopieren', 'Copy curl Command')}
              </>
            )}
          </button>
        </div>

        <pre className="p-4 rounded-md bg-slate-900 dark:bg-slate-950 dark:border dark:border-slate-800 text-slate-100 text-xs font-mono overflow-x-auto leading-relaxed">
          <code>{curlSnippet}</code>
        </pre>

        <p className="text-[11px] text-slate-500 dark:text-slate-400">
          {tr('Akzeptierte Header:', 'Accepted headers:')}{' '}
          <code className="font-mono text-slate-700 dark:text-slate-300">X-API-Key: sshc_...</code> {tr('oder', 'or')}{' '}
          <code className="font-mono text-slate-700 dark:text-slate-300">Authorization: Bearer sshc_...</code> ·{' '}
          {tr('Felder:', 'Fields:')}{' '}
          <code className="font-mono text-slate-700 dark:text-slate-300">private_key</code>,{' '}
          <code className="font-mono text-slate-700 dark:text-slate-300">public_key</code>,{' '}
          <code className="font-mono text-slate-700 dark:text-slate-300">cert</code>,{' '}
          <code className="font-mono text-slate-700 dark:text-slate-300">name</code>,{' '}
          <code className="font-mono text-slate-700 dark:text-slate-300">remove_cert=true</code> ·{' '}
          {tr('Auflisten:', 'List:')}{' '}
          <code className="font-mono text-slate-700 dark:text-slate-300">GET /api/v1/certificates</code>.
        </p>
      </div>

      {/* Active API Keys list */}
      <div className="pt-2 border-t border-slate-200 dark:border-slate-800 space-y-3">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
          {tr(`Aktive API-Schlüssel (${apiKeys.length})`, `Active API Keys (${apiKeys.length})`)}
        </h3>

        {loading ? (
          <p className="text-xs text-slate-500 dark:text-slate-400 py-2">
            {tr('Lade API-Schlüssel...', 'Loading API keys...')}
          </p>
        ) : apiKeys.length === 0 ? (
          <div className="flex items-center gap-2.5 text-xs text-slate-500 dark:text-slate-400 py-2">
            <KeyRound className="w-4 h-4 text-slate-400 shrink-0" />
            <span>
              {tr(
                'Noch kein API-Schlüssel erstellt. Erzeugen Sie oben einen Schlüssel für curl-Uploads.',
                'No API key created yet. Generate one above to enable curl uploads.'
              )}
            </span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                  <th className="py-2 pr-4 font-medium">{tr('Bezeichnung', 'Label')}</th>
                  <th className="py-2 pr-4 font-medium">{tr('Präfix', 'Prefix')}</th>
                  <th className="py-2 pr-4 font-medium">{tr('Erstellt', 'Created')}</th>
                  <th className="py-2 pr-4 font-medium">{tr('Zuletzt verwendet', 'Last Used')}</th>
                  <th className="py-2 text-right font-medium">{tr('Aktion', 'Action')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/70">
                {apiKeys.map((k) => (
                  <tr key={k.id}>
                    <td className="py-2.5 pr-4 font-medium text-slate-900 dark:text-slate-100">{k.name}</td>
                    <td className="py-2.5 pr-4 font-mono text-slate-600 dark:text-slate-400">{k.keyPrefix}</td>
                    <td className="py-2.5 pr-4 font-mono text-slate-600 dark:text-slate-400 tabular-nums">
                      {formatDateTime(k.createdAt)}
                    </td>
                    <td className="py-2.5 pr-4 font-mono text-slate-600 dark:text-slate-400 tabular-nums">
                      {formatDateTime(k.lastUsedAt, { emptyText: tr('Noch nie', 'Never') })}
                    </td>
                    <td className="py-2.5 text-right">
                      <button
                        type="button"
                        onClick={() => handleDelete(k.id)}
                        disabled={deletingId === k.id}
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-red-700 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/50 rounded-md transition-colors cursor-pointer disabled:opacity-50"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        {deletingId === k.id
                          ? tr('Widerrufe...', 'Revoking...')
                          : tr('Widerrufen', 'Revoke')}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
