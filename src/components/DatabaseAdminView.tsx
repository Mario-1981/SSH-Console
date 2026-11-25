import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeftRight,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Copy,
  Database,
  HardDrive,
  Lock,
  PlugZap,
  RefreshCw,
  Save,
  Server,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { api, type DatabaseMigrationConflictError } from '../api';
import { useI18n } from '../i18n';
import type {
  DatabaseMigrationResult,
  DatabaseStatus,
  DatabaseTableCount,
  MariaDbTestResult,
} from '../types';

interface DatabaseAdminViewProps {
  onDatabaseMigrated?: () => void;
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let val = bytes;
  let idx = 0;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx += 1;
  }
  return `${val >= 10 || idx === 0 ? val.toFixed(0) : val.toFixed(1)} ${units[idx]}`;
}

export function DatabaseAdminView({ onDatabaseMigrated }: DatabaseAdminViewProps) {
  const { tr, formatDateTime } = useI18n();

  const [status, setStatus] = useState<DatabaseStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // MariaDB form fields
  const [host, setHost] = useState('');
  const [port, setPort] = useState('3306');
  const [database, setDatabase] = useState('ssh_console');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [ssl, setSsl] = useState(false);
  const [sslRejectUnauthorized, setSslRejectUnauthorized] = useState(true);

  // Action states
  const [savingConfig, setSavingConfig] = useState(false);
  const [clearingConfig, setClearingConfig] = useState(false);
  const [testing, setTesting] = useState(false);
  const [migrating, setMigrating] = useState(false);
  const [confirmClearConfig, setConfirmClearConfig] = useState(false);

  // Feedback & diagnostics
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<MariaDbTestResult | null>(null);
  const [lastMigrationResult, setLastMigrationResult] = useState<DatabaseMigrationResult | null>(null);

  // Overwrite confirmation state (when MariaDB target already contains rows)
  const [overwriteWarning, setOverwriteWarning] = useState<{
    message: string;
    existingRowCount: number;
    existingTables: DatabaseTableCount[];
  } | null>(null);
  const [confirmOverwrite, setConfirmOverwrite] = useState(false);

  // SQL helper snippet visibility
  const [showSqlSnippet, setShowSqlSnippet] = useState(false);
  const [copiedSql, setCopiedSql] = useState(false);

  function applyStatus(next: DatabaseStatus, hydrateForm: boolean) {
    setStatus(next);
    if (hydrateForm) {
      setHost(next.mariadb.host || '');
      setPort(String(next.mariadb.port || 3306));
      setDatabase(next.mariadb.database || 'ssh_console');
      setUsername(next.mariadb.username || '');
      setPassword('');
      setSsl(Boolean(next.mariadb.ssl));
      setSslRejectUnauthorized(next.mariadb.sslRejectUnauthorized !== false);
    }
  }

  async function loadStatus(hydrateForm = true) {
    if (hydrateForm) {
      setLoading(true);
    } else {
      setRefreshing(true);
    }
    setError(null);
    try {
      const data = await api.getAdminDatabaseStatus();
      applyStatus(data, hydrateForm);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Datenbankstatus konnte nicht geladen werden.', 'Could not load database status.')
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    void loadStatus(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const parsedPort = useMemo(() => {
    const n = Number(port);
    return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : 3306;
  }, [port]);

  const formHasRequiredFields = useMemo(() => {
    const hasBasic =
      host.trim().length > 0 && database.trim().length > 0 && username.trim().length > 0;
    const hasPass = password.length > 0 || Boolean(status?.mariadb.hasPassword);
    return hasBasic && hasPass;
  }, [host, database, username, password, status?.mariadb.hasPassword]);

  const sqlSetupSnippet = useMemo(() => {
    const safeDb = (database.trim() || 'ssh_console').replace(/[^a-zA-Z0-9_$-]/g, '') || 'ssh_console';
    const safeUser = (username.trim() || 'ssh_console').replace(/['\\`]/g, '') || 'ssh_console';
    return [
      `CREATE DATABASE IF NOT EXISTS \`${safeDb}\``,
      `  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`,
      `CREATE USER IF NOT EXISTS '${safeUser}'@'%' IDENTIFIED BY 'STARKES_PASSWORT';`,
      `GRANT ALL PRIVILEGES ON \`${safeDb}\`.* TO '${safeUser}'@'%';`,
      `FLUSH PRIVILEGES;`,
    ].join('\n');
  }, [database, username]);

  function buildPayload() {
    return {
      host: host.trim(),
      port: parsedPort,
      database: database.trim(),
      username: username.trim(),
      ...(password.length > 0 ? { password } : {}),
      ssl,
      sslRejectUnauthorized,
    };
  }

  async function handleTestConnection() {
    setError(null);
    setSuccess(null);
    setTestResult(null);
    setOverwriteWarning(null);
    setConfirmOverwrite(false);

    if (!host.trim() || !database.trim() || !username.trim()) {
      setError(
        tr(
          'Bitte füllen Sie Host, Datenbankname und Benutzername aus.',
          'Please fill in host, database name, and username.'
        )
      );
      return;
    }

    setTesting(true);
    try {
      const res = await api.testAdminDatabase(buildPayload());
      setTestResult(res);
      if (res.existingRowCount > 0) {
        setOverwriteWarning({
          message: tr(
            `Die Ziel-MariaDB enthält bereits ${res.existingRowCount} Datensätze in bestehenden SSH-Console-Tabellen. Bei einer Migration werden diese überschrieben.`,
            `The target MariaDB already contains ${res.existingRowCount} rows in existing SSH Console tables. Migrating will overwrite them.`
          ),
          existingRowCount: res.existingRowCount,
          existingTables: res.existingTables,
        });
      }
      setSuccess(
        tr(
          `Verbindung zu MariaDB ${res.version} (${res.database}) erfolgreich (${res.latencyMs} ms).`,
          `Connected to MariaDB ${res.version} (${res.database}) in ${res.latencyMs} ms.`
        )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('MariaDB-Verbindungstest fehlgeschlagen.', 'MariaDB connection test failed.')
      );
    } finally {
      setTesting(false);
    }
  }

  async function handleSaveConfig(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setSavingConfig(true);
    try {
      const next = await api.saveAdminDatabaseConfig(buildPayload());
      applyStatus(next, true);
      setSuccess(
        tr(
          'MariaDB-Verbindungsdaten wurden verschlüsselt gespeichert. Die aktive Datenbank wurde noch nicht umgestellt.',
          'MariaDB connection settings were saved encrypted. The active database engine has not been switched yet.'
        )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Konfiguration konnte nicht gespeichert werden.', 'Could not save configuration.')
      );
    } finally {
      setSavingConfig(false);
    }
  }

  async function handleClearMariaDbConfig() {
    setError(null);
    setSuccess(null);
    setClearingConfig(true);
    try {
      const next = await api.clearAdminMariaDbConfig();
      applyStatus(next, true);
      setTestResult(null);
      setOverwriteWarning(null);
      setConfirmOverwrite(false);
      setConfirmClearConfig(false);
      setSuccess(
        tr(
          'Gespeicherte MariaDB-Verbindungsdaten wurden entfernt.',
          'Stored MariaDB connection settings were removed.'
        )
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Konfiguration konnte nicht gelöscht werden.', 'Could not delete configuration.')
      );
    } finally {
      setClearingConfig(false);
    }
  }

  async function handleMigrateToMariaDb() {
    setError(null);
    setSuccess(null);
    setLastMigrationResult(null);
    setMigrating(true);
    try {
      const res = await api.migrateAdminDatabase({
        direction: 'sqlite-to-mariadb',
        mariadb: buildPayload(),
        confirmOverwrite,
      });
      applyStatus(res.status, true);
      setLastMigrationResult(res.migration);
      setOverwriteWarning(null);
      setConfirmOverwrite(false);
      setTestResult(null);
      setSuccess(
        tr(
          `Migration nach MariaDB abgeschlossen (${res.migration.totalRows} Datensätze in ${res.migration.durationMs} ms). MariaDB ist ab sofort aktiv.`,
          `Migration to MariaDB completed (${res.migration.totalRows} rows in ${res.migration.durationMs} ms). MariaDB is now active.`
        )
      );
      onDatabaseMigrated?.();
    } catch (err) {
      const conflict = err as DatabaseMigrationConflictError;
      if (conflict.statusCode === 409 && conflict.code === 'TARGET_NOT_EMPTY') {
        setOverwriteWarning({
          message: conflict.message,
          existingRowCount: conflict.existingRowCount ?? 0,
          existingTables: conflict.existingTables ?? [],
        });
        setConfirmOverwrite(false);
      } else {
        setError(
          err instanceof Error
            ? err.message
            : tr('Migration nach MariaDB fehlgeschlagen.', 'Migration to MariaDB failed.')
        );
      }
    } finally {
      setMigrating(false);
    }
  }

  async function handleMigrateToSqlite() {
    setError(null);
    setSuccess(null);
    setLastMigrationResult(null);
    setMigrating(true);
    try {
      const res = await api.migrateAdminDatabase({
        direction: 'mariadb-to-sqlite',
        confirmOverwrite: true,
      });
      applyStatus(res.status, true);
      setLastMigrationResult(res.migration);
      setOverwriteWarning(null);
      setConfirmOverwrite(false);
      setTestResult(null);
      setSuccess(
        tr(
          `Migration zurück zu SQLite abgeschlossen (${res.migration.totalRows} Datensätze in ${res.migration.durationMs} ms). SQLite ist ab sofort wieder aktiv.`,
          `Migration back to SQLite completed (${res.migration.totalRows} rows in ${res.migration.durationMs} ms). SQLite is active again.`
        )
      );
      onDatabaseMigrated?.();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Migration zu SQLite fehlgeschlagen.', 'Migration to SQLite failed.')
      );
    } finally {
      setMigrating(false);
    }
  }

  async function handleCopySql() {
    try {
      await navigator.clipboard.writeText(sqlSetupSnippet);
      setCopiedSql(true);
      window.setTimeout(() => setCopiedSql(false), 2000);
    } catch {
      // ignore clipboard errors
    }
  }

  if (loading && !status) {
    return (
      <div className="py-12 text-center text-sm text-slate-500">
        {tr('Lade Datenbankstatus...', 'Loading database status...')}
      </div>
    );
  }

  const isMariaDb = status?.engine === 'mariadb';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900">
            {tr('Datenbank & Migration', 'Database & Migration')}
          </h1>
          <p className="text-sm text-slate-500 mt-0.5">
            {tr(
              'Die Ersteinrichtung nutzt standardmäßig SQLite. Optional können Sie jederzeit auf eine externe MariaDB migrieren oder zurück zu SQLite wechseln.',
              'Initial setup always uses SQLite by default. Optionally migrate to an external MariaDB server or switch back to SQLite at any time.'
            )}
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadStatus(false)}
          disabled={refreshing || migrating}
          className="inline-flex items-center gap-2 px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer disabled:opacity-50 self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
          {tr('Status aktualisieren', 'Refresh status')}
        </button>
      </div>

      {/* Global Alerts */}
      {error && (
        <div className="p-3.5 rounded-lg bg-red-50 border border-red-200 text-sm text-red-800 flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
          <div className="min-w-0 break-words">{error}</div>
        </div>
      )}

      {success && (
        <div className="p-3.5 rounded-lg bg-emerald-50 border border-emerald-200 text-sm text-emerald-800 flex items-start gap-2.5">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
          <div className="min-w-0 break-words">{success}</div>
        </div>
      )}

      {status?.lastSyncError && isMariaDb && (
        <div className="p-3.5 rounded-lg bg-amber-50 border border-amber-200 text-sm text-amber-900 flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
          <div className="min-w-0">
            <p className="font-medium">
              {tr('Hinweis zur letzten MariaDB-Synchronisierung', 'Notice on last MariaDB sync')}
            </p>
            <p className="text-xs mt-0.5 break-words">{status.lastSyncError}</p>
          </div>
        </div>
      )}

      {/* Active Engine & Status Overview */}
      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            {isMariaDb ? (
              <Server className="w-5 h-5 text-blue-700" />
            ) : (
              <HardDrive className="w-5 h-5 text-emerald-700" />
            )}
            <div>
              <h2 className="text-sm font-semibold text-slate-900">
                {tr('Aktive Datenbank-Engine', 'Active Database Engine')}
              </h2>
              <p className="text-xs text-slate-500">
                {isMariaDb
                  ? tr(
                      'Externe MariaDB-Instanz ist aktiv und speichert alle Änderungen.',
                      'External MariaDB instance is active and persists all changes.'
                    )
                  : tr(
                      'Lokale SQLite-Datenbank ist aktiv (Standard bei Ersteinrichtung).',
                      'Local SQLite database is active (default on initial setup).'
                    )}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-md border ${
                isMariaDb
                  ? 'bg-blue-50 text-blue-800 border-blue-200'
                  : 'bg-emerald-50 text-emerald-800 border-emerald-200'
              }`}
            >
              <Database className="w-3.5 h-3.5" />
              {isMariaDb ? 'MariaDB' : 'SQLite'}
            </span>
            <span
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md border ${
                status?.connected
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-red-50 text-red-700 border-red-200'
              }`}
            >
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  status?.connected ? 'bg-emerald-600' : 'bg-red-600'
                }`}
              />
              {status?.connected ? tr('Verbunden', 'Connected') : tr('Nicht verbunden', 'Disconnected')}
            </span>
          </div>
        </div>

        <div className="p-5 space-y-5">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-3.5 rounded-md bg-slate-50 border border-slate-200">
              <p className="text-xs font-medium text-slate-500">
                {isMariaDb ? tr('MariaDB-Server', 'MariaDB Server') : tr('SQLite-Speicherort', 'SQLite Location')}
              </p>
              <p className="text-sm font-mono font-medium text-slate-900 mt-1 break-all">
                {isMariaDb
                  ? `${status?.mariadb.host}:${status?.mariadb.port}/${status?.mariadb.database}`
                  : status?.sqlitePath || '—'}
              </p>
              <p className="text-xs text-slate-500 mt-1">
                {isMariaDb
                  ? status?.mariadbVersion
                    ? `Version: ${status.mariadbVersion}`
                    : tr('Version unbekannt', 'Version unknown')
                  : status?.sqliteExists
                    ? `${tr('Dateigröße', 'File size')}: ${formatBytes(status.sqliteSizeBytes)}`
                    : tr('Wird bei Speicherung angelegt', 'Created on write')}
              </p>
            </div>

            <div className="p-3.5 rounded-md bg-slate-50 border border-slate-200">
              <p className="text-xs font-medium text-slate-500">
                {tr('Gesamte Datensätze', 'Total Records')}
              </p>
              <p className="text-xl font-bold font-mono tabular-nums text-slate-900 mt-1">
                {status?.totalRows ?? 0}
              </p>
              <p className="text-xs text-slate-500 mt-1">
                {tr(
                  `Verteilt auf ${status?.tables.length ?? 0} Tabellen`,
                  `Across ${status?.tables.length ?? 0} tables`
                )}
              </p>
            </div>

            <div className="p-3.5 rounded-md bg-slate-50 border border-slate-200">
              <p className="text-xs font-medium text-slate-500">
                {tr('Letzte Migration', 'Last Migration')}
              </p>
              <p className="text-sm font-medium text-slate-900 mt-1">
                {status?.lastMigratedAt ? formatDateTime(status.lastMigratedAt) : tr('Noch keine Migration', 'No migration yet')}
              </p>
              <p className="text-xs text-slate-500 mt-1">
                {status?.lastMigrationDirection === 'sqlite-to-mariadb'
                  ? 'SQLite → MariaDB'
                  : status?.lastMigrationDirection === 'mariadb-to-sqlite'
                    ? 'MariaDB → SQLite'
                    : tr('Standardinstallation (SQLite)', 'Default setup (SQLite)')}
              </p>
            </div>
          </div>

          {/* Table Breakdown */}
          {status && status.tables.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2.5">
                {tr('Tabellenübersicht (Live)', 'Table Overview (Live)')}
              </h3>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
                {status.tables.map((tbl) => (
                  <div
                    key={tbl.table}
                    className="flex items-center justify-between gap-2 px-3 py-2 rounded-md border border-slate-200 bg-white"
                  >
                    <div className="min-w-0">
                      <p className="text-xs font-medium text-slate-800 truncate">{tbl.label}</p>
                      <p className="text-[11px] font-mono text-slate-400 truncate">{tbl.table}</p>
                    </div>
                    <span className="text-xs font-mono font-semibold tabular-nums text-slate-900 shrink-0">
                      {tbl.rows}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Post-migration Result Banner */}
      {lastMigrationResult && (
        <section className="bg-emerald-50/70 border border-emerald-200 rounded-lg p-5 space-y-2.5">
          <div className="flex items-center gap-2 text-emerald-900 font-semibold text-sm">
            <CheckCircle2 className="w-4 h-4 text-emerald-700" />
            {lastMigrationResult.direction === 'sqlite-to-mariadb'
              ? tr('Migrationsbericht: SQLite → MariaDB', 'Migration Report: SQLite → MariaDB')
              : tr('Migrationsbericht: MariaDB → SQLite', 'Migration Report: MariaDB → SQLite')}
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs text-emerald-900">
            <div>
              <span className="text-emerald-700">{tr('Übertragene Datensätze', 'Migrated rows')}: </span>
              <span className="font-mono font-semibold">{lastMigrationResult.totalRows}</span>
            </div>
            <div>
              <span className="text-emerald-700">{tr('Dauer', 'Duration')}: </span>
              <span className="font-mono font-semibold">{lastMigrationResult.durationMs} ms</span>
            </div>
            {lastMigrationResult.mariadbVersion && (
              <div>
                <span className="text-emerald-700">MariaDB: </span>
                <span className="font-mono font-semibold">{lastMigrationResult.mariadbVersion}</span>
              </div>
            )}
            {lastMigrationResult.backupFileName && (
              <div className="sm:col-span-3">
                <span className="text-emerald-700">{tr('SQLite-Backup erstellt', 'SQLite backup created')}: </span>
                <span className="font-mono font-semibold">{lastMigrationResult.backupFileName}</span>
              </div>
            )}
          </div>
        </section>
      )}

      {/* MariaDB Connection Configuration */}
      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">
              {tr('MariaDB-Verbindung konfigurieren', 'Configure MariaDB Connection')}
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              {tr(
                'Das Passwort wird verschlüsselt gespeichert und niemals im Klartext ausgegeben.',
                'The password is stored encrypted and is never displayed in plaintext.'
              )}
            </p>
          </div>
          {status?.mariadb.configured && (
            <span className="inline-flex items-center gap-1 text-xs font-medium text-slate-600 bg-slate-100 px-2.5 py-1 rounded-md">
              <Lock className="w-3 h-3" />
              {tr('Konfiguration hinterlegt', 'Configuration saved')}
            </span>
          )}
        </div>

        <form onSubmit={handleSaveConfig} className="p-5 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
            <div className="md:col-span-6">
              <label className="block text-xs font-medium text-slate-700 mb-1">
                {tr('MariaDB Host / IP-Adresse', 'MariaDB Host / IP Address')}
              </label>
              <input
                type="text"
                value={host}
                onChange={(e) => {
                  setHost(e.target.value);
                  setTestResult(null);
                }}
                placeholder="127.0.0.1 oder mariadb.intern"
                disabled={isMariaDb}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-600 disabled:bg-slate-100 disabled:text-slate-600 font-mono"
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-xs font-medium text-slate-700 mb-1">Port</label>
              <input
                type="number"
                min={1}
                max={65535}
                value={port}
                onChange={(e) => {
                  setPort(e.target.value);
                  setTestResult(null);
                }}
                disabled={isMariaDb}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-600 disabled:bg-slate-100 disabled:text-slate-600 font-mono"
              />
            </div>

            <div className="md:col-span-4">
              <label className="block text-xs font-medium text-slate-700 mb-1">
                {tr('Datenbankname', 'Database Name')}
              </label>
              <input
                type="text"
                value={database}
                onChange={(e) => {
                  setDatabase(e.target.value);
                  setTestResult(null);
                }}
                placeholder="ssh_console"
                disabled={isMariaDb}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-600 disabled:bg-slate-100 disabled:text-slate-600 font-mono"
              />
            </div>

            <div className="md:col-span-6">
              <label className="block text-xs font-medium text-slate-700 mb-1">
                {tr('Benutzername', 'Username')}
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => {
                  setUsername(e.target.value);
                  setTestResult(null);
                }}
                placeholder="ssh_console"
                autoComplete="off"
                disabled={isMariaDb}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-600 disabled:bg-slate-100 disabled:text-slate-600 font-mono"
              />
            </div>

            <div className="md:col-span-6">
              <label className="block text-xs font-medium text-slate-700 mb-1">
                {tr('Passwort', 'Password')}
                {status?.mariadb.hasPassword && (
                  <span className="ml-2 text-[11px] font-normal text-emerald-700">
                    ({tr('verschlüsselt hinterlegt – leer lassen zum Beibehalten', 'stored encrypted – leave blank to keep')})
                  </span>
                )}
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  setTestResult(null);
                }}
                placeholder={
                  status?.mariadb.hasPassword
                    ? '••••••••••••••••'
                    : tr('MariaDB-Passwort eingeben', 'Enter MariaDB password')
                }
                autoComplete="new-password"
                disabled={isMariaDb}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-600 disabled:bg-slate-100 disabled:text-slate-600"
              />
            </div>
          </div>

          {/* TLS/SSL Options */}
          <div className="flex flex-col sm:flex-row sm:items-center gap-4 pt-1">
            <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-700 cursor-pointer">
              <input
                type="checkbox"
                checked={ssl}
                disabled={isMariaDb}
                onChange={(e) => {
                  setSsl(e.target.checked);
                  setTestResult(null);
                }}
                className="rounded border-slate-300 text-blue-700 focus:ring-blue-500"
              />
              {tr('TLS/SSL-Verbindung verwenden', 'Use TLS/SSL connection')}
            </label>

            {ssl && (
              <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-700 cursor-pointer">
                <input
                  type="checkbox"
                  checked={sslRejectUnauthorized}
                  disabled={isMariaDb}
                  onChange={(e) => {
                    setSslRejectUnauthorized(e.target.checked);
                    setTestResult(null);
                  }}
                  className="rounded border-slate-300 text-blue-700 focus:ring-blue-500"
                />
                {tr('Server-Zertifikat streng prüfen (empfohlen)', 'Verify server certificate (recommended)')}
              </label>
            )}
          </div>

          {isMariaDb && (
            <p className="text-xs text-slate-500 bg-slate-50 border border-slate-200 rounded-md px-3 py-2">
              {tr(
                'Die Zugangsdaten sind schreibgeschützt, solange MariaDB aktiv ist. Um auf eine andere MariaDB zu wechseln, migrieren Sie zuerst zurück zu SQLite.',
                'Connection fields are read-only while MariaDB is active. To switch to another MariaDB instance, migrate back to SQLite first.'
              )}
            </p>
          )}

          {/* Connection Test Output */}
          {testResult && (
            <div className="p-3.5 rounded-md bg-blue-50 border border-blue-200 text-xs text-blue-950 space-y-1.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-blue-700" />
                  {tr('Verbindungstest erfolgreich', 'Connection test succeeded')}
                </span>
                <span className="font-mono text-blue-800">
                  {testResult.version} · {testResult.latencyMs} ms
                </span>
              </div>
              <p className="text-blue-800">
                {testResult.existingRowCount > 0
                  ? tr(
                      `In "${testResult.database}" wurden bereits ${testResult.existingRowCount} bestehende Datensätze gefunden.`,
                      `Found ${testResult.existingRowCount} existing rows in "${testResult.database}".`
                    )
                  : tr(
                      `Datenbank "${testResult.database}" ist leer und bereit für die Migration.`,
                      `Database "${testResult.database}" is empty and ready for migration.`
                    )}
              </p>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-100">
            <div className="flex flex-wrap items-center gap-2.5">
              <button
                type="button"
                onClick={() => void handleTestConnection()}
                disabled={testing || migrating || !formHasRequiredFields}
                className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-slate-800 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <PlugZap className="w-3.5 h-3.5 text-blue-700" />
                {testing
                  ? tr('Teste Verbindung...', 'Testing connection...')
                  : tr('Verbindung testen', 'Test connection')}
              </button>

              {!isMariaDb && (
                <button
                  type="submit"
                  disabled={savingConfig || migrating || !formHasRequiredFields}
                  className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-white bg-slate-800 hover:bg-slate-900 rounded-md transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Save className="w-3.5 h-3.5" />
                  {savingConfig
                    ? tr('Speichere...', 'Saving...')
                    : tr('Verbindungsdaten speichern', 'Save connection settings')}
                </button>
              )}
            </div>

            {!isMariaDb && status?.mariadb.configured && (
              <div>
                {confirmClearConfig ? (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-red-700">
                      {tr('Daten entfernen?', 'Remove settings?')}
                    </span>
                    <button
                      type="button"
                      onClick={() => void handleClearMariaDbConfig()}
                      disabled={clearingConfig}
                      className="px-2.5 py-1.5 text-xs font-medium text-white bg-red-600 hover:bg-red-700 rounded-md cursor-pointer disabled:opacity-50"
                    >
                      {tr('Ja, löschen', 'Yes, remove')}
                    </button>
                    <button
                      type="button"
                      onClick={() => setConfirmClearConfig(false)}
                      className="px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md cursor-pointer"
                    >
                      {tr('Abbrechen', 'Cancel')}
                    </button>
                  </div>
                ) : (
                  <button
                    type="button"
                    onClick={() => setConfirmClearConfig(true)}
                    className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-red-700 hover:bg-red-50 rounded-md transition-colors cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    {tr('Gespeicherte MariaDB-Daten löschen', 'Delete saved MariaDB settings')}
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Collapsible MariaDB SQL Prep Helper */}
          <div className="pt-1">
            <button
              type="button"
              onClick={() => setShowSqlSnippet((v) => !v)}
              className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-700 hover:text-blue-900 cursor-pointer"
            >
              {showSqlSnippet ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              {tr('SQL-Vorlage zum Anlegen von Datenbank & Benutzer in MariaDB anzeigen', 'Show SQL snippet to create database & user in MariaDB')}
            </button>
            {showSqlSnippet && (
              <div className="mt-2.5 rounded-md bg-slate-900 text-slate-100 p-3.5 relative">
                <button
                  type="button"
                  onClick={() => void handleCopySql()}
                  className="absolute top-2.5 right-2.5 inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 cursor-pointer"
                >
                  <Copy className="w-3 h-3" />
                  {copiedSql ? tr('Kopiert', 'Copied') : tr('Kopieren', 'Copy')}
                </button>
                <pre className="text-xs font-mono overflow-x-auto pr-20 leading-relaxed">
                  {sqlSetupSnippet}
                </pre>
              </div>
            )}
          </div>
        </form>
      </section>

      {/* Bidirectional Migration Card */}
      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex items-center gap-2.5">
          <ArrowLeftRight className="w-4 h-4 text-blue-700" />
          <div>
            <h2 className="text-sm font-semibold text-slate-900">
              {tr('Datenbank-Migration', 'Database Migration')}
            </h2>
            <p className="text-xs text-slate-500">
              {tr(
                'Alle Benutzer, Gruppen, Server, Befehle, SSH-Zertifikate, CAs, Passkeys, API-Schlüssel und Protokolle werden vollständig und konsistent übertragen.',
                'All users, groups, servers, commands, SSH certificates, CAs, passkeys, API keys, and logs are migrated completely and consistently.'
              )}
            </p>
          </div>
        </div>

        <div className="p-5 space-y-4">
          {!isMariaDb ? (
            <>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-md bg-slate-50 border border-slate-200">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                    <span>SQLite</span>
                    <ArrowRight className="w-4 h-4 text-blue-700" />
                    <span>MariaDB</span>
                  </div>
                  <p className="text-xs text-slate-600 max-w-2xl">
                    {tr(
                      'Erstellt das Tabellen-Schema in MariaDB, überträgt alle vorhandenen Datensätze in einer Transaktion, prüft die Datensatzanzahl und schaltet die laufende Instanz nahtlos auf MariaDB um. Die lokale SQLite-Datei bleibt als Sicherheitskopie unverändert erhalten.',
                      'Creates the schema in MariaDB, transfers all records inside a transaction, verifies total row counts, and switches the running instance seamlessly to MariaDB. Your local SQLite file remains untouched as a backup.'
                    )}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => void handleMigrateToMariaDb()}
                  disabled={
                    migrating ||
                    !formHasRequiredFields ||
                    (Boolean(overwriteWarning) && !confirmOverwrite)
                  }
                  className="inline-flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-semibold text-white bg-blue-700 hover:bg-blue-800 rounded-md transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
                >
                  <Database className="w-4 h-4" />
                  {migrating
                    ? tr('Migriere nach MariaDB...', 'Migrating to MariaDB...')
                    : tr('Von SQLite zu MariaDB migrieren', 'Migrate SQLite to MariaDB')}
                </button>
              </div>

              {overwriteWarning && (
                <div className="p-4 rounded-md bg-amber-50 border border-amber-300 space-y-3">
                  <div className="flex items-start gap-2.5">
                    <AlertTriangle className="w-4 h-4 text-amber-700 shrink-0 mt-0.5" />
                    <div className="text-xs text-amber-950 space-y-1">
                      <p className="font-semibold">
                        {tr('Ziel-Datenbank ist nicht leer', 'Target database is not empty')}
                      </p>
                      <p>{overwriteWarning.message}</p>
                      {overwriteWarning.existingTables.length > 0 && (
                        <p className="font-mono text-[11px] text-amber-800">
                          {overwriteWarning.existingTables
                            .filter((t) => t.rows > 0)
                            .map((t) => `${t.table}: ${t.rows}`)
                            .join(' · ')}
                        </p>
                      )}
                    </div>
                  </div>
                  <label className="inline-flex items-center gap-2 text-xs font-medium text-amber-950 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={confirmOverwrite}
                      onChange={(e) => setConfirmOverwrite(e.target.checked)}
                      className="rounded border-amber-400 text-amber-700 focus:ring-amber-500"
                    />
                    {tr(
                      'Ich bestätige, dass vorhandene SSH-Console-Daten in der Ziel-MariaDB überschrieben werden dürfen.',
                      'I confirm that existing SSH Console data in the target MariaDB may be overwritten.'
                    )}
                  </label>
                </div>
              )}
            </>
          ) : (
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-md bg-slate-50 border border-slate-200">
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                  <span>MariaDB</span>
                  <ArrowRight className="w-4 h-4 text-emerald-700" />
                  <span>SQLite</span>
                </div>
                <p className="text-xs text-slate-600 max-w-2xl">
                  {tr(
                    'Liest den aktuellen Stand aus MariaDB, legt automatisch eine Sicherungskopie der bisherigen SQLite-Datei an, schreibt alle Datensätze atomar nach SQLite und schaltet sofort zurück auf SQLite. Die Daten in MariaDB werden dabei nicht gelöscht.',
                    'Reads the latest state from MariaDB, creates a timestamped backup of the previous SQLite file, writes all records atomically to SQLite, and switches back immediately. Data in MariaDB is not deleted.'
                  )}
                </p>
              </div>
              <button
                type="button"
                onClick={() => void handleMigrateToSqlite()}
                disabled={migrating}
                className="inline-flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-semibold text-white bg-emerald-700 hover:bg-emerald-800 rounded-md transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
              >
                <HardDrive className="w-4 h-4" />
                {migrating
                  ? tr('Migriere zu SQLite...', 'Migrating to SQLite...')
                  : tr('Von MariaDB zu SQLite migrieren', 'Migrate MariaDB to SQLite')}
              </button>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
