import React, { useEffect, useState } from 'react';
import { Play, Terminal, KeyRound, Server, AlertTriangle, CheckCircle2, ChevronDown, ChevronRight } from 'lucide-react';
import { api } from '../api';
import { translateCategory, useI18n } from '../i18n';
import type {
  ActiveTab,
  ExecutionLog,
  SshCommand,
  User,
  UserCertificate,
  UserServer,
} from '../types';

interface ExecuteViewProps {
  user: User;
  opensshAvailable: boolean;
  commands: SshCommand[];
  servers: UserServer[];
  certificates: UserCertificate[];
  onNavigate: (tab: ActiveTab) => void;
  onExecutionComplete: () => Promise<void>;
}

export function ExecuteView({
  user,
  opensshAvailable,
  commands,
  servers,
  certificates,
  onNavigate,
  onExecutionComplete,
}: ExecuteViewProps) {
  const { locale, tr } = useI18n();
  const activeCommands = commands.filter((c) => c.enabled);

  const [selectedCommandId, setSelectedCommandId] = useState<string>('');
  const [selectedCertId, setSelectedCertId] = useState<string>('');
  const [selectedServerIds, setSelectedServerIds] = useState<string[]>([]);

  // Ad-hoc direct IP input so users can immediately enter an IP without saving first
  const [useDirectIp, setUseDirectIp] = useState<boolean>(servers.length === 0);
  const [directIp, setDirectIp] = useState('');
  const [directPort, setDirectPort] = useState('22');
  const [directSshUser, setDirectSshUser] = useState(user.defaultSshUser || 'root');

  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<ExecutionLog[]>([]);
  const [expandedInvocations, setExpandedInvocations] = useState<Record<string, boolean>>({});

  useEffect(() => {
    if (activeCommands.length === 0) {
      setSelectedCommandId('');
    } else if (!activeCommands.some((c) => c.id === selectedCommandId)) {
      setSelectedCommandId(activeCommands[0].id);
    }
  }, [activeCommands, selectedCommandId]);

  useEffect(() => {
    if (certificates.length === 0) {
      setSelectedCertId('');
    } else if (!certificates.some((c) => c.id === selectedCertId)) {
      setSelectedCertId(certificates[0].id);
    }
  }, [certificates, selectedCertId]);

  useEffect(() => {
    if (servers.length > 0 && selectedServerIds.length === 0 && !useDirectIp) {
      setSelectedServerIds([servers[0].id]);
    }
  }, [servers, selectedServerIds.length, useDirectIp]);

  const selectedCommand = activeCommands.find((c) => c.id === selectedCommandId) ?? null;
  const selectedCert = certificates.find((c) => c.id === selectedCertId) ?? null;

  function toggleServer(id: string) {
    setSelectedServerIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  }

  async function handleRun(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!selectedCommand) {
      setError(
        tr(
          'Bitte wählen Sie einen SSH-Befehl aus.',
          'Please select an SSH command.'
        )
      );
      return;
    }
    if (!selectedCert) {
      setError(
        tr(
          'Bitte laden Sie zuerst ein SSH-Schlüssel- oder Zertifikatspaket hoch.',
          'Please upload an SSH key or certificate bundle first.'
        )
      );
      return;
    }

    const targets: Array<
      { serverId: string } | { ipAddress: string; port: number; sshUser: string }
    > = [];

    if (useDirectIp) {
      if (!directIp.trim()) {
        setError(tr('Bitte geben Sie eine Ziel-IP-Adresse ein.', 'Please enter a target IP address.'));
        return;
      }
      targets.push({
        ipAddress: directIp.trim(),
        port: Number(directPort) || 22,
        sshUser: directSshUser.trim() || user.defaultSshUser || 'root',
      });
    } else {
      if (selectedServerIds.length === 0) {
        setError(tr('Bitte wählen Sie mindestens einen Zielserver aus.', 'Please select at least one target server.'));
        return;
      }
      for (const id of selectedServerIds) {
        targets.push({ serverId: id });
      }
    }

    setRunning(true);
    try {
      const res = await api.execute({
        commandId: selectedCommand.id,
        certificateId: selectedCert.id,
        targets,
      });
      setResults(res.results);
      await onExecutionComplete();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Ausführung fehlgeschlagen.', 'Execution failed.')
      );
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
            {tr('SSH-Befehle ausführen', 'Run SSH Commands')}
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            {tr(
              'Wählen Sie eigene oder vom Administrator geteilte Ziel-IPs, SSH-Befehle und Zertifikatspakete für die Ausführung.',
              'Select your own or administrator-shared target IPs, SSH commands, and key/certificate bundles for execution.'
            )}
          </p>
        </div>

        <div className="text-xs text-slate-500 whitespace-nowrap shrink-0">
          {opensshAvailable
            ? tr('OpenSSH-Client lokal verfügbar · Live-Ausführung', 'OpenSSH client available locally · Live execution')
            : tr('Vorschau-Sandbox ohne /usr/bin/ssh · Zertifikats- & TCP-Prüflauf', 'Preview sandbox without /usr/bin/ssh · Certificate & TCP dry-run')}
        </div>
      </div>

      {error && (
        <div role="alert" className="px-4 py-3 rounded-md bg-red-50 border border-red-200 text-sm text-red-800">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* Left: Execution Configuration */}
        <form
          onSubmit={handleRun}
          className="xl:col-span-5 bg-white border border-slate-200 rounded-lg p-6 space-y-6"
        >
          {/* Step 1: Target IPs */}
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2">
              <label className="text-sm font-semibold text-slate-900">
                {tr('1. Zielserver / IP-Adresse', '1. Target Server / IP Address')}
              </label>
              <div className="inline-flex items-center gap-1 p-0.5 bg-slate-100 rounded-md">
                <button
                  type="button"
                  onClick={() => setUseDirectIp(false)}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                    !useDirectIp ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {tr(`Gespeicherte (${servers.length})`, `Saved (${servers.length})`)}
                </button>
                <button
                  type="button"
                  onClick={() => setUseDirectIp(true)}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                    useDirectIp ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {tr('Direkte IP', 'Direct IP')}
                </button>
              </div>
            </div>

            {useDirectIp ? (
              <div className="grid grid-cols-12 gap-3">
                <div className="col-span-6">
                  <label htmlFor="exec-ip" className="block text-xs text-slate-600 mb-1">
                    {tr('IP-Adresse', 'IP Address')}
                  </label>
                  <input
                    id="exec-ip"
                    type="text"
                    value={directIp}
                    onChange={(e) => setDirectIp(e.target.value)}
                    placeholder="10.0.10.15"
                    className="w-full px-3 py-2 text-sm font-mono tabular-nums border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                    required
                  />
                </div>
                <div className="col-span-2">
                  <label htmlFor="exec-port" className="block text-xs text-slate-600 mb-1">
                    Port
                  </label>
                  <input
                    id="exec-port"
                    type="number"
                    min={1}
                    max={65535}
                    value={directPort}
                    onChange={(e) => setDirectPort(e.target.value)}
                    className="w-full px-2.5 py-2 text-sm font-mono tabular-nums border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                    required
                  />
                </div>
                <div className="col-span-4">
                  <label htmlFor="exec-user" className="block text-xs text-slate-600 mb-1">
                    {tr('SSH-Benutzer', 'SSH User')}
                  </label>
                  <input
                    id="exec-user"
                    type="text"
                    value={directSshUser}
                    onChange={(e) => setDirectSshUser(e.target.value)}
                    placeholder="root"
                    className="w-full px-3 py-2 text-sm font-mono border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                    required
                  />
                </div>
              </div>
            ) : servers.length === 0 ? (
              <div className="border border-slate-200 rounded-md p-4 bg-slate-50 text-xs text-slate-600 flex items-center justify-between gap-3">
                <span>{tr('Noch keine Server gespeichert.', 'No servers saved yet.')}</span>
                <button
                  type="button"
                  onClick={() => onNavigate('servers')}
                  className="text-blue-700 hover:text-blue-900 font-medium whitespace-nowrap cursor-pointer"
                >
                  {tr('Server anlegen', 'Add Server')}
                </button>
              </div>
            ) : (
              <div className="border border-slate-200 rounded-md divide-y divide-slate-200 max-h-48 overflow-y-auto">
                {servers.map((srv) => {
                  const checked = selectedServerIds.includes(srv.id);
                  return (
                    <label
                      key={srv.id}
                      className="flex items-center justify-between gap-3 px-3.5 py-2.5 hover:bg-slate-50 cursor-pointer"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleServer(srv.id)}
                          className="rounded border-slate-300 text-blue-700 focus:ring-blue-600"
                        />
                        <div className="min-w-0">
                          <p className="text-sm font-medium text-slate-900 truncate">
                            {srv.label}
                            {srv.userId !== user.id && (
                              <span className="ml-1.5 text-xs font-normal text-blue-800">
                                · {tr('Geteilt', 'Shared')}
                              </span>
                            )}
                          </p>
                          <p className="text-xs font-mono text-slate-500 tabular-nums truncate">
                            {srv.sshUser}@{srv.ipAddress}:{srv.port}
                          </p>
                        </div>
                      </div>
                    </label>
                  );
                })}
              </div>
            )}
          </div>

          {/* Step 2: SSH Command */}
          <div className="space-y-2.5 pt-4 border-t border-slate-200">
            <div className="flex items-center justify-between gap-2">
              <label htmlFor="exec-cmd" className="text-sm font-semibold text-slate-900">
                {tr('2. SSH-Befehl / Befehlskette', '2. SSH Command / Command Chain')}
              </label>
              <button
                type="button"
                onClick={() => onNavigate('admin-commands')}
                className="text-xs font-medium text-blue-700 hover:text-blue-900 cursor-pointer whitespace-nowrap"
              >
                {tr('Befehle verwalten', 'Manage Commands')}
              </button>
            </div>

            {activeCommands.length === 0 ? (
              <div className="border border-slate-200 rounded-md p-4 bg-slate-50 text-xs text-slate-600 space-y-2">
                <p>{tr('Es wurden noch keine SSH-Befehle angelegt.', 'No SSH commands have been created yet.')}</p>
                <button
                  type="button"
                  onClick={() => onNavigate('admin-commands')}
                  className="text-blue-700 hover:text-blue-900 font-medium cursor-pointer"
                >
                  {tr('Jetzt erste SSH-Befehle anlegen', 'Create your first SSH commands')}
                </button>
              </div>
            ) : (
              <>
                <select
                  id="exec-cmd"
                  value={selectedCommandId}
                  onChange={(e) => setSelectedCommandId(e.target.value)}
                  className="w-full px-3 py-2 text-sm bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600"
                >
                  {activeCommands.map((cmd) => (
                    <option key={cmd.id} value={cmd.id}>
                      [{translateCategory(cmd.category, locale)}] {cmd.name}
                      {cmd.kind === 'chain'
                        ? tr(` (Kette · ${cmd.steps.length} Schritte)`, ` (Chain · ${cmd.steps.length} steps)`)
                        : ''}
                      {cmd.userId !== user.id ? tr(' · Geteilt', ' · Shared') : ''}
                    </option>
                  ))}
                </select>
                {selectedCommand && (
                  <div className="rounded-md bg-slate-50 border border-slate-200 p-3 space-y-2">
                    {selectedCommand.kind === 'chain' && selectedCommand.steps.length > 0 ? (
                      <div className="space-y-1.5">
                        <p className="text-xs font-medium text-slate-700">
                          {tr(
                            'Ablauf der Befehlskette (ausgeführt als ein SSH-Befehl · ',
                            'Command chain sequence (executed as a single SSH command · '
                          )}
                          {selectedCommand.stopOnError
                            ? tr('Abbruch bei Fehler', 'Abort on error')
                            : tr('Fortfahren bei Fehler', 'Continue on error')}
                          )
                        </p>
                        <ol className="space-y-1 font-mono text-xs text-slate-800">
                          {selectedCommand.steps.map((step, idx) => (
                            <li key={idx} className="space-y-0.5">
                              <div className="break-all">
                                <span className="text-slate-400 tabular-nums mr-1.5">{idx + 1}.</span>
                                {step.command}
                              </div>
                              {idx < selectedCommand.steps.length - 1 && step.sleepAfterSec > 0 && (
                                <div className="pl-4 text-[11px] text-blue-700 tabular-nums">
                                  ↳ sleep {step.sleepAfterSec}s
                                </div>
                              )}
                            </li>
                          ))}
                        </ol>
                        <div className="pt-1.5 border-t border-slate-200">
                          <code className="block font-mono text-[11px] text-slate-500 break-all">
                            {selectedCommand.command}
                          </code>
                        </div>
                      </div>
                    ) : (
                      <code className="block font-mono text-xs text-slate-900 break-all">
                        {selectedCommand.command}
                      </code>
                    )}
                    {selectedCommand.description && (
                      <p className="text-xs text-slate-500">{selectedCommand.description}</p>
                    )}
                    <p className="text-xs text-slate-500 tabular-nums">
                      {tr('Kategorie', 'Category')}: {translateCategory(selectedCommand.category, locale)} · Timeout:{' '}
                      {selectedCommand.timeoutSec}s
                    </p>
                  </div>
                )}
              </>
            )}
          </div>

          {/* Step 3: SSH Key / Certificate Bundle */}
          <div className="space-y-2.5 pt-4 border-t border-slate-200">
            <div className="flex items-center justify-between gap-2">
              <label htmlFor="exec-cert" className="text-sm font-semibold text-slate-900">
                {tr('3. SSH-Schlüssel / Zertifikat', '3. SSH Key / Certificate')}
              </label>
              <button
                type="button"
                onClick={() => onNavigate('certificates')}
                className="text-xs font-medium text-blue-700 hover:text-blue-900 cursor-pointer whitespace-nowrap"
              >
                {tr('Zertifikate verwalten', 'Manage Certificates')}
              </button>
            </div>

            {certificates.length === 0 ? (
              <div className="border border-slate-200 rounded-md p-4 bg-slate-50 text-xs text-slate-600 space-y-2">
                <p>
                  {tr('Für die passwortlose Anmeldung werden ', 'Passwordless login requires ')}
                  <code className="font-mono">zertifikat</code> {tr('und', 'and')}{' '}
                  <code className="font-mono">zertifikat.pub</code>{' '}
                  {tr('(optional mit ', '(optionally with ')}
                  <code className="font-mono">zertifikat-cert.pub</code>
                  {tr(') benötigt.', ').')}
                </p>
                <button
                  type="button"
                  onClick={() => onNavigate('certificates')}
                  className="inline-flex items-center gap-1.5 text-blue-700 hover:text-blue-900 font-medium cursor-pointer"
                >
                  <KeyRound className="w-3.5 h-3.5" />
                  {tr('Schlüssel / Zertifikat hochladen', 'Upload Key / Certificate')}
                </button>
              </div>
            ) : (
              <>
                <select
                  id="exec-cert"
                  value={selectedCertId}
                  onChange={(e) => setSelectedCertId(e.target.value)}
                  className="w-full px-3 py-2 text-sm bg-white border border-slate-300 rounded-md text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600"
                >
                  {certificates.map((cert) => {
                    const hasCert = cert.metadata.hasCertificate !== false && Boolean(cert.certFileName);
                    return (
                      <option key={cert.id} value={cert.id}>
                        {cert.name} (
                        {hasCert
                          ? cert.metadata.keyId || cert.certFileName
                          : tr('Schlüsselpaar ohne CA-Cert', 'Keypair without CA cert')}
                        )
                        {cert.userId !== user.id ? tr(' · Geteilt', ' · Shared') : ''}
                      </option>
                    );
                  })}
                </select>
                {selectedCert && (() => {
                  const hasCert =
                    selectedCert.metadata.hasCertificate !== false && Boolean(selectedCert.certFileName);
                  return (
                    <div className="text-xs text-slate-600 space-y-1 px-1">
                      {hasCert ? (
                        <p>
                          Principals:{' '}
                          <span className="font-mono text-slate-800">
                            {selectedCert.metadata.principals.length > 0
                              ? selectedCert.metadata.principals.join(', ')
                              : tr('(alle)', '(all)')}
                          </span>
                        </p>
                      ) : (
                        <p>
                          {tr('Modus', 'Mode')}:{' '}
                          <span className="font-mono text-slate-800">
                            {tr('SSH-Schlüsselpaar (authorized_keys)', 'SSH Keypair (authorized_keys)')}
                          </span>
                        </p>
                      )}
                      <p className="font-mono text-slate-500">
                        {selectedCert.privateKeyFileName} · {selectedCert.publicKeyFileName}
                        {hasCert ? ` · ${selectedCert.certFileName}` : ''}
                      </p>
                      {hasCert && selectedCert.metadata.isExpired && (
                        <p className="text-red-700 font-medium">
                          {tr(
                            'Warnung: Dieses Zertifikat ist abgelaufen.',
                            'Warning: This certificate has expired.'
                          )}
                        </p>
                      )}
                    </div>
                  );
                })()}
              </>
            )}
          </div>

          <div className="pt-2">
            <button
              type="submit"
              disabled={running || !selectedCommand || !selectedCert}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
            >
              <Play className="w-4 h-4" />
              {running ? tr('SSH-Ausführung läuft...', 'Executing SSH command...') : tr('Befehl ausführen', 'Run Command')}
            </button>
          </div>
        </form>

        {/* Right: Terminal Output Viewport */}
        <section className="xl:col-span-7 bg-[#0B1120] text-slate-100 rounded-lg border border-slate-800 overflow-hidden flex flex-col min-h-[540px]">
          <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between gap-4 bg-slate-950/60">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-slate-400" />
              <span className="text-xs font-medium text-slate-200 tracking-wide">
                {tr('Konsolenausgabe', 'Console Output')}
              </span>
            </div>
            <span className="text-xs font-mono text-slate-400 tabular-nums">
              {results.length > 0
                ? tr(
                    `${results.length} Ziel${results.length === 1 ? '' : 'e'} ausgeführt`,
                    `${results.length} target${results.length === 1 ? '' : 's'} executed`
                  )
                : tr('Bereit', 'Ready')}
            </span>
          </div>

          <div className="flex-1 p-5 overflow-y-auto space-y-5 font-mono text-xs leading-relaxed">
            {running ? (
              <div className="text-slate-400 py-8 text-center">
                {tr(
                  'Verbinde per OpenSSH-Schlüssel/Zertifikat und führe Befehl aus...',
                  'Connecting via OpenSSH key/certificate and executing command...'
                )}
              </div>
            ) : results.length === 0 ? (
              <div className="py-12 text-center space-y-2 text-slate-400 font-sans">
                <Server className="w-6 h-6 mx-auto text-slate-500" />
                <p className="text-sm text-slate-300 font-medium">
                  {tr('Noch keine Ausgabe vorhanden', 'No output yet')}
                </p>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  {tr(
                    'Konfigurieren Sie links Ziel-IP, Befehl und OpenSSH-Zertifikat und starten Sie die passwortlose Ausführung.',
                    'Configure target IP, command, and OpenSSH key/certificate on the left to start passwordless execution.'
                  )}
                </p>
              </div>
            ) : (
              results.map((res) => {
                const ok = res.exitCode === 0;
                const showCmd = Boolean(expandedInvocations[res.id]);
                return (
                  <div
                    key={res.id}
                    className="border border-slate-800 rounded-md overflow-hidden bg-slate-950/50"
                  >
                    <div className="px-4 py-2.5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2 bg-slate-900/70">
                      <div className="flex items-center gap-2">
                        {ok ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        ) : (
                          <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                        )}
                        <span className="text-slate-100 font-medium">
                          {res.sshUser}@{res.targetIp}:{res.targetPort}
                        </span>
                        <span className="text-slate-500">·</span>
                        <span className="text-slate-400">{res.commandName}</span>
                      </div>
                      <div className="flex items-center gap-3 tabular-nums">
                        <span className={ok ? 'text-emerald-400' : 'text-red-400'}>
                          Exit {res.exitCode}
                        </span>
                        <span className="text-slate-400">{res.durationMs} ms</span>
                      </div>
                    </div>

                    <div className="p-4 space-y-3">
                      <button
                        type="button"
                        onClick={() =>
                          setExpandedInvocations((prev) => ({ ...prev, [res.id]: !prev[res.id] }))
                        }
                        className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 cursor-pointer"
                      >
                        {showCmd ? (
                          <ChevronDown className="w-3.5 h-3.5" />
                        ) : (
                          <ChevronRight className="w-3.5 h-3.5" />
                        )}
                        {tr('OpenSSH-Aufrufparameter anzeigen', 'Show OpenSSH invocation')}
                      </button>

                      {showCmd && (
                        <pre className="p-2.5 rounded bg-slate-900 text-slate-300 text-[11px] whitespace-pre-wrap break-all border border-slate-800">
                          {res.sshInvocation}
                        </pre>
                      )}

                      {res.stdout && (
                        <pre className="text-slate-200 whitespace-pre-wrap break-words">
                          {res.stdout}
                        </pre>
                      )}

                      {res.stderr && (
                        <pre className="text-amber-300 whitespace-pre-wrap break-words border-t border-slate-800 pt-3">
                          {res.stderr}
                        </pre>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
