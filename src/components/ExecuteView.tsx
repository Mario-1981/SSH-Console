import React, { useEffect, useState } from 'react';
import { Play, Terminal, KeyRound, Server, AlertTriangle, CheckCircle2, ChevronDown, ChevronRight } from 'lucide-react';
import { api } from '../api';
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
      setError('Bitte wählen Sie einen vom Administrator freigegebenen SSH-Befehl aus.');
      return;
    }
    if (!selectedCert) {
      setError('Bitte laden Sie zuerst ein 3-Dateien-SSH-Zertifikatspaket hoch.');
      return;
    }

    const targets: Array<
      { serverId: string } | { ipAddress: string; port: number; sshUser: string }
    > = [];

    if (useDirectIp) {
      if (!directIp.trim()) {
        setError('Bitte geben Sie eine Ziel-IP-Adresse ein.');
        return;
      }
      targets.push({
        ipAddress: directIp.trim(),
        port: Number(directPort) || 22,
        sshUser: directSshUser.trim() || user.defaultSshUser || 'root',
      });
    } else {
      if (selectedServerIds.length === 0) {
        setError('Bitte wählen Sie mindestens einen Zielserver aus.');
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
      setError(err instanceof Error ? err.message : 'Ausführung fehlgeschlagen.');
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
            SSH-Befehle ausführen
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            Wählen Sie eigene oder vom Administrator geteilte Ziel-IPs, SSH-Befehle und Zertifikatspakete für die Ausführung.
          </p>
        </div>

        <div className="text-xs text-slate-500 whitespace-nowrap shrink-0">
          {opensshAvailable
            ? 'OpenSSH-Client lokal verfügbar · Live-Ausführung'
            : 'Vorschau-Sandbox ohne /usr/bin/ssh · Zertifikats- & TCP-Prüflauf'}
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
                1. Zielserver / IP-Adresse
              </label>
              <div className="inline-flex items-center gap-1 p-0.5 bg-slate-100 rounded-md">
                <button
                  type="button"
                  onClick={() => setUseDirectIp(false)}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                    !useDirectIp ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Gespeicherte ({servers.length})
                </button>
                <button
                  type="button"
                  onClick={() => setUseDirectIp(true)}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                    useDirectIp ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Direkte IP
                </button>
              </div>
            </div>

            {useDirectIp ? (
              <div className="grid grid-cols-12 gap-3">
                <div className="col-span-6">
                  <label htmlFor="exec-ip" className="block text-xs text-slate-600 mb-1">
                    IP-Adresse
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
                    SSH-Benutzer
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
                <span>Noch keine Server gespeichert.</span>
                <button
                  type="button"
                  onClick={() => onNavigate('servers')}
                  className="text-blue-700 hover:text-blue-900 font-medium whitespace-nowrap cursor-pointer"
                >
                  Server anlegen
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
                                · Geteilt
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
                2. SSH-Befehl / Befehlskette
              </label>
              <button
                type="button"
                onClick={() => onNavigate('admin-commands')}
                className="text-xs font-medium text-blue-700 hover:text-blue-900 cursor-pointer whitespace-nowrap"
              >
                Befehle verwalten
              </button>
            </div>

            {activeCommands.length === 0 ? (
              <div className="border border-slate-200 rounded-md p-4 bg-slate-50 text-xs text-slate-600 space-y-2">
                <p>Es wurden noch keine SSH-Befehle angelegt.</p>
                <button
                  type="button"
                  onClick={() => onNavigate('admin-commands')}
                  className="text-blue-700 hover:text-blue-900 font-medium cursor-pointer"
                >
                  Jetzt erste SSH-Befehle anlegen
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
                      [{cmd.category}] {cmd.name}
                      {cmd.kind === 'chain' ? ` (Kette · ${cmd.steps.length} Schritte)` : ''}
                      {cmd.userId !== user.id ? ` · Geteilt` : ''}
                    </option>
                  ))}
                </select>
                {selectedCommand && (
                  <div className="rounded-md bg-slate-50 border border-slate-200 p-3 space-y-2">
                    {selectedCommand.kind === 'chain' && selectedCommand.steps.length > 0 ? (
                      <div className="space-y-1.5">
                        <p className="text-xs font-medium text-slate-700">
                          Ablauf der Befehlskette (ausgeführt als ein SSH-Befehl ·{' '}
                          {selectedCommand.stopOnError ? 'Abbruch bei Fehler' : 'Fortfahren bei Fehler'})
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
                      Kategorie: {selectedCommand.category} · Timeout: {selectedCommand.timeoutSec}s
                    </p>
                  </div>
                )}
              </>
            )}
          </div>

          {/* Step 3: 3-File Certificate Bundle */}
          <div className="space-y-2.5 pt-4 border-t border-slate-200">
            <div className="flex items-center justify-between gap-2">
              <label htmlFor="exec-cert" className="text-sm font-semibold text-slate-900">
                3. OpenSSH-Zertifikatspaket
              </label>
              <button
                type="button"
                onClick={() => onNavigate('certificates')}
                className="text-xs font-medium text-blue-700 hover:text-blue-900 cursor-pointer whitespace-nowrap"
              >
                Zertifikate verwalten
              </button>
            </div>

            {certificates.length === 0 ? (
              <div className="border border-slate-200 rounded-md p-4 bg-slate-50 text-xs text-slate-600 space-y-2">
                <p>
                  Für die passwortlose Anmeldung werden{' '}
                  <code className="font-mono">zertifikat</code>,{' '}
                  <code className="font-mono">zertifikat.pub</code> und{' '}
                  <code className="font-mono">zertifikat-cert.pub</code> benötigt.
                </p>
                <button
                  type="button"
                  onClick={() => onNavigate('certificates')}
                  className="inline-flex items-center gap-1.5 text-blue-700 hover:text-blue-900 font-medium cursor-pointer"
                >
                  <KeyRound className="w-3.5 h-3.5" />
                  Zertifikatspaket hochladen
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
                  {certificates.map((cert) => (
                    <option key={cert.id} value={cert.id}>
                      {cert.name} ({cert.metadata.keyId || cert.certFileName})
                      {cert.userId !== user.id ? ' · Geteilt' : ''}
                    </option>
                  ))}
                </select>
                {selectedCert && (
                  <div className="text-xs text-slate-600 space-y-1 px-1">
                    <p>
                      Principals:{' '}
                      <span className="font-mono text-slate-800">
                        {selectedCert.metadata.principals.length > 0
                          ? selectedCert.metadata.principals.join(', ')
                          : '(alle)'}
                      </span>
                    </p>
                    <p className="font-mono text-slate-500">
                      {selectedCert.privateKeyFileName} · {selectedCert.publicKeyFileName} ·{' '}
                      {selectedCert.certFileName}
                    </p>
                    {selectedCert.metadata.isExpired && (
                      <p className="text-red-700 font-medium">
                        Warnung: Dieses Zertifikat ist abgelaufen.
                      </p>
                    )}
                  </div>
                )}
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
              {running ? 'SSH-Ausführung läuft...' : 'Befehl ausführen'}
            </button>
          </div>
        </form>

        {/* Right: Terminal Output Viewport */}
        <section className="xl:col-span-7 bg-[#0B1120] text-slate-100 rounded-lg border border-slate-800 overflow-hidden flex flex-col min-h-[540px]">
          <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between gap-4 bg-slate-950/60">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-slate-400" />
              <span className="text-xs font-medium text-slate-200 tracking-wide">
                Konsolenausgabe
              </span>
            </div>
            <span className="text-xs font-mono text-slate-400 tabular-nums">
              {results.length > 0
                ? `${results.length} Ziel${results.length === 1 ? '' : 'e'} ausgeführt`
                : 'Bereit'}
            </span>
          </div>

          <div className="flex-1 p-5 overflow-y-auto space-y-5 font-mono text-xs leading-relaxed">
            {running ? (
              <div className="text-slate-400 py-8 text-center">
                Verbinde per OpenSSH-Zertifikat und führe Befehl aus...
              </div>
            ) : results.length === 0 ? (
              <div className="py-12 text-center space-y-2 text-slate-400 font-sans">
                <Server className="w-6 h-6 mx-auto text-slate-500" />
                <p className="text-sm text-slate-300 font-medium">Noch keine Ausgabe vorhanden</p>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  Konfigurieren Sie links Ziel-IP, Befehl und OpenSSH-Zertifikat und starten Sie die
                  passwortlose Ausführung.
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
                        OpenSSH-Aufrufparameter anzeigen
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
