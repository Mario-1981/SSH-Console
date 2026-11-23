import React, { useEffect, useRef, useState } from 'react';
import { Terminal as XTerm } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import {
  Terminal,
  Plug,
  Unplug,
  RotateCcw,
  Trash2,
  Maximize2,
  Minimize2,
  KeyRound,
  Server,
  AlertTriangle,
} from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import type { ActiveTab, User, UserCertificate, UserServer } from '../types';

interface SshShellViewProps {
  user: User;
  opensshAvailable: boolean;
  allowInsecureHostKey?: boolean;
  servers: UserServer[];
  certificates: UserCertificate[];
  onNavigate: (tab: ActiveTab) => void;
  onSessionEnded: () => Promise<void>;
}

type ConnectionState = 'idle' | 'connecting' | 'connected' | 'preview' | 'closed' | 'error';

export function SshShellView({
  user,
  opensshAvailable,
  allowInsecureHostKey = false,
  servers,
  certificates,
  onNavigate,
  onSessionEnded,
}: SshShellViewProps) {
  const { tr } = useI18n();

  const [targetMode, setTargetMode] = useState<'saved' | 'custom'>(
    servers.length > 0 ? 'saved' : 'custom'
  );
  const [selectedServerId, setSelectedServerId] = useState<string>(servers[0]?.id ?? '');
  const [customIp, setCustomIp] = useState('');
  const [customPort, setCustomPort] = useState(22);
  const [customIgnoreHostKey, setCustomIgnoreHostKey] = useState(false);
  const [sshUser, setSshUser] = useState(
    servers[0]?.sshUser || user.defaultSshUser || 'root'
  );
  const [selectedCertId, setSelectedCertId] = useState<string>(certificates[0]?.id ?? '');

  const [connState, setConnState] = useState<ConnectionState>('idle');
  const [activeTargetLabel, setActiveTargetLabel] = useState<string>('');
  const [activeCertLabel, setActiveCertLabel] = useState<string>('');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [hostKeyNotice, setHostKeyNotice] = useState<string | null>(null);
  const [resettingHostKey, setResettingHostKey] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isExpanded, setIsExpanded] = useState(false);

  const terminalHostRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const pingTimerRef = useRef<number | null>(null);
  const connectAttemptRef = useRef<number>(0);
  const onSessionEndedRef = useRef(onSessionEnded);
  onSessionEndedRef.current = onSessionEnded;

  // Keep server/cert selection valid if workspace data changes
  useEffect(() => {
    if (servers.length > 0 && !servers.some((s) => s.id === selectedServerId)) {
      setSelectedServerId(servers[0].id);
      if (targetMode === 'saved') {
        setSshUser(servers[0].sshUser || user.defaultSshUser || 'root');
      }
    }
    if (servers.length === 0 && targetMode === 'saved') {
      setTargetMode('custom');
    }
  }, [servers, selectedServerId, targetMode, user.defaultSshUser]);

  useEffect(() => {
    if (certificates.length > 0 && !certificates.some((c) => c.id === selectedCertId)) {
      setSelectedCertId(certificates[0].id);
    }
  }, [certificates, selectedCertId]);

  function handleSelectServer(id: string) {
    setSelectedServerId(id);
    const srv = servers.find((s) => s.id === id);
    if (srv) {
      setSshUser(srv.sshUser || user.defaultSshUser || 'root');
    }
  }

  function stopKeepalive() {
    if (pingTimerRef.current !== null) {
      window.clearInterval(pingTimerRef.current);
      pingTimerRef.current = null;
    }
  }

  function closeSocket(silent = false) {
    connectAttemptRef.current += 1;
    stopKeepalive();
    const ws = wsRef.current;
    wsRef.current = null;
    if (ws) {
      ws.onopen = null;
      ws.onmessage = null;
      ws.onerror = null;
      ws.onclose = null;
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close(1000, 'Client disconnect');
      }
    }
    if (!silent) {
      setConnState('closed');
      setStatusMessage(tr('Sitzung getrennt.', 'Session disconnected.'));
    }
  }

  // Initialize xterm.js once
  useEffect(() => {
    const container = terminalHostRef.current;
    if (!container) return;

    const term = new XTerm({
      cursorBlink: true,
      fontFamily: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
      fontSize: 13,
      lineHeight: 1.3,
      scrollback: 5000,
      theme: {
        background: '#0f172a',
        foreground: '#e2e8f0',
        cursor: '#38bdf8',
        cursorAccent: '#0f172a',
        selectionBackground: '#334155',
        black: '#0f172a',
        red: '#f87171',
        green: '#4ade80',
        yellow: '#facc15',
        blue: '#60a5fa',
        magenta: '#c084fc',
        cyan: '#22d3ee',
        white: '#f1f5f9',
        brightBlack: '#64748b',
        brightRed: '#fca5a5',
        brightGreen: '#86efac',
        brightYellow: '#fde047',
        brightBlue: '#93c5fd',
        brightMagenta: '#d8b4fe',
        brightCyan: '#67e8f9',
        brightWhite: '#ffffff',
      },
    });

    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(container);
    fit.fit();

    term.writeln(
      '\x1b[1;34mSSH Console\x1b[0m \x1b[90m— Interaktive OpenSSH-Shell (serverseitig)\x1b[0m'
    );
    term.writeln(
      '\x1b[90mWählen Sie oben Ziel-IP und Zertifikat aus und klicken Sie auf „Verbinden“.\x1b[0m'
    );

    const dataDisposable = term.onData((data) => {
      const ws = wsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'input', data }));
      }
    });

    const resizeDisposable = term.onResize(({ cols, rows }) => {
      const ws = wsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', cols, rows }));
      }
    });

    const observer = new ResizeObserver(() => {
      try {
        fit.fit();
      } catch {
        // ignore layout transition errors
      }
    });
    observer.observe(container);

    termRef.current = term;
    fitRef.current = fit;

    return () => {
      closeSocket(true);
      observer.disconnect();
      dataDisposable.dispose();
      resizeDisposable.dispose();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, []);

  // Re-fit terminal when toggling expanded view
  useEffect(() => {
    const id = window.setTimeout(() => {
      try {
        fitRef.current?.fit();
      } catch {
        // ignore
      }
    }, 50);
    return () => window.clearTimeout(id);
  }, [isExpanded]);

  async function handleConnect(e?: React.FormEvent) {
    if (e) e.preventDefault();
    if (connState === 'connected' || connState === 'connecting') {
      return;
    }
    setError(null);
    setStatusMessage(null);

    if (!selectedCertId) {
      setError(
        tr(
          'Bitte wählen Sie ein SSH-Zertifikat oder Schlüsselpaar aus.',
          'Please select an SSH certificate or keypair.'
        )
      );
      return;
    }

    if (targetMode === 'saved' && !selectedServerId) {
      setError(tr('Bitte wählen Sie einen Server aus.', 'Please select a server.'));
      return;
    }

    if (targetMode === 'custom' && !customIp.trim()) {
      setError(tr('Bitte geben Sie eine Ziel-IP-Adresse ein.', 'Please enter a target IP address.'));
      return;
    }

    closeSocket(true);
    const attemptId = ++connectAttemptRef.current;
    setConnState('connecting');

    const term = termRef.current;
    const fit = fitRef.current;
    try {
      fit?.fit();
    } catch {
      // ignore
    }
    const cols = term?.cols || 100;
    const rows = term?.rows || 30;

    try {
      const ticketRes = await api.createShellTicket({
        ...(targetMode === 'saved'
          ? { serverId: selectedServerId, sshUser: sshUser.trim() || undefined }
          : {
              ipAddress: customIp.trim(),
              port: customPort,
              sshUser: sshUser.trim() || user.defaultSshUser || 'root',
              ignoreHostKey: allowInsecureHostKey ? customIgnoreHostKey : false,
            }),
        certificateId: selectedCertId,
        cols,
        rows,
      });

      if (connectAttemptRef.current !== attemptId) {
        return;
      }

      setActiveTargetLabel(
        `${ticketRes.sshUser}@${ticketRes.targetIp}:${ticketRes.targetPort}`
      );
      setActiveCertLabel(ticketRes.certificateName);

      if (term) {
        term.reset();
        term.writeln(
          `\x1b[90mVerbinde zu ${ticketRes.sshUser}@${ticketRes.targetIp}:${ticketRes.targetPort} (${ticketRes.certificateName})...\x1b[0m`
        );
      }

      const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${wsProto}//${window.location.host}/api/ws/shell?ticket=${encodeURIComponent(ticketRes.ticket)}`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        stopKeepalive();
        pingTimerRef.current = window.setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
          }
        }, 25_000);
        if (term) {
          ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
          term.focus();
        }
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(String(event.data)) as {
            type?: string;
            mode?: string;
            data?: string;
            code?: number;
            reason?: string;
            message?: string;
          };
          if (msg.type === 'ready') {
            if (msg.mode === 'sandbox-preview') {
              setConnState('preview');
              setStatusMessage(
                tr(
                  'Vorschau-Modus aktiv (kein /usr/bin/ssh in dieser Sandbox).',
                  'Preview mode active (no /usr/bin/ssh in this sandbox).'
                )
              );
            } else {
              setConnState('connected');
              setStatusMessage(null);
            }
            term?.focus();
          } else if (msg.type === 'output' && typeof msg.data === 'string') {
            term?.write(msg.data);
          } else if (msg.type === 'error') {
            const errMsg = msg.message || tr('SSH-Verbindungsfehler.', 'SSH connection error.');
            setError(errMsg);
            setConnState('error');
            term?.writeln(`\r\n\x1b[31m[Fehler] ${errMsg}\x1b[0m`);
          } else if (msg.type === 'exit') {
            const reason =
              msg.reason ||
              tr(
                `Verbindung beendet (Exit-Code ${msg.code ?? 0}).`,
                `Connection closed (exit code ${msg.code ?? 0}).`
              );
            setConnState('closed');
            setStatusMessage(reason);
            term?.writeln(`\r\n\x1b[90m[${reason}]\x1b[0m`);
            void onSessionEndedRef.current();
          }
        } catch {
          // ignore non-JSON frames
        }
      };

      ws.onerror = () => {
        setError(
          tr(
            'WebSocket-Verbindung zur SSH-Shell fehlgeschlagen.',
            'WebSocket connection to the SSH shell failed.'
          )
        );
        setConnState('error');
      };

      ws.onclose = () => {
        stopKeepalive();
        if (wsRef.current === ws) {
          wsRef.current = null;
          setConnState((prev) => (prev === 'error' ? prev : 'closed'));
          void onSessionEndedRef.current();
        }
      };
    } catch (err) {
      setConnState('error');
      setError(
        err instanceof Error
          ? err.message
          : tr('SSH-Shell konnte nicht gestartet werden.', 'Could not start SSH shell.')
      );
    }
  }

  function handleDisconnect(e: React.MouseEvent<HTMLButtonElement>) {
    e.preventDefault();
    e.stopPropagation();
    closeSocket(false);
    termRef.current?.writeln(
      `\r\n\x1b[33m[${tr('Verbindung getrennt', 'Disconnected')}]\x1b[0m`
    );
    void onSessionEnded();
  }

  function handleClearTerminal() {
    termRef.current?.clear();
    termRef.current?.focus();
  }

  async function handleResetHostKey() {
    setError(null);
    setHostKeyNotice(null);
    if (targetMode === 'saved' && !selectedServerId) {
      setError(tr('Bitte wählen Sie zuerst einen Server aus.', 'Please select a server first.'));
      return;
    }
    if (targetMode === 'custom' && !customIp.trim()) {
      setError(tr('Bitte geben Sie zuerst eine Ziel-IP-Adresse ein.', 'Please enter a target IP address first.'));
      return;
    }
    setResettingHostKey(true);
    try {
      const res = await api.resetHostKey(
        targetMode === 'saved'
          ? { serverId: selectedServerId }
          : { ipAddress: customIp.trim(), port: customPort }
      );
      const msg =
        res.removedCount > 0
          ? tr(
              `Alter Host-Key für ${res.ipAddress}:${res.port} gelöscht (${res.removedCount} Eintrag/Einträge entfernt).`,
              `Old host key for ${res.ipAddress}:${res.port} deleted (${res.removedCount} entry/entries removed).`
            )
          : tr(
              `Für ${res.ipAddress}:${res.port} war kein gespeicherter Host-Key vorhanden.`,
              `No stored host key was found for ${res.ipAddress}:${res.port}.`
            );
      setHostKeyNotice(msg);
      termRef.current?.writeln(`\r\n\x1b[32m[Host-Key] ${msg}\x1b[0m`);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : tr('Host-Key konnte nicht gelöscht werden.', 'Could not delete host key.')
      );
    } finally {
      setResettingHostKey(false);
    }
  }

  const selectedCert = certificates.find((c) => c.id === selectedCertId);
  const selectedServer = servers.find((s) => s.id === selectedServerId);
  const isLive = connState === 'connected' || connState === 'connecting';
  const effectiveIgnoreHostKey =
    targetMode === 'saved'
      ? Boolean(allowInsecureHostKey && selectedServer?.ignoreHostKey)
      : Boolean(allowInsecureHostKey && customIgnoreHostKey);

  const statusBadge = (() => {
    switch (connState) {
      case 'connected':
        return {
          dot: 'bg-emerald-400',
          label: tr('Verbunden', 'Connected'),
          text: 'text-emerald-300',
        };
      case 'connecting':
        return {
          dot: 'bg-amber-400 animate-pulse',
          label: tr('Verbinde...', 'Connecting...'),
          text: 'text-amber-300',
        };
      case 'preview':
        return {
          dot: 'bg-sky-400',
          label: tr('Vorschau', 'Preview'),
          text: 'text-sky-300',
        };
      case 'error':
        return {
          dot: 'bg-red-400',
          label: tr('Fehler', 'Error'),
          text: 'text-red-300',
        };
      case 'closed':
        return {
          dot: 'bg-slate-400',
          label: tr('Getrennt', 'Disconnected'),
          text: 'text-slate-300',
        };
      default:
        return {
          dot: 'bg-slate-500',
          label: tr('Bereit', 'Ready'),
          text: 'text-slate-400',
        };
    }
  })();

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
            SSH-Shell
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            {tr(
              'Öffnen Sie direkt im Browser eine passwortlose, interaktive SSH-Sitzung (PTY) über den Server zu einer gewählten IP-Adresse.',
              'Open a passwordless interactive SSH session (PTY) directly in your browser through the server to any selected target IP.'
            )}
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {certificates.length === 0 && (
            <button
              type="button"
              onClick={() => onNavigate('certificates')}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-blue-800 bg-blue-50 border border-blue-200 hover:bg-blue-100 rounded-md transition-colors cursor-pointer whitespace-nowrap"
            >
              <KeyRound className="w-3.5 h-3.5" />
              {tr('Zertifikat hochladen', 'Upload Certificate')}
            </button>
          )}
          {servers.length === 0 && (
            <button
              type="button"
              onClick={() => onNavigate('servers')}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
            >
              <Server className="w-3.5 h-3.5" />
              {tr('Server anlegen', 'Add Server')}
            </button>
          )}
        </div>
      </div>

      {!opensshAvailable && (
        <div className="px-4 py-3 rounded-md bg-amber-50 border border-amber-200 text-xs text-amber-900 flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-amber-700 shrink-0 mt-0.5" />
          <span>
            {tr(
              'In dieser Vorschau-Sandbox ist kein /usr/bin/ssh installiert. Beim Verbinden wird die Zertifikatsprüfung und ein TCP-Test im Terminal angezeigt. Auf Debian 13 (Trixie) startet hier direkt eine echte interaktive OpenSSH-Shell.',
              'No /usr/bin/ssh binary is installed in this preview sandbox. Connecting displays certificate verification and a live TCP check in the terminal. On Debian 13 (Trixie), this opens a real interactive OpenSSH shell.'
            )}
          </span>
        </div>
      )}

      {error && (
        <div role="alert" className="px-4 py-3 rounded-md bg-red-50 border border-red-200 text-sm text-red-800">
          {error}
        </div>
      )}

      {/* Connection Setup Bar */}
      <form
        onSubmit={handleConnect}
        className="bg-white border border-slate-200 rounded-lg p-5 space-y-4"
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="inline-flex rounded-md border border-slate-200 bg-slate-50 p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setTargetMode('saved')}
              disabled={servers.length === 0}
              className={`px-3 py-1.5 rounded font-medium transition-colors cursor-pointer disabled:opacity-50 ${
                targetMode === 'saved'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {tr(`Gespeicherter Server (${servers.length})`, `Saved Server (${servers.length})`)}
            </button>
            <button
              type="button"
              onClick={() => setTargetMode('custom')}
              className={`px-3 py-1.5 rounded font-medium transition-colors cursor-pointer ${
                targetMode === 'custom'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {tr('Freie IP-Adresse', 'Custom IP Address')}
            </button>
          </div>

          {selectedCert?.metadata.hasCertificate !== false && selectedCert?.metadata.isExpired && (
            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-red-700">
              <AlertTriangle className="w-3.5 h-3.5" />
              {tr('Gewähltes Zertifikat ist abgelaufen', 'Selected certificate is expired')}
            </span>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          {targetMode === 'saved' ? (
            <div className="md:col-span-4">
              <label htmlFor="shell-server" className="block text-xs font-medium text-slate-700 mb-1">
                {tr('Ziel-Server (IP)', 'Target Server (IP)')}
              </label>
              <select
                id="shell-server"
                value={selectedServerId}
                onChange={(e) => handleSelectServer(e.target.value)}
                disabled={isLive}
                className="w-full px-3 py-2 text-sm bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:bg-slate-50"
              >
                {servers.map((srv) => (
                  <option key={srv.id} value={srv.id}>
                    {srv.label} — {srv.ipAddress}:{srv.port}
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <>
              <div className="md:col-span-3">
                <label htmlFor="shell-ip" className="block text-xs font-medium text-slate-700 mb-1">
                  {tr('Ziel-IP-Adresse', 'Target IP Address')}
                </label>
                <input
                  id="shell-ip"
                  type="text"
                  value={customIp}
                  onChange={(e) => setCustomIp(e.target.value)}
                  disabled={isLive}
                  placeholder="10.0.10.25"
                  className="w-full px-3 py-2 text-sm font-mono bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:bg-slate-50"
                />
              </div>
              <div className="md:col-span-1">
                <label htmlFor="shell-port" className="block text-xs font-medium text-slate-700 mb-1">
                  Port
                </label>
                <input
                  id="shell-port"
                  type="number"
                  min={1}
                  max={65535}
                  value={customPort}
                  onChange={(e) => setCustomPort(Number(e.target.value) || 22)}
                  disabled={isLive}
                  className="w-full px-2.5 py-2 text-sm font-mono bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:bg-slate-50"
                />
              </div>
            </>
          )}

          <div className="md:col-span-2">
            <label htmlFor="shell-ssh-user" className="block text-xs font-medium text-slate-700 mb-1">
              {tr('SSH-Benutzer', 'SSH User')}
            </label>
            <input
              id="shell-ssh-user"
              type="text"
              value={sshUser}
              onChange={(e) => setSshUser(e.target.value)}
              disabled={isLive}
              placeholder="root"
              className="w-full px-3 py-2 text-sm font-mono bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:bg-slate-50"
            />
          </div>

          <div className="md:col-span-4">
            <label htmlFor="shell-cert" className="block text-xs font-medium text-slate-700 mb-1">
              {tr('SSH-Zertifikat / Schlüsselpaar', 'SSH Certificate / Keypair')}
            </label>
            <select
              id="shell-cert"
              value={selectedCertId}
              onChange={(e) => setSelectedCertId(e.target.value)}
              disabled={isLive || certificates.length === 0}
              className="w-full px-3 py-2 text-sm bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:bg-slate-50"
            >
              {certificates.length === 0 ? (
                <option value="">
                  {tr('Kein Zertifikat vorhanden', 'No certificates available')}
                </option>
              ) : (
                certificates.map((cert) => {
                  const hasCert = cert.metadata.hasCertificate !== false && Boolean(cert.certFileName);
                  return (
                    <option key={cert.id} value={cert.id}>
                      {cert.name} (
                      {hasCert
                        ? cert.metadata.isExpired
                          ? tr('CA-Cert · abgelaufen', 'CA Cert · expired')
                          : tr('CA-Cert', 'CA Cert')
                        : tr('Keypair', 'Keypair')}
                      )
                    </option>
                  );
                })
              )}
            </select>
          </div>

          <div className="md:col-span-2 flex items-center gap-2">
            {isLive ? (
              <button
                key="disconnect-btn"
                type="button"
                onClick={handleDisconnect}
                className="w-full inline-flex items-center justify-center gap-1.5 px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                <Unplug className="w-4 h-4" />
                {tr('Trennen', 'Disconnect')}
              </button>
            ) : (
              <button
                key="connect-btn"
                type="submit"
                disabled={certificates.length === 0}
                className="w-full inline-flex items-center justify-center gap-1.5 px-4 py-2 text-sm font-medium text-white bg-blue-700 hover:bg-blue-800 disabled:opacity-50 rounded-md transition-colors cursor-pointer whitespace-nowrap"
              >
                {connState === 'closed' || connState === 'error' ? (
                  <>
                    <RotateCcw className="w-4 h-4" />
                    {tr('Neu verbinden', 'Reconnect')}
                  </>
                ) : (
                  <>
                    <Plug className="w-4 h-4" />
                    {tr('Verbinden', 'Connect')}
                  </>
                )}
              </button>
            )}
          </div>
        </div>

        <div className="pt-2 border-t border-slate-100 flex flex-wrap items-center justify-between gap-3">
          {targetMode === 'custom' ? (
            <label
              className={`inline-flex items-center gap-2 text-xs ${
                allowInsecureHostKey && !isLive
                  ? 'text-slate-700 cursor-pointer'
                  : 'text-slate-400 cursor-not-allowed'
              }`}
            >
              <input
                type="checkbox"
                checked={allowInsecureHostKey ? customIgnoreHostKey : false}
                disabled={isLive || !allowInsecureHostKey}
                onChange={(e) => setCustomIgnoreHostKey(e.target.checked)}
                className="rounded border-slate-300 text-amber-600 focus:ring-amber-600 disabled:opacity-50"
              />
              <span>
                {tr('Host-Key-Prüfung deaktivieren', 'Disable Host Key Checking')}{' '}
                <code className="font-mono text-[11px] text-slate-500">
                  (StrictHostKeyChecking=no, UserKnownHostsFile=/dev/null)
                </code>
                {!allowInsecureHostKey && (
                  <span className="text-amber-700 ml-1.5">
                    ({tr('vom Admin global verboten', 'globally prohibited by admin')})
                  </span>
                )}
              </span>
            </label>
          ) : selectedServer?.ignoreHostKey ? (
            <div className="text-xs flex items-center gap-1.5">
              <AlertTriangle
                className={`w-3.5 h-3.5 shrink-0 ${
                  allowInsecureHostKey ? 'text-amber-600' : 'text-slate-400'
                }`}
              />
              {allowInsecureHostKey ? (
                <span className="text-amber-800">
                  {tr(
                    'Host-Key-Prüfung für diesen Server deaktiviert:',
                    'Host key checking disabled for this server:'
                  )}{' '}
                  <code className="font-mono text-[11px]">
                    StrictHostKeyChecking=no · UserKnownHostsFile=/dev/null
                  </code>
                </span>
              ) : (
                <span className="text-slate-500">
                  {tr(
                    'Host-Key-Prüfung wird trotz Server-Option vom Administrator global erzwungen.',
                    'Host key checking is globally enforced by the administrator despite this server’s setting.'
                  )}
                </span>
              )}
            </div>
          ) : (
            <span className="text-xs text-slate-500">
              {tr(
                'Host-Key-Prüfung aktiv (StrictHostKeyChecking=accept-new)',
                'Host key verification active (StrictHostKeyChecking=accept-new)'
              )}
            </span>
          )}

          {!effectiveIgnoreHostKey && (
            <button
              type="button"
              onClick={handleResetHostKey}
              disabled={
                resettingHostKey ||
                isLive ||
                (targetMode === 'saved' ? !selectedServerId : !customIp.trim())
              }
              title={tr(
                'Gespeicherten SSH Host-Key für diese IP/Port-Kombination aus known_hosts entfernen (z. B. nach Neuinstallation des Zielservers)',
                'Remove the stored SSH host key for this IP/port from known_hosts (e.g. after reinstalling the target server)'
              )}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 disabled:opacity-50 rounded border border-slate-200 transition-colors cursor-pointer whitespace-nowrap"
            >
              <Trash2 className="w-3.5 h-3.5 text-slate-600" />
              {resettingHostKey
                ? tr('Löscht Host-Key...', 'Deleting host key...')
                : tr('Alten Host-Key löschen', 'Delete Old Host Key')}
            </button>
          )}
        </div>

        {hostKeyNotice && (
          <div className="px-3 py-2 rounded-md bg-emerald-50 border border-emerald-200 text-xs text-emerald-900">
            {hostKeyNotice}
          </div>
        )}
      </form>

      {/* Interactive Terminal Surface */}
      <section
        className={`rounded-lg border border-slate-800 bg-slate-950 overflow-hidden shadow-sm flex flex-col ${
          isExpanded ? 'fixed inset-4 z-50' : ''
        }`}
      >
        <div className="h-11 px-4 bg-slate-900 border-b border-slate-800 flex items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-2.5 min-w-0 text-xs">
            <Terminal className="w-4 h-4 text-sky-400 shrink-0" />
            <span className="inline-flex items-center gap-1.5 shrink-0">
              <span className={`w-2 h-2 rounded-full ${statusBadge.dot}`} />
              <span className={`font-medium ${statusBadge.text}`}>{statusBadge.label}</span>
            </span>
            {activeTargetLabel && (
              <>
                <span aria-hidden="true" className="text-slate-600">·</span>
                <span className="font-mono text-slate-200 truncate">{activeTargetLabel}</span>
              </>
            )}
            {activeCertLabel && (
              <>
                <span aria-hidden="true" className="text-slate-600 hidden sm:inline">·</span>
                <span className="text-slate-400 truncate hidden sm:inline">{activeCertLabel}</span>
              </>
            )}
          </div>

          <div className="flex items-center gap-1.5 shrink-0">
            {statusMessage && (
              <span className="hidden md:inline text-[11px] text-slate-400 mr-2 truncate max-w-xs">
                {statusMessage}
              </span>
            )}
            <button
              type="button"
              onClick={handleClearTerminal}
              title={tr('Terminal leeren', 'Clear terminal')}
              className="inline-flex items-center gap-1 px-2.5 py-1 text-xs text-slate-300 hover:text-white hover:bg-slate-800 rounded transition-colors cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{tr('Leeren', 'Clear')}</span>
            </button>
            <button
              type="button"
              onClick={() => setIsExpanded((v) => !v)}
              title={
                isExpanded
                  ? tr('Vollbild verlassen', 'Exit fullscreen')
                  : tr('Vergrößern', 'Expand')
              }
              className="inline-flex items-center gap-1 px-2.5 py-1 text-xs text-slate-300 hover:text-white hover:bg-slate-800 rounded transition-colors cursor-pointer"
            >
              {isExpanded ? (
                <Minimize2 className="w-3.5 h-3.5" />
              ) : (
                <Maximize2 className="w-3.5 h-3.5" />
              )}
              <span className="hidden sm:inline">
                {isExpanded ? tr('Verkleinern', 'Minimize') : tr('Vollbild', 'Fullscreen')}
              </span>
            </button>
          </div>
        </div>

        <div
          ref={terminalHostRef}
          onClick={() => termRef.current?.focus()}
          className={`w-full p-3 bg-slate-950 ${
            isExpanded ? 'flex-1 min-h-0' : 'h-[520px]'
          }`}
        />
      </section>
    </div>
  );
}
