import React, { useCallback, useEffect, useRef, useState } from 'react';
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
  Plus,
  X,
  Lock,
} from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import type { ActiveTab, User, UserCertificate, UserServer } from '../types';

interface SshShellViewProps {
  user: User;
  isVisible?: boolean;
  opensshAvailable: boolean;
  allowInsecureHostKey?: boolean;
  servers: UserServer[];
  certificates: UserCertificate[];
  onNavigate: (tab: ActiveTab) => void;
  onSessionEnded: () => Promise<void>;
}

type ConnectionState = 'idle' | 'connecting' | 'connected' | 'preview' | 'closed' | 'error';

interface ShellTabMeta {
  id: string;
  number: number;
  initialServerId: string;
  selectedServerId: string;
  title: string;
  subtitle: string;
  connState: ConnectionState;
  isLive: boolean;
}

interface SshShellTabPaneProps {
  tabId: string;
  tabNumber: number;
  initialServerId: string;
  isActive: boolean;
  isVisible: boolean;
  isExpanded: boolean;
  user: User;
  allowInsecureHostKey: boolean;
  servers: UserServer[];
  certificates: UserCertificate[];
  onToggleExpand: () => void;
  onExitExpand: () => void;
  onMetaChange: (
    tabId: string,
    patch: Pick<ShellTabMeta, 'title' | 'subtitle' | 'connState' | 'isLive' | 'selectedServerId'>
  ) => void;
  onSessionEnded: () => Promise<void>;
}

const MAX_SHELL_TABS = 12;

function getTabDotClass(state: ConnectionState, dark = false): string {
  switch (state) {
    case 'connected':
      return 'bg-emerald-500';
    case 'connecting':
      return 'bg-amber-400 animate-pulse';
    case 'preview':
      return 'bg-sky-400';
    case 'error':
      return 'bg-red-500';
    case 'closed':
      return dark ? 'bg-slate-500' : 'bg-slate-400';
    default:
      return dark ? 'bg-slate-600' : 'bg-slate-300';
  }
}

function SshShellTabPane({
  tabId,
  tabNumber,
  initialServerId,
  isActive,
  isVisible,
  isExpanded,
  user,
  allowInsecureHostKey,
  servers,
  certificates,
  onToggleExpand,
  onExitExpand,
  onMetaChange,
  onSessionEnded,
}: SshShellTabPaneProps) {
  const { tr } = useI18n();

  const canUseCustomIp =
    user.role === 'admin' || user.permissions?.useSshShellCustomIp !== false;

  const initialServer =
    servers.find((s) => s.id === initialServerId) ?? servers[0];

  const [targetMode, setTargetMode] = useState<'saved' | 'custom'>(
    canUseCustomIp ? (servers.length > 0 ? 'saved' : 'custom') : 'saved'
  );
  const [selectedServerId, setSelectedServerId] = useState<string>(initialServer?.id ?? '');
  const [customIp, setCustomIp] = useState('');
  const [customPort, setCustomPort] = useState(22);
  const [customIgnoreHostKey, setCustomIgnoreHostKey] = useState(false);
  const [sshUser, setSshUser] = useState(
    initialServer?.sshUser || user.defaultSshUser || 'root'
  );
  const [selectedCertId, setSelectedCertId] = useState<string>(certificates[0]?.id ?? '');
  const [keyPassphrase, setKeyPassphrase] = useState<string>('');

  const [connState, setConnState] = useState<ConnectionState>('idle');
  const [activeTargetLabel, setActiveTargetLabel] = useState<string>('');
  const [activeCertLabel, setActiveCertLabel] = useState<string>('');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [hostKeyNotice, setHostKeyNotice] = useState<string | null>(null);
  const [resettingHostKey, setResettingHostKey] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const terminalHostRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const pingTimerRef = useRef<number | null>(null);
  const connectAttemptRef = useRef<number>(0);
  const onSessionEndedRef = useRef(onSessionEnded);
  onSessionEndedRef.current = onSessionEnded;

  // Keep server/cert selection valid if workspace data or permissions change
  useEffect(() => {
    if (!canUseCustomIp && targetMode === 'custom') {
      setTargetMode('saved');
    }
    if (servers.length > 0 && !servers.some((s) => s.id === selectedServerId)) {
      setSelectedServerId(servers[0].id);
      if (targetMode === 'saved') {
        setSshUser(servers[0].sshUser || user.defaultSshUser || 'root');
      }
    }
    if (servers.length === 0 && targetMode === 'saved' && canUseCustomIp) {
      setTargetMode('custom');
    }
  }, [servers, selectedServerId, targetMode, canUseCustomIp, user.defaultSshUser]);

  useEffect(() => {
    if (certificates.length > 0 && !certificates.some((c) => c.id === selectedCertId)) {
      setSelectedCertId(certificates[0].id);
    }
  }, [certificates, selectedCertId]);

  useEffect(() => {
    setKeyPassphrase('');
  }, [selectedCertId]);

  const selectedCert = certificates.find((c) => c.id === selectedCertId);
  const selectedServer = servers.find((s) => s.id === selectedServerId);
  const needsRuntimePassphrase = Boolean(
    selectedCert?.metadata.privateKeyEncrypted && !selectedCert?.hasStoredPassphrase
  );
  const isLive = connState === 'connected' || connState === 'connecting';

  // Report tab metadata up to tab bar
  useEffect(() => {
    let title = tr(`Tab ${tabNumber}`, `Tab ${tabNumber}`);
    let subtitle = '';

    if (
      activeTargetLabel &&
      (connState === 'connected' || connState === 'connecting' || connState === 'preview')
    ) {
      if (targetMode === 'saved' && selectedServer) {
        title = selectedServer.label;
        subtitle = activeTargetLabel;
      } else {
        title = activeTargetLabel;
      }
    } else if (targetMode === 'saved' && selectedServer) {
      title = selectedServer.label;
      subtitle = `${selectedServer.ipAddress}:${selectedServer.port}`;
    } else if (targetMode === 'custom' && customIp.trim()) {
      const effectiveUser = sshUser.trim() || user.defaultSshUser || 'root';
      title = `${effectiveUser}@${customIp.trim()}`;
      subtitle = `Port ${customPort}`;
    }

    onMetaChange(tabId, {
      title,
      subtitle,
      connState,
      isLive,
      selectedServerId: targetMode === 'saved' ? selectedServerId : '',
    });
  }, [
    tabId,
    tabNumber,
    activeTargetLabel,
    connState,
    isLive,
    targetMode,
    selectedServer,
    selectedServerId,
    customIp,
    customPort,
    sshUser,
    user.defaultSshUser,
    onMetaChange,
    tr,
  ]);

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

  // Initialize xterm.js once per tab
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
    try {
      fit.fit();
    } catch {
      // ignore if hidden during initial mount
    }

    term.writeln(
      `\x1b[1;34mSSH Console\x1b[0m \x1b[90m— Tab #${tabNumber} · Interaktive OpenSSH-Shell (serverseitig)\x1b[0m`
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
      if (container.offsetWidth === 0 || container.offsetHeight === 0) return;
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
      const hadLiveSocket = wsRef.current !== null;
      closeSocket(true);
      if (hadLiveSocket) {
        void onSessionEndedRef.current();
      }
      observer.disconnect();
      dataDisposable.dispose();
      resizeDisposable.dispose();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, []);

  // Re-fit & focus terminal when tab becomes active, view becomes visible, or fullscreen toggles
  useEffect(() => {
    if (!isActive || !isVisible) return;
    const id = window.setTimeout(() => {
      try {
        fitRef.current?.fit();
        if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
          termRef.current?.focus();
        }
      } catch {
        // ignore
      }
    }, 50);
    return () => window.clearTimeout(id);
  }, [isActive, isVisible, isExpanded]);

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

    if (targetMode === 'custom' && !canUseCustomIp) {
      setError(
        tr(
          'Ihre Benutzergruppe darf keine freie IP-Adresse in der SSH-Shell eingeben.',
          'Your user group is not allowed to enter a custom IP address in the SSH shell.'
        )
      );
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

    const passToUse = needsRuntimePassphrase && keyPassphrase ? keyPassphrase : undefined;
    setKeyPassphrase('');

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
        ...(passToUse ? { passphrase: passToUse } : {}),
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
    if (targetMode === 'custom' && !canUseCustomIp) {
      setError(
        tr(
          'Ihre Benutzergruppe darf keine freie IP-Adresse in der SSH-Shell eingeben.',
          'Your user group is not allowed to enter a custom IP address in the SSH shell.'
        )
      );
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
    <div
      className={
        isActive
          ? isExpanded
            ? 'flex-1 min-h-0 flex flex-col'
            : 'space-y-4'
          : 'hidden'
      }
    >
      {error && !isExpanded && (
        <div role="alert" className="px-4 py-3 rounded-md bg-red-50 border border-red-200 text-sm text-red-800">
          {error}
        </div>
      )}

      {/* Connection Setup Bar */}
      <form
        onSubmit={handleConnect}
        className={
          isExpanded
            ? 'hidden'
            : 'bg-white border border-slate-200 rounded-b-lg rounded-tr-lg p-5 space-y-4'
        }
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="inline-flex rounded-md border border-slate-200 bg-slate-50 p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setTargetMode('saved')}
              disabled={servers.length === 0 || isLive}
              className={`px-3 py-1.5 rounded font-medium transition-colors cursor-pointer disabled:opacity-50 ${
                targetMode === 'saved'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {tr(`Gespeicherter Server (${servers.length})`, `Saved Server (${servers.length})`)}
            </button>
            {canUseCustomIp && (
              <button
                type="button"
                onClick={() => setTargetMode('custom')}
                disabled={isLive}
                className={`px-3 py-1.5 rounded font-medium transition-colors cursor-pointer disabled:opacity-50 ${
                  targetMode === 'custom'
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {tr('Freie IP-Adresse', 'Custom IP Address')}
              </button>
            )}
          </div>

          {selectedCert?.metadata.hasCertificate !== false && selectedCert?.metadata.isExpired && (
            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-red-700">
              <AlertTriangle className="w-3.5 h-3.5" />
              {tr('Gewähltes Zertifikat ist abgelaufen', 'Selected certificate is expired')}
            </span>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          {targetMode === 'saved' || !canUseCustomIp ? (
            <div className="md:col-span-4">
              <label htmlFor={`${tabId}-server`} className="block text-xs font-medium text-slate-700 mb-1">
                {tr('Ziel-Server (IP)', 'Target Server (IP)')}
              </label>
              <select
                id={`${tabId}-server`}
                value={selectedServerId}
                onChange={(e) => handleSelectServer(e.target.value)}
                disabled={isLive || servers.length === 0}
                className="w-full px-3 py-2 text-sm bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:bg-slate-50"
              >
                {servers.length === 0 ? (
                  <option value="">
                    {tr('Kein gespeicherter Server verfügbar', 'No saved server available')}
                  </option>
                ) : (
                  servers.map((srv) => (
                    <option key={srv.id} value={srv.id}>
                      {srv.label} — {srv.ipAddress}:{srv.port}
                    </option>
                  ))
                )}
              </select>
            </div>
          ) : (
            <>
              <div className="md:col-span-3">
                <label htmlFor={`${tabId}-ip`} className="block text-xs font-medium text-slate-700 mb-1">
                  {tr('Ziel-IP-Adresse', 'Target IP Address')}
                </label>
                <input
                  id={`${tabId}-ip`}
                  type="text"
                  value={customIp}
                  onChange={(e) => setCustomIp(e.target.value)}
                  disabled={isLive}
                  placeholder="10.0.10.25"
                  className="w-full px-3 py-2 text-sm font-mono bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:bg-slate-50"
                />
              </div>
              <div className="md:col-span-1">
                <label htmlFor={`${tabId}-port`} className="block text-xs font-medium text-slate-700 mb-1">
                  Port
                </label>
                <input
                  id={`${tabId}-port`}
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
            <label htmlFor={`${tabId}-ssh-user`} className="block text-xs font-medium text-slate-700 mb-1">
              {tr('SSH-Benutzer', 'SSH User')}
            </label>
            <input
              id={`${tabId}-ssh-user`}
              type="text"
              value={sshUser}
              onChange={(e) => setSshUser(e.target.value)}
              disabled={isLive}
              placeholder="root"
              className="w-full px-3 py-2 text-sm font-mono bg-white border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:bg-slate-50"
            />
          </div>

          <div className="md:col-span-4">
            <label htmlFor={`${tabId}-cert`} className="block text-xs font-medium text-slate-700 mb-1">
              {tr('SSH-Zertifikat / Schlüsselpaar', 'SSH Certificate / Keypair')}
            </label>
            <select
              id={`${tabId}-cert`}
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
                  const lockHint = cert.metadata.privateKeyEncrypted
                    ? cert.hasStoredPassphrase
                      ? tr(' · Passwort hinterlegt', ' · Passphrase stored')
                      : tr(' · Passwortgeschützt', ' · Passphrase protected')
                    : '';
                  return (
                    <option key={cert.id} value={cert.id}>
                      {cert.name} (
                      {hasCert
                        ? cert.metadata.isExpired
                          ? tr('CA-Cert · abgelaufen', 'CA Cert · expired')
                          : tr('CA-Cert', 'CA Cert')
                        : tr('Keypair', 'Keypair')}
                      )
                      {lockHint}
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
                disabled={
                  certificates.length === 0 ||
                  ((targetMode === 'saved' || !canUseCustomIp) && servers.length === 0)
                }
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

        {needsRuntimePassphrase && (
          <div className="pt-2.5 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center gap-3">
            <label
              htmlFor={`${tabId}-key-passphrase`}
              className="inline-flex items-center gap-1.5 text-xs font-medium text-amber-900 whitespace-nowrap"
            >
              <Lock className="w-3.5 h-3.5 text-amber-700 shrink-0" />
              {tr('Schlüssel-Passwort:', 'Key passphrase:')}
            </label>
            <input
              id={`${tabId}-key-passphrase`}
              type="password"
              autoComplete="off"
              disabled={isLive}
              value={keyPassphrase}
              onChange={(e) => setKeyPassphrase(e.target.value)}
              placeholder={tr(
                'Zum Entsperren eingeben (oder leer für Terminal-Abfrage)...',
                'Enter to unlock (or leave blank for terminal prompt)...'
              )}
              className="w-full sm:max-w-sm px-3 py-1.5 text-sm bg-white border border-amber-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:bg-slate-50"
            />
            <span className="text-[11px] text-slate-500">
              {tr(
                'Wird nicht gespeichert und beim Verbinden sofort geleert.',
                'Not stored and cleared immediately upon connecting.'
              )}
            </span>
          </div>
        )}

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
        className={`bg-slate-950 overflow-hidden flex flex-col ${
          isExpanded
            ? 'flex-1 min-h-0'
            : 'rounded-lg border border-slate-800 shadow-sm'
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
            {isExpanded && isLive && (
              <button
                type="button"
                onClick={handleDisconnect}
                className="inline-flex items-center gap-1 px-2.5 py-1 text-xs text-red-300 hover:text-white hover:bg-red-900/60 rounded transition-colors cursor-pointer"
              >
                <Unplug className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">{tr('Trennen', 'Disconnect')}</span>
              </button>
            )}
            {isExpanded && !isLive && (
              <button
                type="button"
                onClick={onExitExpand}
                className="inline-flex items-center gap-1 px-2.5 py-1 text-xs text-sky-300 hover:text-white hover:bg-slate-800 rounded transition-colors cursor-pointer"
              >
                <Plug className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">{tr('Verbindung konfigurieren', 'Configure Connection')}</span>
              </button>
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
              onClick={onToggleExpand}
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

export function SshShellView({
  user,
  isVisible = true,
  opensshAvailable,
  allowInsecureHostKey = false,
  servers,
  certificates,
  onNavigate,
  onSessionEnded,
}: SshShellViewProps) {
  const { tr } = useI18n();
  const nextTabNumberRef = useRef(2);
  const [isExpanded, setIsExpanded] = useState(false);

  const [tabs, setTabs] = useState<ShellTabMeta[]>(() => [
    {
      id: 'shell-tab-1',
      number: 1,
      initialServerId: servers[0]?.id ?? '',
      selectedServerId: servers[0]?.id ?? '',
      title: servers[0]?.label ?? 'Tab 1',
      subtitle: servers[0] ? `${servers[0].ipAddress}:${servers[0].port}` : '',
      connState: 'idle',
      isLive: false,
    },
  ]);
  const [activeTabId, setActiveTabId] = useState<string>('shell-tab-1');

  const handleMetaChange = useCallback(
    (
      tabId: string,
      patch: Pick<ShellTabMeta, 'title' | 'subtitle' | 'connState' | 'isLive' | 'selectedServerId'>
    ) => {
      setTabs((prev) => {
        let changed = false;
        const next = prev.map((t) => {
          if (t.id !== tabId) return t;
          if (
            t.title === patch.title &&
            t.subtitle === patch.subtitle &&
            t.connState === patch.connState &&
            t.isLive === patch.isLive &&
            t.selectedServerId === patch.selectedServerId
          ) {
            return t;
          }
          changed = true;
          return { ...t, ...patch };
        });
        return changed ? next : prev;
      });
    },
    []
  );

  function handleAddTab() {
    if (tabs.length >= MAX_SHELL_TABS) return;
    const number = nextTabNumberRef.current++;
    const id = `shell-tab-${number}`;
    const usedServerIds = new Set(tabs.map((t) => t.selectedServerId).filter(Boolean));
    const nextServer = servers.find((s) => !usedServerIds.has(s.id)) ?? servers[0];

    const newTab: ShellTabMeta = {
      id,
      number,
      initialServerId: nextServer?.id ?? '',
      selectedServerId: nextServer?.id ?? '',
      title: nextServer?.label ?? tr(`Tab ${number}`, `Tab ${number}`),
      subtitle: nextServer ? `${nextServer.ipAddress}:${nextServer.port}` : '',
      connState: 'idle',
      isLive: false,
    };

    setTabs((prev) => [...prev, newTab]);
    setActiveTabId(id);
    if (isExpanded) {
      setIsExpanded(false);
    }
  }

  function handleCloseTab(e: React.MouseEvent<HTMLButtonElement>, tabId: string) {
    e.preventDefault();
    e.stopPropagation();

    const index = tabs.findIndex((t) => t.id === tabId);
    if (index === -1) return;

    if (tabs.length === 1) {
      const number = nextTabNumberRef.current++;
      const id = `shell-tab-${number}`;
      const freshTab: ShellTabMeta = {
        id,
        number,
        initialServerId: servers[0]?.id ?? '',
        selectedServerId: servers[0]?.id ?? '',
        title: servers[0]?.label ?? tr(`Tab ${number}`, `Tab ${number}`),
        subtitle: servers[0] ? `${servers[0].ipAddress}:${servers[0].port}` : '',
        connState: 'idle',
        isLive: false,
      };
      setTabs([freshTab]);
      setActiveTabId(id);
      setIsExpanded(false);
      return;
    }

    const remaining = tabs.filter((t) => t.id !== tabId);
    setTabs(remaining);
    if (activeTabId === tabId) {
      const fallback = remaining[Math.max(0, index - 1)] ?? remaining[0];
      setActiveTabId(fallback.id);
    }
  }

  const activeConnectionCount = tabs.filter((t) => t.connState === 'connected').length;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
              SSH-Shell
            </h1>
            {activeConnectionCount > 0 && (
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-700 tabular-nums">
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
                {activeConnectionCount === 1
                  ? tr('1 aktive Verbindung', '1 active connection')
                  : tr(
                      `${activeConnectionCount} aktive Verbindungen`,
                      `${activeConnectionCount} active connections`
                    )}
              </span>
            )}
          </div>
          <p className="text-sm text-slate-600 mt-1">
            {tr(
              'Öffnen Sie eine oder mehrere parallele, passwortlose SSH-Sitzungen (PTY) direkt im Browser und wechseln Sie bequem per Tabs dazwischen.',
              'Open one or more parallel passwordless interactive SSH sessions (PTY) directly in your browser and switch smoothly between tabs.'
            )}
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {certificates.length === 0 &&
            (user.role === 'admin' || user.permissions?.uploadCertificates !== false) && (
            <button
              type="button"
              onClick={() => onNavigate('certificates')}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-blue-800 bg-blue-50 border border-blue-200 hover:bg-blue-100 rounded-md transition-colors cursor-pointer whitespace-nowrap"
            >
              <KeyRound className="w-3.5 h-3.5" />
              {tr('Zertifikat hochladen', 'Upload Certificate')}
            </button>
          )}
          {servers.length === 0 &&
            (user.role === 'admin' || user.permissions?.manageOwnServers !== false) && (
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

      {/* Multi-Tab Shell Workspace (stays structurally stable across fullscreen toggle) */}
      <div
        className={
          isExpanded
            ? 'fixed inset-4 z-50 flex flex-col bg-slate-950 rounded-lg border border-slate-800 shadow-2xl overflow-hidden'
            : ''
        }
      >
        {/* Tab Bar */}
        <div
          role="tablist"
          aria-label={tr('SSH-Sitzungen', 'SSH Sessions')}
          className={
            isExpanded
              ? 'flex items-center gap-1 px-2 pt-2 bg-slate-950 border-b border-slate-800 overflow-x-auto shrink-0'
              : 'flex items-end gap-1 overflow-x-auto -mb-px relative z-10'
          }
        >
          {tabs.map((tab) => {
            const isCurrent = tab.id === activeTabId;
            return (
              <div
                key={tab.id}
                role="tab"
                aria-selected={isCurrent}
                tabIndex={isCurrent ? 0 : -1}
                onClick={() => setActiveTabId(tab.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    setActiveTabId(tab.id);
                  }
                }}
                title={tab.subtitle ? `${tab.title} (${tab.subtitle})` : tab.title}
                className={`group inline-flex items-center gap-2 pl-3 pr-2 py-2 text-xs font-medium rounded-t-md border transition-colors cursor-pointer select-none max-w-[230px] shrink-0 ${
                  isExpanded
                    ? isCurrent
                      ? 'bg-slate-900 text-slate-100 border-slate-700 border-b-slate-900'
                      : 'bg-slate-950 text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-900/60'
                    : isCurrent
                    ? 'bg-white text-slate-900 border-slate-200 border-b-white'
                    : 'bg-slate-100/80 text-slate-600 border-slate-200/80 hover:bg-slate-100 hover:text-slate-900'
                }`}
              >
                <span
                  className={`w-2 h-2 rounded-full shrink-0 ${getTabDotClass(
                    tab.connState,
                    isExpanded
                  )}`}
                />
                <span className="truncate">{tab.title}</span>
                <button
                  type="button"
                  onClick={(e) => handleCloseTab(e, tab.id)}
                  aria-label={tr(`Tab ${tab.title} schließen`, `Close tab ${tab.title}`)}
                  title={
                    tab.isLive
                      ? tr('Verbindung trennen und Tab schließen', 'Disconnect and close tab')
                      : tr('Tab schließen', 'Close tab')
                  }
                  className={`p-0.5 rounded transition-colors cursor-pointer shrink-0 ${
                    isExpanded
                      ? 'text-slate-500 hover:text-slate-100 hover:bg-slate-800'
                      : 'text-slate-400 hover:text-slate-700 hover:bg-slate-200/80'
                  }`}
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            );
          })}

          <button
            type="button"
            onClick={handleAddTab}
            disabled={tabs.length >= MAX_SHELL_TABS}
            title={
              tabs.length >= MAX_SHELL_TABS
                ? tr(
                    `Maximal ${MAX_SHELL_TABS} parallele Tabs möglich`,
                    `Maximum of ${MAX_SHELL_TABS} parallel tabs reached`
                  )
                : tr('Neuen SSH-Tab öffnen', 'Open new SSH tab')
            }
            className={`inline-flex items-center gap-1 px-2.5 py-2 text-xs font-medium rounded-t-md transition-colors cursor-pointer whitespace-nowrap shrink-0 disabled:opacity-40 disabled:cursor-not-allowed ${
              isExpanded
                ? 'text-slate-400 hover:text-white hover:bg-slate-900'
                : 'text-slate-600 hover:text-blue-700 hover:bg-slate-100 mb-0.5'
            }`}
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{tr('Neuer Tab', 'New Tab')}</span>
          </button>
        </div>

        {/* Tab Panes (all tabs stay mounted to preserve live SSH WebSockets & scrollback) */}
        <div className={isExpanded ? 'flex-1 min-h-0 flex flex-col' : ''}>
          {tabs.map((tab) => (
            <SshShellTabPane
              key={tab.id}
              tabId={tab.id}
              tabNumber={tab.number}
              initialServerId={tab.initialServerId}
              isActive={tab.id === activeTabId}
              isVisible={isVisible}
              isExpanded={isExpanded}
              user={user}
              allowInsecureHostKey={allowInsecureHostKey}
              servers={servers}
              certificates={certificates}
              onToggleExpand={() => setIsExpanded((v) => !v)}
              onExitExpand={() => setIsExpanded(false)}
              onMetaChange={handleMetaChange}
              onSessionEnded={onSessionEnded}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
