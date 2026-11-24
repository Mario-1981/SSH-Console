import React, { Suspense, lazy, useCallback, useEffect, useState } from 'react';
import { Menu } from 'lucide-react';
import { api, setUnauthorizedHandler } from './api';
import { LanguageSwitcher, useI18n } from './i18n';
import { DashboardView } from './components/DashboardView';
import { LoginView } from './components/LoginView';
import { SetupView } from './components/SetupView';
import { Sidebar } from './components/Sidebar';

const AccountView = lazy(() =>
  import('./components/AccountView').then((m) => ({ default: m.AccountView }))
);
const AuditLogView = lazy(() =>
  import('./components/AuditLogView').then((m) => ({ default: m.AuditLogView }))
);
const AuthSecurityAdminView = lazy(() =>
  import('./components/AuthSecurityAdminView').then((m) => ({ default: m.AuthSecurityAdminView }))
);
const CertificatesView = lazy(() =>
  import('./components/CertificatesView').then((m) => ({ default: m.CertificatesView }))
);
const CommandsAdminView = lazy(() =>
  import('./components/CommandsAdminView').then((m) => ({ default: m.CommandsAdminView }))
);
const ServersView = lazy(() =>
  import('./components/ServersView').then((m) => ({ default: m.ServersView }))
);
const SshShellView = lazy(() =>
  import('./components/SshShellView').then((m) => ({ default: m.SshShellView }))
);
const UsersAdminView = lazy(() =>
  import('./components/UsersAdminView').then((m) => ({ default: m.UsersAdminView }))
);
import type {
  ActiveTab,
  AppSettings,
  ExecutionLog,
  SshCommand,
  User,
  UserCertificate,
  UserServer,
} from './types';

export default function App() {
  const { tr } = useI18n();
  const [loading, setLoading] = useState(true);
  const [initialized, setInitialized] = useState(false);
  const [opensshAvailable, setOpensshAvailable] = useState(false);
  const [settings, setSettings] = useState<AppSettings>({
    instanceName: 'SSH Console',
    initializedAt: null,
    pingAllowed: true,
    pingIntervalSec: 60,
    pingOfflineThreshold: 5,
    pingOfflineMultiplier: 5,
    ssoEnabled: false,
    ssoProviderName: 'SSO',
    ssoAutoCreateUsers: true,
    ssoConfigured: false,
    ssoTestedAt: null,
    localLoginDisabled: false,
    twoFactorEnabled: false,
    twoFactorEnforced: false,
    passkeyEnabled: false,
    passkeyEnforced: false,
    allowInsecureHostKey: false,
    publicUrl: '',
  });
  const [user, setUser] = useState<User | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [shellMounted, setShellMounted] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [commands, setCommands] = useState<SshCommand[]>([]);
  const [servers, setServers] = useState<UserServer[]>([]);
  const [certificates, setCertificates] = useState<UserCertificate[]>([]);
  const [logs, setLogs] = useState<ExecutionLog[]>([]);
  const [users, setUsers] = useState<User[]>([]);

  const loadWorkspaceData = useCallback(async (currentUser: User) => {
    if (currentUser.mustSetupTwoFactor || currentUser.mustSetupPasskey) {
      return;
    }
    const isAdmin = currentUser.role === 'admin';
    const [cmdRes, srvRes, certRes, logRes, usrRes] = await Promise.all([
      api.listCommands(true),
      api.listServers(),
      api.listCertificates(),
      api.listLogs(),
      isAdmin ? api.listUsers() : Promise.resolve({ users: [] }),
    ]);
    setCommands(cmdRes.commands);
    setServers(srvRes.servers);
    setCertificates(certRes.certificates);
    setLogs(logRes.logs);
    setUsers(usrRes.users);
  }, []);

  const bootstrap = useCallback(async () => {
    try {
      const status = await api.getStatus();
      setInitialized(status.initialized);
      setSettings(status.settings);
      setOpensshAvailable(status.opensshAvailable);
      setUser(status.user);
      if (status.user) {
        if (status.user.mustSetupTwoFactor || status.user.mustSetupPasskey) {
          setActiveTab('account');
        } else {
          await loadWorkspaceData(status.user);
        }
      }
    } finally {
      setLoading(false);
    }
  }, [loadWorkspaceData]);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUser(null);
      setShellMounted(false);
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  useEffect(() => {
    if (activeTab === 'shell') {
      setShellMounted(true);
    }
  }, [activeTab]);

  useEffect(() => {
    bootstrap();
  }, [bootstrap]);

  useEffect(() => {
    if (!user || activeTab !== 'logs' || user.mustSetupTwoFactor || user.mustSetupPasskey) return;
    let cancelled = false;
    void api
      .listLogs()
      .then((res) => {
        if (!cancelled) setLogs(res.logs);
      })
      .catch(() => {
        // ignore transient refresh error
      });
    return () => {
      cancelled = true;
    };
  }, [activeTab, user]);

  async function handleSetupComplete(admin: User, newSettings: AppSettings) {
    setInitialized(true);
    setSettings(newSettings);
    setUser(admin);
    setActiveTab('admin-commands');
    await loadWorkspaceData(admin);
  }

  async function handleLogin(loggedInUser: User) {
    setUser(loggedInUser);
    if (loggedInUser.mustSetupTwoFactor || loggedInUser.mustSetupPasskey) {
      setActiveTab('account');
      return;
    }
    setActiveTab('dashboard');
    await loadWorkspaceData(loggedInUser);
  }

  async function handleUserSecurityUpdated(updatedUser: User) {
    const wasLocked = Boolean(user?.mustSetupTwoFactor || user?.mustSetupPasskey);
    const isStillLocked = Boolean(updatedUser.mustSetupTwoFactor || updatedUser.mustSetupPasskey);
    setUser(updatedUser);
    if (wasLocked && !isStillLocked) {
      await loadWorkspaceData(updatedUser);
    }
  }

  async function handleLogout() {
    await api.logout();
    setUser(null);
    setShellMounted(false);
    setCommands([]);
    setServers([]);
    setCertificates([]);
    setLogs([]);
    setUsers([]);
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <p className="text-sm text-slate-500">
          {tr('Initialisiere SSH Console...', 'Initializing SSH Console...')}
        </p>
      </div>
    );
  }

  if (!initialized) {
    return <SetupView onComplete={handleSetupComplete} />;
  }

  if (!user) {
    return <LoginView settings={settings} onLogin={handleLogin} />;
  }

  const securitySetupRequired = Boolean(user.mustSetupTwoFactor || user.mustSetupPasskey);
  const effectiveTab: ActiveTab =
    securitySetupRequired && activeTab !== 'account' && activeTab !== 'admin-auth'
      ? 'account'
      : activeTab;

  const breadcrumbs: Record<ActiveTab, { group: string; title: string }> = {
    dashboard: { group: tr('Arbeitsbereich', 'Workspace'), title: 'Dashboard' },
    shell: { group: tr('Arbeitsbereich', 'Workspace'), title: 'SSH-Shell' },
    servers: { group: tr('Arbeitsbereich', 'Workspace'), title: tr('Meine Server (IPs)', 'My Servers (IPs)') },
    certificates: { group: tr('Arbeitsbereich', 'Workspace'), title: tr('SSH-Zertifikate', 'SSH Certificates') },
    logs: { group: tr('Arbeitsbereich', 'Workspace'), title: tr('Ausführungsprotokoll', 'Execution Log') },
    account: { group: tr('Konto', 'Account'), title: tr('Konto & Sicherheit', 'Account & Security') },
    'admin-commands': { group: tr('Arbeitsbereich', 'Workspace'), title: tr('SSH-Befehle', 'SSH Commands') },
    'admin-users': { group: 'Administration', title: tr('Benutzerverwaltung', 'User Management') },
    'admin-auth': { group: 'Administration', title: tr('Authentifizierung & SSO', 'Auth & SSO') },
  };

  const crumb = breadcrumbs[effectiveTab];

  return (
    <div className="min-h-screen bg-slate-50 flex">
      <Sidebar
        instanceName={settings.instanceName}
        user={user}
        activeTab={effectiveTab}
        onSelectTab={setActiveTab}
        onLogout={handleLogout}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
      />

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-14 bg-white border-b border-slate-200 px-6 flex items-center justify-between gap-4 shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-1.5 -ml-1.5 text-slate-600 hover:text-slate-900 rounded-md"
              aria-label={tr('Menü öffnen', 'Open menu')}
            >
              <Menu className="w-5 h-5" />
            </button>
            <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-sm truncate">
              <span className="text-slate-500 whitespace-nowrap">{crumb.group}</span>
              <span className="text-slate-300" aria-hidden="true">/</span>
              <span className="font-medium text-slate-900 truncate">{crumb.title}</span>
            </nav>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <LanguageSwitcher />
            {!securitySetupRequired &&
              (effectiveTab !== 'dashboard' ? (
                <button
                  type="button"
                  onClick={() => setActiveTab('dashboard')}
                  className="px-3.5 py-1.5 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
                >
                  {tr('Zum Dashboard', 'Go to Dashboard')}
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => setActiveTab('servers')}
                  className="px-3.5 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
                >
                  {tr(`Server verwalten (${servers.length})`, `Manage Servers (${servers.length})`)}
                </button>
              ))}
          </div>
        </header>

        <main className="flex-1 overflow-y-auto px-6 py-8">
          <div className="max-w-6xl mx-auto">
            <Suspense
              fallback={
                <div className="py-12 text-center text-sm text-slate-500">
                  {tr('Lade Ansicht...', 'Loading view...')}
                </div>
              }
            >
            {effectiveTab === 'dashboard' && (
              <DashboardView
                currentUser={user}
                settings={settings}
                servers={servers}
                commands={commands}
                certificates={certificates}
                onNavigate={setActiveTab}
                onRefreshServers={async () => {
                  const res = await api.listServers();
                  setServers(res.servers);
                }}
                onUpdateUser={setUser}
                onUpdateSettings={setSettings}
                onExecutionComplete={async () => {
                  const res = await api.listLogs();
                  setLogs(res.logs);
                }}
              />
            )}

            {shellMounted && !securitySetupRequired && (
              <div className={effectiveTab === 'shell' ? '' : 'hidden'}>
                <SshShellView
                  user={user}
                  isVisible={effectiveTab === 'shell'}
                  opensshAvailable={opensshAvailable}
                  allowInsecureHostKey={settings.allowInsecureHostKey}
                  servers={servers}
                  certificates={certificates}
                  onNavigate={setActiveTab}
                  onSessionEnded={async () => {
                    const res = await api.listLogs();
                    setLogs(res.logs);
                  }}
                />
              </div>
            )}

            {effectiveTab === 'servers' && (
              <ServersView
                user={user}
                users={users}
                servers={servers}
                globalPingAllowed={settings.pingAllowed}
                allowInsecureHostKey={settings.allowInsecureHostKey}
                onUpdateSettings={setSettings}
                onRefresh={async () => {
                  const res = await api.listServers();
                  setServers(res.servers);
                }}
              />
            )}

            {effectiveTab === 'certificates' && (
              <CertificatesView
                user={user}
                users={users}
                certificates={certificates}
                publicUrl={settings.publicUrl}
                onUpdateSettings={setSettings}
                onRefresh={async () => {
                  const res = await api.listCertificates();
                  setCertificates(res.certificates);
                }}
              />
            )}

            {effectiveTab === 'logs' && (
              <AuditLogView
                currentUser={user}
                users={users}
                logs={logs}
                onRefresh={async () => {
                  const res = await api.listLogs();
                  setLogs(res.logs);
                }}
              />
            )}

            {effectiveTab === 'account' && (
              <AccountView
                user={user}
                settings={settings}
                onUserUpdated={handleUserSecurityUpdated}
                onUpdateSettings={setSettings}
              />
            )}

            {effectiveTab === 'admin-commands' && (
              <CommandsAdminView
                currentUser={user}
                users={users}
                commands={commands}
                onRefresh={async () => {
                  const res = await api.listCommands(true);
                  setCommands(res.commands);
                }}
              />
            )}

            {effectiveTab === 'admin-users' && user.role === 'admin' && (
              <UsersAdminView
                currentUser={user}
                users={users}
                onRefresh={async () => {
                  const res = await api.listUsers();
                  setUsers(res.users);
                }}
              />
            )}

            {effectiveTab === 'admin-auth' && user.role === 'admin' && (
              <AuthSecurityAdminView
                onSettingsUpdated={(nextSettings, updatedUser) => {
                  setSettings(nextSettings);
                  if (updatedUser) {
                    void handleUserSecurityUpdated(updatedUser);
                  }
                }}
              />
            )}
            </Suspense>
          </div>
        </main>
      </div>
    </div>
  );
}
