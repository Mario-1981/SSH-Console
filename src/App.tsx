import React, { useCallback, useEffect, useState } from 'react';
import { Menu } from 'lucide-react';
import { api, setUnauthorizedHandler } from './api';
import { AccountView } from './components/AccountView';
import { AuditLogView } from './components/AuditLogView';
import { CertificatesView } from './components/CertificatesView';
import { CommandsAdminView } from './components/CommandsAdminView';
import { DashboardView } from './components/DashboardView';
import { ExecuteView } from './components/ExecuteView';
import { LoginView } from './components/LoginView';
import { RustDeployView } from './components/RustDeployView';
import { ServersView } from './components/ServersView';
import { SetupView } from './components/SetupView';
import { Sidebar } from './components/Sidebar';
import { UsersAdminView } from './components/UsersAdminView';
import type {
  ActiveTab,
  AppSettings,
  ExecutionLog,
  SshCommand,
  User,
  UserCertificate,
  UserServer,
} from './types';

const TAB_BREADCRUMBS: Record<ActiveTab, { group: string; title: string }> = {
  dashboard: { group: 'Arbeitsbereich', title: 'Dashboard' },
  execute: { group: 'Arbeitsbereich', title: 'Befehle ausführen' },
  servers: { group: 'Arbeitsbereich', title: 'Meine Server (IPs)' },
  certificates: { group: 'Arbeitsbereich', title: 'SSH-Zertifikate' },
  logs: { group: 'Arbeitsbereich', title: 'Ausführungsprotokoll' },
  account: { group: 'Konto', title: 'Passwort ändern' },
  'admin-commands': { group: 'Arbeitsbereich', title: 'SSH-Befehle' },
  'admin-users': { group: 'Administration', title: 'Benutzerverwaltung' },
  'rust-deploy': { group: 'Bereitstellung', title: 'Rust & Debian Trixie' },
};

export default function App() {
  const [loading, setLoading] = useState(true);
  const [initialized, setInitialized] = useState(false);
  const [opensshAvailable, setOpensshAvailable] = useState(false);
  const [settings, setSettings] = useState<AppSettings>({
    instanceName: 'TrixieSSH',
    initializedAt: null,
  });
  const [user, setUser] = useState<User | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [commands, setCommands] = useState<SshCommand[]>([]);
  const [servers, setServers] = useState<UserServer[]>([]);
  const [certificates, setCertificates] = useState<UserCertificate[]>([]);
  const [logs, setLogs] = useState<ExecutionLog[]>([]);
  const [users, setUsers] = useState<User[]>([]);

  const loadWorkspaceData = useCallback(async (currentUser: User) => {
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
        await loadWorkspaceData(status.user);
      }
    } finally {
      setLoading(false);
    }
  }, [loadWorkspaceData]);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUser(null);
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  useEffect(() => {
    bootstrap();
  }, [bootstrap]);

  async function handleSetupComplete(admin: User, newSettings: AppSettings) {
    setInitialized(true);
    setSettings(newSettings);
    setUser(admin);
    // Guide admin directly to defining SSH commands right after initial setup
    setActiveTab('admin-commands');
    await loadWorkspaceData(admin);
  }

  async function handleLogin(loggedInUser: User) {
    setUser(loggedInUser);
    setActiveTab('dashboard');
    await loadWorkspaceData(loggedInUser);
  }

  async function handleLogout() {
    await api.logout();
    setUser(null);
    setCommands([]);
    setServers([]);
    setCertificates([]);
    setLogs([]);
    setUsers([]);
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <p className="text-sm text-slate-500">Initialisiere TrixieSSH...</p>
      </div>
    );
  }

  if (!initialized) {
    return <SetupView onComplete={handleSetupComplete} />;
  }

  if (!user) {
    return <LoginView instanceName={settings.instanceName} onLogin={handleLogin} />;
  }

  const crumb = TAB_BREADCRUMBS[activeTab];

  return (
    <div className="min-h-screen bg-slate-50 flex">
      <Sidebar
        instanceName={settings.instanceName}
        user={user}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onLogout={handleLogout}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
      />

      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Bar Contract: Breadcrumb on left, single contextual action on right */}
        <header className="h-14 bg-white border-b border-slate-200 px-6 flex items-center justify-between gap-8 shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-1.5 -ml-1.5 text-slate-600 hover:text-slate-900 rounded-md"
              aria-label="Menü öffnen"
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
            {activeTab !== 'dashboard' ? (
              <button
                type="button"
                onClick={() => setActiveTab('dashboard')}
                className="px-3.5 py-1.5 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
              >
                Zum Dashboard
              </button>
            ) : (
              <button
                type="button"
                onClick={() => setActiveTab('servers')}
                className="px-3.5 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 hover:bg-slate-50 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
              >
                Server verwalten ({servers.length})
              </button>
            )}
          </div>
        </header>

        <main className="flex-1 overflow-y-auto px-6 py-8">
          <div className="max-w-6xl mx-auto">
            {activeTab === 'dashboard' && (
              <DashboardView
                currentUser={user}
                servers={servers}
                commands={commands}
                certificates={certificates}
                onNavigate={setActiveTab}
                onExecutionComplete={async () => {
                  const res = await api.listLogs();
                  setLogs(res.logs);
                }}
              />
            )}

            {activeTab === 'execute' && (
              <ExecuteView
                user={user}
                opensshAvailable={opensshAvailable}
                commands={commands}
                servers={servers}
                certificates={certificates}
                onNavigate={setActiveTab}
                onExecutionComplete={async () => {
                  const res = await api.listLogs();
                  setLogs(res.logs);
                }}
              />
            )}

            {activeTab === 'servers' && (
              <ServersView
                user={user}
                users={users}
                servers={servers}
                onRefresh={async () => {
                  const res = await api.listServers();
                  setServers(res.servers);
                }}
              />
            )}

            {activeTab === 'certificates' && (
              <CertificatesView
                user={user}
                users={users}
                certificates={certificates}
                onRefresh={async () => {
                  const res = await api.listCertificates();
                  setCertificates(res.certificates);
                }}
              />
            )}

            {activeTab === 'logs' && <AuditLogView logs={logs} />}

            {activeTab === 'account' && <AccountView user={user} />}

            {activeTab === 'admin-commands' && (
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

            {activeTab === 'admin-users' && user.role === 'admin' && (
              <UsersAdminView
                currentUser={user}
                users={users}
                onRefresh={async () => {
                  const res = await api.listUsers();
                  setUsers(res.users);
                }}
              />
            )}

            {activeTab === 'rust-deploy' && <RustDeployView />}
          </div>
        </main>
      </div>
    </div>
  );
}
