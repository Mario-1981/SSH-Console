import React, { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Menu } from 'lucide-react';
import { api, setUnauthorizedHandler } from './api';
import { LanguageSwitcher, useI18n } from './i18n';
import { ThemeSwitcher } from './theme';
import { BackgroundJobsBell } from './components/BackgroundJobsBell';
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
const BackgroundJobsView = lazy(() =>
  import('./components/BackgroundJobsView').then((m) => ({ default: m.BackgroundJobsView }))
);
const CaAdminView = lazy(() =>
  import('./components/CaAdminView').then((m) => ({ default: m.CaAdminView }))
);
const CertificatesView = lazy(() =>
  import('./components/CertificatesView').then((m) => ({ default: m.CertificatesView }))
);
const CommandsAdminView = lazy(() =>
  import('./components/CommandsAdminView').then((m) => ({ default: m.CommandsAdminView }))
);
const DatabaseAdminView = lazy(() =>
  import('./components/DatabaseAdminView').then((m) => ({ default: m.DatabaseAdminView }))
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
  BackgroundJob,
  BackgroundJobStatus,
  ExecutionLog,
  ShareableUser,
  SshCommand,
  User,
  UserCertificate,
  UserGroup,
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
    maxBackgroundJobs: 5,
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
  const [groups, setGroups] = useState<UserGroup[]>([]);
  const [shareableUsers, setShareableUsers] = useState<ShareableUser[]>([]);

  // Global background quick-command jobs (persist across all tabs incl. SSH-Shell)
  const [bgJobs, setBgJobs] = useState<BackgroundJob[]>([]);
  const [bgActiveCount, setBgActiveCount] = useState(0);
  const [bgTotalActiveCount, setBgTotalActiveCount] = useState(0);
  const [bgUnreadCount, setBgUnreadCount] = useState(0);
  const [bgMaxJobs, setBgMaxJobs] = useState(5);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [selectedExternalJob, setSelectedExternalJob] = useState<BackgroundJob | null>(null);
  const [toastJob, setToastJob] = useState<BackgroundJob | null>(null);
  const prevJobStatusRef = useRef<Map<string, BackgroundJobStatus>>(new Map());
  const toastTimerRef = useRef<number | null>(null);
  const bgPollInFlightRef = useRef(false);

  const selectedJob = useMemo(() => {
    if (!selectedJobId) return null;
    const own = bgJobs.find((j) => j.id === selectedJobId);
    if (own) return own;
    if (selectedExternalJob && selectedExternalJob.id === selectedJobId) {
      return selectedExternalJob;
    }
    return null;
  }, [bgJobs, selectedJobId, selectedExternalJob]);

  const showCompletionToast = useCallback((job: BackgroundJob) => {
    setToastJob(job);
    if (toastTimerRef.current !== null) {
      window.clearTimeout(toastTimerRef.current);
    }
    toastTimerRef.current = window.setTimeout(() => {
      setToastJob((curr) => (curr?.id === job.id ? null : curr));
      toastTimerRef.current = null;
    }, 10_000);
  }, []);

  useEffect(() => {
    return () => {
      if (toastTimerRef.current !== null) {
        window.clearTimeout(toastTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (typeof settings.maxBackgroundJobs === 'number' && settings.maxBackgroundJobs >= 1) {
      setBgMaxJobs(settings.maxBackgroundJobs);
    }
  }, [settings.maxBackgroundJobs]);

  const fetchBackgroundJobs = useCallback(async () => {
    if (bgPollInFlightRef.current) return;
    bgPollInFlightRef.current = true;
    try {
      const res = await api.listBackgroundJobs();
      const prevMap = prevJobStatusRef.current;
      let newlyFinished: BackgroundJob | null = null;
      const nextMap = new Map<string, BackgroundJobStatus>();

      for (const job of res.jobs) {
        nextMap.set(job.id, job.status);
        const prevStatus = prevMap.get(job.id);
        if (prevStatus === 'running' && job.status !== 'running') {
          if (!newlyFinished) newlyFinished = job;
        }
      }
      prevJobStatusRef.current = nextMap;

      setBgJobs(res.jobs);
      setBgActiveCount(res.activeCount);
      setBgTotalActiveCount(
        typeof res.totalActiveCount === 'number' ? res.totalActiveCount : res.activeCount
      );
      setBgUnreadCount(res.unreadCount);
      setBgMaxJobs(res.maxBackgroundJobs);

      if (newlyFinished) {
        showCompletionToast(newlyFinished);
        if (user && (user.role === 'admin' || user.permissions?.viewOwnLogs !== false)) {
          void api
            .listLogs()
            .then((l) => setLogs(l.logs))
            .catch(() => {
              // ignore transient log refresh error
            });
        }
      }
    } catch {
      // ignore transient background poll errors
    } finally {
      bgPollInFlightRef.current = false;
    }
  }, [showCompletionToast, user]);

  const loadWorkspaceData = useCallback(async (currentUser: User) => {
    if (currentUser.mustSetupTwoFactor || currentUser.mustSetupPasskey) {
      return;
    }
    const isAdmin = currentUser.role === 'admin';
    const canViewLogs = isAdmin || currentUser.permissions?.viewOwnLogs !== false;
    const canShare = isAdmin || Boolean(currentUser.permissions?.shareResources);

    const [cmdRes, srvRes, certRes, logRes, usrRes, grpRes, shareRes] = await Promise.all([
      api.listCommands(true),
      api.listServers(),
      api.listCertificates(),
      canViewLogs ? api.listLogs() : Promise.resolve({ logs: [] as ExecutionLog[] }),
      isAdmin ? api.listUsers() : Promise.resolve({ users: [] as User[] }),
      isAdmin ? api.listGroups() : Promise.resolve({ groups: [] as UserGroup[] }),
      !isAdmin && canShare
        ? api.listShareableUsers().catch(() => ({ users: [] as ShareableUser[] }))
        : Promise.resolve({ users: [] as ShareableUser[] }),
    ]);
    setCommands(cmdRes.commands);
    setServers(srvRes.servers);
    setCertificates(certRes.certificates);
    setLogs(logRes.logs);
    setUsers(usrRes.users);
    setGroups(grpRes.groups);
    setShareableUsers(isAdmin ? usrRes.users : shareRes.users);
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
    if (
      !user ||
      activeTab !== 'logs' ||
      user.mustSetupTwoFactor ||
      user.mustSetupPasskey ||
      (user.role !== 'admin' && user.permissions?.viewOwnLogs === false)
    ) {
      return;
    }
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

  // Adaptive background job polling: fast (2s) while any job is running, relaxed (15s) while idle
  useEffect(() => {
    if (!user || user.mustSetupTwoFactor || user.mustSetupPasskey) return;
    void fetchBackgroundJobs();
    const intervalMs = bgActiveCount > 0 ? 2000 : 15_000;
    const timer = window.setInterval(() => {
      if (bgActiveCount > 0 || typeof document === 'undefined' || !document.hidden) {
        void fetchBackgroundJobs();
      }
    }, intervalMs);
    const onVisibility = () => {
      if (typeof document !== 'undefined' && !document.hidden) {
        void fetchBackgroundJobs();
      }
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [user, bgActiveCount, fetchBackgroundJobs]);

  const handleBackgroundJobStarted = useCallback(
    (job: BackgroundJob, activeCount: number, maxBackgroundJobs: number) => {
      prevJobStatusRef.current.set(job.id, job.status);
      setBgJobs((prev) => [job, ...prev.filter((item) => item.id !== job.id)]);
      setBgActiveCount(activeCount);
      setBgTotalActiveCount((prev) => Math.max(activeCount, prev + 1));
      setBgMaxJobs(maxBackgroundJobs);
    },
    []
  );

  const handleSelectBackgroundJob = useCallback((job: BackgroundJob | null) => {
    setSelectedJobId(job ? job.id : null);
    setSelectedExternalJob(job);
    if (job && user && job.userId === user.id && job.status !== 'running' && !job.read) {
      setBgJobs((prev) => prev.map((j) => (j.id === job.id ? { ...j, read: true } : j)));
      setBgUnreadCount((prev) => Math.max(0, prev - 1));
      void api
        .markBackgroundJobRead(job.id)
        .then((res) => {
          setBgJobs((prev) => prev.map((j) => (j.id === res.job.id ? res.job : j)));
          setBgUnreadCount(res.unreadCount);
        })
        .catch(() => {
          // ignore transient error
        });
    }
  }, [user]);

  const handleSyncAdminJob = useCallback((job: BackgroundJob) => {
    setSelectedExternalJob((curr) => (curr && curr.id === job.id ? job : curr));
  }, []);

  const handleMarkAllJobsRead = useCallback(async () => {
    setBgJobs((prev) => prev.map((j) => (j.status !== 'running' ? { ...j, read: true } : j)));
    setBgUnreadCount(0);
    try {
      const res = await api.markAllBackgroundJobsRead();
      setBgUnreadCount(res.unreadCount);
    } catch {
      void fetchBackgroundJobs();
    }
  }, [fetchBackgroundJobs]);

  const handleDeleteBackgroundJob = useCallback(
    async (jobId: string) => {
      setSelectedJobId((curr) => (curr === jobId ? null : curr));
      setToastJob((curr) => (curr?.id === jobId ? null : curr));
      try {
        await api.deleteBackgroundJob(jobId);
        setBgJobs((prev) => {
          const next = prev.filter((j) => j.id !== jobId);
          setBgUnreadCount(next.filter((j) => j.status !== 'running' && !j.read).length);
          return next;
        });
      } catch {
        void fetchBackgroundJobs();
      }
    },
    [fetchBackgroundJobs]
  );

  const handleUpdateBackgroundJobLimit = useCallback(async (nextLimit: number) => {
    const res = await api.updateBackgroundJobSettings(nextLimit);
    setSettings(res.settings);
    setBgMaxJobs(res.maxBackgroundJobs);
    setBgActiveCount(res.activeCount);
    if (typeof res.totalActiveCount === 'number') {
      setBgTotalActiveCount(res.totalActiveCount);
    }
  }, []);

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
    setGroups([]);
    setShareableUsers([]);
    setBgJobs([]);
    setBgActiveCount(0);
    setBgTotalActiveCount(0);
    setBgUnreadCount(0);
    setSelectedJobId(null);
    setSelectedExternalJob(null);
    setToastJob(null);
    prevJobStatusRef.current.clear();
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex items-center justify-center">
        <p className="text-sm text-slate-500 dark:text-slate-400">
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
  const canUseShell = user.role === 'admin' || user.permissions?.useSshShell !== false;
  const canViewLogs = user.role === 'admin' || user.permissions?.viewOwnLogs !== false;
  const canExecuteCommands = user.role === 'admin' || user.permissions?.executeCommands !== false;

  const effectiveTab: ActiveTab =
    securitySetupRequired && activeTab !== 'account' && activeTab !== 'admin-auth'
      ? 'account'
      : activeTab === 'shell' && !canUseShell
        ? 'dashboard'
        : activeTab === 'logs' && !canViewLogs
          ? 'dashboard'
          : (activeTab === 'admin-users' ||
                activeTab === 'admin-ca' ||
                activeTab === 'admin-auth' ||
                activeTab === 'admin-database') &&
              user.role !== 'admin'
            ? 'dashboard'
            : activeTab;

  const breadcrumbs: Record<ActiveTab, { group: string; title: string }> = {
    dashboard: { group: tr('Arbeitsbereich', 'Workspace'), title: 'Dashboard' },
    shell: { group: tr('Arbeitsbereich', 'Workspace'), title: 'SSH-Shell' },
    jobs: { group: tr('Arbeitsbereich', 'Workspace'), title: tr('Hintergrundprozesse', 'Background Jobs') },
    servers: { group: tr('Arbeitsbereich', 'Workspace'), title: tr('Meine Server (IPs)', 'My Servers (IPs)') },
    certificates: { group: tr('Arbeitsbereich', 'Workspace'), title: tr('SSH-Zertifikate', 'SSH Certificates') },
    logs: { group: tr('Arbeitsbereich', 'Workspace'), title: tr('Ausführungsprotokoll', 'Execution Log') },
    account: { group: tr('Konto', 'Account'), title: tr('Konto & Sicherheit', 'Account & Security') },
    'admin-commands': { group: tr('Arbeitsbereich', 'Workspace'), title: tr('SSH-Befehle', 'SSH Commands') },
    'admin-users': { group: 'Administration', title: tr('Benutzer & Gruppen', 'Users & Groups') },
    'admin-ca': { group: 'Administration', title: tr('CA-Zertifikate', 'CA Certificates') },
    'admin-auth': { group: 'Administration', title: tr('Authentifizierung & SSO', 'Auth & SSO') },
    'admin-database': { group: 'Administration', title: tr('Datenbank', 'Database') },
  };

  const crumb = breadcrumbs[effectiveTab];

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex">
      <Sidebar
        instanceName={settings.instanceName}
        user={user}
        activeTab={effectiveTab}
        onSelectTab={setActiveTab}
        onLogout={handleLogout}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
        activeJobsCount={
          user.role === 'admin' ? bgTotalActiveCount : bgActiveCount
        }
      />

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-14 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 px-6 flex items-center justify-between gap-4 shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-1.5 -ml-1.5 text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-slate-100 rounded-md"
              aria-label={tr('Menü öffnen', 'Open menu')}
            >
              <Menu className="w-5 h-5" />
            </button>
            <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-sm truncate">
              <span className="text-slate-500 dark:text-slate-400 whitespace-nowrap">{crumb.group}</span>
              <span className="text-slate-300 dark:text-slate-600" aria-hidden="true">/</span>
              <span className="font-medium text-slate-900 dark:text-slate-100 truncate">{crumb.title}</span>
            </nav>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            {!securitySetupRequired && (canExecuteCommands || bgJobs.length > 0) && (
              <BackgroundJobsBell
                jobs={bgJobs}
                activeCount={bgActiveCount}
                unreadCount={bgUnreadCount}
                maxBackgroundJobs={bgMaxJobs}
                isAdmin={user.role === 'admin'}
                selectedJob={selectedJob}
                toastJob={toastJob}
                onSelectJob={handleSelectBackgroundJob}
                onDismissToast={() => setToastJob(null)}
                onMarkAllRead={handleMarkAllJobsRead}
                onDeleteJob={handleDeleteBackgroundJob}
                onUpdateLimit={handleUpdateBackgroundJobLimit}
                onNavigateLogs={setActiveTab}
              />
            )}
            <ThemeSwitcher />
            <LanguageSwitcher />
            {!securitySetupRequired &&
              (effectiveTab !== 'dashboard' ? (
                <button
                  type="button"
                  onClick={() => setActiveTab('dashboard')}
                  className="px-3.5 py-1.5 text-xs font-medium text-white bg-blue-700 hover:bg-blue-800 dark:bg-blue-600 dark:hover:bg-blue-500 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
                >
                  {tr('Zum Dashboard', 'Go to Dashboard')}
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => setActiveTab('servers')}
                  className="px-3.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700 rounded-md transition-colors cursor-pointer whitespace-nowrap shrink-0"
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
                <div className="py-12 text-center text-sm text-slate-500 dark:text-slate-400">
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
                bgJobs={bgJobs}
                bgActiveCount={bgActiveCount}
                bgMaxJobs={bgMaxJobs}
                onBackgroundJobStarted={handleBackgroundJobStarted}
                onOpenBackgroundJob={handleSelectBackgroundJob}
              />
            )}

            {shellMounted && !securitySetupRequired && canUseShell && (
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
                    if (canViewLogs) {
                      const res = await api.listLogs();
                      setLogs(res.logs);
                    }
                  }}
                />
              </div>
            )}

            {effectiveTab === 'jobs' && (
              <BackgroundJobsView
                currentUser={user}
                myJobs={bgJobs}
                myActiveCount={bgActiveCount}
                totalActiveCount={bgTotalActiveCount}
                maxBackgroundJobs={bgMaxJobs}
                onRefreshMyJobs={fetchBackgroundJobs}
                onSelectJob={handleSelectBackgroundJob}
                onDeleteJob={handleDeleteBackgroundJob}
                onUpdateLimit={handleUpdateBackgroundJobLimit}
                onSyncAdminJob={handleSyncAdminJob}
              />
            )}

            {effectiveTab === 'servers' && (
              <ServersView
                user={user}
                users={shareableUsers}
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
                users={shareableUsers}
                certificates={certificates}
                publicUrl={settings.publicUrl}
                onUpdateSettings={setSettings}
                onRefresh={async () => {
                  const res = await api.listCertificates();
                  setCertificates(res.certificates);
                }}
              />
            )}

            {effectiveTab === 'logs' && canViewLogs && (
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
                users={shareableUsers}
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
                groups={groups}
                onRefresh={async () => {
                  const res = await api.listUsers();
                  setUsers(res.users);
                  setShareableUsers(res.users);
                }}
                onRefreshGroups={async () => {
                  const res = await api.listGroups();
                  setGroups(res.groups);
                }}
              />
            )}

            {effectiveTab === 'admin-ca' && user.role === 'admin' && (
              <CaAdminView currentUser={user} />
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

            {effectiveTab === 'admin-database' && user.role === 'admin' && (
              <DatabaseAdminView
                onDatabaseMigrated={() => {
                  void loadWorkspaceData(user);
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
