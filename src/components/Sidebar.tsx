import React from 'react';
import {
  LayoutDashboard,
  Terminal,
  Server,
  KeyRound,
  History,
  SlidersHorizontal,
  Users,
  ShieldCheck,
  LogOut,
  Lock,
  X,
  Activity,
  FileKey2,
} from 'lucide-react';
import { useI18n } from '../i18n';
import type { ActiveTab, User } from '../types';

interface SidebarProps {
  instanceName: string;
  user: User;
  activeTab: ActiveTab;
  onSelectTab: (tab: ActiveTab) => void;
  onLogout: () => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
  activeJobsCount?: number;
}

interface NavItem {
  id: ActiveTab;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}

export function Sidebar({
  instanceName,
  user,
  activeTab,
  onSelectTab,
  onLogout,
  mobileOpen,
  onCloseMobile,
  activeJobsCount = 0,
}: SidebarProps) {
  const { tr } = useI18n();

  const isAdmin = user.role === 'admin';
  const canUseShell = isAdmin || user.permissions?.useSshShell !== false;
  const canViewLogs = isAdmin || user.permissions?.viewOwnLogs !== false;
  const canExecuteCommands = isAdmin || user.permissions?.executeCommands !== false;

  const workspaceItems: NavItem[] = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    ...(canUseShell ? [{ id: 'shell' as ActiveTab, label: 'SSH-Shell', icon: Terminal }] : []),
    ...(canExecuteCommands || activeJobsCount > 0
      ? [{ id: 'jobs' as ActiveTab, label: tr('Hintergrundprozesse', 'Background Jobs'), icon: Activity }]
      : []),
    { id: 'admin-commands', label: tr('SSH-Befehle', 'SSH Commands'), icon: SlidersHorizontal },
    { id: 'servers', label: tr('Meine Server (IPs)', 'My Servers (IPs)'), icon: Server },
    { id: 'certificates', label: tr('SSH-Zertifikate', 'SSH Certificates'), icon: KeyRound },
    ...(canViewLogs
      ? [{ id: 'logs' as ActiveTab, label: tr('Ausführungsprotokoll', 'Execution Log'), icon: History }]
      : []),
  ];

  const adminItems: NavItem[] = [
    { id: 'admin-users', label: tr('Benutzer & Gruppen', 'Users & Groups'), icon: Users },
    { id: 'admin-ca', label: tr('CA-Zertifikate', 'CA Certificates'), icon: FileKey2 },
    { id: 'admin-auth', label: tr('Authentifizierung & SSO', 'Auth & SSO'), icon: ShieldCheck },
  ];

  const setupLocked = Boolean(user.mustSetupTwoFactor || user.mustSetupPasskey);

  function handleNav(tab: ActiveTab) {
    if (setupLocked && tab !== 'account' && tab !== 'admin-auth') {
      onSelectTab('account');
      onCloseMobile();
      return;
    }
    onSelectTab(tab);
    onCloseMobile();
  }

  const content = (
    <div className="flex flex-col h-full bg-white border-r border-slate-200 w-[256px]">
      <div className="h-14 px-5 flex items-center justify-between border-b border-slate-200 shrink-0">
        <span className="font-display text-base font-bold tracking-tight text-slate-900 truncate">
          {instanceName}
        </span>
        <button
          type="button"
          onClick={onCloseMobile}
          className="lg:hidden p-1.5 text-slate-500 hover:text-slate-900 rounded-md"
          aria-label={tr('Navigation schließen', 'Close navigation')}
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
        <div>
          <p className="px-2.5 mb-2 text-xs font-medium text-slate-500">
            {tr('Arbeitsbereich', 'Workspace')}
          </p>
          <ul className="space-y-0.5">
            {workspaceItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <li key={item.id}>
                  <button
                    type="button"
                    disabled={setupLocked}
                    onClick={() => handleNav(item.id)}
                    className={`w-full flex items-center gap-2.5 px-2.5 py-2 text-sm rounded-md transition-colors whitespace-nowrap ${
                      setupLocked
                        ? 'text-slate-400 cursor-not-allowed'
                        : isActive
                          ? 'bg-blue-50 text-blue-800 font-medium cursor-pointer'
                          : 'text-slate-700 hover:bg-slate-100 hover:text-slate-900 cursor-pointer'
                    }`}
                  >
                    <Icon
                      className={`w-4 h-4 shrink-0 ${
                        setupLocked ? 'text-slate-300' : isActive ? 'text-blue-700' : 'text-slate-500'
                      }`}
                    />
                    <span className="truncate flex-1 text-left">{item.label}</span>
                    {item.id === 'jobs' && activeJobsCount > 0 && !setupLocked && (
                      <span className="px-1.5 py-0.5 text-[10px] font-mono font-semibold tabular-nums rounded bg-blue-600 text-white shrink-0">
                        {activeJobsCount}
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>

        {user.role === 'admin' && (
          <div>
            <p className="px-2.5 mb-2 text-xs font-medium text-slate-500">Administration</p>
            <ul className="space-y-0.5">
              {adminItems.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <li key={item.id}>
                    <button
                      type="button"
                      onClick={() => handleNav(item.id)}
                      className={`w-full flex items-center gap-2.5 px-2.5 py-2 text-sm rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                        isActive
                          ? 'bg-blue-50 text-blue-800 font-medium'
                          : 'text-slate-700 hover:bg-slate-100 hover:text-slate-900'
                      }`}
                    >
                      <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-blue-700' : 'text-slate-500'}`} />
                      <span className="truncate">{item.label}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        )}
      </nav>

      <div className="p-4 border-t border-slate-200 shrink-0 space-y-3">
        <div className="flex items-center justify-between gap-2">
          <div className="min-w-0">
            <p className="text-sm font-medium text-slate-900 truncate">{user.displayName}</p>
            <p className="text-xs text-slate-500 truncate">
              <span className="font-mono">{user.username}</span> ·{' '}
              {user.groupName || (user.role === 'admin' ? 'Administratoren' : tr('Benutzer', 'User'))}
            </p>
          </div>
          <button
            type="button"
            onClick={onLogout}
            title={tr('Abmelden', 'Sign out')}
            aria-label={tr('Abmelden', 'Sign out')}
            className="p-2 text-slate-500 hover:text-slate-900 hover:bg-slate-100 rounded-md transition-colors cursor-pointer shrink-0"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
        <button
          type="button"
          onClick={() => handleNav('account')}
          className={`w-full flex items-center justify-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md border transition-colors cursor-pointer whitespace-nowrap ${
            setupLocked
              ? 'bg-amber-50 border-amber-300 text-amber-900'
              : activeTab === 'account'
                ? 'bg-blue-50 border-blue-200 text-blue-800'
                : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50 hover:text-slate-900'
          }`}
        >
          <Lock className="w-3.5 h-3.5 shrink-0" />
          {setupLocked
            ? tr('Sicherheit einrichten!', 'Complete Security Setup!')
            : tr('Konto & Sicherheit', 'Account & Security')}
        </button>
      </div>
    </div>
  );

  return (
    <>
      <aside className="hidden lg:block shrink-0">{content}</aside>
      {mobileOpen && (
        <div className="fixed inset-0 z-40 lg:hidden flex">
          <div
            className="fixed inset-0 bg-slate-900/40"
            onClick={onCloseMobile}
            aria-hidden="true"
          />
          <aside className="relative z-50 h-full">{content}</aside>
        </div>
      )}
    </>
  );
}
