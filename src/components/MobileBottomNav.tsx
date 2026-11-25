import React from 'react';
import {
  LayoutDashboard,
  Menu,
  Server,
  SlidersHorizontal,
  Terminal,
} from 'lucide-react';
import { useI18n } from '../i18n';
import type { ActiveTab } from '../types';

interface MobileBottomNavProps {
  activeTab: ActiveTab;
  canUseShell: boolean;
  setupLocked: boolean;
  activeJobsCount: number;
  onSelectTab: (tab: ActiveTab) => void;
  onOpenMenu: () => void;
}

interface BottomNavItem {
  id: ActiveTab | 'more';
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: number;
}

export function MobileBottomNav({
  activeTab,
  canUseShell,
  setupLocked,
  activeJobsCount,
  onSelectTab,
  onOpenMenu,
}: MobileBottomNavProps) {
  const { tr } = useI18n();

  const items: BottomNavItem[] = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    ...(canUseShell ? [{ id: 'shell' as const, label: 'Shell', icon: Terminal }] : []),
    { id: 'servers', label: 'Server', icon: Server },
    { id: 'admin-commands', label: tr('Befehle', 'Commands'), icon: SlidersHorizontal },
    {
      id: 'more',
      label: tr('Mehr', 'More'),
      icon: Menu,
      badge: activeJobsCount > 0 ? activeJobsCount : undefined,
    },
  ];

  const primaryIds = new Set(items.filter((i) => i.id !== 'more').map((i) => i.id));
  const moreIsActive = !primaryIds.has(activeTab);

  return (
    <nav
      aria-label={tr('Mobile Hauptnavigation', 'Mobile main navigation')}
      className="lg:hidden fixed bottom-0 left-0 right-0 z-30 bg-white/95 dark:bg-slate-900/95 backdrop-blur-md border-t border-slate-200 dark:border-slate-800 pb-safe"
    >
      <div
        className={`grid h-14 items-center ${
          items.length === 5 ? 'grid-cols-5' : 'grid-cols-4'
        }`}
      >
        {items.map((item) => {
          const Icon = item.icon;
          const isMore = item.id === 'more';
          const isActive = isMore ? moreIsActive : activeTab === item.id;
          const disabled = setupLocked && !isMore;

          return (
            <button
              key={item.id}
              type="button"
              disabled={disabled}
              onClick={() => {
                if (item.id === 'more') {
                  onOpenMenu();
                } else {
                  onSelectTab(item.id);
                }
              }}
              aria-current={isActive && !isMore ? 'page' : undefined}
              className={`relative flex flex-col items-center justify-center gap-0.5 h-full min-h-[48px] px-1 transition-colors select-none ${
                disabled
                  ? 'text-slate-300 dark:text-slate-700 cursor-not-allowed'
                  : isActive
                    ? 'text-blue-700 dark:text-blue-400 cursor-pointer'
                    : 'text-slate-500 dark:text-slate-400 active:text-slate-900 dark:active:text-slate-100 cursor-pointer'
              }`}
            >
              <span className="relative inline-flex items-center justify-center">
                <Icon className="w-5 h-5" />
                {item.badge !== undefined && !setupLocked && (
                  <span className="absolute -top-1.5 -right-2.5 min-w-[16px] h-4 px-1 rounded-full bg-blue-600 text-[10px] font-mono font-semibold tabular-nums text-white flex items-center justify-center">
                    {item.badge > 9 ? '9+' : item.badge}
                  </span>
                )}
              </span>
              <span className="text-[11px] font-medium leading-none tracking-tight truncate max-w-full">
                {item.label}
              </span>
              {isActive && !disabled && (
                <span
                  aria-hidden="true"
                  className="absolute top-0 left-1/2 -translate-x-1/2 w-8 h-0.5 rounded-b-full bg-blue-700 dark:bg-blue-400"
                />
              )}
            </button>
          );
        })}
      </div>
    </nav>
  );
}
