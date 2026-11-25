import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { Moon, Sun } from 'lucide-react';
import { useI18n } from './i18n';

export type Theme = 'light' | 'dark';

const STORAGE_KEY = 'ssh_console_theme';

function readInitialTheme(): Theme {
  if (typeof document !== 'undefined' && document.documentElement.classList.contains('dark')) {
    return 'dark';
  }
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved === 'dark' || saved === 'light') return saved;
  } catch {
    // ignore storage errors in restricted iframes
  }
  if (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-color-scheme: dark)').matches
  ) {
    return 'dark';
  }
  return 'light';
}

interface ThemeContextValue {
  theme: Theme;
  isDark: boolean;
  setTheme: (next: Theme) => void;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(readInitialTheme);

  const setTheme = useCallback((next: Theme) => {
    setThemeState(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // ignore storage errors
    }
  }, []);

  const toggleTheme = useCallback(() => {
    setThemeState((prev) => {
      const next: Theme = prev === 'dark' ? 'light' : 'dark';
      try {
        window.localStorage.setItem(STORAGE_KEY, next);
      } catch {
        // ignore storage errors
      }
      return next;
    });
  }, []);

  useEffect(() => {
    if (typeof document === 'undefined') return;
    const root = document.documentElement;
    root.classList.toggle('dark', theme === 'dark');
    root.style.colorScheme = theme;
    const metaTheme = document.querySelector('meta[name="theme-color"]');
    if (metaTheme) {
      metaTheme.setAttribute('content', theme === 'dark' ? '#020617' : '#f8fafc');
    }
  }, [theme]);

  const value = useMemo<ThemeContextValue>(
    () => ({
      theme,
      isDark: theme === 'dark',
      setTheme,
      toggleTheme,
    }),
    [theme, setTheme, toggleTheme]
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error('useTheme must be used within ThemeProvider');
  }
  return ctx;
}

export function ThemeSwitcher({ compact = false }: { compact?: boolean }) {
  const { theme, setTheme } = useTheme();
  const { tr } = useI18n();

  return (
    <div
      role="group"
      aria-label={tr('Farbschema', 'Color theme')}
      className="inline-flex items-center p-0.5 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-md shrink-0"
    >
      <button
        type="button"
        onClick={() => setTheme('light')}
        aria-pressed={theme === 'light'}
        title={tr('Heller Modus', 'Light mode')}
        aria-label={tr('Heller Modus', 'Light mode')}
        className={`inline-flex items-center justify-center ${
          compact ? 'px-1.5 py-1' : 'px-2 py-1'
        } rounded transition-colors cursor-pointer ${
          theme === 'light'
            ? 'bg-white text-amber-600 shadow-xs'
            : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
        }`}
      >
        <Sun className="w-3.5 h-3.5" />
      </button>
      <button
        type="button"
        onClick={() => setTheme('dark')}
        aria-pressed={theme === 'dark'}
        title={tr('Dunkler Modus', 'Dark mode')}
        aria-label={tr('Dunkler Modus', 'Dark mode')}
        className={`inline-flex items-center justify-center ${
          compact ? 'px-1.5 py-1' : 'px-2 py-1'
        } rounded transition-colors cursor-pointer ${
          theme === 'dark'
            ? 'bg-slate-900 text-blue-400 shadow-xs'
            : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
        }`}
      >
        <Moon className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}
