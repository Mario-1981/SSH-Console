import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

export type Locale = 'de' | 'en';

const STORAGE_KEY = 'ssh_console_lang';

function readInitialLocale(): Locale {
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved === 'en' || saved === 'de') return saved;
  } catch {
    // ignore storage errors in restricted iframes
  }
  return 'de';
}

interface I18nContextValue {
  locale: Locale;
  isEn: boolean;
  setLocale: (next: Locale) => void;
  tr: (de: string, en: string) => string;
  formatDateTime: (iso: string | null | undefined, options?: { seconds?: boolean; emptyText?: string }) => string;
  formatClockTime: (iso: string | null | undefined) => string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export function LanguageProvider({ children }: { children: React.ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(readInitialLocale);

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // ignore storage errors
    }
  }, []);

  useEffect(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.lang = locale;
    }
  }, [locale]);

  const value = useMemo<I18nContextValue>(() => {
    const isEn = locale === 'en';
    const intlLocale = isEn ? 'en-US' : 'de-DE';

    const tr = (de: string, en: string) => (isEn ? en : de);

    const formatDateTime = (
      iso: string | null | undefined,
      options?: { seconds?: boolean; emptyText?: string }
    ): string => {
      if (!iso) return options?.emptyText ?? '—';
      if (iso.startsWith('Unbegrenzt')) return isEn ? 'Unlimited' : iso;
      const d = new Date(iso);
      if (Number.isNaN(d.getTime())) return iso;
      return d.toLocaleString(intlLocale, {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        ...(options?.seconds ? { second: '2-digit' } : {}),
      });
    };

    const formatClockTime = (iso: string | null | undefined): string => {
      if (!iso) return '—';
      const d = new Date(iso);
      if (Number.isNaN(d.getTime())) return '—';
      return d.toLocaleTimeString(intlLocale, {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    };

    return { locale, isEn, setLocale, tr, formatDateTime, formatClockTime };
  }, [locale, setLocale]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) {
    throw new Error('useI18n must be used within LanguageProvider');
  }
  return ctx;
}

export function translateCategory(category: string, locale: Locale): string {
  if (locale !== 'en') return category;
  const map: Record<string, string> = {
    Diagnose: 'Diagnostics',
    Dienste: 'Services',
    Wartung: 'Maintenance',
    Netzwerk: 'Network',
    Sicherheit: 'Security',
    Allgemein: 'General',
  };
  return map[category] ?? category;
}

export function LanguageSwitcher({ compact = false }: { compact?: boolean }) {
  const { locale, setLocale } = useI18n();
  return (
    <div
      role="group"
      aria-label="Language / Sprache"
      className="inline-flex items-center p-0.5 bg-slate-100 border border-slate-200 rounded-md shrink-0"
    >
      {(['de', 'en'] as const).map((code) => {
        const active = locale === code;
        return (
          <button
            key={code}
            type="button"
            onClick={() => setLocale(code)}
            aria-pressed={active}
            className={`${compact ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-1 text-xs'} font-medium uppercase rounded transition-colors cursor-pointer ${
              active
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-500 hover:text-slate-900'
            }`}
          >
            {code}
          </button>
        );
      })}
    </div>
  );
}
