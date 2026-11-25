import { useState } from 'react';
import { Download, PlusSquare, Share, Smartphone, X } from 'lucide-react';
import { useI18n } from '../i18n';
import { usePWAInstall } from '../hooks/usePWAInstall';

interface PWAInstallButtonProps {
  variant?: 'header' | 'sidebar';
}

export function PWAInstallButton({ variant = 'header' }: PWAInstallButtonProps) {
  const { tr } = useI18n();
  const { isInstallable, isInstalled, isIOS, install } = usePWAInstall();
  const [showIOSGuide, setShowIOSGuide] = useState(false);

  if (isInstalled) {
    return null;
  }

  const handleClick = () => {
    if (isInstallable) {
      void install();
    } else if (isIOS) {
      setShowIOSGuide(true);
    }
  };

  if (!isInstallable && !isIOS) {
    return null;
  }

  const isSidebar = variant === 'sidebar';

  return (
    <>
      <button
        type="button"
        onClick={handleClick}
        title={tr('Als Web-App installieren', 'Install as Web App')}
        className={
          isSidebar
            ? 'w-full flex items-center justify-center gap-2 px-3 py-2 min-h-[40px] text-xs font-medium rounded-md border border-blue-200 dark:border-blue-800/80 bg-blue-50 dark:bg-blue-950/50 text-blue-800 dark:text-blue-300 hover:bg-blue-100 dark:hover:bg-blue-900/60 transition-colors cursor-pointer whitespace-nowrap'
            : 'inline-flex items-center justify-center gap-1.5 px-2.5 sm:px-3 py-1.5 min-h-[36px] text-xs font-medium rounded-md border border-blue-200 dark:border-blue-800/80 bg-blue-50 dark:bg-blue-950/50 text-blue-800 dark:text-blue-300 hover:bg-blue-100 dark:hover:bg-blue-900/60 transition-colors cursor-pointer whitespace-nowrap shrink-0'
        }
      >
        {isInstallable ? (
          <Download className="w-3.5 h-3.5 shrink-0" />
        ) : (
          <Smartphone className="w-3.5 h-3.5 shrink-0" />
        )}
        <span className={isSidebar ? '' : 'hidden sm:inline'}>
          {isInstallable
            ? tr('App installieren', 'Install App')
            : tr('Auf Home-Bildschirm', 'Add to Home Screen')}
        </span>
      </button>

      {showIOSGuide && (
        <div
          className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-slate-950/60 backdrop-blur-xs p-0 sm:p-4"
          onClick={() => setShowIOSGuide(false)}
          role="dialog"
          aria-modal="true"
          aria-labelledby="ios-pwa-guide-title"
        >
          <div
            className="w-full sm:max-w-sm rounded-t-2xl sm:rounded-xl bg-white dark:bg-slate-900 border-t sm:border border-slate-200 dark:border-slate-800 p-5 pb-safe shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="w-10 h-1 rounded-full bg-slate-300 dark:bg-slate-700 mx-auto mb-4 sm:hidden" />
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <div className="w-9 h-9 rounded-lg bg-blue-50 dark:bg-blue-950/60 border border-blue-200 dark:border-blue-800/70 flex items-center justify-center text-blue-700 dark:text-blue-400 shrink-0">
                  <Smartphone className="w-4 h-4" />
                </div>
                <div>
                  <h3
                    id="ios-pwa-guide-title"
                    className="font-display text-base font-semibold text-slate-900 dark:text-slate-100"
                  >
                    {tr('Auf iPhone / iPad installieren', 'Install on iPhone / iPad')}
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {tr('Als eigenständige Vollbild-Web-App nutzen', 'Use as a standalone full-screen web app')}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowIOSGuide(false)}
                aria-label={tr('Schließen', 'Close')}
                className="p-2 -mr-1.5 -mt-1.5 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 rounded-md cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <ol className="mt-4 space-y-3 text-sm text-slate-700 dark:text-slate-300">
              <li className="flex items-start gap-3">
                <span className="w-6 h-6 rounded-full bg-slate-100 dark:bg-slate-800 text-xs font-semibold text-slate-700 dark:text-slate-200 flex items-center justify-center shrink-0 mt-0.5">
                  1
                </span>
                <span>
                  {tr('Tippen Sie in Safari auf das', 'Tap the')}{' '}
                  <span className="inline-flex items-center gap-1 font-medium text-slate-900 dark:text-slate-100">
                    <Share className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
                    {tr('Teilen-Symbol', 'Share button')}
                  </span>{' '}
                  {tr('in der unteren Symbolleiste.', 'in the Safari toolbar.')}
                </span>
              </li>
              <li className="flex items-start gap-3">
                <span className="w-6 h-6 rounded-full bg-slate-100 dark:bg-slate-800 text-xs font-semibold text-slate-700 dark:text-slate-200 flex items-center justify-center shrink-0 mt-0.5">
                  2
                </span>
                <span>
                  {tr('Wählen Sie', 'Scroll down and tap')}{' '}
                  <span className="inline-flex items-center gap-1 font-medium text-slate-900 dark:text-slate-100">
                    <PlusSquare className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
                    {tr('Zum Home-Bildschirm', 'Add to Home Screen')}
                  </span>{' '}
                  {tr('und bestätigen Sie mit „Hinzufügen“.', 'and confirm with "Add".')}
                </span>
              </li>
            </ol>

            <button
              type="button"
              onClick={() => setShowIOSGuide(false)}
              className="mt-5 w-full min-h-[44px] rounded-lg bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium hover:bg-slate-800 dark:hover:bg-slate-200 transition-colors cursor-pointer"
            >
              {tr('Verstanden', 'Got it')}
            </button>
          </div>
        </div>
      )}
    </>
  );
}
