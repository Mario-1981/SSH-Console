import { WifiOff } from 'lucide-react';
import { useI18n } from '../i18n';
import { useOnlineStatus } from '../hooks/usePWAInstall';

export function OfflineIndicator() {
  const isOnline = useOnlineStatus();
  const { tr } = useI18n();

  if (isOnline) {
    return null;
  }

  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed bottom-20 lg:bottom-4 left-1/2 -translate-x-1/2 lg:left-4 lg:translate-x-0 z-50 flex items-center gap-2 rounded-lg bg-amber-600 dark:bg-amber-700 px-3.5 py-2 text-xs font-medium text-white shadow-lg border border-amber-500/40 whitespace-nowrap"
    >
      <WifiOff className="w-3.5 h-3.5 shrink-0" />
      <span>
        {tr(
          'Offline — Keine Verbindung zum Server',
          'Offline — No connection to server'
        )}
      </span>
    </div>
  );
}
