import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import { Check, ChevronDown, Search, X } from 'lucide-react';
import { useI18n } from '../i18n';
import type { UserServer } from '../types';

interface SearchableServerSelectProps {
  id?: string;
  servers: UserServer[];
  value: string;
  currentUserId: string;
  onChange: (serverId: string) => void;
  disabled?: boolean;
}

export function SearchableServerSelect({
  id,
  servers,
  value,
  currentUserId,
  onChange,
  disabled = false,
}: SearchableServerSelectProps) {
  const { tr } = useI18n();
  const listboxId = useId();
  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [highlightedIndex, setHighlightedIndex] = useState(0);

  const selectedServer = useMemo(
    () => servers.find((s) => s.id === value) ?? null,
    [servers, value]
  );

  const formatServerSummary = (srv: UserServer): string => {
    const sharedSuffix = srv.userId !== currentUserId ? tr(' · Geteilt', ' · Shared') : '';
    return `${srv.label} — ${srv.ipAddress}:${srv.port}${sharedSuffix}`;
  };

  const filteredServers = useMemo(() => {
    const raw = query.trim().toLowerCase();
    if (!raw) return servers;
    const tokens = raw.split(/\s+/).filter(Boolean);
    return servers.filter((srv) => {
      const sharedTags = srv.userId !== currentUserId ? 'geteilt shared' : '';
      const categoryText = Array.isArray(srv.categories) ? srv.categories.join(' ') : '';
      const haystack = [
        srv.label,
        srv.ipAddress,
        `${srv.ipAddress}:${srv.port}`,
        String(srv.port),
        srv.sshUser,
        srv.bmcIpAddress,
        srv.bmcIpAddress2,
        categoryText,
        srv.notes,
        srv.ownerUsername,
        sharedTags,
      ]
        .join(' ')
        .toLowerCase();
      return tokens.every((tok) => haystack.includes(tok));
    });
  }, [servers, query, currentUserId]);

  useEffect(() => {
    if (disabled && open) {
      setOpen(false);
    }
  }, [disabled, open]);

  useEffect(() => {
    if (!open) return;
    const handlePointerDown = (event: MouseEvent | TouchEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false);
        triggerRef.current?.focus();
      }
    };
    document.addEventListener('mousedown', handlePointerDown);
    document.addEventListener('touchstart', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handlePointerDown);
      document.removeEventListener('touchstart', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [open]);

  useEffect(() => {
    if (open) {
      const idx = filteredServers.findIndex((s) => s.id === value);
      setHighlightedIndex(idx >= 0 ? idx : 0);
      const timer = window.setTimeout(() => {
        searchInputRef.current?.focus();
      }, 10);
      return () => window.clearTimeout(timer);
    }
    setQuery('');
  }, [open]);

  useEffect(() => {
    setHighlightedIndex(0);
  }, [query]);

  useEffect(() => {
    if (!open || !listRef.current) return;
    const item = listRef.current.querySelector<HTMLElement>(
      `[data-srv-index="${highlightedIndex}"]`
    );
    item?.scrollIntoView({ block: 'nearest' });
  }, [highlightedIndex, open]);

  function handleSelect(serverId: string) {
    onChange(serverId);
    setOpen(false);
    setQuery('');
    triggerRef.current?.focus();
  }

  function handleSearchKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (filteredServers.length > 0) {
        setHighlightedIndex((prev) => (prev + 1) % filteredServers.length);
      }
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (filteredServers.length > 0) {
        setHighlightedIndex((prev) => (prev - 1 + filteredServers.length) % filteredServers.length);
      }
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const target = filteredServers[highlightedIndex];
      if (target) {
        handleSelect(target.id);
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      setOpen(false);
      triggerRef.current?.focus();
    }
  }

  const isDisabled = disabled || servers.length === 0;

  return (
    <div ref={containerRef} className="relative">
      <button
        ref={triggerRef}
        id={id}
        type="button"
        disabled={isDisabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listboxId : undefined}
        onClick={() => {
          if (!isDisabled) setOpen((prev) => !prev);
        }}
        className="w-full min-h-[38px] px-3 py-2 text-sm text-left bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:bg-slate-50 dark:disabled:bg-slate-800/50 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer flex items-center justify-between gap-2"
      >
        <span className="truncate">
          {selectedServer
            ? formatServerSummary(selectedServer)
            : tr('Kein gespeicherter Server verfügbar', 'No saved server available')}
        </span>
        <ChevronDown
          className={`w-4 h-4 text-slate-400 shrink-0 transition-transform duration-150 ${
            open ? 'rotate-180' : ''
          }`}
          aria-hidden="true"
        />
      </button>

      {open && (
        <div className="absolute left-0 right-0 mt-1.5 z-40 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 shadow-xl overflow-hidden">
          {/* Free-text Filter Input */}
          <div className="p-2 border-b border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60">
            <div className="relative flex items-center">
              <Search
                className="w-4 h-4 text-slate-400 absolute left-2.5 pointer-events-none"
                aria-hidden="true"
              />
              <input
                ref={searchInputRef}
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={handleSearchKeyDown}
                placeholder={tr(
                  'Server, IP, Benutzer oder Kategorie filtern...',
                  'Filter server, IP, user, or category...'
                )}
                aria-label={tr('Ziel-Server filtern', 'Filter target servers')}
                autoComplete="off"
                spellCheck={false}
                className="w-full pl-8 pr-16 py-1.5 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
              <div className="absolute right-2 flex items-center gap-1">
                {query.trim().length > 0 && (
                  <>
                    <span className="text-[11px] font-mono tabular-nums text-slate-400">
                      {filteredServers.length}/{servers.length}
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        setQuery('');
                        searchInputRef.current?.focus();
                      }}
                      aria-label={tr('Filter leeren', 'Clear filter')}
                      className="p-1 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 rounded cursor-pointer"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Filtered Server List */}
          <div
            ref={listRef}
            id={listboxId}
            role="listbox"
            aria-label={tr('Ziel-Server (IP)', 'Target Server (IP)')}
            className="max-h-72 overflow-y-auto py-1 divide-y divide-slate-100 dark:divide-slate-800/70"
          >
            {filteredServers.length === 0 ? (
              <div className="px-4 py-6 text-center space-y-2">
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {tr(
                    `Keine Server für „${query.trim()}“ gefunden.`,
                    `No servers found for "${query.trim()}".`
                  )}
                </p>
                <button
                  type="button"
                  onClick={() => {
                    setQuery('');
                    searchInputRef.current?.focus();
                  }}
                  className="text-xs font-medium text-blue-700 dark:text-blue-400 hover:underline cursor-pointer"
                >
                  {tr('Filter zurücksetzen', 'Reset filter')}
                </button>
              </div>
            ) : (
              filteredServers.map((srv, idx) => {
                const isSelected = srv.id === value;
                const isHighlighted = idx === highlightedIndex;
                const categories = Array.isArray(srv.categories)
                  ? srv.categories.filter((c) => c.trim().length > 0)
                  : [];
                const endpoint = srv.sshUser
                  ? `${srv.sshUser}@${srv.ipAddress}:${srv.port}`
                  : `${srv.ipAddress}:${srv.port}`;
                const notesPreview = srv.notes?.trim() ?? '';

                return (
                  <button
                    key={srv.id}
                    type="button"
                    role="option"
                    aria-selected={isSelected}
                    data-srv-index={idx}
                    onMouseEnter={() => setHighlightedIndex(idx)}
                    onClick={() => handleSelect(srv.id)}
                    className={`w-full px-3 py-2.5 min-h-[44px] text-left flex items-start justify-between gap-2 transition-colors cursor-pointer ${
                      isHighlighted
                        ? 'bg-blue-50 dark:bg-blue-950/50'
                        : isSelected
                          ? 'bg-slate-50 dark:bg-slate-800/50'
                          : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="min-w-0 flex-1 space-y-0.5">
                      <div className="flex items-center gap-1.5 text-sm font-medium text-slate-900 dark:text-slate-100">
                        <span className="truncate">{srv.label}</span>
                      </div>
                      <div className="flex items-center flex-wrap gap-x-1.5 gap-y-0.5 text-xs text-slate-500 dark:text-slate-400">
                        <span className="font-mono text-slate-600 dark:text-slate-300">
                          {endpoint}
                        </span>
                        {categories.length > 0 && (
                          <>
                            <span aria-hidden="true">·</span>
                            <span className="truncate">{categories.join(', ')}</span>
                          </>
                        )}
                        {srv.userId !== currentUserId && (
                          <>
                            <span aria-hidden="true">·</span>
                            <span>{tr('Geteilt', 'Shared')}</span>
                          </>
                        )}
                      </div>
                      {notesPreview && (
                        <p className="text-[11px] text-slate-400 dark:text-slate-500 truncate">
                          {notesPreview}
                        </p>
                      )}
                    </div>
                    {isSelected && (
                      <Check
                        className="w-4 h-4 text-blue-700 dark:text-blue-400 shrink-0 mt-0.5"
                        aria-hidden="true"
                      />
                    )}
                  </button>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
