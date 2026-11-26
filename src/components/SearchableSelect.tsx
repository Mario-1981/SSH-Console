import React, { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Check, ChevronDown, Search, X } from 'lucide-react';
import { useI18n } from '../i18n';

export interface SearchableSelectOption {
  value: string;
  label: string;
  triggerLabel?: string;
  meta?: string;
  detail?: string;
  group?: string;
  searchText?: string;
  disabled?: boolean;
}

export interface SearchableSelectProps {
  id?: string;
  value: string;
  options: SearchableSelectOption[];
  onChange: (value: string) => void;
  disabled?: boolean;
  placeholder?: string;
  emptyText?: string;
  searchPlaceholder?: string;
  ariaLabel?: string;
  size?: 'sm' | 'xs' | 'compact';
  mono?: boolean;
  className?: string;
  minMenuWidth?: number;
}

interface MenuCoords {
  left: number;
  width: number;
  top?: number;
  bottom?: number;
  maxListHeight: number;
}

export function SearchableSelect({
  id,
  value,
  options,
  onChange,
  disabled = false,
  placeholder,
  emptyText,
  searchPlaceholder,
  ariaLabel,
  size = 'sm',
  mono = false,
  className = 'w-full',
  minMenuWidth = 240,
}: SearchableSelectProps) {
  const { tr } = useI18n();
  const listboxId = useId();
  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [highlightedIndex, setHighlightedIndex] = useState(0);
  const [coords, setCoords] = useState<MenuCoords | null>(null);

  const selectedOption = useMemo(
    () => options.find((o) => o.value === value) ?? null,
    [options, value]
  );

  const filteredOptions = useMemo(() => {
    const raw = query.trim().toLowerCase();
    if (!raw) return options;
    const tokens = raw.split(/\s+/).filter(Boolean);
    return options.filter((opt) => {
      const haystack = [
        opt.label,
        opt.triggerLabel ?? '',
        opt.meta ?? '',
        opt.detail ?? '',
        opt.group ?? '',
        opt.searchText ?? '',
        opt.value,
      ]
        .join(' ')
        .toLowerCase();
      return tokens.every((tok) => haystack.includes(tok));
    });
  }, [options, query]);

  const updateCoords = useCallback(() => {
    const trigger = triggerRef.current;
    if (!trigger) return;
    const rect = trigger.getBoundingClientRect();
    const vw = window.visualViewport?.width ?? window.innerWidth;
    const vh = window.visualViewport?.height ?? window.innerHeight;
    const offsetTop = window.visualViewport?.offsetTop ?? 0;

    const maxWidth = Math.max(180, vw - 16);
    const width = Math.min(Math.max(rect.width, minMenuWidth), maxWidth);
    const left = Math.max(8, Math.min(rect.left, vw - width - 8));

    const visibleBottom = offsetTop + vh;
    const spaceBelow = visibleBottom - rect.bottom - 12;
    const spaceAbove = rect.top - offsetTop - 12;

    const openUpward = spaceBelow < 210 && spaceAbove > spaceBelow;
    if (openUpward) {
      const maxListHeight = Math.min(280, Math.max(110, spaceAbove - 58));
      setCoords({
        left,
        width,
        bottom: window.innerHeight - rect.top + 6,
        maxListHeight,
      });
    } else {
      const maxListHeight = Math.min(280, Math.max(110, spaceBelow - 58));
      setCoords({
        left,
        width,
        top: rect.bottom + 6,
        maxListHeight,
      });
    }
  }, [minMenuWidth]);

  useEffect(() => {
    if (disabled && open) {
      setOpen(false);
    }
  }, [disabled, open]);

  useLayoutEffect(() => {
    if (!open) {
      setCoords(null);
      return;
    }
    updateCoords();
    const handleScroll = (event: Event) => {
      if (menuRef.current && event.target instanceof Node && menuRef.current.contains(event.target)) {
        return;
      }
      updateCoords();
    };
    window.addEventListener('resize', updateCoords);
    window.addEventListener('scroll', handleScroll, true);
    window.visualViewport?.addEventListener('resize', updateCoords);
    window.visualViewport?.addEventListener('scroll', updateCoords);
    return () => {
      window.removeEventListener('resize', updateCoords);
      window.removeEventListener('scroll', handleScroll, true);
      window.visualViewport?.removeEventListener('resize', updateCoords);
      window.visualViewport?.removeEventListener('scroll', updateCoords);
    };
  }, [open, updateCoords]);

  useEffect(() => {
    if (!open) return;
    const handlePointerDown = (event: MouseEvent | TouchEvent) => {
      const target = event.target as Node;
      if (
        containerRef.current?.contains(target) ||
        menuRef.current?.contains(target)
      ) {
        return;
      }
      setOpen(false);
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
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
      const idx = filteredOptions.findIndex((o) => o.value === value && !o.disabled);
      const firstEnabled = filteredOptions.findIndex((o) => !o.disabled);
      setHighlightedIndex(idx >= 0 ? idx : firstEnabled >= 0 ? firstEnabled : 0);
      const timer = window.setTimeout(() => {
        searchInputRef.current?.focus({ preventScroll: true });
      }, 10);
      return () => window.clearTimeout(timer);
    }
    setQuery('');
  }, [open]);

  useEffect(() => {
    const firstEnabled = filteredOptions.findIndex((o) => !o.disabled);
    setHighlightedIndex(firstEnabled >= 0 ? firstEnabled : 0);
  }, [query]);

  useEffect(() => {
    if (!open || !listRef.current) return;
    const item = listRef.current.querySelector<HTMLElement>(
      `[data-opt-index="${highlightedIndex}"]`
    );
    item?.scrollIntoView({ block: 'nearest' });
  }, [highlightedIndex, open]);

  function handleSelect(optValue: string) {
    onChange(optValue);
    setOpen(false);
    setQuery('');
    triggerRef.current?.focus();
  }

  function moveHighlight(delta: number) {
    const len = filteredOptions.length;
    if (len === 0) return;
    for (let step = 1; step <= len; step++) {
      const next = (highlightedIndex + delta * step + len * 10) % len;
      if (!filteredOptions[next]?.disabled) {
        setHighlightedIndex(next);
        return;
      }
    }
  }

  function handleSearchKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      moveHighlight(1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      moveHighlight(-1);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const target = filteredOptions[highlightedIndex];
      if (target && !target.disabled) {
        handleSelect(target.value);
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      setOpen(false);
      triggerRef.current?.focus();
    }
  }

  const isDisabled = disabled || options.length === 0;

  const sizeClasses =
    size === 'compact'
      ? 'min-h-[28px] px-2 py-1 text-xs rounded'
      : size === 'xs'
        ? 'min-h-[34px] px-2.5 py-1.5 text-xs rounded-md'
        : 'min-h-[38px] px-3 py-2 text-sm rounded-md';

  const triggerText = selectedOption
    ? (selectedOption.triggerLabel ?? selectedOption.label)
    : options.length === 0
      ? (emptyText ?? tr('Keine Optionen verfügbar', 'No options available'))
      : (placeholder ?? tr('Bitte auswählen...', 'Please select...'));

  const dropdownPortal =
    open && coords && typeof document !== 'undefined'
      ? createPortal(
          <div
            ref={menuRef}
            style={{
              position: 'fixed',
              left: coords.left,
              width: coords.width,
              top: coords.top,
              bottom: coords.bottom,
            }}
            className="z-[100] rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 shadow-xl overflow-hidden"
          >
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
                  placeholder={searchPlaceholder ?? tr('Filtern...', 'Filter...')}
                  aria-label={searchPlaceholder ?? tr('Optionen filtern', 'Filter options')}
                  autoComplete="off"
                  spellCheck={false}
                  className="w-full pl-8 pr-16 py-1.5 text-sm bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
                <div className="absolute right-2 flex items-center gap-1">
                  {query.trim().length > 0 && (
                    <>
                      <span className="text-[11px] font-mono tabular-nums text-slate-400">
                        {filteredOptions.length}/{options.length}
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

            {/* Filtered Options List */}
            <div
              ref={listRef}
              id={listboxId}
              role="listbox"
              aria-label={ariaLabel}
              style={{ maxHeight: coords.maxListHeight }}
              className="overflow-y-auto py-1 divide-y divide-slate-100 dark:divide-slate-800/70"
            >
              {filteredOptions.length === 0 ? (
                <div className="px-4 py-5 text-center space-y-2">
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {tr(
                      `Keine Einträge für „${query.trim()}“ gefunden.`,
                      `No entries found for "${query.trim()}".`
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
                filteredOptions.map((opt, idx) => {
                  const isSelected = opt.value === value;
                  const isHighlighted = idx === highlightedIndex;
                  const prevGroup = idx > 0 ? filteredOptions[idx - 1]?.group : undefined;
                  const showGroupHeader = Boolean(opt.group && opt.group !== prevGroup);

                  return (
                    <React.Fragment key={`${opt.value}-${idx}`}>
                      {showGroupHeader && (
                        <div className="px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 bg-slate-50/90 dark:bg-slate-800/60 select-none">
                          {opt.group}
                        </div>
                      )}
                      <button
                        type="button"
                        role="option"
                        disabled={opt.disabled}
                        aria-selected={isSelected}
                        data-opt-index={idx}
                        onMouseEnter={() => {
                          if (!opt.disabled) setHighlightedIndex(idx);
                        }}
                        onClick={() => {
                          if (!opt.disabled) handleSelect(opt.value);
                        }}
                        className={`w-full px-3 py-2 min-h-[40px] text-left flex items-start justify-between gap-2 transition-colors ${
                          opt.disabled
                            ? 'opacity-45 cursor-not-allowed'
                            : 'cursor-pointer'
                        } ${
                          isHighlighted && !opt.disabled
                            ? 'bg-blue-50 dark:bg-blue-950/50'
                            : isSelected
                              ? 'bg-slate-50 dark:bg-slate-800/50'
                              : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                        }`}
                      >
                        <div className="min-w-0 flex-1 space-y-0.5">
                          <div
                            className={`text-sm font-medium text-slate-900 dark:text-slate-100 truncate ${
                              mono ? 'font-mono tabular-nums text-xs' : ''
                            }`}
                          >
                            {opt.label}
                          </div>
                          {opt.meta && (
                            <div className="text-xs text-slate-500 dark:text-slate-400 truncate">
                              {opt.meta}
                            </div>
                          )}
                          {opt.detail && (
                            <p className="text-[11px] font-mono text-slate-400 dark:text-slate-500 truncate">
                              {opt.detail}
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
                    </React.Fragment>
                  );
                })
              )}
            </div>
          </div>,
          document.body
        )
      : null;

  return (
    <div ref={containerRef} className={`relative ${className}`}>
      <button
        ref={triggerRef}
        id={id}
        type="button"
        disabled={isDisabled}
        aria-label={ariaLabel}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listboxId : undefined}
        onClick={() => {
          if (!isDisabled) setOpen((prev) => !prev);
        }}
        className={`w-full ${sizeClasses} ${
          mono ? 'font-mono tabular-nums' : ''
        } text-left bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600 disabled:bg-slate-50 dark:disabled:bg-slate-800/50 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer flex items-center justify-between gap-2`}
      >
        <span className="truncate">{triggerText}</span>
        <ChevronDown
          className={`w-4 h-4 text-slate-400 shrink-0 transition-transform duration-150 ${
            open ? 'rotate-180' : ''
          }`}
          aria-hidden="true"
        />
      </button>

      {dropdownPortal}
    </div>
  );
}
