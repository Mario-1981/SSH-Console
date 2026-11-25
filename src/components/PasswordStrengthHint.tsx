import React from 'react';
import { Check, Circle, X } from 'lucide-react';
import { useI18n } from '../i18n';
import { evaluatePasswordComplexity } from '../passwordPolicy';

interface PasswordStrengthHintProps {
  password: string;
  compact?: boolean;
}

export function PasswordStrengthHint({ password, compact = false }: PasswordStrengthHintProps) {
  const { tr } = useI18n();
  const status = evaluatePasswordComplexity(password);
  const started = password.length > 0;

  const categories = [
    {
      key: 'upper',
      met: status.hasUppercase,
      label: tr('Großbuchstabe (A–Z)', 'Uppercase (A–Z)'),
    },
    {
      key: 'lower',
      met: status.hasLowercase,
      label: tr('Kleinbuchstabe (a–z)', 'Lowercase (a–z)'),
    },
    {
      key: 'digit',
      met: status.hasDigit,
      label: tr('Zahl (0–9)', 'Digit (0–9)'),
    },
    {
      key: 'special',
      met: status.hasSpecial,
      label: tr('Sonderzeichen (!@#…)', 'Special char (!@#…)'),
    },
  ];

  const categoriesSatisfied = status.categoriesMet >= 3;

  return (
    <div
      className={`mt-1.5 rounded-md border text-[11px] ${
        compact ? 'px-2.5 py-2 space-y-1.5' : 'px-3 py-2.5 space-y-2'
      } ${
        !started
          ? 'bg-slate-50 border-slate-200 text-slate-600'
          : status.valid
            ? 'bg-emerald-50/70 border-emerald-200 text-emerald-900'
            : 'bg-amber-50/70 border-amber-200 text-amber-950'
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
        <span className="inline-flex items-center gap-1.5 font-medium">
          {status.hasMinLength ? (
            <Check className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
          ) : started ? (
            <X className="w-3.5 h-3.5 text-amber-700 shrink-0" />
          ) : (
            <Circle className="w-3 h-3 text-slate-400 shrink-0" />
          )}
          <span
            className={
              status.hasMinLength
                ? 'text-emerald-800'
                : started
                  ? 'text-amber-900'
                  : 'text-slate-700'
            }
          >
            {tr('Mindestens 8 Zeichen (Pflicht)', 'At least 8 characters (required)')}
          </span>
        </span>
        <span
          className={`tabular-nums font-medium ${
            categoriesSatisfied
              ? 'text-emerald-800'
              : started
                ? 'text-amber-900'
                : 'text-slate-600'
          }`}
        >
          {tr(
            `Zeichenarten: ${status.categoriesMet}/4 (mind. 3)`,
            `Character types: ${status.categoriesMet}/4 (min. 3)`
          )}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-x-3 gap-y-1">
        {categories.map((cat) => (
          <div key={cat.key} className="flex items-center gap-1.5 min-w-0">
            {cat.met ? (
              <Check className="w-3 h-3 text-emerald-600 shrink-0" />
            ) : (
              <Circle className="w-2.5 h-2.5 text-slate-400 shrink-0" />
            )}
            <span
              className={`truncate ${
                cat.met ? 'text-emerald-800 font-medium' : 'text-slate-600'
              }`}
            >
              {cat.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
