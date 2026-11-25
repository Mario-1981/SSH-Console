export interface PasswordComplexityResult {
  valid: boolean;
  hasMinLength: boolean;
  hasUppercase: boolean;
  hasLowercase: boolean;
  hasDigit: boolean;
  hasSpecial: boolean;
  categoriesMet: number;
  error?: string;
}

export function evaluatePasswordComplexity(password: string): PasswordComplexityResult {
  const chars = Array.from(password);
  const hasMinLength = chars.length >= 8;
  const hasUppercase = /\p{Lu}/u.test(password);
  const hasLowercase = /\p{Ll}/u.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSpecial = /[^\p{L}\p{N}]/u.test(password);
  const categoriesMet =
    Number(hasUppercase) + Number(hasLowercase) + Number(hasDigit) + Number(hasSpecial);
  const valid = hasMinLength && categoriesMet >= 3;

  let error: string | undefined;
  if (!valid) {
    if (!hasMinLength) {
      error =
        'Das Passwort muss mindestens 8 Zeichen lang sein und mindestens 3 der 4 Zeichenarten enthalten (Großbuchstaben, Kleinbuchstaben, Zahlen, Sonderzeichen).';
    } else {
      error = `Passwort zu schwach (${categoriesMet} von 4 Zeichenarten erfüllt): Es müssen mindestens 3 der 4 Zeichenarten enthalten sein (Großbuchstaben, Kleinbuchstaben, Zahlen, Sonderzeichen).`;
    }
  }

  return {
    valid,
    hasMinLength,
    hasUppercase,
    hasLowercase,
    hasDigit,
    hasSpecial,
    categoriesMet,
    error,
  };
}

export function validatePasswordComplexity(password: unknown): string | null {
  if (typeof password !== 'string') {
    return 'Das Passwort muss mindestens 8 Zeichen lang sein und mindestens 3 der 4 Zeichenarten enthalten (Großbuchstaben, Kleinbuchstaben, Zahlen, Sonderzeichen).';
  }
  const result = evaluatePasswordComplexity(password);
  return result.valid ? null : result.error ?? 'Das Passwort erfüllt nicht die Komplexitätsanforderungen.';
}
