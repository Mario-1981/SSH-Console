export interface PasswordComplexityResult {
  valid: boolean;
  hasMinLength: boolean;
  hasUppercase: boolean;
  hasLowercase: boolean;
  hasDigit: boolean;
  hasSpecial: boolean;
  categoriesMet: number;
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

  return {
    valid,
    hasMinLength,
    hasUppercase,
    hasLowercase,
    hasDigit,
    hasSpecial,
    categoriesMet,
  };
}

export function getPasswordComplexityError(
  password: string,
  tr: (de: string, en: string) => string
): string | null {
  const res = evaluatePasswordComplexity(password);
  if (res.valid) return null;
  if (!res.hasMinLength) {
    return tr(
      'Das Passwort muss mindestens 8 Zeichen lang sein und mindestens 3 der 4 Zeichenarten enthalten (Großbuchstaben, Kleinbuchstaben, Zahlen, Sonderzeichen).',
      'The password must be at least 8 characters long and include at least 3 of the 4 character types (uppercase, lowercase, digits, special characters).'
    );
  }
  return tr(
    `Passwort zu schwach (${res.categoriesMet} von 4 Zeichenarten erfüllt): Es müssen mindestens 3 der 4 Zeichenarten enthalten sein (Großbuchstaben, Kleinbuchstaben, Zahlen, Sonderzeichen).`,
    `Password too weak (${res.categoriesMet} of 4 character types met): At least 3 of the 4 character types are required (uppercase, lowercase, digits, special characters).`
  );
}
