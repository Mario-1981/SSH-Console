use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Argon2-Hashing fehlgeschlagen: {e}"))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub fn validate_username(username: &str) -> Result<String, String> {
    let clean = username.trim().to_lowercase();
    if clean.len() < 2 || clean.len() > 32 {
        return Err("Benutzername muss zwischen 2 und 32 Zeichen lang sein.".into());
    }
    if !clean
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        return Err("Benutzername darf nur Kleinbuchstaben, Ziffern, ., _ und - enthalten.".into());
    }
    Ok(clean)
}

pub fn validate_password_complexity(password: &str) -> Result<(), String> {
    let char_count = password.chars().count();
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    let categories_met = usize::from(has_upper)
        + usize::from(has_lower)
        + usize::from(has_digit)
        + usize::from(has_special);

    if char_count < 8 {
        return Err(
            "Das Passwort muss mindestens 8 Zeichen lang sein und mindestens 3 der 4 Zeichenarten enthalten (Großbuchstaben, Kleinbuchstaben, Zahlen, Sonderzeichen)."
                .into(),
        );
    }
    if categories_met < 3 {
        return Err(format!(
            "Passwort zu schwach ({categories_met} von 4 Zeichenarten erfüllt): Es müssen mindestens 3 der 4 Zeichenarten enthalten sein (Großbuchstaben, Kleinbuchstaben, Zahlen, Sonderzeichen)."
        ));
    }
    Ok(())
}
