use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use zeroize::Zeroizing;

pub struct Vault {
    key: Zeroizing<[u8; 32]>,
}

impl Vault {
    /// Lädt den 32-Byte AES-256-GCM Master-Key aus der Umgebungsvariable
    /// `TRIXIESSH_MASTER_KEY` (Hex) oder aus `<data_dir>/master.key` (Modus 0600).
    pub fn load_or_create(data_dir: &Path) -> Result<Self, String> {
        if let Ok(hex_key) = std::env::var("TRIXIESSH_MASTER_KEY") {
            let bytes = hex::decode(hex_key.trim())
                .map_err(|e| format!("Ungültiger TRIXIESSH_MASTER_KEY (Hex erwartet): {e}"))?;
            if bytes.len() != 32 {
                return Err("TRIXIESSH_MASTER_KEY muss exakt 32 Bytes (64 Hex-Zeichen) lang sein.".into());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(Self { key: Zeroizing::new(key) });
        }

        let key_path = data_dir.join("master.key");
        if key_path.exists() {
            let content = fs::read_to_string(&key_path)
                .map_err(|e| format!("Master-Key konnte nicht gelesen werden: {e}"))?;
            let bytes = hex::decode(content.trim())
                .map_err(|e| format!("Beschädigter Master-Key: {e}"))?;
            if bytes.len() != 32 {
                return Err("master.key hat eine ungültige Länge.".into());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(Self { key: Zeroizing::new(key) });
        }

        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        fs::write(&key_path, hex::encode(key))
            .map_err(|e| format!("Master-Key konnte nicht gespeichert werden: {e}"))?;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Berechtigungen für master.key konnten nicht gesetzt werden: {e}"))?;

        Ok(Self { key: Zeroizing::new(key) })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|e| format!("AES-Initialisierungsfehler: {e}"))?;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("Verschlüsselung fehlgeschlagen: {e}"))?;
        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce_bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        if nonce_bytes.len() != 12 {
            return Err("Ungültige AES-GCM Nonce-Länge.".into());
        }
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|e| format!("AES-Initialisierungsfehler: {e}"))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Entschlüsselung des privaten SSH-Schlüssels fehlgeschlagen.".to_string())?;
        Ok(Zeroizing::new(plaintext))
    }
}
