---
title: Zertifikate, Passphrases & API
lang: de
alt_url: /en/certificates-api.html
---

# Zertifikate, Passphrases & `curl`-Upload-API

SSH Console unterstützt sowohl **CA-signierte OpenSSH-Benutzerzertifikate** (3-Dateien-Modell) als auch **klassische SSH-Schlüsselpaare** (2-Dateien-Modell) – inklusive **passwortgeschützter privater Schlüssel** und automatisierter Rotation über `curl`.

---

## Unterstützte Schlüssel- & Zertifikatsformate

| Modus | Dateien | Konfiguration auf dem Zielserver |
| --- | --- | --- |
| **3-Dateien-OpenSSH-Zertifikat** | `zertifikat` (Privater Schlüssel) + `zertifikat.pub` (Öffentlicher Schlüssel) + `zertifikat-cert.pub` (CA-signiertes Zertifikat) | `TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub` in `/etc/ssh/sshd_config` |
| **2-Dateien-SSH-Schlüsselpaar** | `zertifikat` (Privater Schlüssel) + `zertifikat.pub` (Öffentlicher Schlüssel) | Öffentlicher Schlüssel in `~/.ssh/authorized_keys` |

Bei jedem Upload oder Update prüft SSH Console automatisch:
- Format des privaten Schlüssels (`openssh-v1`, PEM RSA/EC/PKCS#8) und ob eine Passphrase-Verschlüsselung vorliegt
- Kryptografische Übereinstimmung zwischen `zertifikat.pub` und `zertifikat-cert.pub`
- Zertifikats-Key-ID, Seriennummer, Principals, Extensions, CA-Fingerabdruck und Gültigkeitszeitraum (`validAfter` / `validBefore` inkl. Ablaufwarnung)

### OpenSSH-User-CA auf Zielservern einrichten

1. Einmalig einen User-CA-Schlüssel auf einem sicheren CA-Host erzeugen:
   ```bash
   ssh-keygen -t ed25519 -f ssh_user_ca -C "SSH Console User CA"
   ```
2. `ssh_user_ca.pub` auf alle Linux-Zielserver kopieren und in `/etc/ssh/sshd_config` eintragen:
   ```text
   TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub
   ```
   OpenSSH neu laden:
   ```bash
   sudo systemctl reload ssh
   ```
3. Benutzerschlüssel erzeugen und zeitlich begrenzt signieren (z. B. 7 Tage):
   ```bash
   ssh-keygen -t ed25519 -f zertifikat -N ""
   ssh-keygen -s ssh_user_ca -I "ops-alice" -n root,deploy -V +7d zertifikat.pub
   ```

---

## Passwortgeschützte private Schlüssel (Passphrases)

Ist Ihr privater Schlüssel (`zertifikat`) mit einer Passphrase verschlüsselt, erkennt SSH Console dies automatisch und bietet **zwei Betriebsarten**:

1. **Passphrase verschlüsselt hinterlegen (Komfort / Automatisierung)**
   - Passphrase direkt beim Upload, nachträglich über **Passphrase** unter **SSH-Schlüssel & Zertifikate** oder per `curl`-API (`-F "passphrase=..."`) speichern.
   - Wird serverseitig mit **AES-256-GCM** verschlüsselt abgelegt und niemals an den Browser zurückgegeben.
   - Kann jederzeit geändert oder wieder entfernt werden (`clear_passphrase=true`).
2. **Passphrase bei jeder Nutzung eingeben (Maximale Sicherheit)**
   - Beim Upload das Passphrase-Feld leer lassen.
   - Sobald dieses Zertifikat im **Dashboard** (Schnellauswahl/Sammelausführung) oder in der **SSH-Shell** ausgewählt wird, erscheint automatisch ein Passwortfeld zum Entsperren.
   - Die Passphrase gilt ausschließlich für diese eine Ausführung bzw. Sitzung, wird über ein temporäres `SSH_ASKPASS`-Skript (`0700`/`0600`) an OpenSSH übergeben und sofort wieder gelöscht.

---

## Automatisierte `curl`-Upload- & Rotations-API

Persönliche API-Keys (`sshc_...`) lassen sich unter **Konto & Sicherheit** oder über **Upload per curl & API-Key** unter **SSH-Schlüssel & Zertifikate** erzeugen und widerrufen.

### Endpunkte

```text
GET    /api/v1/certificates
POST   /api/v1/certificates/upload
PATCH  /api/v1/certificates/<name-oder-id>
PUT    /api/v1/certificates/<name-oder-id>
```

### Authentifizierung

Übergeben Sie Ihren API-Key über einen der folgenden Header:
- `X-API-Key: sshc_<ihr-key>`
- `Authorization: Bearer sshc_<ihr-key>`

### 1. 3-Dateien-Zertifikatsbündel hochladen oder ersetzen

Existiert für den Benutzer bereits ein Bündel mit demselben `name`, wird es nach Validierung direkt aktualisiert (`HTTP 200`, `"replaced": true`); andernfalls wird ein neuer Eintrag angelegt (`HTTP 201`, `"replaced": false`).

```bash
curl -X POST "https://ssh.example.net/api/v1/certificates/upload" \
  -H "X-API-Key: sshc_IHR_API_KEY" \
  -F "name=prod-ed25519" \
  -F "private_key=@./zertifikat" \
  -F "public_key=@./zertifikat.pub" \
  -F "cert=@./zertifikat-cert.pub"
```

Optional mit gespeicherter Passphrase für einen verschlüsselten Schlüssel:

```bash
curl -X POST "https://ssh.example.net/api/v1/certificates/upload" \
  -H "X-API-Key: sshc_IHR_API_KEY" \
  -F "name=prod-ed25519" \
  -F "private_key=@./zertifikat" \
  -F "public_key=@./zertifikat.pub" \
  -F "cert=@./zertifikat-cert.pub" \
  -F "passphrase=IHRE_KEY_PASSPHRASE"
```

### 2. 2-Dateien-SSH-Schlüsselpaar hochladen (ohne CA-Zertifikat)

```bash
curl -X POST "https://ssh.example.net/api/v1/certificates/upload" \
  -H "X-API-Key: sshc_IHR_API_KEY" \
  -F "name=prod-keypair" \
  -F "private_key=@./zertifikat" \
  -F "public_key=@./zertifikat.pub"
```

### 3. Nur `zertifikat-cert.pub` rotieren (Teil-Update)

Der gespeicherte private und öffentliche Schlüssel (sowie Freigaben und hinterlegte Passphrase) bleiben unverändert – nur das signierte Zertifikat wird per `name` oder `id` ausgetauscht:

```bash
curl -X PATCH "https://ssh.example.net/api/v1/certificates/prod-ed25519" \
  -H "X-API-Key: sshc_IHR_API_KEY" \
  -F "cert=@./zertifikat-cert.pub"
```

### 4. Hinterlegte Passphrase ändern oder entfernen

```bash
# Passphrase setzen / aktualisieren
curl -X PATCH "https://ssh.example.net/api/v1/certificates/prod-ed25519" \
  -H "X-API-Key: sshc_IHR_API_KEY" \
  -F "passphrase=NEUE_PASSPHRASE"

# Hinterlegte Passphrase löschen (wieder Abfrage bei jeder Nutzung)
curl -X PATCH "https://ssh.example.net/api/v1/certificates/prod-ed25519" \
  -H "X-API-Key: sshc_IHR_API_KEY" \
  -F "clear_passphrase=true"
```

### 5. Eigene Zertifikate auflisten

```bash
curl -H "X-API-Key: sshc_IHR_API_KEY" \
  "https://ssh.example.net/api/v1/certificates"
```

### Feld-Referenz (`multipart/form-data` & `application/json`)

| Feld | Pflicht | Akzeptierte Aliase | Beschreibung |
| --- | --- | --- | --- |
| `private_key` | Bei Anlage | `privateKey`, `zertifikat`, `key` | Privater OpenSSH-/PEM-Schlüssel |
| `public_key` | Bei Anlage | `publicKey`, `zertifikat_pub`, `pub` | Passender öffentlicher Schlüssel (`.pub`) |
| `cert` | Nein | `certificate`, `cert_pub`, `zertifikat_cert` | Optionales CA-signiertes OpenSSH-Zertifikat (`-cert.pub`) |
| `name` | Nein | `label` | Bezeichnung des Bündels (Standard: Zertifikats-`keyId` oder Dateiname) |
| `passphrase` | Nein | `key_passphrase`, `keyPassphrase` | Optionale Passphrase für verschlüsselten privaten Schlüssel (AES-256-GCM) |
| `clear_passphrase` | Nein | `clearPassphrase` | Bei `PATCH`/`PUT` auf `true` setzen, um eine hinterlegte Passphrase zu entfernen |
| `remove_cert` | Nein | `removeCert` | Bei `PATCH`/`PUT` auf `true` setzen, um `cert` zu entfernen (Umwandlung in 2-Dateien-Schlüsselpaar) |

---

Weiter: **[Fehlerbehebung & FAQ](./fehlerbehebung.html)**
