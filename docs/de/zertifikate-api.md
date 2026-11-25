---
title: Zertifikate, CA-Signierung & API
lang: de
alt_url: /en/certificates-api.html
---

# Zertifikate, CA-Signierung, Auto-Neuzertifizierung & API

SSH Console unterstützt **CA-signierte OpenSSH-Benutzerzertifikate** (3-Dateien-Modell) und **klassische SSH-Schlüsselpaare** (2-Dateien-Modell) – inklusive **Schlüsselerzeugung im Browser**, **integrierter SSH-CA-Verwaltung**, **Einzel- und Sammelsignierung**, **Benutzer-Selbstsignierung**, **automatischer Neuzertifizierung** sowie einer **`curl`-Upload- & Rotations-API**.

---

## Unterstützte Schlüssel- & Zertifikatsformate

| Modus | Dateien | Konfiguration auf dem Zielserver |
| --- | --- | --- |
| **3-Dateien-OpenSSH-Zertifikat** | `zertifikat` (Privater Schlüssel) + `zertifikat.pub` (Öffentlicher Schlüssel) + `zertifikat-cert.pub` (CA-signiertes Zertifikat) | `TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub` in `/etc/ssh/sshd_config` |
| **2-Dateien-SSH-Schlüsselpaar** | `zertifikat` (Privater Schlüssel) + `zertifikat.pub` (Öffentlicher Schlüssel) | Öffentlicher Schlüssel in `~/.ssh/authorized_keys` |

Bei jedem Upload oder Update prüft SSH Console automatisch:
- Format des privaten Schlüssels (`openssh-v1`, PEM RSA/EC/PKCS#8) und ob eine Passphrase-Verschlüsselung vorliegt
- Kryptografische Übereinstimmung zwischen `zertifikat.pub` und `zertifikat-cert.pub`
- Zertifikats-Key-ID, Seriennummer, Principals (`-n`), Extensions, CA-Fingerabdruck und Gültigkeitszeitraum (`validAfter` / `validBefore` inkl. Ablaufwarnung)

---

## Schlüsselerzeugung, Duplikatschutz & Passphrase-Richtlinien

### 1. Direkte Schlüsselerzeugung & Passwortpflicht
- Unter **SSH-Schlüssel & Zertifikate** lassen sich neue SSH-Schlüssel direkt im Browser erzeugen (sofern die Benutzergruppe das Recht besitzt).
- Beim Erzeugen wird der Benutzer nach einer **Passphrase** gefragt:
  - Ist in den Gruppenrechten **Zertifikatspasswort erzwingen** (`requireCertificatePassphrase`) aktiv, ist eine Passphrase verpflichtend; andernfalls darf das Feld für einen unverschlüsselten Schlüssel leer bleiben.
  - Jede vergebene Zertifikatspassphrase muss die **Passwortkomplexitätsregel** erfüllen (**mind. 8 Zeichen** und **mindestens 3 von 4 Zeichenklassen**: Großbuchstaben, Kleinbuchstaben, Ziffern, Sonderzeichen).
- Ob eine Passphrase verschlüsselt in SSH Console hinterlegt werden darf, steuert das Gruppenrecht **Speichern von Zertifikatspasswörtern erlauben** (`storeCertificatePassphrase`).

### 2. Schutz vor versehentlichem Überschreiben
- Bereits während der Eingabe des Zertifikatsnamens (beim Erzeugen oder Hochladen) zeigt SSH Console einen deutlichen **Live-Hinweis**, falls bereits ein Zertifikat mit demselben Namen existiert.
- Bestehende Zertifikate werden **niemals still überschrieben** – vor dem Ersetzen erscheint stets eine ausdrückliche Bestätigungsabfrage.

### 3. Hochladen eigener `zertifikat-cert.pub`-Dateien steuern
- Über das Gruppenrecht **Eigene signierte `zertifikat-cert.pub` hochladen** (`uploadSignedCert`) legen Administratoren fest, ob Benutzer selbst signierte Zertifikate hochladen dürfen oder ausschließlich durch interne CAs signieren lassen sollen.

### 4. Passwortgeschützte private Schlüssel (zwei Betriebsarten)
1. **Passphrase verschlüsselt hinterlegen** (sofern per Gruppenrecht erlaubt): Wird mit **AES-256-GCM** gespeichert, niemals an den Browser zurückgegeben und kann jederzeit geändert oder wieder entfernt werden (`clear_passphrase=true`).
2. **Passphrase bei jeder Nutzung eingeben**: Bleibt die Passphrase leer, erscheint im **Dashboard** oder in der **SSH-Shell** ein Entsperrfeld. Die Passphrase wird ausschließlich für diese eine Ausführung per temporärem `SSH_ASKPASS`-Skript (`0700`/`0600`) verwendet und sofort gelöscht.

### 5. Admin-Übersicht über Zertifikate anderer Benutzer
- Administratoren sehen unter **SSH-Schlüssel & Zertifikate** neben ihren eigenen Zertifikaten auch alle Zertifikate anderer Benutzer (mit Suche und Filter nach Benutzer, Typ, Status).
- Administratoren können fremde Zertifikate **einsehen (Metadaten), mit einer CA signieren und löschen**, erhalten aber **keinen Zugriff auf fremde private Schlüssel** und können fremde Schlüsselpakete nicht bearbeiten.

---

## Integrierte SSH-CA-Verwaltung (`Admin → CA-Zertifikate`)

Administratoren verwalten OpenSSH-Zertifizierungsstellen direkt im Menü **Administration → CA-Zertifikate**:

1. **CA erzeugen oder importieren**:
   - Neue OpenSSH-User-CA (`ca` + `ca.pub`, z. B. Ed25519/ECDSA/RSA) direkt erzeugen oder ein vorhandenes CA-Schlüsselpaar hochladen.
   - **Verpflichtendes starkes CA-Passwort**: Jede CA muss mit einem Passwort gemäß Komplexitätsrichtlinie geschützt sein.
   - **Optionales Speichern des CA-Passworts**: Wie bei SSH-Zertifikaten kann das CA-Passwort optional **AES-256-GCM-verschlüsselt** auf dem Server hinterlegt werden.
     - *Ohne gespeichertes Passwort:* Manuelle Admin-Signierung erfordert jedes Mal die Eingabe des CA-Passworts.
     - *Mit gespeichertem Passwort:* Ermöglicht **Benutzer-Selbstsignierung** und **automatische Neuzertifizierung**.
2. **`ca.pub` auf Zielservern verteilen**:
   - `ca.pub` direkt in der CA-Übersicht herunterladen oder kopieren, auf die Zielserver unter `/etc/ssh/ssh_user_ca.pub` ablegen und in `/etc/ssh/sshd_config` eintragen:
     ```text
     TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub
     ```
   - Danach OpenSSH neu laden (`sudo systemctl reload ssh`).

---

## Zertifikate mit einer CA signieren

### Admin-Signierung (Einzel- & Sammelsignierung)
- Administratoren können ein einzelnes Zertifikat oder mehrere ausgewählte Zertifikate per **Sammelsignierung** mit einer verwalteten CA unterschreiben:
  - Auswahl der **CA**, Eingabe der **Principals (`-n`)** (optional inkl. Benutzername des jeweiligen Zertifikatsbesitzers), **Gültigkeitsdauer (`-V`)** und optionalem **Key-ID-Präfix**.
  - Entsperrung über das gespeicherte CA-Passwort oder per Einmal-Eingabe.

### Benutzer-Selbstsignierung (Einzeln & Sammelupdate)
- Besitzt die Benutzergruppe das Recht **Eigene Zertifikate selbst signieren** (`selfSignCertificates`) und ist mindestens eine CA mit hinterlegtem Passwort zugewiesen, sehen Benutzer auf **SSH-Schlüssel & Zertifikate** die Aktion **Selbst signieren** bzw. **Sammelupdate**.
- Benutzer wählen lediglich eine ihrer Gruppe zugewiesene CA sowie eines oder mehrere ihrer eigenen Zertifikate aus.
- **Principals (`-n`)**, **Gültigkeitsdauer (`-V`)** und **Startzeitpunkt der automatischen Neusignierung** werden transparent angezeigt und **strikt aus der Gruppen-/CA-Konfiguration übernommen** (nicht durch den Benutzer überschreibbar).

### Fremd-CA-Warnung beim Überschreiben
- Besitzt eines oder mehrere der gewählten Zertifikate bereits eine `zertifikat-cert.pub`-Datei, die **nicht** von der aktuell gewählten CA signiert wurde, zeigt SSH Console vor dem Signieren eine deutliche **Warnmeldung** mit allen betroffenen Zertifikaten und dem Fingerabdruck bzw. Namen der bisherigen CA an.
- Das Überschreiben erfolgt erst nach expliziter Bestätigung per Checkbox (auch serverseitig per HTTP `409 Conflict` abgesichert).

---

## Automatische Neuzertifizierung (bis auf Widerruf oder Rechteentzug)

Sowohl bei der **Admin-Signierung** als auch bei der **Benutzer-Selbstsignierung** (sofern die Gruppe das Recht **Automatische Neuzertifizierung erlauben** / `autoRenewCertificates` besitzt) kann die **automatische Neuzertifizierung** aktiviert werden:

- **Voraussetzungen**:
  - Die gewählte CA besitzt ein serverseitig hinterlegtes CA-Passwort.
  - Die Gültigkeitsdauer ist endlich (nicht `forever`).
  - Für Benutzer: Die Gruppe besitzt sowohl `selfSignCertificates` als auch `autoRenewCertificates` und die CA ist der Gruppe zugewiesen.
- **Erneuerungszeitpunkt**:
  - Bei **Benutzern** gilt verbindlich der vom Administrator **pro Gruppe und pro CA** festgelegte Vorlaufzeitpunkt (z. B. *Automatisch ab 20 % vor Ablauf*, *Ab 24 Stunden vor Ablauf* oder benutzerdefinierte Minuten/Stunden/Tage).
  - Bei **Admin-Signierungen** wählt der Administrator den gewünschten Vorlaufzeitpunkt direkt im Signierungsdialog.
  - Der Hintergrund-Scheduler (sowohl im Rust- als auch im Node.js-Backend) prüft regelmäßig fällige Zertifikate, verhindert Erneuerungsschleifen und übernimmt bei benutzerinitiierten Erneuerungen stets die aktuell gültigen Gruppen-/CA-Parameter (`-n`, `-V`, Vorlaufzeit).
- **Widerruf & sofortiger Rechteentzug**:
  - Jedes Zertifikat mit aktiver automatischer Neuzertifizierung zeigt Status, CA, `-V`, Vorlaufzeit und letzten Erneuerungszeitpunkt direkt auf der Karte an und lässt sich jederzeit einzeln (**Widerrufen**) oder per Sammelaktion (**Auto-Erneuerung widerrufen**) durch den Besitzer oder einen Administrator beenden.
  - Bei **Rechteentzug** wird die automatische Neuzertifizierung **sofort** und zusätzlich vor jedem Erneuerungslauf gestoppt (mit dokumentiertem Grund), insbesondere wenn:
    - der Gruppe das Recht zur Selbstsignierung oder automatischen Neuzertifizierung entzogen wird,
    - die CA aus der Gruppe entfernt oder die Gültigkeit auf `forever` umgestellt wird,
    - die CA gelöscht oder ihr gespeichertes Passwort entfernt wird,
    - das Benutzerkonto deaktiviert/gelöscht oder die Admin-Rolle des freigebenden Admins entzogen wird,
    - das Zertifikat manuell ersetzt oder neu hochgeladen wird.

---

## Automatisierte `curl`-Upload- & Rotations-API

Persönliche API-Keys (`sshc_...`) lassen sich unter **Konto & Sicherheit** oder über **Upload per curl & API-Key** unter **SSH-Schlüssel & Zertifikate** erzeugen und widerrufen (erfordert das Gruppenrecht `useApi`).

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

Optional mit gespeicherter Passphrase für einen verschlüsselten Schlüssel (sofern per Gruppenrecht erlaubt; Komplexitätsregeln gelten):

```bash
curl -X POST "https://ssh.example.net/api/v1/certificates/upload" \
  -H "X-API-Key: sshc_IHR_API_KEY" \
  -F "name=prod-ed25519" \
  -F "private_key=@./zertifikat" \
  -F "public_key=@./zertifikat.pub" \
  -F "cert=@./zertifikat-cert.pub" \
  -F "passphrase=IHRE_STARKE_PASSPHRASE"
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

Der gespeicherte private und öffentliche Schlüssel (sowie Freigaben und hinterlegte Passphrase) bleiben unverändert – nur das signierte Zertifikat wird per `name` oder `id` ausgetauscht (erfordert das Gruppenrecht `uploadSignedCert`; eine aktive automatische Neuzertifizierung wird dabei beendet):

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
  -F "passphrase=NEUE_STARKE_PASSPHRASE"

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
| `cert` | Nein | `certificate`, `cert_pub`, `zertifikat_cert` | Optionales CA-signiertes OpenSSH-Zertifikat (`-cert.pub`, unterliegt `uploadSignedCert`) |
| `name` | Nein | `label` | Bezeichnung des Bündels (Standard: Zertifikats-`keyId` oder Dateiname) |
| `passphrase` | Nein | `key_passphrase`, `keyPassphrase` | Optionale Passphrase für verschlüsselten privaten Schlüssel (AES-256-GCM; Gruppenrechte & Komplexitätsregel beachten) |
| `clear_passphrase` | Nein | `clearPassphrase` | Bei `PATCH`/`PUT` auf `true` setzen, um eine hinterlegte Passphrase zu entfernen |
| `remove_cert` | Nein | `removeCert` | Bei `PATCH`/`PUT` auf `true` setzen, um `cert` zu entfernen (Umwandlung in 2-Dateien-Schlüsselpaar) |

---

Weiter: **[Fehlerbehebung & FAQ](./fehlerbehebung.html)**
