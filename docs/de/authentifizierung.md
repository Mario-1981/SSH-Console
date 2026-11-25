---
title: Authentifizierung, Gruppen, SSO & 2FA
lang: de
alt_url: /en/authentication.html
---

# Authentifizierung, Benutzergruppen, SSO & 2FA

SSH Console ist für interne Infrastruktur- und Betriebsteams konzipiert: Es gibt **keine öffentliche Selbstregistrierung**, alle neuen Passwörter unterliegen festen **Komplexitätsregeln**, und Administratoren können **Benutzergruppen mit feingranularen Rechten**, **OIDC/OAuth-2.0-SSO**, **Zwei-Faktor-Authentifizierung (TOTP & FIDO2)** und **Passkeys** flexibel kombinieren.

---

## Ersteinrichtung & Benutzerverwaltung

1. **Einmalige Admin-Ersteinrichtung**: Beim ersten Aufruf erscheint der Einrichtungsassistent für Instanznamen und erstes `admin`-Konto. Direkt im Anschluss wird `/api/setup` dauerhaft gesperrt.
2. **Benutzerverwaltung**: Administratoren verwalten alle Konten unter **Admin → Benutzer**:
   - Lokale Benutzer anlegen, einer **Benutzergruppe** zuordnen (z. B. `Administratoren`, `Standard-Benutzer` oder eigene Gruppen), Anzeigename, E-Mail und Standard-SSH-Benutzer pflegen.
   - Passwörter zurücksetzen, Konten aktivieren/deaktivieren oder löschen.
   - Bei Geräteverlust 2FA und Passkeys eines Benutzers mit einem Klick zurücksetzen (`POST /api/admin/users/:id/reset-auth`).
3. **Datenschutz & Admin-Freigaben**:
   - Alle Befehle, Server, Kategorien, Zertifikate und Ausführungs-Logs sind standardmäßig **privat** für ihren Ersteller.
   - Administratoren können eigene **Befehle**, **Server** und **Zertifikate** gezielt für **ausgewählte Benutzer** oder **alle Benutzer** freigeben.
   - Bei geteilten Zertifikaten werden niemals private Schlüssel oder gespeicherte Passphrases offengelegt – Benutzer können sie lediglich zur SSH-Ausführung bzw. Shell-Verbindung verwenden.

---

## Passwort- & Passphrase-Komplexitätsrichtlinie

Für alle neu vergebenen Passwörter – einschließlich **Ersteinrichtung**, **Benutzeranlage**, **Passwortänderung / -reset**, **Zertifikatspassphrases** (bei Erzeugung, Upload und Aktualisierung) sowie **CA-Passphrases** – gilt serverseitig und in der Oberfläche dieselbe Richtlinie:

- **Pflicht:** Mindestens **8 Zeichen** Gesamtlänge.
- **Zeichenklassen (mindestens 3 von 4 erforderlich):**
  1. Mindestens ein **Kleinbuchstabe** (`a–z`)
  2. Mindestens ein **Großbuchstabe** (`A–Z`)
  3. Mindestens eine **Ziffer** (`0–9`)
  4. Mindestens ein **Sonderzeichen** (z. B. `!@#$%^&*...`)

Während der Eingabe zeigt die Oberfläche live an, welche Kriterien bereits erfüllt sind.

---

## Benutzergruppen & feingranulare Berechtigungen

Unter **Admin → Benutzer → Benutzergruppen** verwalten Administratoren neben den Systemgruppen (**Administratoren** – unveränderlich mit Vollzugriff – und **Standard-Benutzer**) beliebig viele eigene Benutzergruppen. Über Schnellvorlagen (*Standard*, *Vollzugriff*, *Minimal-Operator*) lassen sich typische Profile mit einem Klick vorbelegen.

### Verfügbare Gruppenrechte

| Bereich | Berechtigungen |
| --- | --- |
| **Server & Verbindung** | Eigene Server (IPs) & Kategorien verwalten · Interaktive SSH-Shell nutzen · Beliebige Ad-hoc-IPs in der SSH-Shell zulassen · SSH-Befehle ausführen |
| **SSH-Befehle** | Einzelbefehle anlegen · Einfache Befehlsketten anlegen · Komplexe JSON-Workflows anlegen |
| **SSH-Schlüssel, Zertifikate & CA** | Zertifikate/Schlüssel hochladen · Eigene signierte `zertifikat-cert.pub`-Dateien hochladen · SSH-Schlüssel in der App erzeugen · **Zertifikatspasswort erzwingen** · **Speichern von Zertifikatspasswörtern erlauben** · **Eigene Zertifikate mit zugewiesener CA selbst signieren** · **Automatische Neuzertifizierung erlauben** |
| **API, Freigaben & Logs** | Persönliche API-Keys (`curl`-API) nutzen · Eigene Ressourcen freigeben · Eigene Ausführungs-Logs einsehen |

### CA-Zuweisungen pro Benutzergruppe & CA

Innerhalb jeder Nicht-Admin-Benutzergruppe lassen sich **eine oder mehrere SSH-CAs** gezielt für die Benutzer-Selbstsignierung zuweisen. Für **jede Kombination aus Gruppe und CA** legt der Administrator verbindlich fest:

1. **Erlaubte Principals (`-n`)**: Kommagetrennte Liste zulässiger SSH-Benutzernamen (z. B. `deploy, debian`) sowie optional die Checkbox **Eigenen Benutzernamen des Anwenders automatisch zu `-n` hinzufügen**.
2. **Gültigkeit der Signatur (`-V`)**: Wahl aus Schnellvorlagen (`+1h`, `+8h`, `+24h`, `+3d`, `+7d`, `+14d`, `+30d`, `+90d`, `+52w`, `forever`) oder **benutzerdefinierter OpenSSH-Dauer** (z. B. `+12h`, `+45d`, `+2w`).
3. **Automatisch neusignieren ab (Vorlaufzeit vor Ablauf)**:
   - **Automatisch (ab 20 % vor Ablauf)** – passt sich dynamisch an die jeweilige Laufzeit an.
   - **Feste Vorlaufzeiten** (`15 Min.` bis `30 Tage` vor Ablauf) oder **benutzerdefinierte Minuten, Stunden oder Tage**.
   - Die Vorlaufzeit wird serverseitig gegen die Signatur-Gültigkeit geprüft (muss stets kürzer als `-V` sein; bei `forever` ist automatische Neusignierung deaktiviert).

> **Verbindliche Richtlinie:** Benutzer können weder `-n`, noch `-V`, noch den Startzeitpunkt der automatischen Neusignierung eigenständig ändern. Ändert ein Administrator später Gruppenrechte oder CA-Parameter, werden bestehende automatische Benutzer-Neuzertifizierungen **sofort angepasst** bzw. bei Rechteentzug (oder Umstellung auf `forever`) **unmittelbar widerrufen**.

---

## OIDC / OAuth 2.0 Single Sign-On (SSO)

Die Einrichtung erfolgt unter **Admin → Anmeldung & SSO**. SSH Console verwendet den **Authorization Code Flow mit PKCE (`S256`)** und unterstützt jeden standardkonformen Identity Provider (Keycloak, Authentik, Microsoft Entra ID, Google Workspace, Okta, GitLab, Zitadel u. a.).

### Einrichtungsschritte

1. Unter **Öffentliche URL** die externe HTTPS-Adresse eintragen (z. B. `https://ssh.example.net`).
2. Die angezeigte **Callback-URL** (`https://ssh.example.net/api/auth/sso/callback`) kopieren und im Identity Provider als zulässige Redirect-URI hinterlegen.
3. **Issuer-URL** eintragen (z. B. `https://idp.example.net/realms/infra`) und auf **Auto-Discovery** klicken, um Authorization-, Token- und Userinfo-Endpunkte automatisch zu übernehmen (oder manuell eingeben).
4. **Client-ID**, **Client-Secret** (wird mit AES-256-GCM verschlüsselt gespeichert), **Anzeigename des Anbieters** und **Scopes** (Standard: `openid profile email`) hinterlegen.
5. Optional: **Neue Benutzer bei erstem SSO-Login automatisch anlegen** aktivieren (neue Konten erhalten immer die Standardgruppe `Standard-Benutzer`, niemals `admin`).
6. Speichern und **SSO-Verbindung testen** ausführen, um einen echten Anmeldedurchlauf zu verifizieren.

### Aussperrschutz (Anti-Lockout)

Die Option **Lokale Anmeldung mit Benutzername/Passwort deaktivieren** lässt sich erst aktivieren, *nachdem* ein erfolgreicher SSO-Verbindungstest protokolliert wurde (`ssoTestedAt`). So können sich Administratoren nicht versehentlich durch eine fehlerhafte IdP-Konfiguration aussperren.

---

## Zwei-Faktor-Authentifizierung (2FA)

Unter **Admin → Anmeldung & SSO** können Administratoren:
- **2FA aktivieren**: Benutzer können ihren lokalen Login freiwillig mit 2FA absichern.
- **2FA erzwingen**: Alle Benutzer mit lokalem Login müssen 2FA direkt nach dem Anmelden einrichten, bevor Zugriff auf Dashboard, SSH-Shell, Server, Befehle oder Zertifikate gewährt wird.

### Unterstützte zweite Faktoren

Benutzer verwalten ihre Faktoren selbst unter **Konto & Sicherheit**:
1. **Authenticator-App (TOTP)**
   - Standardisierte 6-stellige RFC-6238-Codes (z. B. Google Authenticator, Bitwarden, 1Password, KeePassXC, Aegis) per QR-Code oder manuellem Schlüssel.
   - Erzeugt bei Aktivierung **Einmal-Wiederherstellungscodes** (gehasht gespeichert; jeder Code ist einmalig nutzbar).
2. **Hardware-Sicherheitsschlüssel (FIDO2 / WebAuthn)**
   - Ein oder mehrere USB-/NFC-Sicherheitsschlüssel (z. B. YubiKey, SoloKey, Nitrokey).

---

## Passwortlose Passkeys (WebAuthn)

Administratoren können Passkeys unabhängig **aktivieren** und optional **erzwingen**:
- Benutzer registrieren unter **Konto & Sicherheit** discoverable WebAuthn-Zugangsdaten (Touch ID, Windows Hello, Android-/iOS-Passkeys, Passwortmanager-Passkeys oder residente FIDO2-Keys).
- Auf der Anmeldeseite genügt ein Klick auf **Mit Passkey anmelden** – ganz ohne Passwort.
- Mehrere Passkeys pro Konto können benannt, anhand des letzten Nutzungszeitpunkts geprüft und einzeln widerrufen werden.

> **Voraussetzung:** WebAuthn (Sicherheitsschlüssel & Passkeys) erfordert einen sicheren Kontext (`https://` mit gültigem Zertifikat oder `http://localhost` bei lokaler Entwicklung). Hinter einem Reverse-Proxy muss unter **Admin → Anmeldung & SSO** die passende **Öffentliche URL** gesetzt sein.

---

Weiter: **[Dashboard, Auto-Ping & BMC](./dashboard-ping-bmc.html)**
