---
title: Authentifizierung, SSO, 2FA & Passkeys
lang: de
alt_url: /en/authentication.html
---

# Authentifizierung, SSO, 2FA & Passkeys

SSH Console ist für interne Infrastruktur- und Betriebsteams konzipiert: Es gibt **keine öffentliche Selbstregistrierung**, und Administratoren können lokale Passwörter flexibel mit **OIDC/OAuth-2.0-SSO**, **Zwei-Faktor-Authentifizierung (TOTP & FIDO2)** und **Passkeys** kombinieren.

---

## Ersteinrichtung & Benutzerverwaltung

1. **Einmalige Admin-Ersteinrichtung**: Beim ersten Aufruf erscheint der Einrichtungsassistent für Instanznamen und erstes `admin`-Konto. Direkt im Anschluss wird `/api/setup` dauerhaft gesperrt.
2. **Benutzerverwaltung**: Administratoren verwalten alle Konten unter **Admin → Benutzer**:
   - Lokale Benutzer mit Rolle `admin` oder `user`, Anzeigename, E-Mail und Standard-SSH-Benutzer anlegen.
   - Konten sperren/aktivieren oder löschen.
   - Bei Geräteverlust 2FA und Passkeys eines Benutzers mit einem Klick zurücksetzen (`POST /api/admin/users/:id/reset-auth`).
3. **Datenschutz & Admin-Freigaben**:
   - Alle Befehle, Server, Kategorien, Zertifikate und Ausführungs-Logs sind standardmäßig **privat** für ihren Ersteller.
   - Administratoren können eigene **Befehle**, **Server** und **Zertifikate** gezielt für **ausgewählte Benutzer** oder **alle Benutzer** freigeben.
   - Bei geteilten Zertifikaten werden niemals private Schlüssel oder gespeicherte Passphrases offengelegt – Benutzer können sie lediglich zur SSH-Ausführung bzw. Shell-Verbindung verwenden.

---

## OIDC / OAuth 2.0 Single Sign-On (SSO)

Die Einrichtung erfolgt unter **Admin → Anmeldung & SSO**. SSH Console verwendet den **Authorization Code Flow mit PKCE (`S256`)** und unterstützt jeden standardkonformen Identity Provider (Keycloak, Authentik, Microsoft Entra ID, Google Workspace, Okta, GitLab, Zitadel u. a.).

### Einrichtungsschritte

1. Unter **Öffentliche URL** die externe HTTPS-Adresse eintragen (z. B. `https://ssh.example.net`).
2. Die angezeigte **Callback-URL** (`https://ssh.example.net/api/auth/sso/callback`) kopieren und im Identity Provider als zulässige Redirect-URI hinterlegen.
3. **Issuer-URL** eintragen (z. B. `https://idp.example.net/realms/infra`) und auf **Auto-Discovery** klicken, um Authorization-, Token- und Userinfo-Endpunkte automatisch zu übernehmen (oder manuell eingeben).
4. **Client-ID**, **Client-Secret** (wird mit AES-256-GCM verschlüsselt gespeichert), **Anzeigename des Anbieters** und **Scopes** (Standard: `openid profile email`) hinterlegen.
5. Optional: **Neue Benutzer bei erstem SSO-Login automatisch anlegen** aktivieren (neue Konten erhalten immer die Standardrolle `user`, niemals `admin`).
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
