---
title: Überblick & Architektur
lang: de
alt_url: /en/overview.html
---

# Überblick & Architektur

**SSH Console** ist eine selbstgehostete Webkonsole für Linux-Serverflotten mit **OpenSSH-Benutzerzertifikaten** oder **klassischen SSH-Schlüsselpaaren**. Sie vereint integrierte **SSH-CA-Verwaltung & automatische Neuzertifizierung**, **feingranulare Benutzergruppen**, Erreichbarkeits-Monitoring, Dual-BMC-Verwaltung, parallele Befehls- & JSON-Workflow-Ausführung mit Hintergrund-Jobs sowie ein interaktives Multi-Tab-SSH-Terminal im Browser in einer schlanken Anwendung.

---

## Funktionsumfang

- **Integrierte SSH-CA-Verwaltung, CA-Signierung & automatische Neuzertifizierung**
  - Eigenes Admin-Menü **Admin → CA-Zertifikate** zum Erzeugen, Importieren, Prüfen, Aktualisieren und Löschen von OpenSSH-User-CAs (`ca` und `ca.pub`) inklusive Download von `ca.pub` für `TrustedUserCAKeys`.
  - **Admin-Einzel- & Sammelsignierung**: Signierung einzelner oder mehrerer Benutzerzertifikate mit konfigurierbaren Principals (`-n`), Gültigkeitsdauer (`-V`), optionalem Key-ID-Präfix sowie hinterlegtem oder einmaligem CA-Passwort.
  - **Richtliniengesteuerte Benutzer-Selbstsignierung**: Administratoren weisen Benutzergruppen gezielt eine oder mehrere CAs zu und legen pro Gruppe und CA die erlaubten Principals (`-n`), die Signatur-Gültigkeit (`-V`, Vorlagen oder benutzerdefiniert) sowie den Startzeitpunkt der automatischen Neusignierung fest. Benutzer können ihre eigenen Zertifikate einzeln oder per Sammelupdate signieren, ohne jemals Zugriff auf CA-Schlüssel oder Passwörter zu erhalten.
  - **Fremd-CA-Warnung**: Explizite Warnmeldung und Bestätigungspflicht, wenn eine bestehende `zertifikat-cert.pub`-Datei einer anderen CA überschrieben würde.
  - **Automatische Neuzertifizierung (bis auf Widerruf oder Rechteentzug)**: Automatische Hintergrund-Erneuerung vor Ablauf – einzeln oder per Sammelaktion widerrufbar und mit sofortigem automatischem Stopp bei Rechteentzug, CA-Änderung oder manuellem Zertifikatstausch.
- **OpenSSH-Zertifikate, Schlüsselerzeugung & Passphrase-Richtlinien**
  - Unterstützt 3-Dateien-OpenSSH-Zertifikatsbündel (`zertifikat`, `zertifikat.pub`, `zertifikat-cert.pub`) sowie klassische 2-Dateien-SSH-Schlüsselpaare (`zertifikat`, `zertifikat.pub`).
  - Direkte Schlüsselerzeugung im Browser mit Live-Duplikatwarnung und expliziter Überschreibbestätigung (kein stilles Überschreiben).
  - Durchsetzung von **Passwortkomplexitätsregeln** (mind. 8 Zeichen und mindestens 3 von 4 Zeichenarten) für Benutzerpasswörter, Zertifikatspassphrases und CA-Passphrases.
  - Gruppenrechte steuern Passphrase-Pflicht, erlaubte Passphrase-Speicherung (AES-256-GCM) sowie das Hochladen eigener `zertifikat-cert.pub`-Dateien.
  - **Datenschutzkonforme Admin-Zertifikatsübersicht**: Administratoren können Zertifikate aller Benutzer suchen, filtern, signieren und löschen – ohne jemals fremde private Schlüssel zu sehen oder zu bearbeiten.
  - Automatisierte `curl`-Upload- & Rotations-API (`/api/v1/certificates/...`) mit persönlichen API-Keys (`sshc_...`).
- **Benutzergruppen, Authentifizierung, SSO, 2FA & Passkeys**
  - Geschlossene Registrierung (einmalige Admin-Ersteinrichtung) plus benutzerdefinierte **Benutzergruppen** mit feingranularen Berechtigungen.
  - OIDC / OAuth 2.0 SSO mit PKCE (`S256`), Auto-Discovery und Anti-Aussperr-Verbindungstest.
  - Optionale oder verpflichtende 2FA (TOTP-Authenticator-Apps + Einmal-Wiederherstellungscodes, FIDO2/WebAuthn-Sicherheitsschlüssel) sowie passwortlose Passkeys.
  - Standardmäßig private Ressourcen (Server, Kategorien, Befehle, Zertifikate, Logs) mit gezielter Admin-Freigabe.
- **Skalierbares Ping-Dashboard (10 bis 1.000+ Hosts) & Dual-BMC**
  - Gleichmäßig über das konfigurierte Intervall gestaffeltes Auto-Ping-Pacing ohne Netzwerklast-Spitzen und adaptive Offline-Drosselung (Backoff) mit sofortigem Reset bei Erreichbarkeit.
  - Getrennte Auto-Ping-Schalter (global, pro Konto, pro IP), Mehrfach-Kategorien (`ODER`/`UND`), Volltextsuche, Seitenumbruch (`10`, `20`, `50`, `Alle`) und persistente Anzeige „Zuletzt online“.
  - Bis zu zwei BMC-/IPMI-/iDRAC-/iLO-Adressen (`BMC 1` und `BMC 2`) pro Server mit `https://`-Link und Port-`443`-Erreichbarkeitsprüfung.
- **Befehle, JSON-Workflows, Hintergrund-Jobs & Multi-Tab-SSH-Shell**
  - Einzelbefehle, lineare Befehlsketten (`sleep`, `&&` / `;`) und komplexe **JSON-Workflows** (Laufzeit-Variablen inkl. maskierter Geheimnisse, `if`/`else`, `loop`, Ausgabefilter und Tabellen-/JSON-/Vorlagen-Ausgabe).
  - Parallele Sammelausführung direkt aus dem Dashboard sowie **Hintergrund-Jobs** für länger laufende Aufträge mit Fortschrittsverfolgung.
  - Interaktive Multi-Tab-PTY-SSH-Shell (`xterm.js` über WebSockets) für gespeicherte Server oder Ad-hoc-IPs.
- **Zweisprachige Oberfläche (`DE / EN`)**
  - Sofortige Sprachumschaltung auf jeder Ansicht.

---

## Systemarchitektur

SSH Console besteht aus **einem gemeinsamen React-/TypeScript-Frontend** und **zwei funktionsgleichen Backends**:

| Komponente | Produktions-Backend (Debian 13 / Docker) | Entwicklungs-Backend (Node.js) |
| --- | --- | --- |
| **Laufzeitumgebung** | Natives Rust (`Axum` + `Tokio`) | Node.js 20+ (`Express` + `tsx`) |
| **Datenbank** | SQLite (`WAL`-Modus) unter `/var/lib/ssh-console/ssh-console.sqlite` | Lokaler JSON-Speicher unter `data/trixiessh.json` |
| **Geheimnis-Vault** | AES-256-GCM mit 256-Bit `/var/lib/ssh-console/vault.key` (`0600`) | AES-256-GCM mit `data/master.key` (`0600`) oder `TRIXIESSH_MASTER_KEY` |
| **Passwort-Hashing** | Argon2id (zufälliges Salt pro Benutzer) | `scrypt` (zufälliges Salt pro Benutzer) |
| **SSH- & CA-Engine** | Nativer OpenSSH-Client (`/usr/bin/ssh`, `ssh-keygen`) + PTY-WebSocket-Bridge | Nativer OpenSSH-Client (`ssh`, `ssh-keygen`) + PTY-WebSocket-Bridge |
| **Hintergrund-Dienste** | Staggered Ping-Monitor, Hintergrund-Jobs, Auto-Renew-Scheduler (60 s) | Staggered Ping-Monitor, Hintergrund-Jobs, Auto-Renew-Scheduler (60 s) |
| **Ping-Engine** | `/bin/ping` (ICMP) mit automatischem TCP-Connect-Fallback | `/bin/ping` (ICMP) mit automatischem TCP-Connect-Fallback |
| **Frontend** | Vorab gebautes Vite-Bundle aus `/opt/ssh-console/dist` | Vite-Dev-Middleware auf Port `3000` |

---

## Sicherheitsmodell

1. **Verschlüsselung im Ruhezustand (AES-256-GCM)**
   - Alle privaten SSH-Schlüssel, verwalteten CA-Privatschlüssel, optional hinterlegten Schlüssel- und CA-Passphrases, TOTP-Geheimnisse und das SSO-Client-Secret werden mit **AES-256-GCM** und individueller zufälliger Nonce verschlüsselt gespeichert.
   - Klartext-Privatschlüssel und Passphrases werden **niemals** an den Browser zurückgesendet.
2. **Strikte serverseitige Gruppen- & CA-Richtlinien**
   - Berechtigungen pro Benutzergruppe sowie CA-Zuweisungen (`-n` Principals, `-V` Signatur-Gültigkeit und Startzeitpunkt der automatischen Neusignierung) werden ausschließlich serverseitig durchgesetzt.
   - Bei Widerruf, Rechteentzug, CA-Änderung oder Kontodeaktivierung werden aktive automatische Neuzertifizierungen unmittelbar gestoppt.
3. **Passwort- & Passphrase-Komplexität**
   - Alle neu gesetzten Kontopasswörter, Zertifikatspassphrases und CA-Passphrases müssen mindestens **8 Zeichen** lang sein und mindestens **3 von 4 Zeichenklassen** (Kleinbuchstaben, Großbuchstaben, Ziffern, Sonderzeichen) erfüllen.
4. **Temporäre OpenSSH-Bereitstellung**
   - Für jede Befehlsausführung, CA-Signierung oder SSH-Shell-Sitzung wird ein isoliertes temporäres Verzeichnis (`0700`) erstellt, das Schlüsselmaterial mit `0600` bereitgestellt, über ein temporäres `SSH_ASKPASS`-Skript entsperrt (niemals als CLI-Parameter oder im Log) und anschließend sofort gelöscht.
5. **Keine offene Selbstregistrierung & gehashte API-Keys**
   - `/api/setup` wird dauerhaft gesperrt, sobald das erste Administratorkonto existiert.
   - Persönliche API-Keys (`sshc_...`) besitzen 256 Bit Entropie, werden nur einmal angezeigt und ausschließlich als **SHA-256**-Hash gespeichert.
6. **Datenschutz & SSH-Host-Key-Prüfung**
   - Normale Benutzer sehen ausschließlich eigene Ressourcen sowie gezielt von Admins freigegebene Einträge; Administratoren erhalten auch in der benutzerübergreifenden Zertifikatsübersicht keinen Zugriff auf fremde private Schlüssel.
   - Getrennte `known_hosts`-Dateien pro Benutzer mit `StrictHostKeyChecking=accept-new`; harmlose Erstverbindungs-Hinweise werden gefiltert, echte Schlüsseländerungen (`REMOTE HOST IDENTIFICATION HAS CHANGED`) bleiben vollständig sichtbar.

---

Weiter: **[Installation & Docker](./installation.html)**
