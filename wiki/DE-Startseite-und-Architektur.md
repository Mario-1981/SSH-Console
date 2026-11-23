> [🏠 Startseite](Home) · [🇬🇧 English Version](EN-Overview-and-Architecture)

# Überblick & Architektur

**SSH Console** ist eine selbstgehostete Webkonsole für Linux-Serverflotten mit **OpenSSH-Benutzerzertifikaten** oder **klassischen SSH-Schlüsselpaaren**. Sie vereint Erreichbarkeits-Monitoring, BMC-Verwaltung, parallele Befehlsausführung und ein interaktives Multi-Tab-SSH-Terminal im Browser in einer schlanken Anwendung.

---

## Funktionsumfang

- **Skalierbares Ping-Dashboard (10 bis 1.000+ Hosts)**
  - Gleichmäßig über das konfigurierte Intervall gestaffeltes Auto-Ping-Pacing (keine Netzwerklast-Spitzen).
  - Adaptive Offline-Drosselung (Backoff), die das Prüfintervall bei dauerhaft nicht erreichbaren Hosts automatisch verlängert und bei Online-Antwort sofort wieder auf Standard zurücksetzt.
  - Getrennte Auto-Ping-Schalter (global für Admins, pro Konto und pro IP) – manuelles Prüfen bleibt jederzeit möglich.
  - Mehrfach-Kategorien mit `ODER`- / `UND`-Filter, Volltextsuche, Statusfilter und Seitenumbruch (`10`, `20`, `50`, `Alle`).
  - Persistente Anzeige „Zuletzt online“ pro IP-Adresse.
- **Dual-BMC-Verwaltung**
  - Bis zu zwei BMC-/IPMI-/iDRAC-/iLO-Adressen (`BMC 1` und `BMC 2`) pro Server mit direktem `https://`-Link und Ein-Klick-HTTPS-Port-`443`-Erreichbarkeitsprüfung.
- **Schnellauswahl & Sammelausführung (Batch)**
  - Wiederverwendbare Einzelbefehle und mehrstufige Befehlsketten (mit `sleep`-Pausen sowie Fehlerabbruch via `&&` oder Weiterlaufen via `;`) in einer gemeinsamen SSH-Sitzung.
  - Parallele Ausführung auf beliebig vielen markierten Servern direkt aus dem Dashboard – die Ergebnisse erscheinen übersichtlich direkt unter der Schnellauswahl und oberhalb der IP-Liste.
- **Interaktive Multi-Tab-SSH-Shell im Browser**
  - Mehrere parallele, interaktive PTY-SSH-Sitzungen (`xterm.js` über WebSockets) in Tabs – für gespeicherte Server oder beliebige Ad-hoc-IP-Adressen.
- **OpenSSH-Zertifikate, Schlüsselpaare & Passphrase-Schutz**
  - Unterstützt 3-Dateien-OpenSSH-Zertifikatsbündel (`zertifikat`, `zertifikat.pub`, `zertifikat-cert.pub`) sowie klassische 2-Dateien-SSH-Schlüsselpaare (`zertifikat`, `zertifikat.pub`).
  - Unterstützung für passwortgeschützte private Schlüssel: Passphrase optional verschlüsselt (AES-256-GCM) hinterlegen **oder** bei jeder Ausführung / Shell-Sitzung gezielt eingeben.
  - Kryptografische Prüfung (Schlüssel-Zertifikat-Zuordnung & Gültigkeitszeitraum) direkt beim Upload.
  - Automatisierte `curl`-Upload- & Rotations-API (`/api/v1/certificates/...`) mit persönlichen API-Keys (`sshc_...`).
- **Unternehmensreife Authentifizierung & Datenschutz**
  - Geschlossene Registrierung: Einmalige Admin-Ersteinrichtung; alle weiteren Konten werden durch Admins angelegt (oder per OIDC-SSO automatisch provisioniert).
  - OIDC / OAuth 2.0 SSO mit PKCE (`S256`), Auto-Discovery und Anti-Aussperr-Verbindungstest.
  - Optionale oder verpflichtende 2FA (TOTP-Authenticator-Apps + Einmal-Wiederherstellungscodes, FIDO2/WebAuthn-Sicherheitsschlüssel) sowie passwortlose Passkeys.
  - Standardmäßig private Ressourcen (Server, Kategorien, Befehle, Zertifikate, Logs) mit gezielter Admin-Freigabe.
- **Zweisprachige Oberfläche (`DE / EN`)**
  - Sofortige Sprachumschaltung auf jeder Ansicht.

---

## Systemarchitektur

SSH Console besteht aus **einem gemeinsamen React-/TypeScript-Frontend** und **zwei funktionsgleichen Backends**:

| Komponente | Produktions-Backend (Debian 13 / Trixie) | Entwicklungs-Backend (Node.js) |
| --- | --- | --- |
| **Laufzeitumgebung** | Natives Rust (`Axum` + `Tokio`) | Node.js 20+ (`Express` + `tsx`) |
| **Datenbank** | SQLite (`WAL`-Modus) unter `/var/lib/ssh-console/ssh-console.sqlite` | Lokaler JSON-Speicher unter `data/trixiessh.json` |
| **Geheimnis-Vault** | AES-256-GCM mit 256-Bit `/var/lib/ssh-console/vault.key` (`0600`) | AES-256-GCM mit `data/master.key` (`0600`) oder `TRIXIESSH_MASTER_KEY` |
| **Passwort-Hashing** | Argon2id (zufälliges Salt pro Benutzer) | `scrypt` (zufälliges Salt pro Benutzer) |
| **SSH-Engine** | Nativer OpenSSH-Client (`/usr/bin/ssh`) + PTY-WebSocket-Bridge | Nativer OpenSSH-Client (`ssh`) + PTY-WebSocket-Bridge |
| **Ping-Engine** | `/bin/ping` (ICMP) mit automatischem TCP-Connect-Fallback | `/bin/ping` (ICMP) mit automatischem TCP-Connect-Fallback |
| **Frontend** | Vorab gebautes Vite-Bundle aus `/opt/ssh-console/dist` | Vite-Dev-Middleware auf Port `3000` |

---

## Sicherheitsmodell

1. **Verschlüsselung im Ruhezustand (AES-256-GCM)**
   - Alle hochgeladenen privaten SSH-Schlüssel, optional hinterlegten Passphrases, TOTP-Geheimnisse und das SSO-Client-Secret werden mit **AES-256-GCM** und individueller zufälliger Nonce verschlüsselt gespeichert.
   - Klartext-Schlüssel und Passphrases werden **niemals** an den Browser zurückgesendet.
2. **Temporäre OpenSSH-Bereitstellung**
   - Für jede Befehlsausführung oder SSH-Shell-Sitzung wird ein isoliertes temporäres Verzeichnis (`0700`) erstellt, der Schlüssel mit `0600` bereitgestellt, ein verschlüsselter Schlüssel über ein temporäres `SSH_ASKPASS`-Hilfsskript entsperrt (niemals als CLI-Parameter oder im Log) und anschließend sofort sicher gelöscht.
3. **Keine offene Selbstregistrierung**
   - `/api/setup` wird dauerhaft gesperrt, sobald das erste Administratorkonto angelegt wurde.
4. **Gehashte API-Keys**
   - Persönliche API-Keys (`sshc_...`) besitzen 256 Bit kryptografische Entropie, werden nur einmal bei Erstellung angezeigt und ausschließlich als **SHA-256**-Hash gespeichert.
5. **Private Ressourcen & sichere Freigaben**
   - Normale Benutzer sehen ausschließlich eigene Server, Kategorien, Befehle, Zertifikate und Audit-Logs sowie gezielt von Admins freigegebene Einträge.
   - Das Teilen eines Zertifikats erlaubt ausschließlich dessen Verwendung – private Schlüssel und Passphrases bleiben unzugänglich.
6. **SSH-Host-Key-Prüfung**
   - Getrennte `known_hosts`-Dateien pro Benutzer mit `StrictHostKeyChecking=accept-new`.
   - Harmlose Erstverbindungs-Hinweise (`Permanently added ... to the list of known hosts`) werden automatisch ausgeblendet; echte Schlüsseländerungen (`REMOTE HOST IDENTIFICATION HAS CHANGED`) bleiben hingegen vollständig sichtbar.
