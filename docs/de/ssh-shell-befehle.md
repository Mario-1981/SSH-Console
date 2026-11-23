---
title: SSH-Shell, Befehle & Host-Keys
lang: de
alt_url: /en/ssh-shell-commands.html
---

# SSH-Shell, Befehle & Host-Keys

SSH Console kombiniert ein **interaktives Multi-Tab-SSH-Terminal im Browser** mit einem **strukturierten Katalog aus Einzelbefehlen und Befehlsketten** – inklusive vollständigem Audit-Log und sauberer OpenSSH-Host-Key-Prüfung.

---

## Interaktive Multi-Tab-SSH-Shell im Browser

Über den Tab **SSH-Shell** öffnen Sie interaktive OpenSSH-PTY-Terminals direkt im Browser (`xterm.js` über WebSockets):

- **Mehrere parallele Tabs**: Mit **`+ Neuer Tab`** öffnen Sie beliebig viele SSH-Verbindungen gleichzeitig (z. B. um Logs auf mehreren Hosts parallel zu beobachten).
- **Schnelles Wechseln & Statusanzeige**: Jeder Tab zeigt Serverbezeichnung/IP und aktuellen Verbindungsstatus (verbunden, verbindend, getrennt) und kann unabhängig neu verbunden oder geschlossen werden.
- **Gespeicherte Server oder Ad-hoc-IP**: Wählen Sie einen hinterlegten Server (IP, Port, SSH-Benutzer und Host-Key-Option werden automatisch übernommen) oder geben Sie frei eine beliebige IP/Port/Benutzer-Kombination ein.
- **Passphrase-Unterstützung**: Bei passwortgeschützten Schlüsseln ohne hinterlegte Passphrase kann das Passwort direkt in der Verbindungsleiste des jeweiligen Tabs zum Entsperren eingegeben werden (wird nicht gespeichert).
- **Dynamische Fenstergröße**: Änderungen der Browsergröße werden automatisch an das Remote-PTY (`SIGWINCH`) weitergegeben.

---

## SSH-Befehle & mehrstufige Befehlsketten

Die Verwaltung erfolgt unter **SSH-Befehle**:

### Einzelbefehle
- Hinterlegen Sie häufig genutzte Shell-Befehle (z. B. `systemctl status nginx --no-pager`, `df -h`, `uptime`) samt Kategorie, Beschreibung und Timeout (`5–600 s`).

### Befehlsketten
- Verketten Sie mehrere aufeinanderfolgende Schritte innerhalb **einer einzigen SSH-Sitzung** (ideal für Wartungsabläufe wie Dienst stoppen, warten, neu starten und Status prüfen).
- Nach jedem Schritt lässt sich eine optionale **Wartezeit (`sleep` in Sekunden)** festlegen.
- Wählbares Fehlerverhalten:
  - **Bei Fehler stoppen (`&&`)**: Bricht die Kette sofort ab, sobald ein Schritt einen Exit-Code ungleich `0` liefert.
  - **Trotz Fehler fortfahren (`;`)**: Führt alle Schritte unabhängig von einzelnen Exit-Codes aus.

### Vorlagen & Admin-Freigaben
- Mit einem Klick lassen sich praxisnahe Linux-Diagnose-Vorlagen laden.
- Befehle sind privat für ihren Ersteller; Administratoren können eigene Befehle für alle oder ausgewählte Benutzer freigeben.

---

## SSH-Host-Key-Prüfung & bereinigte Ausgabe

SSH Console verwendet `StrictHostKeyChecking=accept-new` mit getrennten `known_hosts`-Dateien pro Benutzer:

- **Erstverbindung (TOFU – Trust On First Use)**: Der Host-Key des Zielservers wird beim ersten Verbindungsaufbau automatisch gespeichert.
- **Ausblenden harmloser Hinweise**: Routine-Meldungen wie
  ```text
  Warning: Permanently added '10.28.193.239' (ED25519) to the list of known hosts.
  ```
  werden in der Dashboard-Befehlsausgabe automatisch ausgeblendet, damit `stderr` bei erfolgreichen Befehlen übersichtlich bleibt.
- **Echte Schlüsseländerungen bleiben sichtbar**: Hat sich der Host-Key eines Servers tatsächlich geändert (z. B. nach Neuinstallation oder möglichem MITM-Angriff), bricht OpenSSH ab und zeigt die vollständige Warnung **`WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!`** klar im Antwortfenster an.
- **Host-Keys zurücksetzen**:
  - Nach einer legitimen Server-Neuinstallation können Benutzer den gespeicherten Host-Key unter **Meine Server (IPs)** (oder per `POST /api/host-keys/reset`) gezielt zurücksetzen.
  - Administratoren können gespeicherte Host-Keys benutzerübergreifend unter **Admin → Anmeldung & SSO → Bekannte Host-Keys** einsehen und bereinigen.
- **Optional für Labor-/Test-VMs**: Administratoren können optional pro Server das Überspringen der Host-Key-Prüfung (`StrictHostKeyChecking=no`) freischalten. Im Produktivbetrieb sollte diese Option deaktiviert bleiben.

---

## Audit-Log

Jede einzelne und gesammelte SSH-Befehlsausführung wird im **Audit-Log** protokolliert:

- Zeitstempel, ausführender Benutzer, Ziel-Server/IP/Port, SSH-Benutzername
- Befehlsname und ausgeführter Befehlstext
- Verwendetes Zertifikat / Key-ID
- OpenSSH-Aufrufparameter (Geheimnisse und Passphrases werden niemals protokolliert)
- Exit-Code, Ausführungsdauer (`ms`), vollständiges `stdout` und `stderr`

Normale Benutzer sehen ausschließlich ihre eigenen Ausführungen; Administratoren können die Logs aller Benutzer filtern und einsehen.

---

Weiter: **[Zertifikate, Passphrases & API](./zertifikate-api.html)**
