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

### Befehlsketten (einfach)
- Verketten Sie mehrere aufeinanderfolgende Schritte innerhalb **einer einzigen SSH-Sitzung** (ideal für lineare Wartungsabläufe wie Dienst stoppen, warten, neu starten und Status prüfen).
- Nach jedem Schritt lässt sich eine optionale **Wartezeit (`sleep` in Sekunden)** festlegen.
- Wählbares Fehlerverhalten:
  - **Bei Fehler stoppen (`&&`)**: Bricht die Kette sofort ab, sobald ein Schritt einen Exit-Code ungleich `0` liefert.
  - **Trotz Fehler fortfahren (`;`)**: Führt alle Schritte unabhängig von einzelnen Exit-Codes aus.

### Komplexe Befehlsketten (JSON-Workflows)
Für verzweigte Abläufe mit **Wenn-Dann-Sonst-Logik**, **Ausgabefiltern** und **formatierter Ausgabe** steht der Befehlstyp **Komplexe Kette (JSON)** zur Verfügung:

- **Schritttypen (`steps`)**:
  - `run`: Führt einen SSH-Befehl aus (`id`, `command`, `continueOnError`, `sleepAfterSec`, `silent`, optionaler `filter`).
  - `sleep`: Pausiert die Ausführung um `seconds` (`0–600`).
  - `if`: Wertet Bedingungen (`when` mit `all` / `any` / `not` sowie Operatoren wie `equals`, `notEquals`, `contains`, `matches`, `isEmpty`, `gt`, `gte`, `lt`, `lte` auf `stdout`, `stderr`, `exitCode`, `ok`, `linesCount` oder Variablen) aus und verzweigt in `then` und optional `else` (verschachtelbar).
  - `set` & `log`: Setzt Variablen (optional gefiltert) bzw. schreibt eigene Logzeilen.
  - `stop` / `fail`: Beendet den Workflow vorzeitig mit eigenem Exit-Code und Meldung.
- **Ausgabe filtern (`filter`)**: Pro Schritt oder für die Gesamtausgabe lassen sich Ausgaben mit `trim`, `dropEmpty`, `include`, `exclude`, `regex` / `regexGroup` / `regexAll`, `replace`, `columns` + `delimiter`, `sort`, `unique`, `head`, `tail`, `prefix`, `suffix` und `joinWith` bereinigen.
- **Ausgabe formatieren (`output`)**:
  - `template` / `text`: Frei gestaltete Textvorlage mit Platzhaltern.
  - `table`: Sauber ausgerichtete ASCII-Tabelle aus `rows`, `fields` oder `source` + `columns`.
  - `json`: Strukturierte JSON-Ausgabe (`fields` + `autoType`).
  - `lines`: Gefilterte Zeilenliste.
- **Platzhalter & Vorlagen**: Über {% raw %}`{{stepId.stdout}}`, `{{stepId.exitCode}}`, `{{last.stdout}}`, `{{vars.name}}`, `{{target.ip}}` und `{{target.label}}`{% endraw %} stehen Ergebnisse aller Schritte in Befehlen, Variablen und Ausgabeformaten bereit. Im Editor sind direkte **Starter-Vorlagen**, **Live-Validierung**, **JSON-Formatierung** und eine **Ablaufvorschau** integriert.

{% raw %}
```json
{
  "stopOnError": true,
  "vars": { "service": "nginx" },
  "steps": [
    {
      "type": "run",
      "id": "check",
      "command": "systemctl is-active {{vars.service}}",
      "continueOnError": true,
      "filter": { "trim": true }
    },
    {
      "type": "if",
      "when": { "from": "check", "field": "stdout", "op": "notEquals", "value": "active" },
      "then": [
        { "type": "run", "id": "restart", "command": "systemctl restart {{vars.service}}" },
        { "type": "sleep", "seconds": 3 },
        { "type": "run", "id": "verify", "command": "systemctl is-active {{vars.service}}", "filter": { "trim": true } }
      ]
    }
  ],
  "output": {
    "format": "table",
    "headers": ["Eigenschaft", "Wert"],
    "rows": [
      { "label": "Host", "value": "{{target.label}} ({{target.ip}})" },
      { "label": "Status", "value": "{{last.stdout}}" }
    ]
  }
}
```
{% endraw %}

### Vorlagen & Admin-Freigaben
- Mit einem Klick lassen sich praxisnahe Linux-Diagnose-Vorlagen (inkl. JSON-Workflow) laden.
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
