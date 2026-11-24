# Komplexe SSH-Befehlsketten (JSON-Workflows)

Dieser Ordner enthält alle Beispiel- und Referenz-**JSON-Workflows** für den Befehlstyp **Komplexe Kette (JSON)** in **SSH Console**. Beispiele werden ausschließlich hier im Repository gepflegt und nicht fest im Programm hinterlegt.

## Enthaltene Beispiele

| Datei | Beschreibung | Laufzeit-Variablen (`inputs`) | Empfohlener Timeout |
|---|---|---|---|
| [`dell-idrac-reset.json`](./dell-idrac-reset.json) | Vollständiger Dell-iDRAC-Werksreset (`racadm racresetcfg -all`), automatisches Reset-Polling auf `dedicated` (bis zu 5 Minuten im 10-Sekunden-Takt), anschließende NIC-Auswahl (`LOM1` / `LOM3` / `dedicated`), DHCP-Aktivierung (`racadm setniccfg -d`) und Setzen des Benutzerpassworts (`idrac.users.2.password`). | `nicSelection` (`select`: `LOM1`, `LOM3`, `dedicated`), `idracPassword` (`password`, Pflichtfeld, im Audit-Log maskiert) | `600` Sekunden |
| [`service-heal.json`](./service-heal.json) | Prüft einen Systemd-Dienst, startet ihn bei Inaktivität mit `sleep`-Pause neu und gibt eine formatierte Status-Tabelle aus. | `service` (`text`, Standard: `nginx`) | `30` Sekunden |
| [`disk-threshold.json`](./disk-threshold.json) | Filtert lokale Dateisysteme, extrahiert die Root-Auslastung per Regex, prüft gegen einen konfigurierbaren Schwellenwert und formatiert die Ausgabe per Template. | `threshold` (`number`, Standard: `80`) | `20` Sekunden |
| [`system-json-report.json`](./system-json-report.json) | Sammelt Hostname, Kernel, Load-Average und fehlgeschlagene Systemd-Units und gibt einen strukturierten JSON-Bericht zurück. | — | `20` Sekunden |

## Verwendung in SSH Console

1. Öffnen Sie in der Web-Oberfläche **SSH-Befehle → Komplexe Kette (JSON)**.
2. Kopieren Sie den Inhalt der gewünschten `.json`-Datei aus diesem Ordner in das JSON-Editorfeld.
3. Setzen Sie den passenden **Befehls-Timeout** (z. B. `600` Sekunden für `dell-idrac-reset.json`) und speichern Sie den Befehl.
4. Wählen Sie den gespeicherten Workflow im **Dashboard** unter **Schnellauswahl & Sammelausführung** aus:
   - Eventuelle **Workflow-Variablen (`inputs`)** erscheinen automatisch als Eingabefelder vor der Ausführung.
   - Passwort-/Geheim-Variablen werden nicht gespeichert, nach dem Lauf sofort geleert und im Audit-Log durch `********` maskiert.
5. *(Optional bei iDRAC-Reset)* Da sich nach einem Werksreset der SSH-Host-Key ändern kann, aktivieren Sie für das Ziel-iDRAC bei Bedarf **Host-Key-Prüfung deaktivieren** (sofern vom Administrator erlaubt) oder setzen Sie den gespeicherten Host-Key anschließend über **Key löschen** zurück.
6. Markieren Sie ein oder mehrere Zielsysteme und starten Sie die Ausführung.
