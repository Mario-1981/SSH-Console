# Komplexe SSH-Befehlsketten (JSON-Workflows)

Dieser Ordner enthält vorgefertigte **JSON-Workflows** für den Befehlstyp **Komplexe Kette (JSON)** in **SSH Console**.

## Enthaltene Workflows

| Datei | Beschreibung | Empfohlener Timeout |
|---|---|---|
| [`dell-idrac-reset.json`](./dell-idrac-reset.json) | Vollständiger Dell-iDRAC-Werksreset (`racadm racresetcfg -all`), automatisches Reset-Polling auf `dedicated` (bis zu 5 Minuten im 10-Sekunden-Takt), anschließende NIC-Auswahl (`LOM1` / `LOM3` / `dedicated`), DHCP-Aktivierung (`racadm setniccfg -d`) und Setzen des Benutzerpassworts (`idrac.users.2.password`). | `600` Sekunden |

## Verwendung in SSH Console

1. Öffnen Sie in der Web-Oberfläche **SSH-Befehle → Komplexe Kette (JSON)**.
2. Kopieren Sie den Inhalt der gewünschten `.json`-Datei (z. B. `workflows/dell-idrac-reset.json`) in das JSON-Editorfeld.
3. Passen Sie im Abschnitt `"vars"` die Parameter an:
   - `nicSelection`: `"LOM1"`, `"LOM3"` oder `"dedicated"`
   - `idracPassword`: gewünschtes iDRAC-Benutzerpasswort (aus Sicherheitsgründen steht im Repository nur ein Platzhalter; der Workflow bricht automatisch ab, solange der Platzhalter nicht ersetzt wurde).
4. Setzen Sie den **Befehls-Timeout** auf mindestens **`600` Sekunden** (20 s initiales Warten + bis zu 300 s Reset-Polling + 60 s Stabilisierung + Folgeschritte).
5. *(Optional)* Da sich nach einem iDRAC-Reset der SSH-Host-Key ändern kann, aktivieren Sie für das Ziel-iDRAC bei Bedarf **Host-Key-Prüfung deaktivieren** (sofern vom Administrator erlaubt) oder setzen Sie den gespeicherten Host-Key anschließend über **Key löschen** zurück.
6. Speichern Sie den Befehl und führen Sie ihn einzeln oder per Sammelausführung über das Dashboard aus.
