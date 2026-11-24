# Komplexe SSH-Befehlsketten (JSON-Workflows)

Dieser Ordner enthält vorgefertigte **JSON-Workflows** für den Befehlstyp **Komplexe Kette (JSON)** in **SSH Console**.

## Enthaltene Workflows

| Datei | Beschreibung | Laufzeit-Variablen (`inputs`) | Empfohlener Timeout |
|---|---|---|---|
| [`dell-idrac-reset.json`](./dell-idrac-reset.json) | Vollständiger Dell-iDRAC-Werksreset (`racadm racresetcfg -all`), automatisches Reset-Polling auf `dedicated` (bis zu 5 Minuten im 10-Sekunden-Takt), anschließende NIC-Auswahl (`LOM1` / `LOM3` / `dedicated`), DHCP-Aktivierung (`racadm setniccfg -d`) und Setzen des Benutzerpassworts (`idrac.users.2.password`). | `nicSelection` (`select`: `LOM1`, `LOM3`, `dedicated`), `idracPassword` (`password`, Pflichtfeld, im Audit-Log maskiert) | `600` Sekunden |

## Verwendung in SSH Console

1. Öffnen Sie in der Web-Oberfläche **SSH-Befehle → Komplexe Kette (JSON)**.
2. Kopieren Sie den Inhalt der gewünschten `.json`-Datei (z. B. `workflows/dell-idrac-reset.json`) in das JSON-Editorfeld – oder wählen Sie dort direkt die integrierte Vorlage **Dell iDRAC Werksreset (Loop + Variablen)**.
3. Setzen Sie den **Befehls-Timeout** auf mindestens **`600` Sekunden** (20 s initiales Warten + bis zu 300 s Reset-Polling + 60 s Stabilisierung + Folgeschritte) und speichern Sie den Befehl.
4. Wählen Sie den gespeicherten Workflow im **Dashboard** unter **Schnellauswahl & Sammelausführung** aus:
   - Die definierten **Workflow-Variablen (`inputs`)** erscheinen automatisch als Eingabefelder:
     - **Netzwerkkartenoption (`nicSelection`)** als Auswahlmenü (`LOM1`, `LOM3`, `dedicated`)
     - **Neues iDRAC-Passwort (`idracPassword`)** als Passwortfeld (wird nicht gespeichert, nach dem Lauf sofort geleert und im Audit-Log durch `********` maskiert).
5. *(Optional)* Da sich nach einem iDRAC-Reset der SSH-Host-Key ändern kann, aktivieren Sie für das Ziel-iDRAC bei Bedarf **Host-Key-Prüfung deaktivieren** (sofern vom Administrator erlaubt) oder setzen Sie den gespeicherten Host-Key anschließend über **Key löschen** zurück.
6. Markieren Sie ein oder mehrere Ziel-iDRACs und starten Sie die Ausführung.
