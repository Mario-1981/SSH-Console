> [🏠 Startseite](Home) · [🇬🇧 English Version](EN-Dashboard-Ping-and-BMC)

# Dashboard, Auto-Ping & BMC-Monitoring

Das **Dashboard** bietet Live-Übersicht über alle Server-IPs, BMC-Schnittstellen und Sammelausführungen – ausgelegt für einen reibungslosen Betrieb von **10 bis über 1.000 Servern**.

---

## Skalierbare Auto-Ping-Engine

### 1. Gleichmäßige zeitliche Staffelung (Pacing ohne Lastspitzen)

Statt zu Zyklusbeginn alle Server gleichzeitig anzupingen, verteilt SSH Console die Prüfungen **gleichmäßig über das eingestellte Intervall `T`**:

$$\text{Startzeit}(i) = \text{Zyklusstart} + \left\lfloor \frac{i \cdot T}{N} \right\rfloor$$

- Durch eine stabile Sortierung nach Server-ID wird **jede einzelne IP weiterhin exakt im konfigurierten Intervall `T`** geprüft, während die Netzwerklast konstant und gleichmäßig bleibt:
  - **10 IPs bei 60 s Intervall**: ~1 Ping alle **6,0 s**
  - **1.000 IPs bei 60 s Intervall**: ~1 Ping alle **60 ms** (~16,7 Pings/s konstant statt 1.000 Pings auf einmal)
- **Begrenzte Parallelität & Überlappungsschutz**:
  - Automatische Pings laufen mit maximal **32 gleichzeitigen Prüfungen** – auch bei vielen Timeouts entstehen keine offenen Socket- oder Prozess-Fluten.
  - Läuft für eine IP bereits eine Prüfung, wird kein doppelter paralleler Ping gestartet.
  - Auch das manuelle **„Alle prüfen“** ist parallelitätsbegrenzt (**max. 24 gleichzeitig**, ab > 20 IPs zusätzlich mit kleiner Start-Staffelung).
  - Änderungen am Intervall oder das Abschalten des globalen Auto-Pings brechen einen laufenden Zyklus sofort ab.
- **Anzeige im Dashboard**: Bei mehr als einer fälligen IP zeigt die **Auto-Ping-Kachel** die aktuelle Taktung an (z. B. `Verteilt: ~1 IP alle 6,0 s` bzw. `~1 IP alle 60 ms`).

### 2. Adaptive Offline-Intervallverlängerung (Backoff)

Um Netzwerklast und Timeout-Wartezeiten bei dauerhaft ausgeschalteten oder nicht erreichbaren Hosts zusätzlich zu reduzieren, zählt SSH Console aufeinanderfolgende Fehlversuche pro IP:

- **Automatische Verlängerung**: Sobald eine IP `pingOfflineThreshold`-mal hintereinander offline war (Standard: **`5×`**), wird ihr Prüfintervall automatisch um den Faktor `pingOfflineMultiplier` verlängert (Standard: **`× 5`**, also z. B. `60 s → 5 min / 300 s`, max. `24 h`).
- **Sofortiger Reset bei Online-Antwort**: Sobald ein automatischer **oder manueller** Ping für diese IP wieder **Online** meldet, wird der Zähler sofort auf `0` zurückgesetzt und die IP läuft unmittelbar wieder im Standardintervall.
- **Einstellungen für Admins**: Direkt in der **Auto-Ping-Steuerung** im Dashboard konfigurierbar:
  - **Intervall (Sek.)**: `10–3600` (Standard `60`)
  - **Ab `X` × Offline**: `0–100` (Standard `5`; `0` deaktiviert die Offline-Drosselung)
  - **Faktor (`→ × Y`)**: `2–60` (Standard `5`)
- **Sichtbares Feedback**:
  - In der Server-Tabelle erscheint bei wiederholtem Ausfall die Anzahl der Fehlversuche (`Offline (5×)`) sowie bei aktiver Drosselung ein kompakter Hinweis (z. B. `alle 5 min`).
  - Die Auto-Ping-Kachel zeigt zusammengefasst, wie viele Offline-IPs aktuell im verlängerten Takt laufen (z. B. `12 Offline-IPs im 5 min-Takt`).

### 3. Auto-Ping-Schalter vs. manuelles Prüfen

Drei unabhängige Schalter steuern **ausschließlich den regelmäßigen Auto-Ping**:
1. **Globaler Schalter (Admin)**: `Auto-Ping global aus / an` in der Dashboard-Steuerleiste.
2. **Kontoschalter (Benutzer)**: `Regelmäßiges Anpingen für mein Konto aktivieren`.
3. **Pro-IP-Schalter (Benutzer)**: Einzeln pro Server in der Tabelle oder unter **Meine Server (IPs)** umschaltbar.

> **Manuelles Prüfen funktioniert immer:** Auch wenn globaler, Konto- oder IP-Auto-Ping deaktiviert ist, führt ein Klick auf **Prüfen** (einzelne IP) oder **Alle prüfen** jederzeit einen sofortigen Live-Ping aus.

### 4. Ping-Verfahren & „Zuletzt online“

- **Verfahren**: Nutzt natives ICMP `/bin/ping -c 1 -W 2` (IPv4 & IPv6) und fällt automatisch auf einen TCP-Connect-Test auf den konfigurierten SSH-Port zurück, falls `ping` fehlt oder keine `CAP_NET_RAW`-Rechte besitzt.
- **Zuletzt online**: Für jede IP wird der Zeitpunkt des letzten erfolgreichen Pings (`lastOnlineAt`) persistent gespeichert und direkt unter dem Ping-Status angezeigt.

---

## Kategorien, Filter & Seitenumbruch

- **Server-Kategorien**: Legen Sie unter **Meine Server (IPs)** (oder direkt im Server-Formular) eigene Kategorien an und ordnen Sie jedem Server **eine oder mehrere Kategorien** zu.
- **Kategorie-Filterleiste im Dashboard**:
  - Klicken Sie eine oder mehrere Kategorien (oder **Ohne Kategorie**) an, um die Serverliste einzugrenzen.
  - Ab zwei ausgewählten Kategorien lässt sich zwischen **`ODER`** (mindestens eine Kategorie) und **`UND`** (alle gewählten Kategorien gleichzeitig) umschalten.
  - Ein Klick auf ein Kategorie-Tag direkt in einer Server-Zeile schaltet den jeweiligen Filter um.
- **Kombinierte Suche & Statusfilter**: Kombinierbar mit **Alle / Online / Offline** und Volltextsuche (Bezeichnung, IP, BMC-IP, SSH-Benutzer, Notizen, Kategorien).
- **Seitenumbruch (Pagination)**: Wählen Sie **`10`**, **`20`**, **`50`** oder **`Alle`** Einträge pro Seite (wird lokal im Browser gemerkt).

---

## Dual-BMC-Monitoring (`BMC 1` & `BMC 2`)

- Pro Server lassen sich bis zu **zwei Out-of-Band-Management-IPs** (`BMC 1` und optional `BMC 2` für redundante IPMI-/iDRAC-/iLO-Interfaces) speichern.
- Ein Klick auf die BMC-IP öffnet `https://<bmc-ip>` in einem neuen Tab.
- Der Prüf-Button führt eine serverseitige **HTTPS-Port-443**-Erreichbarkeitsprüfung aus (akzeptiert selbstsignierte BMC-Zertifikate und zeigt HTTP-Status sowie Latenz an).
- Bei zwei hinterlegten BMCs lässt sich direkt in der Zeile zwischen `BMC 1` und `BMC 2` umschalten.

---

## Schnellauswahl & Sammelausführung

1. In der Leiste **Schnellauswahl & Sammelausführung** ganz oben im Dashboard:
   - Gewünschten **SSH-Befehl** (Einzelbefehl oder Befehlskette) wählen.
   - Gewünschtes **SSH-Zertifikat / Schlüsselpaar** wählen.
   - Bei einem passwortgeschützten Schlüssel ohne hinterlegte Passphrase erscheint automatisch das Entsperr-Eingabefeld für diese Ausführung.
2. Ziel-Server in der Tabelle darunter markieren (einzeln oder per Seiten-Auswahlbox).
3. Auf **Sammelauftrag ausführen** klicken – die Ausführung erfolgt parallel auf allen markierten Zielen.
4. **Direkte Ergebnisanzeige**: Die Ausgaben (`stdout`, `stderr`, Exit-Code, Laufzeit und aufklappbarer SSH-Aufruf) erscheinen **direkt nach der Schnellauswahl und vor der IP-Liste**, sodass Ergebnisse auch bei großen Serverlisten sofort ohne Scrollen sichtbar sind.
