---
title: Fehlerbehebung & FAQ
lang: de
alt_url: /en/troubleshooting.html
---

# Fehlerbehebung & FAQ

---

## SSH-Ausführung & Host-Keys

### `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!`
- **Ursache**: Der SSH-Host-Key des Zielservers hat sich geändert (typisch nach Neuinstallation, VM-Rebuild oder neu vergebener IP).
- **Lösung**: Prüfen Sie, ob die Änderung legitim ist, und klicken Sie anschließend unter **Meine Server (IPs)** auf **Host-Key zurücksetzen** (oder als Admin unter **Admin → Anmeldung & SSO → Bekannte Host-Keys**). Beim nächsten Zugriff wird der neue Host-Key automatisch akzeptiert.

### Ausführung schlägt mit „Passphrase erforderlich“ fehl
- **Ursache**: Der gewählte private Schlüssel ist passwortgeschützt und hat keine in SSH Console gespeicherte Passphrase.
- **Lösung**: Geben Sie die Passphrase vor dem Ausführen direkt im Entsperrfeld im **Dashboard** bzw. in der **SSH-Shell** ein – oder hinterlegen Sie sie (sofern durch die Benutzergruppe erlaubt) verschlüsselt unter **SSH-Schlüssel & Zertifikate → Passphrase**.

### `Permission denied (publickey)` bei einem 3-Dateien-Zertifikat
- Prüfen Sie unter **SSH-Schlüssel & Zertifikate**, ob das Zertifikat noch **gültig** (`validBefore`) ist und der konfigurierte **SSH-Benutzer** (z. B. `root` oder `deploy`) in den **Principals (`-n`)** enthalten ist.
- Stellen Sie sicher, dass auf dem Zielserver `TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub` in `/etc/ssh/sshd_config` eingetragen ist, der Inhalt exakt der `ca.pub` aus **Admin → CA-Zertifikate** entspricht und `sshd` neu geladen wurde.

---

## Zertifikate, CA-Signierung & automatische Neuzertifizierung

### Passwort oder Zertifikatspassphrase wird abgelehnt
- **Ursache**: Die Passwortkomplexitätsrichtlinie ist nicht erfüllt.
- **Lösung**: Verwenden Sie mindestens **8 Zeichen** sowie mindestens **3 von 4 Zeichenklassen** (Kleinbuchstaben, Großbuchstaben, Ziffern, Sonderzeichen). Diese Regel gilt für Benutzerpasswörter, Zertifikatspassphrases und CA-Passphrases gleichermaßen.

### Warnung: „Bestehende `zertifikat-cert.pub` stammt von einer anderen CA“
- **Ursache**: Das ausgewählte Zertifikat besitzt bereits eine signierte `zertifikat-cert.pub`-Datei, deren CA-Fingerabdruck nicht zur aktuell ausgewählten CA passt.
- **Lösung**: Prüfen Sie, ob der Wechsel auf die neue CA beabsichtigt ist, und setzen Sie anschließend das Bestätigungshäkchen in der Warnbox, um das Überschreiben freizugeben.

### Automatische Neuzertifizierung lässt sich nicht aktivieren oder wurde gestoppt
- **Typische Ursachen**:
  - Für die gewählte CA ist **kein CA-Passwort auf dem Server hinterlegt** (erforderlich unter **Admin → CA-Zertifikate**).
  - Die Gültigkeitsdauer (`-V`) steht auf **`forever`** (unbegrenzte Zertifikate laufen nicht ab).
  - Der Benutzergruppe fehlt das Recht **Selbstsignierung** oder **Automatische Neuzertifizierung erlauben**, oder die CA wurde der Gruppe entzogen.
  - Das Zertifikat wurde manuell ersetzt/hochgeladen oder der freigebende Administrator wurde deaktiviert bzw. herabgestuft.
- **Lösung**: Der genaue Widerrufsgrund wird direkt im Statushinweis der jeweiligen Zertifikatskarte angezeigt. Nach Korrektur der Gruppenrechte oder des CA-Passworts kann die automatische Neuzertifizierung durch erneutes Signieren wieder aktiviert werden.

### Gruppenspeicherung meldet ungültige Vorlaufzeit für automatische Neusignierung
- **Ursache**: Der pro Gruppe und CA gewählte Startzeitpunkt für die automatische Neusignierung ist größer oder gleich der eingestellten Signatur-Gültigkeit (`-V`).
- **Lösung**: Wählen Sie eine Vorlaufzeit, die kürzer als die Gültigkeitsdauer der Signatur ist (z. B. bei `+24h` Gültigkeit maximal z. B. `6 Stunden` oder `Automatisch 20 % vor Ablauf`).

---

## Interaktive SSH-Shell

### WebSocket trennt sofort oder verbindet hinter Nginx/Apache nicht
- Prüfen Sie, ob der Reverse-Proxy `Upgrade` und `Connection: upgrade` weiterleitet und ein ausreichend hohes `proxy_read_timeout` (z. B. `3600s`) gesetzt ist. Siehe [Installation & Docker](./installation.html#reverse-proxy-konfiguration-https--websockets).
- Stellen Sie sicher, dass SSH Console über HTTPS ausgeliefert wird (`wss://`) und unter **Öffentliche URL** `https://...` eingetragen ist.

---

## Ping-Dashboard & BMC

### Dashboard zeigt `tcp-ping` statt `icmp-ping`
- **Ursache**: `/bin/ping` ist nicht installiert oder der Prozess besitzt keine ICMP-Rechte (häufig in restriktiven Containern ohne `--cap-add=NET_RAW` oder gehärteten systemd-Units mit leerem `CapabilityBoundingSet`).
- **Verhalten**: SSH Console wechselt automatisch auf einen TCP-Connect-Test auf den SSH-Port des Servers (Standard `22`), der die Erreichbarkeit auch ohne Raw-Sockets zuverlässig ermittelt.

### Warum wird eine Offline-IP seltener geprüft als mein eingestelltes Intervall?
- **Ursache**: Die adaptive **Offline-Drosselung (Backoff)** ist aktiv (Standard: ab `5×` Offline verlängert sich das Intervall um `× 5`).
- **Lösung**: Sobald die IP wieder online antwortet (automatisch oder per manuellem Ping), wird sie sofort wieder auf das Standardintervall zurückgesetzt. Zum Anpassen oder Abschalten kann ein Admin in der **Auto-Ping-Steuerung** `Ab [0]× Offline` speichern.

### Kann ich eine IP manuell prüfen, wenn Auto-Ping abgeschaltet ist?
- **Ja.** Die globalen, Konto- und IP-Schalter deaktivieren ausschließlich den *regelmäßigen* Auto-Ping. Ein Klick auf **Prüfen** oder **Alle prüfen** führt jederzeit sofort einen Live-Ping aus.

---

## SSO, 2FA & Passkeys

### Passkeys oder Sicherheitsschlüssel lassen sich nicht registrieren
- WebAuthn verlangt **HTTPS** mit gültigem Zertifikat (oder `http://localhost` bei lokaler Entwicklung). Unverschlüsselte IP-Aufrufe wie `http://192.168.1.10:3000` werden vom Browser abgelehnt.
- Prüfen Sie, ob **Admin → Anmeldung & SSO → Öffentliche URL** exakt der Domain in der Browser-Adresszeile entspricht.

### SSO meldet „Redirect URI mismatch“
- Hinterlegen Sie unter **Admin → Anmeldung & SSO → Öffentliche URL** exakt Ihre externe HTTPS-URL ohne abschließenden Schrägstrich (z. B. `https://ssh.example.net`).
- Registrieren Sie `https://ssh.example.net/api/auth/sso/callback` exakt so in Ihrem Identity Provider.

### Ein Benutzer hat sein 2FA-Gerät oder seinen Passkey verloren
- Ein Administrator kann unter **Admin → Benutzer** für das Konto auf **2FA / Passkeys zurücksetzen** klicken. Bei erzwungener 2FA/Passkey-Richtlinie richtet der Benutzer beim nächsten Login neue Faktoren ein.

---

## Datenbank & Vault

### Was passiert, wenn `vault.key` verloren geht?
- **Kritisch:** `vault.key` verschlüsselt alle privaten SSH-Schlüssel, verwalteten CA-Privatschlüssel, hinterlegten Schlüssel- und CA-Passphrases, TOTP-Geheimnisse und das SSO-Client-Secret. Ohne `vault.key` können diese Einträge nicht mehr entschlüsselt werden und müssten neu hochgeladen bzw. konfiguriert werden. Sichern Sie `vault.key` daher immer gemeinsam mit `ssh-console.sqlite`.
