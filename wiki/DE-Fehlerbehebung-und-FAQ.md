> [🏠 Startseite](Home) · [🇬🇧 English Version](EN-Troubleshooting-and-FAQ)

# Fehlerbehebung & FAQ

---

## SSH-Ausführung & Host-Keys

### `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!`
- **Ursache**: Der SSH-Host-Key des Zielservers hat sich geändert (typisch nach Neuinstallation, VM-Rebuild oder neu vergebener IP).
- **Lösung**: Prüfen Sie, ob die Änderung legitim ist, und klicken Sie anschließend unter **Meine Server (IPs)** auf **Host-Key zurücksetzen** (oder als Admin unter **Admin → Anmeldung & SSO → Bekannte Host-Keys**). Beim nächsten Zugriff wird der neue Host-Key automatisch akzeptiert.

### Ausführung schlägt mit „Passphrase erforderlich“ fehl
- **Ursache**: Der gewählte private Schlüssel ist passwortgeschützt und hat keine in SSH Console gespeicherte Passphrase.
- **Lösung**: Geben Sie die Passphrase vor dem Ausführen direkt im Entsperrfeld im **Dashboard** bzw. in der **SSH-Shell** ein – oder hinterlegen Sie sie verschlüsselt unter **SSH-Schlüssel & Zertifikate → Passphrase**.

### `Permission denied (publickey)` bei einem 3-Dateien-Zertifikat
- Prüfen Sie unter **SSH-Schlüssel & Zertifikate**, ob das Zertifikat noch **gültig** (`validBefore`) ist und der konfigurierte **SSH-Benutzer** (z. B. `root` oder `deploy`) in den **Principals** enthalten ist.
- Stellen Sie sicher, dass auf dem Zielserver `TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub` in `/etc/ssh/sshd_config` eingetragen ist und `sshd` neu geladen wurde.

---

## Interaktive SSH-Shell

### WebSocket trennt sofort oder verbindet hinter Nginx/Apache nicht
- Prüfen Sie, ob der Reverse-Proxy `Upgrade` und `Connection: upgrade` weiterleitet und ein ausreichend hohes `proxy_read_timeout` (z. B. `3600s`) gesetzt ist. Siehe [Installation & Betrieb](DE-Installation-und-Betrieb#reverse-proxy-konfiguration-https--websockets).
- Stellen Sie sicher, dass SSH Console über HTTPS ausgeliefert wird (`wss://`) und unter **Öffentliche URL** `https://...` eingetragen ist.

---

## Ping-Dashboard & BMC

### Dashboard zeigt `tcp-ping` statt `icmp-ping`
- **Ursache**: `/bin/ping` ist nicht installiert oder der Prozess besitzt keine ICMP-Rechte (häufig in restriktiven Containern oder gehärteten systemd-Units mit leerem `CapabilityBoundingSet`).
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
- **Kritisch:** `vault.key` verschlüsselt alle privaten SSH-Schlüssel, hinterlegten Passphrases, TOTP-Geheimnisse und das SSO-Client-Secret. Ohne `vault.key` können diese Einträge nicht mehr entschlüsselt werden und müssten neu hochgeladen bzw. konfiguriert werden. Sichern Sie `vault.key` daher immer gemeinsam mit `ssh-console.sqlite`.
