# SSH Console — Rust SSH-Befehls-, Zertifikats- & BMC-Konsole für Debian Trixie

Ein schlankes, in Rust (Axum + Tokio + SQLite + Argon2 + AES-256-GCM) geschriebenes Webinterface für **Debian 13 (Trixie)** zur passwortlosen Ausführung von SSH-Befehlen und Befehlsketten mit OpenSSH-Schlüsselpaaren oder CA-signierten Benutzerzertifikaten, 60-Sekunden-Ping-Dashboard und BMC-HTTPS-Prüfung.

## Funktionen

- **Admin-Ersteinrichtung**: Beim ersten Start wird einmalig das Administratorkonto erstellt. Danach ist `/api/setup` dauerhaft gesperrt.
- **Benutzerverwaltung ohne Selbstregistrierung**: Ausschließlich Administratoren legen Konten an, deaktivieren oder entfernen sie. Jeder Benutzer kann sein eigenes Passwort ändern.
- **Private Ressourcen & Admin-Freigaben**: Angelegte SSH-Befehle, Server (IPs) und Zertifikate sind privat für den jeweiligen Ersteller; Administratoren können eigene Einträge gezielt oder für alle Benutzer teilen.
- **Passwortlose OpenSSH-Anmeldung (2- oder 3-Dateien-Modell)**:
  - `zertifikat` (Privater Schlüssel, gespeichert mit AES-256-GCM, temporär mit `0600` bereitgestellt und nach Ausführung genullt)
  - `zertifikat.pub` (Öffentlicher Schlüssel)
  - `zertifikat-cert.pub` (Optionales CA-signiertes OpenSSH-Benutzerzertifikat)

## Installation auf Debian Trixie

Per `.deb`-Paket:

```bash
sudo apt update
sudo apt install ./ssh-console_1.0.0_all.deb
```

Oder direkt aus dem Quellcode:

```bash
chmod +x debian/install-trixie.sh
./debian/install-trixie.sh
```

## OpenSSH-Zertifikat auf Zielservern einrichten

1. CA-Schlüssel erstellen (einmalig auf sicherem CA-Host):
   ```bash
   ssh-keygen -t ed25519 -f ssh_user_ca -C "SSH Console User CA"
   ```
2. Auf allen Zielservern in `/etc/ssh/sshd_config` eintragen:
   ```text
   TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub
   ```
   und `systemctl reload ssh` ausführen.
3. Benutzerschlüssel erstellen und optional mit der CA signieren:
   ```bash
   ssh-keygen -t ed25519 -f zertifikat -N ""
   ssh-keygen -s ssh_user_ca -I "benutzer-01" -n root,deploy -V +90d zertifikat.pub
   ```
