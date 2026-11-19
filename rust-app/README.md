# TrixieSSH — Rust SSH-Befehls- & Zertifikatskonsole für Debian Trixie

Ein schlankes, in Rust (Axum + Tokio + SQLite + Argon2 + AES-256-GCM) geschriebenes Webinterface für **Debian 13 (Trixie)** zur passwortlosen Ausführung von zentral freigegebenen SSH-Befehlen mittels OpenSSH-Zertifikaten.

## Funktionen

- **Admin-Ersteinrichtung**: Beim ersten Start wird einmalig das Administratorkonto erstellt. Danach ist `/api/setup` dauerhaft gesperrt.
- **Benutzerverwaltung ohne Selbstregistrierung**: Ausschließlich Administratoren legen Konten an, deaktivieren oder entfernen sie.
- **Zentrale SSH-Befehlsfreigabe**: Der Administrator definiert erlaubte SSH-Befehle (Allowlist). Benutzer können keine beliebigen Shell-Befehle einschleusen.
- **Passwortlose OpenSSH-Zertifikatsanmeldung (3-Dateien-Modell)**:
  - `zertifikat` (Privater Schlüssel, gespeichert mit AES-256-GCM, temporär mit `0600` bereitgestellt und nach Ausführung genullt)
  - `zertifikat.pub` (Öffentlicher Schlüssel)
  - `zertifikat-cert.pub` (Signiertes OpenSSH-Benutzerzertifikat)
  - Ausführung strikt mit `IdentitiesOnly=yes`, `BatchMode=yes`, `PasswordAuthentication=no` und `-o CertificateFile=...`.

## Installation auf Debian Trixie

```bash
chmod +x debian/install-trixie.sh
./debian/install-trixie.sh
```

## OpenSSH-Zertifikat auf Zielservern einrichten

1. CA-Schlüssel erstellen (einmalig auf sicherem CA-Host):
   ```bash
   ssh-keygen -t ed25519 -f ssh_user_ca -C "TrixieSSH User CA"
   ```
2. Auf allen Zielservern in `/etc/ssh/sshd_config` eintragen:
   ```text
   TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub
   ```
   und `systemctl reload ssh` ausführen.
3. Benutzerschlüssel erstellen und mit der CA signieren:
   ```bash
   ssh-keygen -t ed25519 -f zertifikat -N ""
   ssh-keygen -s ssh_user_ca -I "benutzer-01" -n root,deploy -V +90d zertifikat.pub
   ```
   Dadurch entstehen exakt die drei Dateien `zertifikat`, `zertifikat.pub` und `zertifikat-cert.pub`, die der Benutzer im Webinterface hochlädt.
