---
title: Home / Startseite
description: Official bilingual documentation for SSH Console (English & German)
---

# SSH Console Documentation

Welcome to the official **SSH Console** documentation (English & Deutsch).  
SSH Console is a self-hosted web console for managing Linux servers via **OpenSSH certificates** and **SSH keypairs**, featuring a built-in **SSH Certificate Authority (CA) manager**, **single & batch CA signing**, **policy-enforced user self-signing**, **automatic re-certification until revocation or rights removal**, **granular user groups**, a scalable **staggered Ping & Dual-BMC Dashboard**, **multi-tab interactive browser SSH Shell**, **single commands, command chains & JSON workflows**, **background jobs**, **OIDC SSO / 2FA / Passkeys**, **Docker & Debian 13 (Trixie) packaging**, and an automated **`curl` Certificate Upload & Rotation API**.

---

## English Documentation

| Section | Topics |
| --- | --- |
| **[Overview & Architecture](./en/overview.html)** | Core capabilities, Rust (Debian 13 Trixie) & Node.js parity stack, data storage, and security model |
| **[Installation & Docker](./en/installation.html)** | Docker & Compose, GitHub Actions GHCR builds, Debian 13 `.deb` package, systemd hardening, Nginx/Caddy reverse proxy, and backups |
| **[Auth, Groups, SSO & 2FA](./en/authentication.html)** | Initial admin setup, custom user groups & granular permissions, per-group/per-CA signing policies, password complexity rules, OIDC SSO (PKCE S256), TOTP, FIDO2 Security Keys, and Passkeys |
| **[Dashboard, Auto-Ping & BMC](./en/dashboard-ping-bmc.html)** | Staggered auto-ping pacing (10–1,000+ IPs), adaptive offline backoff, categories, pagination, dual BMC checks, batch execution, and background jobs |
| **[SSH Shell, Workflows & Host Keys](./en/ssh-shell-commands.html)** | Multi-tab `xterm.js` SSH terminal, command chains, complex JSON workflows with runtime variables, SSH host-key verification & reset, and Audit Logs |
| **[Certificates, CA Signing & API](./en/certificates-api.html)** | Key generation, duplicate-name protection, passphrase policies, SSH CA management, Admin & User single/batch signing, foreign-CA overwrite warnings, automatic re-certification, and `curl` API |
| **[Troubleshooting & FAQ](./en/troubleshooting.html)** | Solutions for host-key changes, password/passphrase policies, CA signing & auto-renewal stops, ICMP/TCP ping, reverse proxies, SSO, and WebAuthn |

---

## Deutsche Dokumentation

Willkommen in der offiziellen Dokumentation zu **SSH Console**.  
SSH Console ist eine selbstgehostete Webkonsole für Linux-Server mit **OpenSSH-Zertifikaten** und **SSH-Schlüsselpaaren**, integrierter **SSH-CA-Verwaltung**, **Einzel- & Sammelsignierung**, **richtliniengesteuerter Benutzer-Selbstsignierung**, **automatischer Neuzertifizierung bis auf Widerruf oder Rechteentzug**, **feingranularen Benutzergruppen**, skalierbarem **verteiltem Ping- & Dual-BMC-Dashboard**, **Multi-Tab-SSH-Shell im Browser**, **Einzelbefehlen, Befehlsketten & JSON-Workflows**, **Hintergrund-Jobs**, **OIDC-SSO / 2FA / Passkeys**, **Docker- & Debian-13-Unterstützung** sowie einer **`curl`-API für Zertifikats-Uploads und -Rotation**.

| Bereich | Themen |
| --- | --- |
| **[Überblick & Architektur](./de/ueberblick.html)** | Funktionsumfang, Rust- (Debian 13 Trixie) & Node.js-Stack, Datenhaltung und Sicherheitsarchitektur |
| **[Installation & Docker](./de/installation.html)** | Docker & Compose, GitHub-Actions-GHCR-Builds, Debian-13-`.deb`-Paket, systemd-Härtung, Nginx/Caddy-Reverse-Proxy und Backups |
| **[Auth, Gruppen, SSO & 2FA](./de/authentifizierung.html)** | Admin-Ersteinrichtung, Benutzergruppen & feingranulare Rechte, CA-Zuweisungen pro Gruppe & CA, Passwortkomplexität, OIDC-SSO (PKCE S256), TOTP, FIDO2-Sicherheitsschlüssel und Passkeys |
| **[Dashboard, Auto-Ping & BMC](./de/dashboard-ping-bmc.html)** | Gleichmäßiges Auto-Ping-Pacing (10–1.000+ IPs), adaptive Offline-Drosselung, Kategorien, Seitenumbruch, Dual-BMC, Sammelausführung und Hintergrund-Jobs |
| **[SSH-Shell, Workflows & Host-Keys](./de/ssh-shell-befehle.html)** | Multi-Tab-SSH-Terminal (`xterm.js`), Befehlsketten, komplexe JSON-Workflows mit Laufzeit-Variablen, Host-Key-Prüfung & -Reset sowie Audit-Log |
| **[Zertifikate, CA-Signierung & API](./de/zertifikate-api.html)** | Schlüsselerzeugung, Duplikatschutz, Passphrase-Regeln, SSH-CA-Verwaltung, Admin- & Benutzer-Signierung, Fremd-CA-Warnung, automatische Neuzertifizierung und `curl`-API |
| **[Fehlerbehebung & FAQ](./de/fehlerbehebung.html)** | Lösungen bei Host-Key-Änderungen, Passwort-/Passphrase-Regeln, CA-Signierung & gestoppter Auto-Erneuerung, ICMP/TCP-Ping, Reverse-Proxy, SSO und WebAuthn |
