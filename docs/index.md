---
title: Home / Startseite
description: Official bilingual documentation for SSH Console (English & German)
---

# SSH Console Documentation

Welcome to the official **SSH Console** documentation (English & Deutsch).  
SSH Console is a self-hosted web console for managing Linux servers via **OpenSSH certificates** and **SSH keypairs**, featuring a scalable **staggered Ping & BMC Dashboard**, **multi-tab interactive browser SSH Shell**, **single commands & multi-step command chains**, **OIDC SSO / 2FA / Passkeys**, **Docker & Debian 13 (Trixie) packaging**, and an automated **`curl` Certificate Upload & Rotation API**.

---

## English Documentation

| Section | Topics |
| --- | --- |
| **[Overview & Architecture](./en/overview.html)** | Core capabilities, Rust (Debian 13 Trixie) & Node.js stack, data storage, and security model |
| **[Installation & Docker](./en/installation.html)** | Docker & Compose, GitHub Actions GHCR builds, Debian 13 `.deb` package, systemd hardening, Nginx/Caddy reverse proxy, and backups |
| **[Authentication, SSO, 2FA & Passkeys](./en/authentication.html)** | Initial admin setup, user roles & sharing, OIDC/OAuth 2.0 SSO (PKCE S256), TOTP, FIDO2 Security Keys, and Passkeys |
| **[Dashboard, Auto-Ping & BMC](./en/dashboard-ping-bmc.html)** | Staggered auto-ping pacing (10–1,000+ IPs), adaptive offline backoff, categories, pagination, dual BMC checks, and batch execution |
| **[SSH Shell, Commands & Host Keys](./en/ssh-shell-commands.html)** | Multi-tab `xterm.js` SSH terminal, command chains, SSH host-key verification & reset, and Audit Logs |
| **[Certificates, Passphrases & API](./en/certificates-api.html)** | 2-file keypairs & 3-file OpenSSH CA certificates, encrypted key passphrases, personal API keys, and `curl` automation |
| **[Troubleshooting & FAQ](./en/troubleshooting.html)** | Solutions for host-key changes, encrypted keys, ICMP/TCP ping, reverse proxies, SSO, and WebAuthn |

---

## Deutsche Dokumentation

Willkommen in der offiziellen Dokumentation zu **SSH Console**.  
SSH Console ist eine selbstgehostete Webkonsole für Linux-Server mit **OpenSSH-Zertifikaten** und **SSH-Schlüsselpaaren**, skalierbarem **verteiltem Ping- & BMC-Dashboard**, **Multi-Tab-SSH-Shell im Browser**, **Einzelbefehlen & Befehlsketten**, **OIDC-SSO / 2FA / Passkeys**, **Docker- & Debian-13-Unterstützung** sowie einer **`curl`-API für Zertifikats-Uploads und -Rotation**.

| Bereich | Themen |
| --- | --- |
| **[Überblick & Architektur](./de/ueberblick.html)** | Funktionsumfang, Rust- (Debian 13 Trixie) & Node.js-Stack, Datenhaltung und Sicherheitsarchitektur |
| **[Installation & Docker](./de/installation.html)** | Docker & Compose, GitHub-Actions-GHCR-Builds, Debian-13-`.deb`-Paket, systemd-Härtung, Nginx/Caddy-Reverse-Proxy und Backups |
| **[Authentifizierung, SSO, 2FA & Passkeys](./de/authentifizierung.html)** | Admin-Ersteinrichtung, Benutzerrollen & Freigaben, OIDC/OAuth-2.0-SSO (PKCE S256), TOTP, FIDO2-Sicherheitsschlüssel und Passkeys |
| **[Dashboard, Auto-Ping & BMC](./de/dashboard-ping-bmc.html)** | Gleichmäßiges Auto-Ping-Pacing (10–1.000+ IPs), adaptive Offline-Drosselung, Kategorien, Seitenumbruch, Dual-BMC und Sammelausführung |
| **[SSH-Shell, Befehle & Host-Keys](./de/ssh-shell-befehle.html)** | Multi-Tab-SSH-Terminal (`xterm.js`), Befehlsketten, Host-Key-Prüfung & -Reset sowie Audit-Log |
| **[Zertifikate, Passphrases & API](./de/zertifikate-api.html)** | 2-Dateien-Schlüsselpaare & 3-Dateien-OpenSSH-CA-Zertifikate, Passphrase-Entsperrung, API-Keys und `curl`-Automatisierung |
| **[Fehlerbehebung & FAQ](./de/fehlerbehebung.html)** | Lösungen bei Host-Key-Änderungen, verschlüsselten Keys, ICMP/TCP-Ping, Reverse-Proxy, SSO und WebAuthn |
