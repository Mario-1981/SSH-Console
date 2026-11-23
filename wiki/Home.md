# SSH Console Wiki

**🇬🇧 English** · **[🇩🇪 Deutsch](#deutsch)**

Welcome to the official **SSH Console** documentation.  
SSH Console is a self-hosted web console for managing Linux servers via **OpenSSH certificates** and **SSH keypairs**, featuring a scalable **staggered Ping & BMC Dashboard**, **multi-tab interactive browser SSH Shell**, **single commands & multi-step command chains**, **OIDC SSO / 2FA / Passkeys**, and an automated **`curl` Certificate Upload & Rotation API**.

---

## English Documentation

| Page | Contents |
| --- | --- |
| **[Overview & Architecture](EN-Overview-and-Architecture)** | Core capabilities, Rust (Debian 13 Trixie) & Node.js stack, data storage, and security architecture |
| **[Installation & Deployment](EN-Installation-and-Deployment)** | Debian 13 `.deb` package, source build, Docker, systemd hardening, Nginx/Caddy reverse proxy, and backups |
| **[Authentication, SSO, 2FA & Passkeys](EN-Authentication-SSO-2FA-Passkeys)** | Initial admin setup, user roles & sharing, OIDC/OAuth 2.0 SSO (PKCE S256), TOTP, FIDO2 Security Keys, and Passkeys |
| **[Dashboard, Auto-Ping & BMC](EN-Dashboard-Ping-and-BMC)** | Staggered auto-ping pacing (10–1,000+ IPs), adaptive offline backoff, categories, pagination, dual BMC checks, and batch execution |
| **[SSH Shell, Commands & Host Keys](EN-SSH-Shell-and-Commands)** | Multi-tab `xterm.js` SSH terminal, command chains, SSH host-key verification & reset, and Audit Logs |
| **[Certificates, Passphrases & `curl` API](EN-Certificates-Passphrases-and-API)** | 2-file keypairs & 3-file OpenSSH CA certificates, encrypted key passphrases, personal API keys, and `curl` automation |
| **[Troubleshooting & FAQ](EN-Troubleshooting-and-FAQ)** | Solutions for host-key changes, encrypted keys, ICMP/TCP ping, reverse proxies, SSO, and WebAuthn |

---

<a id="deutsch"></a>

## Deutsche Dokumentation

Willkommen im offiziellen **SSH Console**-Wiki.  
SSH Console ist eine selbstgehostete Webkonsole für Linux-Server mit **OpenSSH-Zertifikaten** und **SSH-Schlüsselpaaren**, skalierbarem **verteiltem Ping- & BMC-Dashboard**, **Multi-Tab-SSH-Shell im Browser**, **Einzelbefehlen & Befehlsketten**, **OIDC-SSO / 2FA / Passkeys** sowie einer **`curl`-API für Zertifikats-Uploads und -Rotation**.

| Seite | Inhalt |
| --- | --- |
| **[Überblick & Architektur](DE-Startseite-und-Architektur)** | Funktionsumfang, Rust- (Debian 13 Trixie) & Node.js-Stack, Datenhaltung und Sicherheitsarchitektur |
| **[Installation & Betrieb](DE-Installation-und-Betrieb)** | Debian-13-`.deb`-Paket, Quellcode-Build, Docker, systemd-Härtung, Nginx/Caddy-Reverse-Proxy und Backups |
| **[Authentifizierung, SSO, 2FA & Passkeys](DE-Authentifizierung-SSO-2FA-Passkeys)** | Admin-Ersteinrichtung, Benutzerrollen & Freigaben, OIDC/OAuth-2.0-SSO (PKCE S256), TOTP, FIDO2-Sicherheitsschlüssel und Passkeys |
| **[Dashboard, Auto-Ping & BMC](DE-Dashboard-Ping-und-BMC)** | Gleichmäßiges Auto-Ping-Pacing (10–1.000+ IPs), adaptive Offline-Drosselung, Kategorien, Seitenumbruch, Dual-BMC und Sammelausführung |
| **[SSH-Shell, Befehle & Host-Keys](DE-SSH-Shell-und-Befehle)** | Multi-Tab-SSH-Terminal (`xterm.js`), Befehlsketten, Host-Key-Prüfung & -Reset sowie Audit-Log |
| **[Zertifikate, Passphrases & `curl`-API](DE-Zertifikate-Passphrases-und-API)** | 2-Dateien-Schlüsselpaare & 3-Dateien-OpenSSH-CA-Zertifikate, Passphrase-Entsperrung, API-Keys und `curl`-Automatisierung |
| **[Fehlerbehebung & FAQ](DE-Fehlerbehebung-und-FAQ)** | Lösungen bei Host-Key-Änderungen, verschlüsselten Keys, ICMP/TCP-Ping, Reverse-Proxy, SSO und WebAuthn |

---

## Publishing this Wiki to GitHub

To push the files in `wiki/` directly into your GitHub repository's Wiki tab:

```bash
git clone https://github.com/<owner>/<repo>.wiki.git
cp wiki/*.md <repo>.wiki/
cd <repo>.wiki
git add .
git commit -m "Add bilingual English & German wiki documentation"
git push
```
