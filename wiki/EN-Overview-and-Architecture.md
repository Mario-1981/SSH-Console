> [🏠 Home](Home) · [🇩🇪 Deutsche Version](DE-Startseite-und-Architektur)

# Overview & Architecture

**SSH Console** is a self-hosted web operations console designed for Linux fleets managed with **OpenSSH User Certificates** or **classic SSH keypairs**. It combines reachability monitoring, BMC access, batch command execution, and a multi-tab browser SSH terminal in a single lightweight application.

---

## Core Capabilities

- **Fleet Ping Dashboard (Scalable to 1,000+ Hosts)**
  - Evenly staggered auto-ping pacing across the configured interval (eliminates network bursts).
  - Adaptive offline backoff that automatically lengthens the check interval for persistently offline hosts and resets immediately upon recovery.
  - Global, account-level, and per-IP auto-ping switches (manual checks always remain available).
  - Multi-category tagging with `ANY` / `ALL` filters, search, status filtering, and configurable pagination (`10`, `20`, `50`, `All`).
  - Persistent `Last Online` timestamp per IP.
- **Dual BMC Management**
  - Store up to two BMC/IPMI/iDRAC/iLO addresses (`BMC 1` and `BMC 2`) per server with direct `https://` links and one-click HTTPS Port `443` TLS reachability checks.
- **Quick & Batch SSH Execution**
  - Define reusable single SSH commands and multi-step command chains (`sleep` delays, `&&` stop-on-error or `;` continue-on-error) running within one SSH session.
  - Execute across multiple selected servers in parallel from the Dashboard, with structured output displayed directly above the server list.
- **Multi-Tab Interactive Browser SSH Shell**
  - Open multiple simultaneous interactive PTY SSH sessions (`xterm.js` over WebSockets) in tabs—against saved servers or ad-hoc IP addresses.
- **OpenSSH Certificates, Keypairs & Encrypted Keys**
  - Full support for 3-file CA-signed OpenSSH certificates (`zertifikat`, `zertifikat.pub`, `zertifikat-cert.pub`) and 2-file SSH keypairs (`zertifikat`, `zertifikat.pub`).
  - Support for passphrase-protected private keys: store the passphrase encrypted at rest (AES-256-GCM) **or** prompt for it per execution / shell session without persisting it.
  - Cryptographic key-to-certificate matching and validity window checks on upload.
  - Automated `curl` Upload & Rotation API (`/api/v1/certificates/...`) using personal `sshc_...` API keys.
- **Enterprise Authentication & Role Separation**
  - Closed registration: one-time initial administrator setup, all subsequent accounts created by administrators (or via OIDC SSO auto-provisioning).
  - OIDC / OAuth 2.0 SSO with PKCE (`S256`), discovery, and mandatory anti-lockout connection test.
  - Optional or enforced 2FA (TOTP Authenticator Apps + recovery codes, FIDO2/WebAuthn Security Keys) and passwordless Passkeys.
  - Private-by-default resources (servers, commands, certificates, logs) with granular administrator sharing.
- **Bilingual Interface (`DE / EN`)**
  - Instant German and English UI switcher on every screen.

---

## System Architecture

SSH Console ships with **one shared React/TypeScript frontend** and **two feature-parity backends**:

| Component | Production Backend (Debian 13 / Trixie) | Development Backend (Node.js) |
| --- | --- | --- |
| **Runtime** | Native Rust (`Axum` + `Tokio`) | Node.js 20+ (`Express` + `tsx`) |
| **Database** | SQLite (`WAL` mode) at `/var/lib/ssh-console/ssh-console.sqlite` | Local JSON store at `data/trixiessh.json` |
| **Secret Vault** | AES-256-GCM with 256-bit `/var/lib/ssh-console/vault.key` (`0600`) | AES-256-GCM with `data/master.key` (`0600`) or `TRIXIESSH_MASTER_KEY` |
| **Password Hashing** | Argon2id (per-user random salt) | `scrypt` (per-user random salt) |
| **SSH Engine** | Native OpenSSH client (`/usr/bin/ssh`) + PTY WebSocket bridge | Native OpenSSH client (`ssh`) + PTY WebSocket bridge |
| **Ping Engine** | `/bin/ping` (ICMP) with automatic TCP connect fallback | `/bin/ping` (ICMP) with automatic TCP connect fallback |
| **Frontend** | Pre-built Vite static bundle served from `/opt/ssh-console/dist` | Vite dev middleware served on port `3000` |

---

## Security Model

1. **Encryption at Rest (AES-256-GCM)**
   - Every uploaded SSH private key, optional stored key passphrase, TOTP secret, and SSO client secret is encrypted using **AES-256-GCM** with a unique random nonce per record.
   - Plaintext private keys and passphrases are **never** returned to the browser.
2. **Ephemeral OpenSSH Materialization**
   - When executing a command or opening an interactive SSH shell, the backend creates an isolated temporary directory (`0700`), writes the key material (`0600`), unlocks passphrase-protected keys via a temporary `SSH_ASKPASS` helper (never passing secrets on the command line or in logs), and wipes the temporary files immediately after use.
3. **Closed User Registration**
   - `/api/setup` is permanently locked once the first administrator account exists.
4. **Hashed API Keys**
   - Personal API keys (`sshc_...`) use 256 bits of cryptographic entropy, are shown once on creation, and are stored exclusively as **SHA-256** digests.
5. **Private-by-Default Sharing**
   - Standard users only see their own servers, categories, commands, certificates, and execution logs, plus entries explicitly shared by an administrator.
   - Sharing a certificate grants execution rights **without** exposing private key bytes or stored passphrases.
6. **SSH Host-Key Protection**
   - Per-user managed `known_hosts` files with `StrictHostKeyChecking=accept-new`.
   - Benign first-connection `Permanently added ... to the list of known hosts` warnings are automatically hidden, while genuine `REMOTE HOST IDENTIFICATION HAS CHANGED` warnings remain visible so MITM or host rebuilds are immediately noticeable.
