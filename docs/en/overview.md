---
title: Overview & Architecture
lang: en
alt_url: /de/ueberblick.html
---

# Overview & Architecture

**SSH Console** is a self-hosted web operations console designed for Linux fleets managed with **OpenSSH User Certificates** or **classic SSH keypairs**. It combines built-in **SSH Certificate Authority (CA) management & automatic re-certification**, **granular user groups**, reachability monitoring, Dual-BMC management, parallel command & JSON workflow execution with background jobs, and a multi-tab interactive browser SSH terminal in a single lightweight application.

---

## Core Capabilities

- **Integrated SSH CA Management, Signing & Automatic Re-Certification**
  - Dedicated **Admin → CA Certificates** area to generate, import, inspect, update, and delete OpenSSH User CAs (`ca` and `ca.pub`), with one-click `ca.pub` download for `TrustedUserCAKeys`.
  - **Admin Single & Batch CA Signing**: Sign one or multiple user certificates at once with configurable Principals (`-n`), validity (`-V`), optional Key-ID prefix, and either the stored or a one-time CA passphrase.
  - **Policy-Enforced User Self-Signing**: Assign one or more CAs per **User Group** and define allowed Principals (`-n`), **signature validity (`-V`, presets or custom)**, and **automatic re-signing start time** per group and per CA. Users can single- or batch-sign their own keys without ever accessing CA secrets or overriding policy limits.
  - **Foreign-CA Overwrite Warning**: Clearly warns and requires explicit confirmation whenever signing would overwrite an existing `zertifikat-cert.pub` issued by a different CA.
  - **Automatic Re-Certification (Until Revocation or Rights Removal)**: Background renewal ahead of expiry — revocable individually or in batch, and automatically stopped immediately upon rights removal, CA change, or manual certificate replacement.
- **OpenSSH Certificates, Key Generation & Passphrase Policies**
  - Full support for 3-file CA-signed OpenSSH certificates (`zertifikat`, `zertifikat.pub`, `zertifikat-cert.pub`) and 2-file SSH keypairs (`zertifikat`, `zertifikat.pub`).
  - Direct in-browser key generation with live duplicate-name detection and explicit overwrite confirmation (never silently overwrites existing bundles).
  - Enforces **password complexity rules** (minimum 8 characters + at least 3 of 4 character classes) for account passwords, certificate passphrases, and CA passphrases.
  - Group permissions govern passphrase requirements, encrypted passphrase storage (AES-256-GCM), and whether users may upload their own `zertifikat-cert.pub` files.
  - **Privacy-Preserving Admin Certificate Overview**: Administrators can search, filter, sign, and delete certificates across all users without ever viewing or editing other users' private keys.
  - Automated `curl` Upload & Rotation API (`/api/v1/certificates/...`) using personal `sshc_...` API keys.
- **User Groups, Authentication, SSO, 2FA & Passkeys**
  - Closed registration (one-time initial admin setup) plus custom **User Groups** with granular permissions.
  - OIDC / OAuth 2.0 SSO with PKCE (`S256`), auto-discovery, and mandatory anti-lockout connection test.
  - Optional or enforced 2FA (TOTP Authenticator Apps + recovery codes, FIDO2/WebAuthn Security Keys) and passwordless Passkeys.
  - Private-by-default resources (servers, categories, commands, certificates, logs) with targeted admin sharing.
- **Fleet Ping Dashboard (Scalable to 1,000+ Hosts) & Dual BMC**
  - Evenly staggered auto-ping pacing (eliminating network bursts) and adaptive offline backoff with instant reset on recovery.
  - Global, account-level, and per-IP auto-ping switches, multi-category `ANY`/`ALL` filters, search, pagination (`10`, `20`, `50`, `All`), and persistent `Last Online` timestamps.
  - Up to two BMC/IPMI/iDRAC/iLO addresses (`BMC 1` and `BMC 2`) per server with direct `https://` links and TLS port `443` reachability checks.
- **Commands, JSON Workflows, Background Jobs & Multi-Tab SSH Shell**
  - Reusable single commands, linear command chains (`sleep`, `&&` / `;`), and complex **JSON Workflows** (typed runtime variables incl. masked secrets, `if`/`else`, `loop`, output filters, and table/JSON/template formatting).
  - Parallel batch execution directly from the Dashboard plus a **Background Jobs** queue for long-running batches with progress tracking.
  - Multi-tab interactive browser PTY SSH terminal (`xterm.js` over WebSockets) for saved servers or ad-hoc IP addresses.
- **Bilingual Interface (`DE / EN`)**
  - Instant German and English UI switcher on every screen.

---

## System Architecture

SSH Console ships with **one shared React/TypeScript frontend** and **two feature-parity backends**:

| Component | Production Backend (Debian 13 / Docker) | Development Backend (Node.js) |
| --- | --- | --- |
| **Runtime** | Native Rust (`Axum` + `Tokio`) | Node.js 20+ (`Express` + `tsx`) |
| **Database** | SQLite (`WAL` mode) at `/var/lib/ssh-console/ssh-console.sqlite` | Local JSON store at `data/trixiessh.json` |
| **Secret Vault** | AES-256-GCM with 256-bit `/var/lib/ssh-console/vault.key` (`0600`) | AES-256-GCM with `data/master.key` (`0600`) or `TRIXIESSH_MASTER_KEY` |
| **Password Hashing** | Argon2id (per-user random salt) | `scrypt` (per-user random salt) |
| **SSH & CA Engine** | Native OpenSSH client (`/usr/bin/ssh`, `ssh-keygen`) + PTY WebSocket bridge | Native OpenSSH client (`ssh`, `ssh-keygen`) + PTY WebSocket bridge |
| **Background Workers** | Staggered Ping Monitor, Background Jobs, Auto-Renew Scheduler (60 s) | Staggered Ping Monitor, Background Jobs, Auto-Renew Scheduler (60 s) |
| **Ping Engine** | `/bin/ping` (ICMP) with automatic TCP connect fallback | `/bin/ping` (ICMP) with automatic TCP connect fallback |
| **Frontend** | Pre-built Vite static bundle served from `/opt/ssh-console/dist` | Vite dev middleware served on port `3000` |

---

## Security Model

1. **Encryption at Rest (AES-256-GCM)**
   - Every SSH private key, managed CA private key, optional stored key/CA passphrase, TOTP secret, and SSO client secret is encrypted using **AES-256-GCM** with a unique random nonce per record.
   - Plaintext private keys and passphrases are **never** returned to the browser.
2. **Strict Server-Side Group & CA Policies**
   - Group permissions and per-group/per-CA signing assignments (`-n` Principals, `-V` validity, and auto-renewal lead time) are enforced strictly on the server.
   - Upon revocation, rights removal, CA changes, or account deactivation, active automatic re-certifications are stopped immediately.
3. **Password & Passphrase Complexity**
   - Every newly set account password, certificate passphrase, and CA passphrase must be at least **8 characters** long and include at least **3 of 4 character classes** (lowercase, uppercase, digits, special characters).
4. **Ephemeral OpenSSH Materialization**
   - For every command execution, CA signing operation, or interactive SSH shell, the backend creates an isolated temporary directory (`0700`), writes key material (`0600`), unlocks encrypted keys via a temporary `SSH_ASKPASS` helper (never passing secrets on the command line or in logs), and wipes all temporary files immediately afterwards.
5. **Closed Registration & Hashed API Keys**
   - `/api/setup` is permanently locked once the first administrator account exists.
   - Personal API keys (`sshc_...`) use 256 bits of cryptographic entropy, are displayed once on creation, and are stored exclusively as **SHA-256** digests.
6. **Privacy & SSH Host-Key Protection**
   - Standard users only see their own resources plus entries shared by an admin; even in the cross-user admin certificate overview, other users' private keys are never accessible or editable.
   - Per-user `known_hosts` files with `StrictHostKeyChecking=accept-new` automatically filter routine first-connect notices while keeping genuine `REMOTE HOST IDENTIFICATION HAS CHANGED` alerts prominent.

---

Next: **[Installation & Docker](./installation.html)**
