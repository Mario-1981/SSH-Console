---
title: Authentication, Groups, SSO & 2FA
lang: en
alt_url: /de/authentifizierung.html
---

# Authentication, User Groups, SSO & 2FA

SSH Console is built for internal infrastructure teams with strict access control: there is **no public self-registration**, all new passwords follow strict **complexity rules**, and administrators can combine **custom user groups with granular permissions**, **OIDC/OAuth 2.0 SSO**, **Two-Factor Authentication (TOTP & FIDO2)**, and **Passkeys**.

---

## Initial Setup & User Management

1. **One-Time Admin Setup**: On first launch, SSH Console presents the setup wizard to set the instance name and create the initial `admin` account. Immediately afterwards, `/api/setup` is permanently disabled.
2. **Managing Users**: Administrators manage all accounts under **Admin → Users**:
   - Create local users, assign them to a **User Group** (`Administrators`, `Standard Users`, or any custom group), and set display name, email, and default SSH username.
   - Reset passwords, activate/deactivate accounts, or delete users.
   - Reset a user's 2FA/Passkey configuration with one click if a device is lost (`POST /api/admin/users/:id/reset-auth`).
3. **Resource Visibility & Sharing**:
   - All commands, servers, categories, certificates, and execution logs are **private** to their owner by default.
   - Administrators can share their own **commands**, **servers**, and **certificates** either with **all users** or with **selected users**.
   - Users can never view or export private keys or passphrases of shared certificates—they can only use them for SSH execution and shell sessions.

---

## Password & Passphrase Complexity Policy

All newly set passwords and passphrases—including **initial setup**, **user creation**, **password changes/resets**, **certificate passphrases** (generation, upload, update), and **CA passphrases**—must satisfy the following server-enforced rules:

- **Mandatory:** At least **8 characters** in length.
- **Character classes (at least 3 of 4 required):**
  1. At least one **lowercase letter** (`a–z`)
  2. At least one **uppercase letter** (`A–Z`)
  3. At least one **digit** (`0–9`)
  4. At least one **special character** (e.g. `!@#$%^&*...`)

The UI displays live feedback showing which criteria are met as you type.

---

## User Groups & Granular Permissions

Under **Admin → Users → User Groups**, administrators can manage system groups (**Administrators** — immutable full access — and **Standard Users**) as well as unlimited custom groups. One-click presets (*Standard*, *Full Access*, *Minimal Operator*) make onboarding fast.

### Available Group Permissions

| Category | Permissions |
| --- | --- |
| **Servers & Connection** | Manage own servers (IPs) & categories · Use interactive SSH shell · Allow ad-hoc custom IPs in SSH shell · Execute SSH commands |
| **SSH Commands** | Create single commands · Create simple command chains · Create complex JSON workflows |
| **SSH Keys, Certificates & CA** | Upload certificates/keys · Upload own signed `zertifikat-cert.pub` files · Generate SSH keys in the app · **Require certificate passphrase** · **Allow storing certificate passphrases** · **Self-sign own certificates with assigned CA** · **Allow automatic re-certification** |
| **API, Sharing & Logs** | Use personal API keys (`curl` API) · Share own resources · View own execution logs |

### Per-Group & Per-CA Signing Assignments

Inside every non-admin user group, administrators can assign **one or more SSH CAs** for user self-signing. For **each group + CA combination**, the administrator defines:

1. **Allowed Principals (`-n`)**: Comma-separated SSH usernames (e.g. `deploy, debian`) plus an optional checkbox to **automatically include the signing user's own username in `-n`**.
2. **Signature Validity (`-V`)**: Pick from presets (`+1h`, `+8h`, `+24h`, `+3d`, `+7d`, `+14d`, `+30d`, `+90d`, `+52w`, `forever`) or enter a **custom OpenSSH duration** (e.g. `+12h`, `+45d`, `+2w`).
3. **Auto Re-Sign Allowed From (Renewal Lead Time)**:
   - **Automatic (from 20% before expiry)** — scales dynamically with the certificate lifetime.
   - **Preset lead times** (`15 min` up to `30 days` before expiry) or **custom minutes, hours, or days**.
   - Validated server-side against the signature validity (must always be shorter than `-V`; disabled when validity is `forever`).

> **Strict Server Enforcement:** Users cannot override `-n`, `-V`, or the automatic re-signing start time. Whenever an administrator updates group permissions or CA parameters, active user-initiated auto-renewals are **updated immediately**—or **revoked immediately** if rights are removed or validity is switched to `forever`.

---

## OIDC / OAuth 2.0 Single Sign-On (SSO)

Configure SSO under **Admin → Authentication & SSO**. SSH Console uses the **Authorization Code Flow with PKCE (`S256`)** and supports any standards-compliant IdP (Keycloak, Authentik, Microsoft Entra ID, Google Workspace, Okta, GitLab, Zitadel, etc.).

### Setup Steps

1. Set **Public URL** to your external HTTPS address (e.g. `https://ssh.example.net`).
2. Copy the displayed **Callback URL** (`https://ssh.example.net/api/auth/sso/callback`) and register it as an allowed Redirect URI in your Identity Provider.
3. Enter the **Issuer URL** (e.g. `https://idp.example.net/realms/infra`) and click **Auto-Discover** to populate the Authorization, Token, and Userinfo endpoints automatically (or enter them manually).
4. Enter **Client ID**, **Client Secret** (encrypted at rest via AES-256-GCM), **Provider Display Name**, and **Scopes** (default: `openid profile email`).
5. Optional: Enable **Auto-create users on first SSO login** (newly created accounts always receive the standard user group, never `admin`).
6. Save settings and click **Test SSO Connection** to verify a real sign-in handshake.

### Anti-Lockout Protection

You can only enable **Disable local username/password login** *after* a successful live SSO test has been recorded (`ssoTestedAt`). This guarantees administrators cannot accidentally lock themselves out due to a misconfigured IdP.

---

## Two-Factor Authentication (2FA)

Under **Admin → Authentication & SSO**, administrators can:
- **Enable 2FA**: Allow users to protect their local login with 2FA.
- **Enforce 2FA**: Require all local-password users to configure 2FA immediately after login before accessing the Dashboard, SSH Shell, servers, commands, or certificates.

### Supported Second Factors

Users configure their factors under **Account & Security**:
1. **Authenticator App (TOTP)**
   - Standard RFC 6238 6-digit codes (compatible with Google Authenticator, Bitwarden, 1Password, KeePassXC, Aegis, etc.) via QR code or manual secret.
   - Generates **one-time recovery codes** upon activation (stored hashed; each code can be used once).
2. **Hardware Security Keys (FIDO2 / WebAuthn)**
   - Register one or multiple USB/NFC security keys (e.g. YubiKey, SoloKey, Nitrokey).

---

## Passwordless Passkeys (WebAuthn)

Administrators can independently **enable** and optionally **enforce** Passkeys:
- Users register discoverable WebAuthn credentials (Touch ID, Windows Hello, Android/iOS Passkeys, Bitwarden/1Password Passkeys, or resident FIDO2 keys) under **Account & Security**.
- On the login screen, users can sign in directly with **Sign in with Passkey**—no password required.
- Multiple passkeys per account can be registered, renamed, audited by last-used timestamp, and revoked individually.

> **Requirement:** WebAuthn (Security Keys & Passkeys) requires a secure context (`https://` with a valid certificate, or `http://localhost` during local development). Always set the matching **Public URL** under Admin → Authentication & SSO when running behind a reverse proxy.

---

Next: **[Dashboard, Auto-Ping & BMC](./dashboard-ping-bmc.html)**
