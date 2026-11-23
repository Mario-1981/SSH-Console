---
title: Authentication, SSO, 2FA & Passkeys
lang: en
alt_url: /de/authentifizierung.html
---

# Authentication, SSO, 2FA & Passkeys

SSH Console is designed for internal infrastructure teams with strict access control: there is **no public self-registration**, and administrators can combine local passwords, **OIDC/OAuth 2.0 SSO**, **Two-Factor Authentication (TOTP & FIDO2)**, and **Passkeys**.

---

## Initial Setup & User Management

1. **One-Time Admin Setup**: On first launch, SSH Console presents the setup wizard to set the instance name and create the initial `admin` account. Immediately afterwards, `/api/setup` is permanently disabled.
2. **Creating Users**: Administrators manage all accounts under **Admin → Users**:
   - Create local users with `admin` or `user` role, display name, email, and default SSH username.
   - Activate/deactivate accounts or delete users.
   - Reset a user's 2FA/Passkey configuration with one click if a device is lost (`POST /api/admin/users/:id/reset-auth`).
3. **Resource Visibility & Sharing**:
   - All commands, servers, categories, certificates, and execution logs are **private** to their owner by default.
   - Administrators can share their own **commands**, **servers**, and **certificates** either with **all users** or with **selected users**.
   - Users can never view or export private keys or passphrases of shared certificates—they can only use them for SSH execution and shell sessions.

---

## OIDC / OAuth 2.0 Single Sign-On (SSO)

Configure SSO under **Admin → Authentication & SSO**. SSH Console uses the **Authorization Code Flow with PKCE (`S256`)** and supports any standards-compliant IdP (Keycloak, Authentik, Microsoft Entra ID, Google Workspace, Okta, GitLab, Zitadel, etc.).

### Setup Steps

1. Set **Public URL** to your external HTTPS address (e.g. `https://ssh.example.net`).
2. Copy the displayed **Callback URL** (`https://ssh.example.net/api/auth/sso/callback`) and register it as an allowed Redirect URI in your Identity Provider.
3. Enter the **Issuer URL** (e.g. `https://idp.example.net/realms/infra`) and click **Auto-Discover** to populate the Authorization, Token, and Userinfo endpoints automatically (or enter them manually).
4. Enter **Client ID**, **Client Secret** (encrypted at rest via AES-256-GCM), **Provider Display Name**, and **Scopes** (default: `openid profile email`).
5. Optional: Enable **Auto-create users on first SSO login** (newly created accounts always receive the standard `user` role, never `admin`).
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
