---
title: Troubleshooting & FAQ
lang: en
alt_url: /de/fehlerbehebung.html
---

# Troubleshooting & FAQ

---

## SSH Execution & Host Keys

### `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!`
- **Cause**: The target server's SSH host key changed (typically after an OS reinstall, VM rebuild, or IP reassignment).
- **Fix**: Verify the change is legitimate, then click **Reset Host Key** for that server in **My Servers (IPs)** (or purge it as an admin under **Admin → Authentication & SSO → Known Hosts**). On the next connection, the new host key will be trusted automatically.

### Command fails with `Passphrase erforderlich` / `Passphrase required`
- **Cause**: The selected private key is passphrase-encrypted and has no passphrase stored in SSH Console.
- **Fix**: Either enter the passphrase in the unlock field on the **Dashboard** / **SSH Shell** right before running, or save the passphrase encrypted under **SSH Keys & Certificates → Passphrase** (if permitted by your user group).

### `Permission denied (publickey)` when using a 3-file certificate
- Check on **SSH Keys & Certificates** that the certificate is **not expired** (`validBefore`) and that the server's **SSH User** (e.g. `root` or `deploy`) is listed in the certificate's **Principals (`-n`)**.
- Verify `/etc/ssh/sshd_config` on the target server contains `TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub`, that its contents match the `ca.pub` from **Admin → CA Certificates**, and that `sshd` was reloaded.

---

## Certificates, CA Signing & Automatic Re-Certification

### Password or certificate passphrase is rejected
- **Cause**: The password complexity policy is not satisfied.
- **Fix**: Use at least **8 characters** and satisfy at least **3 of 4 character classes** (lowercase letters, uppercase letters, digits, special characters). This policy applies to user account passwords, certificate passphrases, and CA passphrases.

### Warning: “Existing `zertifikat-cert.pub` was signed by a different CA”
- **Cause**: One or more selected certificates already have a `zertifikat-cert.pub` whose CA fingerprint does not match the CA you selected for signing.
- **Fix**: Confirm that switching to the new CA is intended, then tick the confirmation checkbox in the warning box to allow overwriting.

### Automatic re-certification cannot be enabled or stopped automatically
- **Common causes**:
  - The chosen CA does **not have a stored passphrase on the server** (configure under **Admin → CA Certificates**).
  - The signature validity (`-V`) is set to **`forever`** (non-expiring certificates do not renew).
  - The user's group lacks **Self-signing** or **Allow automatic re-certification**, or the CA was unassigned from the group.
  - The certificate was manually replaced/uploaded, or the enabling administrator was deactivated or demoted.
- **Fix**: The exact revocation reason is shown directly on the certificate card. Once the group policy or stored CA passphrase is restored, re-sign the certificate with automatic re-certification checked.

### Saving a group fails due to an invalid auto-renewal lead time
- **Cause**: The configured per-group/per-CA auto-renewal lead time is greater than or equal to the signature validity (`-V`).
- **Fix**: Choose a lead time strictly shorter than the signature validity (for example, for `+24h` validity choose `6 hours` or `Automatic 20% before expiry`).

---

## Interactive SSH Shell

### WebSocket disconnects immediately or fails behind Nginx/Apache
- Ensure your reverse proxy forwards `Upgrade` and `Connection: upgrade` headers and has a long `proxy_read_timeout` (e.g. `3600s`). See [Installation & Docker](./installation.html#reverse-proxy-configuration-https--websockets).
- Serve SSH Console over HTTPS and configure **Public URL** with `https://...`.

---

## Ping Dashboard & BMC

### Dashboard shows `tcp-ping` instead of `icmp-ping`
- **Cause**: Either `/bin/ping` is not installed, or the process lacks ICMP permission (common inside restricted containers without `--cap-add=NET_RAW` or hardened systemd units with empty `CapabilityBoundingSet`).
- **Behavior**: SSH Console automatically falls back to a TCP connect probe on each server's SSH port (default `22`), which reliably confirms SSH reachability without needing raw sockets.

### Why is an offline IP checked less frequently than my configured interval?
- **Cause**: Adaptive **Offline Backoff** is active (default: after `5` consecutive offline pings, interval increases by `× 5`).
- **Fix**: As soon as the IP answers online again (auto or manual ping), it resets to the standard interval immediately. To adjust or disable backoff, set `After [0] × offline` in the Dashboard's **Auto-Ping Controls** bar (Admin only).

### Can I still ping a server manually if auto-ping is disabled?
- **Yes.** Global, account, and per-IP switches only pause *periodic* auto-ping. Clicking **Check** or **Check All** always runs an immediate reachability check.

---

## SSO, 2FA & Passkeys

### Passkeys or Security Keys fail to register or sign in
- WebAuthn requires **HTTPS** with a valid certificate (or `http://localhost` in development). Plain IP addresses over HTTP (e.g. `http://192.168.1.10:3000`) are rejected by browsers.
- Make sure **Admin → Authentication & SSO → Public URL** matches the exact origin in the browser address bar.

### SSO callback returns redirect URI mismatch
- Set **Public URL** under **Admin → Authentication & SSO** to your exact external URL (without trailing slash, e.g. `https://ssh.example.net`).
- Register `https://ssh.example.net/api/auth/sso/callback` verbatim in your Identity Provider.

### A user lost their 2FA device or Passkey
- Any administrator can go to **Admin → Users** and click **Reset 2FA / Passkeys** for that account. If 2FA/Passkeys are enforced, the user will be prompted to set them up fresh on their next login.

---

## Database & Vault

### What happens if `vault.key` is lost?
- **Critical:** `vault.key` encrypts all SSH private keys, managed CA private keys, stored key/CA passphrases, TOTP secrets, and the SSO client secret. If `vault.key` is lost and cannot be restored from backup, encrypted keys and CAs must be re-uploaded and 2FA/SSO secrets re-entered. Always back up `vault.key` alongside `ssh-console.sqlite`.
