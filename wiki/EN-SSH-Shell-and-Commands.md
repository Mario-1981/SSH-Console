> [🏠 Home](Home) · [🇩🇪 Deutsche Version](DE-SSH-Shell-und-Befehle)

# SSH Shell, Commands & Host Keys

SSH Console provides both **interactive multi-tab SSH terminals** and a **structured catalog of reusable SSH commands and chains**, backed by full audit logging and OpenSSH host-key verification.

---

## Multi-Tab Interactive Browser SSH Shell

Open the **SSH Shell** tab to launch live, interactive OpenSSH PTY sessions directly in your browser using `xterm.js` over WebSockets:

- **Multiple Simultaneous Tabs**: Click **`+ New Tab`** to open as many parallel SSH sessions as needed (e.g. comparing logs across multiple nodes side by side).
- **Quick Switching & Status Indicators**: Each tab displays its server label/IP and live connection state (connected, connecting, disconnected), and can be reconnected or closed independently without affecting other tabs.
- **Saved Servers or Ad-Hoc IPs**: Connect either to any saved server (automatically filling IP, port, SSH user, and host-key preference) or type a custom IP/port/username on the fly.
- **Passphrase Support**: If you choose a passphrase-protected key without a stored passphrase, enter the passphrase in the tab's connection bar to unlock the key for that session (never saved to disk).
- **Automatic Terminal Resize**: Resizing the browser window dynamically updates the remote PTY rows and columns (`SIGWINCH`).

---

## SSH Commands & Multi-Step Command Chains

Manage commands under **SSH Commands**:

### Single Commands
- Store a single shell command (e.g. `systemctl status nginx --no-pager`, `df -h`, `uptime`), a category, description, and timeout (`5–600 s`).

### Command Chains
- Combine multiple sequential steps inside **one single SSH session** (ideal for maintenance workflows like draining a node, restarting a service, waiting, and verifying status).
- Each step supports an optional **Wait / `sleep` after step (seconds)**.
- Choose error handling:
  - **Stop on error (`&&`)**: Halts the chain immediately if any step returns a non-zero exit code.
  - **Continue on error (`;`)**: Runs all steps regardless of individual exit codes.

### Presets & Admin Sharing
- Load ready-made Linux diagnostics presets with one click.
- Commands are private to their creator; administrators can share commands with all users or selected accounts.

---

## SSH Host-Key Handling & Clean Output

SSH Console uses OpenSSH's `StrictHostKeyChecking=accept-new` with isolated per-user `known_hosts` files:

- **First Connection (TOFU — Trust On First Use)**: The server's host key is accepted and saved automatically.
- **Benign Warning Suppression**: Routine OpenSSH notices like:
  ```text
  Warning: Permanently added '10.28.193.239' (ED25519) to the list of known hosts.
  ```
  are automatically filtered from Dashboard command `stderr` output so successful executions stay clean.
- **Genuine Host-Key Changes Stay Visible**: If a server's SSH host key changes (e.g. after an OS reinstall or potential MITM attack), OpenSSH refuses the connection and displays the full **`WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!`** error clearly in the response window.
- **Resetting Known Host Keys**:
  - Users can reset a server's stored host key directly from their server settings (or via `POST /api/host-keys/reset`) after verifying a legitimate host rebuild.
  - Administrators can inspect and purge entries across users under **Admin → Authentication & SSO → Known Hosts**.
- **Optional Insecure Override**: For lab/ephemeral VMs, administrators can optionally allow per-server `Ignore host key` (`StrictHostKeyChecking=no`). Keep this disabled in production.

---

## Audit Log

Every single and batch SSH command execution is recorded in the **Audit Log**:

- Timestamp, executing user, target server/IP/port, SSH username
- Command name & executed command text
- Certificate name / Key ID
- OpenSSH invocation arguments (secrets/passphrases are never logged)
- Exit code, execution duration (`ms`), full `stdout`, and `stderr`

Standard users see only their own execution history; administrators can filter and inspect logs across all users.
