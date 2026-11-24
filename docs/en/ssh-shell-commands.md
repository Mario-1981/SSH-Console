---
title: SSH Shell, Commands & Host Keys
lang: en
alt_url: /de/ssh-shell-befehle.html
---

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

### Command Chains (Simple)
- Combine multiple sequential steps inside **one single SSH session** (ideal for linear maintenance workflows like draining a node, restarting a service, waiting, and verifying status).
- Each step supports an optional **Wait / `sleep` after step (seconds)**.
- Choose error handling:
  - **Stop on error (`&&`)**: Halts the chain immediately if any step returns a non-zero exit code.
  - **Continue on error (`;`)**: Runs all steps regardless of individual exit codes.

### Complex Command Chains (JSON Workflows)
For branching automations with **if/then/else conditions**, **polling loops**, **runtime variables**, **output filtering**, and **structured formatting**, choose the **Complex Chain (JSON)** command type:

- **Runtime Variables (`inputs`) & Default Variables (`vars`)**:
  - Declare typed input parameters in the optional `inputs` array (`text`, `password`, `select` with `options`, `number`, `boolean`, `default`, `required`, `secret`) that are automatically prompted in the **Dashboard** before execution.
  - Static `vars` can also be overridden at runtime, and custom ad-hoc key/value variables can be added on the fly.
  - Variables of type `password` (or with `"secret": true`) are never persisted, cleared immediately after execution, and automatically redacted (`********`) in invocations and audit logs.
- **Step Types (`steps`)**:
  - `run`: Executes a remote SSH command (`id`, `command`, `continueOnError`, `sleepAfterSec`, `silent`, optional `filter`).
  - `sleep`: Pauses execution for `seconds` (`0–600`).
  - `if`: Evaluates `when` conditions (`all` / `any` / `not` combinators and operators such as `equals`, `notEquals`, `contains`, `matches`, `isEmpty`, `gt`, `gte`, `lt`, `lte` against `stdout`, `stderr`, `exitCode`, `ok`, `linesCount`, or variables) and branches into nestable `then` / `else` blocks.
  - `loop`: Repeats steps up to `maxIterations` (`1–120`) every `intervalSec` (`0–600`) seconds until an `until` condition matches (`onTimeout: "fail" | "continue"`).
  - `set` & `log`: Stores computed/filtered variables or appends custom log lines.
  - `stop` / `fail`: Exits the workflow early with a custom exit code and message.
- **Output Filtering (`filter`)**: Clean and transform step or final output using `trim`, `dropEmpty`, `include`, `exclude`, `regex` / `regexGroup` / `regexAll`, `replace`, `columns` + `delimiter`, `sort`, `unique`, `head`, `tail`, `prefix`, `suffix`, and `joinWith`.
- **Output Formatting (`output`)**:
  - `template` / `text`: Custom text template using placeholders.
  - `table`: Aligned ASCII table built from `rows`, `fields`, or `source` + `columns`.
  - `json`: Structured JSON output (`fields` + `autoType`).
  - `lines`: Filtered line list.
- **Placeholders & Editor Tooling**: Reference step outputs, runtime variables, and target metadata via {% raw %}`{{stepId.stdout}}`, `{{stepId.exitCode}}`, `{{last.stdout}}`, `{{vars.name}}`, `{{target.ip}}`, and `{{target.label}}`{% endraw %}. The UI includes **starter templates** (including Dell iDRAC Reset with `loop` + `inputs`), **live JSON validation**, **auto-formatting**, and a **structural execution preview**.

{% raw %}
```json
{
  "stopOnError": true,
  "inputs": [
    {
      "name": "service",
      "label": "Systemd Service",
      "type": "text",
      "default": "nginx",
      "required": true
    }
  ],
  "steps": [
    {
      "type": "run",
      "id": "check",
      "command": "systemctl is-active {{vars.service}}",
      "continueOnError": true,
      "filter": { "trim": true }
    },
    {
      "type": "if",
      "when": { "from": "check", "field": "stdout", "op": "notEquals", "value": "active" },
      "then": [
        { "type": "run", "id": "restart", "command": "systemctl restart {{vars.service}}" },
        { "type": "sleep", "seconds": 3 },
        { "type": "run", "id": "verify", "command": "systemctl is-active {{vars.service}}", "filter": { "trim": true } }
      ]
    }
  ],
  "output": {
    "format": "table",
    "headers": ["Property", "Value"],
    "rows": [
      { "label": "Host", "value": "{{target.label}} ({{target.ip}})" },
      { "label": "State", "value": "{{last.stdout}}" }
    ]
  }
}
```
{% endraw %}

### Presets & Admin Sharing
- Load ready-made Linux diagnostics presets (including a JSON workflow) with one click.
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

---

Next: **[Certificates, Passphrases & API](./certificates-api.html)**
