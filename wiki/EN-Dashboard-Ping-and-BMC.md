> [🏠 Home](Home) · [🇩🇪 Deutsche Version](DE-Dashboard-Ping-und-BMC)

# Dashboard, Auto-Ping & BMC Monitoring

The **Dashboard** gives you real-time visibility into your entire server fleet, BMC interfaces, and batch SSH execution—engineered to scale cleanly from **10 servers to 1,000+ servers**.

---

## Scalable Auto-Ping Engine

### 1. Evenly Staggered Pacing (Zero Network Bursts)

Instead of firing pings to all servers simultaneously at the start of every cycle, SSH Console distributes probes **evenly across the configured interval `T`**:

$$\text{Launch time}(i) = \text{CycleStart} + \left\lfloor \frac{i \cdot T}{N} \right\rfloor$$

- Servers are sorted deterministically by ID so **every individual IP is still checked at its exact configured interval `T`**, while network traffic stays smooth and constant:
  - **10 IPs @ 60 s interval**: ~1 ping every **6.0 s**
  - **1,000 IPs @ 60 s interval**: ~1 ping every **60 ms** (~16.7 pings/sec steady instead of a 1,000-ping spike)
- **Bounded Concurrency & Overlap Protection**:
  - Automatic pings run with at most **32 concurrent probes**, preventing socket/file-descriptor or process exhaustion even if many targets time out.
  - If a previous probe for a specific IP is still in flight, duplicate overlapping pings for that IP are skipped.
  - Manual **"Check All"** also uses bounded concurrency (**max 24 concurrent**, with a mild launch stagger when > 20 IPs).
  - Changing the interval or disabling global auto-ping immediately aborts any in-progress cycle.
- **Dashboard Indicator**: When more than one IP is scheduled, the **Auto-Ping KPI card** displays the live pacing rate (e.g. `Paced: ~1 IP every 6.0 s` or `~1 IP every 60 ms`).

### 2. Adaptive Offline Backoff

To avoid wasting bandwidth and timeout slots on hosts that are powered down or permanently offline, SSH Console tracks consecutive failed pings per IP:

- **Automatic Slowdown**: Once an IP fails `pingOfflineThreshold` times in a row (default: **`5`**), its check interval is automatically multiplied by `pingOfflineMultiplier` (default: **`× 5`**, e.g. `60 s → 5 min / 300 s`, capped at `24 h`).
- **Instant Recovery Reset**: The moment **any** automatic **or manual** ping succeeds (`Online`), the failure counter resets to `0` and the IP immediately returns to the standard interval.
- **Admin Controls**: In the Dashboard's **Auto-Ping Controls** bar, administrators can configure:
  - **Interval (sec)**: `10–3600` (default `60`)
  - **After `X` × offline**: `0–100` (default `5`; set to `0` to disable backoff)
  - **Multiplier (`→ × Y`)**: `2–60` (default `5`)
- **Visual Feedback**:
  - Offline rows show the consecutive failure count (`Offline (5×)`) and, when throttled, an amber badge (e.g. `every 5 min`).
  - The Auto-Ping KPI card summarizes how many offline IPs are currently in extended backoff (e.g. `12 offline IPs at 5 min backoff`).

### 3. Auto-Ping Switches vs. Manual Checks

Three independent switches control **periodic auto-ping only**:
1. **Global switch (Admin)**: `Disable / Enable auto-ping globally` in the Dashboard control bar.
2. **Account switch (User)**: `Enable periodic auto-ping for my account`.
3. **Per-IP switch (User)**: Toggle auto-ping individually per server in the server list or under **My Servers (IPs)**.

> **Manual checking always works:** Even when global, account, or per-IP auto-ping is disabled, clicking **Check** (single IP) or **Check All** always executes a live ping and updates the status.

### 4. Ping Method & Last-Online Timestamp

- **Method**: Uses native ICMP `/bin/ping -c 1 -W 2` (IPv4 and IPv6) with automatic fallback to a TCP connect check on the server's SSH port if `ping` is unavailable or lacks `CAP_NET_RAW`.
- **Last Online**: Every server persistently stores `lastOnlineAt` (the timestamp of the most recent successful ping), displayed directly under the ping status in each table row.

---

## Categories, Filtering & Pagination

- **Server Categories**: Create custom categories under **My Servers (IPs)** (or inline when adding/editing a server) and assign **one or multiple categories** to each server.
- **Dashboard Category Filter Bar**:
  - Click one or more category chips (or **Uncategorized**) to filter the fleet.
  - When two or more categories are selected, switch between **`ANY` (OR)** and **`ALL` (AND)** matching.
  - Click any category tag directly on a server row to toggle that filter.
- **Combined Search & Status Filter**: Combine category filters with **All / Online / Offline** pills and free-text search (label, IP, BMC IP, SSH user, notes, categories).
- **Pagination**: Choose **`10`**, **`20`**, **`50`**, or **`All`** servers per page (persisted in your browser). Selection checkboxes work cleanly per page or across filtered views.

---

## Dual BMC Monitoring (`BMC 1` & `BMC 2`)

- Each server supports up to **two out-of-band management IPs** (`BMC 1` and optional `BMC 2` for redundant IPMI/iDRAC/iLO interfaces).
- Click the IP link to open `https://<bmc-ip>` in a new tab.
- Click the shield/check button to run a server-side **HTTPS Port 443** reachability check (accepts self-signed BMC TLS certificates and reports HTTP status + latency).
- When two BMC IPs are configured, a compact dropdown lets you switch between `BMC 1` and `BMC 2` right in the row.

---

## Quick Select & Batch Execution

1. In the **Quick Select & Batch Execution** bar at the top of the Dashboard:
   - Select the **SSH Command** (single command or command chain).
   - Select the **SSH Certificate / Keypair**.
   - If the selected private key is passphrase-protected and has no stored passphrase, an unlock input appears automatically for entering the passphrase for this run.
2. Check the desired target servers in the table below (or use **Select All** on the current page).
3. Click **Dispatch Batch** to execute in parallel across all selected targets.
4. **Immediate Results View**: Execution results (`stdout`, `stderr`, exit code, duration, and collapsible SSH command details) appear **directly below the Quick Select bar and above the IP list**, so you never have to scroll past hundreds of servers to read command output.
