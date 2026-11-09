# Command Line Interface (CLI) Reference

**Application:** Universal System Security & Intelligence CLI (`systemscan`)  
**Version:** 1.0.0  
**Binary Entry Points:** `systemscan` and `python -m systemscan`

---

## 1. Global Options & Interactive Mode

When invoked without subcommands in an interactive terminal (TTY), `systemscan` immediately launches the interactive terminal command center dashboard.

```bash
systemscan [OPTIONS] [COMMAND]
```

### Global Options:
| Flag | Short | Description | Default |
|---|---|---|---|
| `--version` | `-v` | Display application version and exit. | `False` |
| `--debug` | `-d` | Enable diagnostic debug mode with full exception tracebacks. | `False` |
| `--verbose` | | Enable informational logging output. | `False` |
| `--no-banner` | | Suppress ASCII/Rich startup header banner. | `False` |
| `--interactive` | `-i` | Explicitly launch interactive terminal dashboard. | `False` |
| `--help` | | Show usage help and command directory. | |

### 1.1. `systemscan dashboard`
Launches the interactive numbered CLI menu.
```bash
systemscan dashboard
```
Provides:
- Compact host summary: OS, CPU, RAM, system status.
- Numbered menu navigation (`1`–`12`, `0` to exit).
- Live real-time scan progress in standard terminal scrolling output.
- Clean prompts and non-intrusive terminal interaction.

---

## 2. System Intelligence & Telemetry Commands

### 2.1. `systemscan info` / `systemscan system-info`
Displays operating system release, kernel, architecture, hostname, uptime, active shell, and sanitized environment metrics.
- **Permissions:** Unprivileged user.
- **Options:**
  - `--format`: Output format (`text` or `json`).
- **Example:**
  ```bash
  systemscan info --format json
  systemscan system-info
  ```

### 2.2. `systemscan hardware`
Inspects host CPU, RAM, GPU, Motherboard/BIOS, and storage volumes.
- **Permissions:** Unprivileged user (BIOS serial numbers are redacted by default).
- **Options:**
  - `--show-serials`: Reveal unredacted hardware serial numbers.
  - `--format`: `text` or `json`.
- **Example:**
  ```bash
  systemscan hardware --format text
  ```

### 2.3. `systemscan processes`
Lists running processes with sub-second execution, sorted by CPU, memory, PID, or name.
- **Permissions:** Unprivileged (inspects user processes; root/admin displays all processes).
- **Options:**
  - `--limit` (`-n`): Max processes to display (default: 20).
  - `--sort-by` (`-s`): Sort field (`cpu`, `memory`, `pid`, `name`).
  - `--format`: `text` or `json`.
- **Example:**
  ```bash
  systemscan processes --sort-by cpu --limit 15
  ```

### 2.4. `systemscan services`
Audits background services and daemons (Windows SCM, Linux systemd, macOS launchd).
- **Permissions:** Unprivileged user.
- **Options:**
  - `--status`: Filter by state (`running`, `stopped`, `all`).
  - `--format`: `text` or `json`.
- **Example:**
  ```bash
  systemscan services --status running
  ```

### 2.5. `systemscan startup`
Discovers startup applications, persistence hooks, Windows Run keys, Linux cron/autostart, and macOS LaunchAgents.
- **Permissions:** Unprivileged user.
- **Options:**
  - `--format`: `text` or `json`.
- **Example:**
  ```bash
  systemscan startup --format json
  ```

### 2.6. `systemscan monitor`
Live, dynamic terminal telemetry dashboard with real-time updating meters for CPU, memory, and disk I/O.
- **Permissions:** Unprivileged user.
- **Options:**
  - `--interval` (`-i`): Refresh interval in seconds (default: 1.0).
  - `--cycles` (`-c`): Number of refresh cycles before exiting (0 for continuous).
- **Example:**
  ```bash
  systemscan monitor --interval 2.0 --cycles 30
  ```

---

## 3. Universal Filesystem & Device Commands

### 3.1. `systemscan scan`
Executes safe, read-only traversal and metadata inspection across target directory roots.
- **Permissions:** Unprivileged user.
- **Options:**
  - `--quick`: Fast heuristic scan of the user profile directory (max depth: 4).
  - `--full`: Comprehensive scan across all accessible storage volumes and mount points.
  - `--path` (`-p`): Target directory path (can be specified multiple times).
  - `--all-volumes`: Discover and scan all accessible logical drives or mounts.
  - `--max-depth`: Restrict traversal recursion depth (default: unlimited).
  - `--include-hidden` / `--no-hidden`: Toggle inclusion of dotfiles and hidden directories.
  - `--follow-symlinks`: Enable safe symlink following with cycle detection (default: false).
  - `--exclude` (`-e`): Exclude paths, directory names, or glob patterns.
  - `--format`: `text` or `json`.
- **Examples:**
  ```bash
  systemscan scan --quick
  systemscan scan --full
  systemscan scan --path /home/user/Documents --exclude "*.tmp" --exclude "node_modules"
  ```

### 3.2. `systemscan devices`
Inspects USB controllers, block devices, and removable storage inventory.
- **Subcommands:**
  - `list`: Enumerate all connected physical storage devices.
  - `inspect <device_id>`: Query detailed vendor, bus, partition, and mount metadata.
  - `monitor`: Launch real-time background watcher for USB plug/unplug events.
- **Example:**
  ```bash
  systemscan devices list --format json
  ```

---

## 4. Threat Detection & Security Audit Commands

### 4.1. `systemscan malware`
Evidence-based static malware detection engine. Uses streaming SHA-256 matching, PE header verification, byte signatures, and entropy heuristics.
- **Subcommands:**
  - `scan <path>`: Scan a file or directory tree for malware indicators.
  - `hashes`: Query or inspect local threat signature databases.
  - `quarantine list`: View files in isolated quarantine storage.
  - `quarantine restore <id>`: Restore a false positive file to its original path.
- **Example:**
  ```bash
  systemscan malware scan ~/Downloads --format text
  ```

### 4.2. `systemscan network`
Cross-platform network security audit and intelligence engine.
- **Subcommands:**
  - `interfaces`: Enumerate network adapters, MAC addresses, IPv4/IPv6, MTU, and gateways.
  - `sockets`: Audit active listening ports and inbound/outbound TCP/UDP connections.
  - `discovery`: Discover active hosts on the local subnet (ARP + bounded ping/TCP probe).
  - `dns`: Measure resolution latency, test DNS anomalies, and inspect configured resolvers.
  - `firewall`: Read-only audit of Windows Firewall, Linux UFW/nftables, or macOS socketfilterfw.
  - `wifi`: Inspect wireless SSID, signal quality, and authentication protocol (read-only).
  - `baseline capture`: Capture network baseline snapshot for drift detection.
  - `baseline diff <file>`: Compare current network state against a prior baseline.
  - `diagnostics`: End-to-end latency and reachability testing for Gateway, DNS, and Internet endpoints.
- **Example:**
  ```bash
  systemscan network sockets --format json
  ```

---

## 5. Storage Analyzer & Safe Cleanup Commands

### 5.1. `systemscan storage`
Multi-dimensional storage utilization analyzer.
- **Subcommands:**
  - `usage`: Summary of filesystem capacity and largest directory footprints.
  - `large`: Find files exceeding a specified size threshold (default: 100 MB).
  - `duplicates`: Detect identical duplicate files using quick-hash and full SHA-256 verification.
  - `extensions`: Group storage consumption by file extension.
  - `hidden`: Measure space consumed by hidden dotfiles and system directories.
- **Example:**
  ```bash
  systemscan storage large --min-size-mb 250 --path /var/log
  ```

### 5.2. `systemscan cache`
Inspects system temporary folders, package manager caches, and browser cache storage.
- **Subcommands:**
  - `scan`: Discover and calculate reclaimable cache volume.
  - `browser`: Specifically audit Chrome, Firefox, Edge, and Safari browser caches.
- **Example:**
  ```bash
  systemscan cache scan
  ```

### 5.3. `systemscan cleanup`
Non-destructive safe cleanup workflow with mandatory human confirmation.
- **Subcommands:**
  - `preview`: Generate preview of reclaimable cache candidates and assign a unique Preview ID.
  - `clean --preview-id <ID> --confirm`: Execute cleanup with TOCTOU modification timestamp guards.
  - `history`: Inspect persistent audit ledger of previous cleanup executions.
- **Example:**
  ```bash
  systemscan cleanup preview
  systemscan cleanup clean --preview-id prev-abc12345 --confirm
  ```

---

## 6. Reporting, History & Diagnostics Commands

### 6.1. `systemscan reports` / `report`
Unified multi-format report generation, inspection, and verification engine.
- **Options / Flags:**
  - `--latest`: Display the executive summary of the most recently generated report.
- **Subcommands:**
  - `list`: Enumerate all stored scan reports.
  - `show <report_id> [--latest]`: Display an executive summary of a report.
  - `export <report_id> --format [json|csv|txt]`: Export report to a designated file.
  - `verify <report_id>`: Verify cryptographic SHA-256 checksum manifest of a report file.
  - `delete <report_id>`: Safely delete an archived report file.
- **Examples:**
  ```bash
  systemscan reports list
  systemscan report --latest
  systemscan report export rep-abc12345 --format json --output report.json
  ```

### 6.2. `systemscan doctor`
Automated host environment diagnostic utility.
- **Audits:** Python version, 64-bit architecture, virtual environment status, storage directory write permissions, core dependency versions, and external binary availability (`nmap`, `yara`, `smartctl`).
- **Options:**
  - `--verbose` (`-v`): Show full paths and detailed dependency specs.
- **Example:**
  ```bash
  systemscan doctor --verbose
  ```

### 6.3. `systemscan dependencies` / `deps`
Inspect and manage application dependencies.
- **Subcommands:**
  - `list`: Display registered dependencies and current installed versions.
  - `missing`: List missing core or optional dependencies.
  - `verify`: Check whether installed packages satisfy version constraints.
  - `install <package>`: Safely install a dependency into the active virtual environment.
- **Example:**
  ```bash
  systemscan dependencies verify
  ```

### 6.4. `systemscan update` / `/update`
10-stage atomic self-update engine with automated backup and rollback.
- **Subcommands:**
  - `check`: Query remote distribution server for newer releases.
  - `status`: Show current version and update policy settings.
  - `download`: Download release asset into isolated staging area.
  - `verify`: Passively verify SHA-256 checksum and zip bomb/zip-slip defenses.
  - `install`: Execute 10-stage atomic update with pre-update snapshot backup.
  - `rollback`: Revert to the previous backup snapshot if an update is unsatisfactory.
  - `history`: View historical update transactions.
- **Example:**
  ```bash
  systemscan update check
  ```

### 6.5. `systemscan uninstall`
Safely uninstalls application components with user data preservation by default.
- **Options:**
  - `--remove-data`: Also purge all user configuration, reports, scan history, and logs.
  - `--dry-run`: Display all affected directories without modifying the filesystem.
  - `--yes` (`-y`): Bypass confirmation prompt.
- **Example:**
  ```bash
  systemscan uninstall --dry-run
  ```

