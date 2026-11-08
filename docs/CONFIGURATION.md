# Configuration Guide & Schema Reference

**Application:** Universal System Security & Intelligence CLI (`systemscan`)  
**Configuration File:** `config.json`  
**Format:** Strictly validated JSON adhering to Pydantic v2 data contracts.

---

## 1. Configuration Locations

`systemscan` stores its configuration file in the standard platform-appropriate directory resolved via `PlatformDirs`:

| Operating System | Default Configuration Directory | Default File Path |
|---|---|---|
| **Linux** | `~/.config/systemscan` | `~/.config/systemscan/config.json` |
| **Windows** | `%APPDATA%\systemscan` | `C:\Users\<User>\AppData\Roaming\systemscan\config.json` |
| **macOS** | `~/Library/Application Support/systemscan` | `~/Library/Application Support/systemscan/config.json` |

To inspect your current active configuration path:
```bash
systemscan config path
```

To display your active configuration settings in terminal:
```bash
systemscan config show
```

---

## 2. Complete Configuration Example

Below is a complete, production-safe `config.json` example matching all default settings (also available in [`examples/configuration/systemscan.json.example`](../examples/configuration/systemscan.json.example)):

```json
{
  "version": "1.0.0",
  "log_level": "INFO",
  "log_file_enabled": true,
  "max_log_size_mb": 5,
  "log_backup_count": 5,
  "interactive_menu": true,
  "enable_banner": true,
  "redact_hardware_serials": true,
  "redact_sensitive_paths": true,
  "performance": {
    "concurrency_mode": "adaptive",
    "max_workers": 4,
    "cpu_throttle_percent": 85.0,
    "memory_throttle_percent": 75.0,
    "battery_saver_enabled": true
  },
  "scan": {
    "default_roots": [],
    "max_depth": null,
    "include_hidden": true,
    "follow_symlinks": false,
    "hash_algorithm": "sha256",
    "max_file_size_mb": 500,
    "chunk_size_kb": 64,
    "exclude_extensions": [
      ".tmp",
      ".swp",
      ".bak"
    ],
    "exclude_directories": [
      ".git",
      ".svn",
      "node_modules",
      "__pycache__",
      ".venv"
    ]
  },
  "malware": {
    "enable_heuristics": true,
    "entropy_threshold": 7.5,
    "enable_pe_analysis": true,
    "max_scan_size_mb": 250,
    "quarantine_directory": null,
    "auto_quarantine": false
  },
  "network": {
    "default_timeout_seconds": 2.0,
    "max_cidr_hosts": 256,
    "allow_public_ip_scans": false,
    "enable_dns_diagnostics": true,
    "enable_wifi_audit": true
  },
  "reporting": {
    "default_format": "json",
    "enable_redaction": true,
    "retention_days": 90,
    "generate_checksum_manifest": true
  },
  "updates": {
    "channel": "stable",
    "auto_check": false,
    "auto_install": false,
    "verify_signatures": false,
    "check_interval_hours": 24,
    "max_backups": 3,
    "prefer_lockfile": true,
    "index_url": null
  }
}
```

---

## 3. Configuration Sections & Parameter Details

### 3.1. Top-Level Core Settings
- `version` (`string`): Schema version string. Used by configuration migrations.
- `log_level` (`string`): Logging verbosity. Options: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. Default: `INFO`.
- `log_file_enabled` (`boolean`): Whether to write structured logs to rotating log files. Default: `true`.
- `max_log_size_mb` (`integer`): Maximum size in MB before a log file rotates. Default: `5`.
- `log_backup_count` (`integer`): Number of historical rotated log backups to retain. Default: `5`.
- `interactive_menu` (`boolean`): Whether launching `systemscan` with no arguments opens the terminal dashboard. Default: `true`.
- `enable_banner` (`boolean`): Whether to print startup banner in interactive and text modes. Default: `true`.
- `redact_hardware_serials` (`boolean`): Masks physical hardware serial numbers in terminal and report outputs. Default: `true`.
- `redact_sensitive_paths` (`boolean`): Replaces user account names and home directory prefixes with `[REDACTED_USER]` in exported reports. Default: `true`.

### 3.2. `performance` Settings
- `concurrency_mode` (`string`): Execution scheduling policy. Options: `adaptive` (dynamically balances worker threads), `fixed` (fixed worker count), `sequential` (single-threaded for resource-constrained targets). Default: `adaptive`.
- `max_workers` (`integer`): Maximum worker threads for parallel file and network operations. Default: `4`.
- `cpu_throttle_percent` (`float`): When host CPU exceeds this percentage, worker threads throttle execution. Default: `85.0`.
- `memory_throttle_percent` (`float`): When system RAM exceeds this threshold, workers throttle to avoid OOM crashes. Default: `75.0`.
- `battery_saver_enabled` (`boolean`): When host battery drops below 20%, clamps concurrency to 1 thread to conserve power. Default: `true`.

### 3.3. `scan` Settings
- `default_roots` (`list[string]`): Default directory paths scanned when `--path` is omitted. Default: `[]` (current working directory).
- `max_depth` (`integer | null`): Maximum filesystem recursion depth. `null` permits unbounded traversal. Default: `null`.
- `include_hidden` (`boolean`): Whether traversal visits dotfiles (`.git`) and Windows hidden files. Default: `true`.
- `follow_symlinks` (`boolean`): Whether to follow symbolic links. Strict default: `false`. Safe follow mode enforces cycle detection.
- `hash_algorithm` (`string`): Cryptographic algorithm used for file integrity fingerprinting (`sha256` or `sha512`). Default: `sha256`.
- `max_file_size_mb` (`integer`): Files larger than this threshold skip full hashing to prevent I/O saturation. Default: `500`.
- `chunk_size_kb` (`integer`): Buffer chunk size for streaming file hashing. Default: `64`.
- `exclude_extensions` (`list[string]`): File extensions skipped during traversal.
- `exclude_directories` (`list[string]`): Directory names skipped during traversal.

### 3.4. `malware` Threat Settings
- `enable_heuristics` (`boolean`): Enables heuristic anomaly detection (packed entropy, suspicious section names). Default: `true`.
- `entropy_threshold` (`float`): Shannon entropy threshold above which binary sections are flagged as packed. Default: `7.5`.
- `enable_pe_analysis` (`boolean`): Enables static PE header inspection on Windows binaries. Default: `true`.
- `max_scan_size_mb` (`integer`): Upper limit on file size for in-depth signature inspection. Default: `250`.
- `auto_quarantine` (`boolean`): Strict default `false`. Quarantining requires explicit user command.

### 3.5. `network` Settings
- `default_timeout_seconds` (`float`): Socket connection and DNS query timeout. Default: `2.0`.
- `max_cidr_hosts` (`integer`): Maximum allowable host discovery count for CIDR probes. Default: `256` (clamps to `/24`).
- `allow_public_ip_scans` (`boolean`): Strict default `false`. Prohibits unauthorized port scanning of public Internet addresses.

### 3.6. `reporting` Settings
- `default_format` (`string`): Default output format for saved reports (`json`, `csv`, `txt`). Default: `json`.
- `enable_redaction` (`boolean`): Ensures privacy redaction policies apply to exported reports. Default: `true`.
- `retention_days` (`integer`): Retention lifespan before archived reports are eligible for automated cleanup. Default: `90`.
- `generate_checksum_manifest` (`boolean`): Automatically generates a `.sha256` manifest alongside saved reports. Default: `true`.

### 3.7. `updates` Settings
- `channel` (`string`): Update release channel (`stable`, `beta`, `dev`). Default: `stable`.
- `auto_check` (`boolean`): Checks for newer versions on launch. Default: `false`.
- `auto_install` (`boolean`): Automatically installs updates without confirmation. Strict default: `false`.
- `max_backups` (`integer`): Maximum pre-update snapshots retained for automated rollback. Default: `3`.

---

## 4. Configuration Migrations & Safety

When updating `systemscan` to a new version:
1. `ConfigMigrationManager` creates a pre-migration backup snapshot in the `backups/` directory.
2. The schema version is validated.
3. Any newly introduced configuration keys are added with their safe defaults.
4. Existing user customizations and preferences are strictly preserved without modification.
5. In the event of a migration parsing failure, the configuration reverts automatically to the pre-migration snapshot.

