# Known Limitations & Operating Boundaries

**Application:** Universal System Security & Intelligence CLI (`systemscan`)  
**Phase:** 11 of 13 — Production QA, Security Audit & Cross-Platform Hardening  
**Last Updated:** 2026-11-08  

---

## 1. Scope & Design Philosophy

`systemscan` is designed as a secure, non-destructive, cross-platform system intelligence and security CLI. To guarantee system stability and user privacy, certain technical boundaries and operating limitations are intentional architectural constraints.

---

## 2. Privilege & Permission Boundaries

### 2.1. Unprivileged (Non-Root / Non-Admin) Execution
- **System Information:** When run as a standard non-root user (Linux/macOS) or un-elevated user (Windows), `systemscan` collects all user-accessible system, hardware, and filesystem metrics.
- **Protected Filesystem Locations:** Traversal of restricted system directories (e.g. `/root`, `/var/log/audit`, `C:\System Volume Information`, `C:\Windows\System32\config`) will encounter `PermissionError`. The crawler records these as `SKIPPED_PERMISSION` in the traversal summary and continues scanning without terminating.
- **Process & Socket Visibility:** On Linux, unprivileged users cannot inspect the socket descriptors or command lines of processes owned by other users (`/proc/<pid>/net` and `/proc/<pid>/cmdline` restrictions).
- **Remediation / Guidance:** Run `systemscan` with administrative privileges (`sudo systemscan ...` or "Run as Administrator") when an exhaustive audit of system-wide root processes is required.

### 2.2. Symbolic Links & Junctions
- **Windows Symlinks:** Creation of symbolic links requires `SeCreateSymbolicLinkPrivilege` or Windows Developer Mode. `systemscan` defaults to `follow_symlinks=False` during traversal and never creates symlinks.
- **Symlink Quarantine:** The quarantine engine strictly refuses to move or quarantine symbolic links or junctions to prevent redirect attacks against sensitive files.

---

## 3. Hardware Inspection Limitations

### 3.1. Disk S.M.A.R.T. Health Data
- Reading direct S.M.A.R.T. disk attributes requires OS kernel drivers or external diagnostic tools (`smartctl` on Linux/macOS, WMI/NVMe storage drivers on Windows).
- If S.M.A.R.T. drivers or privileges are absent, `systemscan` gracefully falls back to reporting volume usage, free space, and device identifiers without failing.

### 3.2. Temperature & Thermal Sensors
- Sensor availability depends on motherboard chipset support and driver accessibility (e.g., `coretemp`, `lm-sensors`, or ACPI). In virtual machines (VMware, VirtualBox, WSL2, cloud instances), thermal sensors are typically not exposed by the hypervisor and return `None`.

---

## 4. Threat Detection & Malware Analysis Boundaries

### 4.1. Heuristic and Entropy Scoring
- **Compressed & Encrypted Files:** High Shannon entropy (> 7.5) occurs naturally in encrypted volumes, compressed archives (`.zip`, `.gz`, `.xz`), high-definition video files, and compiled binary blobs.
- **Design Bound:** High entropy is treated solely as a heuristic indicator (`HIGH_ENTROPY_PACKED`) contributing to the aggregate suspicious score; it will NEVER trigger a confirmed `malware` verdict on its own.
- **Zero Dynamic Execution:** `systemscan` never executes, sandboxes, or dynamically traces suspicious files. Detection is strictly static (SHA-256 signatures, PE header validation, byte patterns, and heuristic rules).

### 4.2. In-Memory / Fileless Malware
- Fileless malware residing solely in volatile process memory or injected threads is not detected by filesystem-based static scans. Phase 12/13 advanced behavioral monitors will provide real-time memory scanning extensions.

---

## 5. Storage Cleanup & Deletion Boundaries

### 5.1. Non-Destructive Invariant
- `systemscan` NEVER cleans or deletes files automatically during analysis or scan workflows.
- Cleanup requires a two-step human-in-the-loop workflow:
  1. Generate preview: `systemscan storage preview`
  2. Execute cleanup: `systemscan storage clean --preview-id <ID> --confirm`
- Files modified within 2 seconds of preview generation (TOCTOU guard) or resolving into `CRITICAL_SYSTEM_PATHS` are automatically aborted and skipped.

---

## 6. Self-Update & Dependency Management

### 6.1. Environment Write Permissions
- The self-update mechanism (`systemscan update install`) requires write access to the Python environment (`sys.prefix` or active virtualenv).
- In system-managed package installations (e.g., system `/usr/bin/python3` on Debian/Ubuntu managed by `dpkg`/`apt`), running `systemscan update` may fail if the environment is externally managed (PEP 668). In such environments, updates should be managed through the system package manager or an isolated `pipx` / virtualenv install.

