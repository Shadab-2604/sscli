# Troubleshooting & Diagnostic Guide

**Application:** Universal System Security & Intelligence CLI (`systemscan`)  
**Version:** 1.0.0

---

## 1. Quick Diagnostic: Running Environment Doctor

Whenever you encounter unexpected errors, missing features, or runtime warnings, start by running the automated diagnostic doctor:

```bash
systemscan doctor --verbose
```

The doctor tests Python runtime version, virtual environment health, write permissions on data directories, core dependencies, and optional external binaries.

---

## 2. Common Issues & Safe Resolutions

### 2.1. Python Not Found or Unsupported Python Version (< 3.10)
- **Symptoms:** `python: command not found`, `SyntaxError`, or installer aborts stating Python 3.10+ required.
- **Likely Cause:** System default Python is 3.8/3.9, or Python was installed without being added to PATH.
- **Diagnostic Command:**
  ```bash
  python3 --version || python --version || py -V
  ```
- **Safe Resolution:**
  - **Ubuntu / Debian / Kali:**
    ```bash
    sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip
    ```
  - **Fedora:**
    ```bash
    sudo dnf install -y python3 python3-pip
    ```
  - **Windows:** Download Python 3.12+ from [python.org](https://www.python.org/downloads/windows/). Ensure **"Add python.exe to PATH"** is selected.
  - **macOS:** Install Python via Homebrew (`brew install python@3.12`) or official PKG installer.

---

### 2.2. PowerShell Execution Policy Restriction on Windows
- **Symptoms:** `.venv\Scripts\Activate.ps1 cannot be loaded because running scripts is disabled on this system.`
- **Likely Cause:** Windows default execution policy restricts execution of unsigned PowerShell scripts.
- **Diagnostic Command:**
  ```powershell
  Get-ExecutionPolicy -List
  ```
- **Safe Resolution:**
  Apply `RemoteSigned` strictly to the current PowerShell process:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
  .venv\Scripts\Activate.ps1
  ```
  *(Alternative: Use Command Prompt and activate with `.venv\Scripts\activate.bat`)*
- **Security Guidance:** Do **NOT** set execution policy to `Unrestricted` or change MachinePolicy globally.

---

### 2.3. Permission Denied on Protected Directories
- **Symptoms:** Traversal outputs `[PermissionError]` or logs `SKIPPED_PERMISSION` for folders like `/root`, `/var/log/audit`, or `C:\System Volume Information`.
- **Likely Cause:** You are executing `systemscan` as an unprivileged user, and the targeted directory has operating system security access controls (ACLs/POSIX permissions).
- **Diagnostic Command:**
  ```bash
  ls -ld /path/to/target
  ```
- **Safe Resolution:**
  `systemscan` is designed to skip inaccessible files gracefully without terminating. If an audit of restricted system files is required, re-run with administrative elevation:
  - Linux/macOS: `sudo systemscan scan --path /restricted`
  - Windows: Launch PowerShell via **"Run as Administrator"** and execute command.
- **Security Guidance:** Never recursively change system folder permissions (`chmod -R 777`) to allow unprivileged scanning.

---

### 2.4. Missing `python3-venv` on Ubuntu / Debian
- **Symptoms:** `Error: Command '['.../.venv/bin/python3', '-Im', 'ensurepip', ...]' returned non-zero exit status 1.`
- **Likely Cause:** Debian and Ubuntu package Python's standard `venv` module in a separate package `python3-venv` that is not installed by default with minimal server images.
- **Diagnostic Command:**
  ```bash
  dpkg -l | grep python3-venv
  ```
- **Safe Resolution:**
  ```bash
  sudo apt-get update && sudo apt-get install -y python3-venv
  ```

---

### 2.5. Optional Binary Not Available (`nmap`, `yara`, `smartctl`)
- **Symptoms:** `systemscan doctor` flags external tools as `[NOT FOUND]` or `[OPTIONAL]`.
- **Likely Cause:** External system utilities are optional and not bundled with Python packages.
- **Diagnostic Command:**
  ```bash
  systemscan dependencies missing
  ```
- **Safe Resolution:**
  Install the optional tools via your system package manager:
  - **Linux (Ubuntu/Debian):** `sudo apt install -y nmap yara smartmontools`
  - **macOS (Homebrew):** `brew install nmap yara smartmontools`
  - **Windows (winget):** `winget install Insecure.Nmap`
- **Notice:** `systemscan` continues to operate completely without these tools; only advanced network probes or raw hardware SMART metrics require them.

---

### 2.6. Scan Interruption & Checkpoint Recovery Failure
- **Symptoms:** A long-running full system scan was interrupted (power loss or terminal kill), and `systemscan scan --resume` reports corrupt state.
- **Likely Cause:** Unclean shutdown while saving or filesystem unmounted while scan was active.
- **Diagnostic Command:**
  ```bash
  systemscan history list
  ```
- **Safe Resolution:**
  `systemscan` automatically quarantines malformed checkpoint JSON files to `<scan_id>.json.corrupt`. To view previous checkpoints or start an incremental scan:
  ```bash
  # Check if target paths are still mounted
  systemscan info
  # Start incremental scan leveraging prior cached fingerprints
  systemscan scan --path /target
  ```

---

### 2.7. Report Overwrite Error
- **Symptoms:** `ReportExporterError: Refusing to overwrite existing report file.`
- **Likely Cause:** An exported report with the same filename already exists at `--output`.
- **Safe Resolution:**
  Pass `--force` or `--overwrite` if you intend to replace the existing report:
  ```bash
  systemscan report export rep-abc12345 --output ./report.json --overwrite
  ```

---

### 2.8. Self-Update Verification Failure
- **Symptoms:** `UpdateSecurityError: Cryptographic checksum mismatch.`
- **Likely Cause:** Downloaded distribution archive is corrupted or tampered with.
- **Diagnostic Command:**
  ```bash
  systemscan update status
  ```
- **Safe Resolution:**
  `systemscan` rejects corrupted update packages automatically before extracting. To purge staging downloads and retry:
  ```bash
  systemscan update check --channel stable
  systemscan update download
  systemscan update verify
  ```
  If an installed update causes runtime issues, immediately roll back to the pre-update snapshot:
  ```bash
  systemscan update rollback
  ```

---

### 2.9. Full Disk Access Required on macOS
- **Symptoms:** `PermissionError` when scanning `~/Library` on macOS Sonoma or Sequoia.
- **Likely Cause:** macOS Transparency, Consent, and Control (TCC) subsystem blocks terminal access to user application storage.
- **Safe Resolution:**
  1. Open **System Settings** → **Privacy & Security** → **Full Disk Access**.
  2. Click **+**, add your terminal app (`Terminal.app` or `iTerm.app`), and enable the toggle.
  3. Restart the terminal application.

