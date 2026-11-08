# Platform-Specific Installation & Setup Guide

**Application:** Universal System Security & Intelligence CLI (`systemscan`)  
**Specification:** CRITICAL REQUIREMENT — TRUE CROSS-PLATFORM COMPATIBILITY  
**Version:** 1.0.0  
**Supported Platforms:** Kali Linux, Windows 10, Windows 11, macOS Intel, macOS Apple Silicon, Ubuntu, Debian, Fedora, Arch  

---

## 1. General Prerequisites & Execution Policy

### Python Runtime Requirements
`systemscan` requires **Python 3.10** or newer (Python 3.12+ recommended).

### Non-Root / Non-Administrator Philosophy
`systemscan` is architected to operate safely as a standard, unprivileged user. You do **NOT** need root or administrator privileges for:
- Basic system information and hardware inspection.
- Filesystem scanning and metadata traversal across user-accessible directories.
- User-space temporary and cache storage analysis.
- Unprivileged socket and network connection auditing.
- Report generation (JSON, CSV, TXT) and export.

> [!IMPORTANT]
> **When are elevated privileges necessary?**
> Elevated privileges (`sudo` on Linux/macOS or "Run as Administrator" on Windows) are only needed if you want to inspect:
> 1. Other users' processes or kernel-level thread information.
> 2. Restricted system directories (e.g. `/root`, `/var/log/audit`, `C:\Windows\System32\config`).
> 3. Raw hardware registers or kernel firewall filtering rules (e.g., `nftables` or WMI storage drivers).

---

## 2. One-Command Automated Installation (Recommended)

`systemscan` includes automated, safe installation scripts that validate prerequisites, create an isolated virtual environment, and verify CLI entry points without touching global system Python.

### Linux and macOS (Bash / Zsh):
```bash
git clone https://github.com/Shadab-2604/sscli.git
cd sscli

# Run the safe installer (provisions .venv and verifies systemscan entry point)
bash scripts/install.sh
```

### Windows (PowerShell):
```powershell
git clone https://github.com/Shadab-2604/sscli.git
cd sscli

# Run the safe Windows installer
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

---

## 3. Dedicated Target: Kali Linux Installation Guide

Kali Linux systems follow Debian packaging guidelines with Python 3.11+ pre-installed.

### Step 1: Install System Dependencies
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip git
```

### Step 2: Clone and Provision Virtual Environment
```bash
git clone https://github.com/Shadab-2604/sscli.git
cd sscli
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Package
```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

### Step 4: (Optional) Install Security Utilities for Enhanced Auditing
Kali users can leverage native security utilities:
```bash
sudo apt-get install -y nmap yara ufw
```

### Step 5: Verify CLI and Platform Matrix
```bash
systemscan --version
systemscan doctor
```
*(The doctor output will identify the host as `Kali Linux` and display the capability matrix).*

---

## 4. Dedicated Target: Windows 10 Installation Guide

Windows 10 environments require PowerShell 5.1+ or PowerShell 7+, and standard Python 3.10+.

### Step 1: Install Python Runtime
Download Python 3.12 from [python.org](https://www.python.org/downloads/windows/) or install via winget:
```powershell
winget install Python.Python.3.12
```
*Ensure "Add python.exe to PATH" is checked during setup.*

### Step 2: Clone Repository
```powershell
git clone https://github.com/Shadab-2604/sscli.git
cd sscli
```

### Step 3: Configure Execution Policy & Create Virtual Environment
```powershell
# Set safe process-level execution policy for current terminal session
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

# Create isolated venv
py -m venv .venv
.venv\Scripts\Activate.ps1
```

### Step 4: Install Package
```powershell
python -m pip install --upgrade pip
python -m pip install -e .
```

### Step 5: Verify Installation
```powershell
systemscan --version
systemscan doctor
```
*(The doctor output will identify the host as `Windows 10` and display Win32 ACL and service capabilities).*

---

## 5. Dedicated Target: Windows 11 Installation Guide

Windows 11 benefits from Windows Terminal, modern WMI providers, and enhanced security profiles.

### Step 1: Install Python Runtime
```powershell
winget install Python.Python.3.12
```

### Step 2: Clone Repository
```powershell
git clone https://github.com/Shadab-2604/sscli.git
cd sscli
```

### Step 3: Create & Activate Virtual Environment
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
py -m venv .venv
.venv\Scripts\Activate.ps1
```

### Step 4: Install Package
```powershell
python -m pip install --upgrade pip
python -m pip install -e .
```

### Step 5: Verify Installation
```powershell
systemscan --version
systemscan doctor
```
*(The doctor output will identify the host as `Windows 11` with build >= 22000).*

---

## 6. Dedicated Target: macOS Intel (x86_64) Installation Guide

For Intel-based MacBooks, Mac mini, and iMac systems:

### Step 1: Install Python Runtime via Homebrew
```bash
# Install Homebrew if not already present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

brew install python@3.12 git
```

### Step 2: Clone Repository & Create Virtual Environment
```bash
git clone https://github.com/Shadab-2604/sscli.git
cd sscli
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Package
```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

### Step 4: Full Disk Access Configuration
To allow scanning system directories without encountering macOS TCC permission blocks:
1. Open **System Settings** → **Privacy & Security** → **Full Disk Access**.
2. Add your terminal emulator (**Terminal**, **iTerm2**, or **Ghostty**).
3. Restart your terminal emulator.

### Step 5: Verify Installation
```bash
systemscan --version
systemscan doctor
```
*(The doctor output will identify the host as `macOS Intel`).*

---

## 7. Dedicated Target: macOS Apple Silicon (arm64: M1/M2/M3/M4) Installation Guide

For modern Apple Silicon hardware, `systemscan` runs natively on ARM64 without requiring Rosetta 2 translation.

### Step 1: Install Native ARM64 Python via Homebrew
```bash
# Homebrew installs natively to /opt/homebrew on Apple Silicon
brew install python@3.12 git
```

### Step 2: Clone Repository & Create Virtual Environment
```bash
git clone https://github.com/Shadab-2604/sscli.git
cd sscli
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Package
```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

### Step 4: Full Disk Access Configuration
1. Open **System Settings** → **Privacy & Security** → **Full Disk Access**.
2. Enable your terminal application.

### Step 5: Verify Native Architecture & Platform Matrix
```bash
systemscan --version
systemscan doctor
```
*(The doctor output will identify the host as `macOS Apple Silicon` and verify native ARM64 execution).*

---

## 8. Other Linux Distributions (Ubuntu, Debian, Fedora, Arch)

### Ubuntu & Debian
```bash
sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip git
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

### Fedora Linux
```bash
sudo dnf install -y python3 python3-pip python3-devel git
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

### Arch Linux
```bash
sudo pacman -S --needed python python-pip git
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

---

## 9. Verification & Health Diagnostics

After installation, verify runtime health, permissions, and tool availability using the built-in diagnostic doctor:

```bash
systemscan doctor
```

The doctor audits:
- Active Python runtime and virtualenv status.
- Storage directories and write permissions (`config`, `data`, `reports`, `logs`).
- Core dependencies and version constraints.
- Optional system tools (`nmap`, `yara`, `powershell`, `ufw`).
- Dynamic platform capabilities & permission matrix across all 14 subsystem categories.

---

## 10. Safe Uninstallation & Data Preservation

To uninstall `systemscan` while preserving your configuration and historical scan reports:
```bash
systemscan uninstall
```

To perform a complete removal and purge all scan data, cache files, and logs:
```bash
systemscan uninstall --remove-data
```

Or using automated scripts:
- **Linux/macOS:** `bash scripts/uninstall.sh`
- **Windows:** `powershell -File scripts\uninstall.ps1`
