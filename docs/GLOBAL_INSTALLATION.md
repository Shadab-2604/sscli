# Global Terminal Installation & Execution Guide

This guide details how to install and execute **SSCLI** (`systemscan`) as a first-class, globally accessible command across **Windows**, **Linux**, and **macOS**.

Once installed, running:
```bash
systemscan
```
from **any terminal** and **any directory** will immediately display the compact CLI welcome screen and interactive numbered menu without requiring manual navigation, virtual environment activation, or running `python main.py`.

---

## 1. Quick Global Installation Options

### Method A: `pipx` (Recommended for Developers & Security Engineers)

[`pipx`](https://pypa.github.io/pipx/) installs Python CLI applications into isolated environments while exposing their command binaries globally on your `PATH`.

#### 1. Install via local source repository:
```bash
# From within the cloned repository
pipx install .
```

#### 2. Install directly from GitHub:
```bash
pipx install git+https://github.com/Shadab-2604/sscli.git
```

#### 3. Verify PATH:
```bash
pipx ensurepath
```

Now open a new terminal window and run:
```bash
systemscan
```

---

### Method B: Automated Installation Scripts (Linux & macOS)

The repository provides an automated installation script that detects your active shell, sets up an isolated environment, and creates a global launcher shim in `~/.local/bin`.

```bash
# Clone the repository
git clone https://github.com/Shadab-2604/sscli.git
cd sscli

# Run the installer
chmod +x scripts/install.sh
./scripts/install.sh --global
```

The installer performs the following operations:
1. Validates Python 3.10+ availability.
2. Creates an isolated environment in `~/.local/share/systemscan/venv`.
3. Installs core dependencies and the `systemscan` package.
4. Symlinks or creates the executable launcher at `~/.local/bin/systemscan`.
5. Checks if `~/.local/bin` is in your shell's `PATH` and advises on adding it if missing.

#### Adding `~/.local/bin` to PATH (if required):
- **Bash** (`~/.bashrc`):
  ```bash
  export PATH="$HOME/.local/bin:$PATH"
  ```
- **Zsh** (`~/.zshrc`):
  ```bash
  export PATH="$HOME/.local/bin:$PATH"
  ```
- **Fish** (`~/.config/fish/config.fish`):
  ```fish
  fish_add_path ~/.local/bin
  ```

---

### Method C: Automated Installation Script (Windows 10 & 11)

On Windows, `scripts/install.ps1` configures an isolated environment and establishes global command shims.

```powershell
# Clone the repository
git clone https://github.com/Shadab-2604/sscli.git
cd sscli

# Run installer with Global flag
powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -Global
```

The Windows installer:
1. Validates Python 3.10+ 64-bit installation.
2. Initializes an isolated virtual environment (`.venv`).
3. Installs package dependencies via `pip install -e .`.
4. Detects directories in your user `PATH` (such as `C:\Users\<User>\AppData\Local\Python\bin` or `C:\Users\<User>\AppData\Local\Microsoft\WindowsApps`).
5. Places `systemscan.cmd` and `systemscan.ps1` into the global user directory.

---

### Method D: Android (Termux) & Kali NetHunter Installation

SSCLI natively supports Android environments via **Termux** and **Kali NetHunter** (rootless, chroot, or rooted).

#### 1. Running on Termux (Android)
Open Termux and execute:
```bash
pkg update && pkg install python python-pip git -y
git clone https://github.com/Shadab-2604/sscli.git
cd sscli
chmod +x scripts/install.sh scripts/systemscan
./scripts/install.sh

# Or link the runner directly into Termux bin for global access:
ln -sf $(pwd)/scripts/systemscan $PREFIX/bin/systemscan

# Run from ANY directory in Termux:
systemscan
```

#### 2. Running on Kali NetHunter (Android)
Inside your Kali NetHunter terminal or chroot:
```bash
sudo apt update && sudo apt install python3 python3-pip python3-venv git -y
git clone https://github.com/Shadab-2604/sscli.git
cd sscli
chmod +x scripts/install.sh scripts/systemscan
./scripts/install.sh

# Run from anywhere:
systemscan
```

### Method D: Manual Global Shim Creation

If you have already created a virtual environment in `c:\D-drive\code\sscli\.venv` (or `/path/to/sscli/.venv`):

#### On Windows (Command Prompt / PowerShell):
Create `systemscan.cmd` inside any folder currently in your `%PATH%` (e.g. `%LOCALAPPDATA%\Python\bin\systemscan.cmd`):
```cmd
@echo off
"c:\D-drive\code\sscli\.venv\Scripts\python.exe" -m systemscan.cli %*
```

#### On Linux / macOS:
Create `~/.local/bin/systemscan`:
```bash
#!/usr/bin/env bash
exec "/path/to/sscli/.venv/bin/python" -m systemscan.cli "$@"
```
Make it executable:
```bash
chmod +x ~/.local/bin/systemscan
```

---

## 2. Command Execution Modes

Once installed globally, `systemscan` supports two primary execution modalities:

### 1. Interactive Command Line Interface (Default)
When run without subcommands from an interactive terminal (TTY):
```bash
systemscan
# or explicitly:
systemscan dashboard
```
Displays a clean, professional welcome screen and numbered interactive menu (`1` to `12`, `0` to Exit) with real-time in-line scan progress.

### 2. Direct Subcommand Execution
All subcommands remain directly executable for scripting, automated pipelines, or quick CLI queries:
```bash
# General diagnostics
systemscan --help
systemscan --version
systemscan doctor
systemscan info

# Security & filesystem scans
systemscan scan --quick
systemscan scan --full
systemscan scan --path /path/to/directory

# Reports & exports
systemscan reports list
systemscan reports show --latest
systemscan reports export --format json --output report.json

# Network & devices
systemscan network firewall
systemscan network interfaces
systemscan devices list
```

---

## 3. Terminal Safety & Non-Interactive Fallbacks

`systemscan` includes built-in safeguards to ensure scripts, CI pipelines, and piped commands do not hang:
- **TTY Detection**: If `sys.stdin` or `sys.stdout` is not an interactive terminal (e.g., inside cron, headless CI, or `systemscan | grep ...`), `systemscan` gracefully outputs help instructions rather than attempting to render a fullscreen TUI.
- **Unprivileged Safety**: No administrative or root access is required for standard diagnostics or interactive navigation.
- **Non-Destructive Invariants**: Scanning engines operate strictly read-only. No files are altered, quarantined, or removed without explicit multi-stage user confirmation.

---

## 4. Verification & Health Diagnostics

To verify that your global installation is operating correctly:

```bash
# 1. Verify global resolution from outside the project directory
cd ~
systemscan --version

# 2. Run the environment doctor
systemscan doctor

# 3. Test non-interactive information query
systemscan info
```

---

## 5. Uninstallation

To remove `systemscan` globally:

### If installed via `pipx`:
```bash
pipx uninstall systemscan
```

### If installed via user launcher shims:
- **Windows**: Delete `systemscan.cmd` and `systemscan.ps1` from your `%LOCALAPPDATA%\Python\bin` or chosen PATH directory.
- **Linux/macOS**: Delete `~/.local/bin/systemscan`.

User configurations in `~/.config/systemscan` and audit reports in `~/.local/share/systemscan/reports` (or Windows `%APPDATA%\systemscan`) are preserved by default unless manually deleted.

