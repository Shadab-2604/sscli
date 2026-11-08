#!/usr/bin/env bash
# ==============================================================================
# Universal System Security & Intelligence CLI (systemscan) - Safe Installer
# Platform: Linux (Ubuntu, Debian, Kali, Fedora, Arch) and macOS
# ==============================================================================

set -euo pipefail

# Text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

MIN_PY_MAJOR=3
MIN_PY_MINOR=10
DEFAULT_VENV_DIR=".venv"
TARGET_VENV="${1:-$DEFAULT_VENV_DIR}"
DRY_RUN=false

for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN=true
            ;;
        --help|-h)
            echo "Usage: ./scripts/install.sh [OPTIONS] [VENV_DIR]"
            echo ""
            echo "Options:"
            echo "  --dry-run    Inspect prerequisites and plan installation without making changes."
            echo "  --help, -h   Show this help message."
            echo ""
            echo "Arguments:"
            echo "  VENV_DIR     Target directory for isolated virtual environment (default: .venv)"
            exit 0
            ;;
    esac
done

echo -e "${CYAN}${BOLD}=== SystemScan Safe Installer (Linux & macOS) ===${NC}"
echo "Starting installation pre-flight checks..."

# 1. Detect OS and Architecture
OS_TYPE="$(uname -s)"
ARCH_TYPE="$(uname -m)"
echo -e "Detected Platform: ${BOLD}${OS_TYPE}${NC} (${ARCH_TYPE})"

case "$OS_TYPE" in
    Linux)
        if [ -f /etc/os-release ]; then
            # shellcheck disable=SC1091
            . /etc/os-release
            echo -e "Distribution:     ${BOLD}${PRETTY_NAME:-Linux}${NC}"
        fi
        ;;
    Darwin)
        SW_VERS="$(sw_vers -productVersion 2>/dev/null || echo 'Unknown')"
        echo -e "macOS Version:    ${BOLD}${SW_VERS}${NC}"
        ;;
    *)
        echo -e "${YELLOW}Notice: Unrecognized UNIX-like OS ($OS_TYPE). Proceeding with standard POSIX checks.${NC}"
        ;;
esac

# 2. Check root privilege warning
if [ "$(id -u)" -eq 0 ]; then
    echo -e "${YELLOW}[!] Warning: Running as root is NOT recommended for package installation.${NC}"
    echo -e "${YELLOW}    SystemScan uses isolated virtual environments and does not need root to install.${NC}"
fi

# 3. Discover Python 3.10+ Executable
PYTHON_BIN=""
for candidate in python3 python python3.13 python3.12 python3.11 python3.10; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PY_VER="$("$candidate" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")' 2>/dev/null || true)"
        if [ -n "$PY_VER" ]; then
            MAJOR="$(echo "$PY_VER" | cut -d. -f1)"
            MINOR="$(echo "$PY_VER" | cut -d. -f2)"
            if [ "$MAJOR" -ge "$MIN_PY_MAJOR" ] && [ "$MINOR" -ge "$MIN_PY_MINOR" ]; then
                PYTHON_BIN="$candidate"
                break
            fi
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[ERROR] Python 3.10 or newer was not found in PATH.${NC}"
    echo "Remediation:"
    echo "  Ubuntu/Debian/Kali: sudo apt-get update && sudo apt-get install python3 python3-venv python3-pip"
    echo "  Fedora:             sudo dnf install python3 python3-pip"
    echo "  Arch Linux:         sudo pacman -S python python-pip"
    echo "  macOS (Homebrew):   brew install python@3.12"
    exit 1
fi

PY_FULL_VER="$("$PYTHON_BIN" -V)"
echo -e "Using Python:     ${GREEN}${BOLD}${PY_FULL_VER}${NC} (${PYTHON_BIN})"

# 4. Dry-run Mode
if [ "$DRY_RUN" = true ]; then
    echo -e "\n${YELLOW}[DRY-RUN] Pre-flight inspection completed successfully.${NC}"
    echo "Planned Actions:"
    echo "  1. Create virtual environment at: ${TARGET_VENV}"
    echo "  2. Upgrade pip inside virtual environment"
    echo "  3. Install systemscan in editable/production mode"
    echo "  4. Verify entry point '${TARGET_VENV}/bin/systemscan --version'"
    exit 0
fi

# 5. Create Isolated Virtual Environment
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ -d "$TARGET_VENV" ]; then
    echo -e "Virtual environment already exists at: ${BOLD}${TARGET_VENV}${NC}"
else
    echo -e "Creating isolated virtual environment at: ${BOLD}${TARGET_VENV}${NC}..."
    "$PYTHON_BIN" -m venv "$TARGET_VENV"
fi

VENV_PYTHON="${TARGET_VENV}/bin/python"
VENV_SYSTEMSCAN="${TARGET_VENV}/bin/systemscan"

if [ ! -f "$VENV_PYTHON" ]; then
    echo -e "${RED}[ERROR] Failed to locate virtual environment python at ${VENV_PYTHON}.${NC}"
    exit 1
fi

# 6. Install Package
echo "Upgrading pip and installing SystemScan..."
"$VENV_PYTHON" -m pip install --upgrade pip --quiet
"$VENV_PYTHON" -m pip install "$REPO_ROOT" --quiet

# 7. Verification
if [ -f "$VENV_SYSTEMSCAN" ]; then
    echo -e "\n${GREEN}${BOLD}=== Installation Successful! ===${NC}"
    "$VENV_SYSTEMSCAN" version
    echo ""
    echo "To activate the environment in your shell:"
    echo -e "  ${BOLD}source ${TARGET_VENV}/bin/activate${NC}"
    echo "Then launch the interactive scanner menu:"
    echo -e "  ${BOLD}systemscan${NC}"
    echo "Or run a non-interactive system overview:"
    echo -e "  ${BOLD}systemscan info${NC}"
else
    echo -e "${RED}[ERROR] 'systemscan' CLI entry point was not created in ${TARGET_VENV}/bin.${NC}"
    echo "You can still run the module directly via: ${VENV_PYTHON} -m systemscan"
    exit 1
fi

