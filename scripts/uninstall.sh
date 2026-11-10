#!/usr/bin/env bash
# ==============================================================================
# Universal System Security & Intelligence CLI (systemscan) - Safe Uninstaller
# Platform: Linux and macOS
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

REMOVE_DATA=false
DRY_RUN=false
ASSUME_YES=false
DEFAULT_VENV_DIR=".venv"
TARGET_VENV="${1:-$DEFAULT_VENV_DIR}"

for arg in "$@"; do
    case "$arg" in
        --remove-data)
            REMOVE_DATA=true
            ;;
        --dry-run)
            DRY_RUN=true
            ;;
        --yes|-y)
            ASSUME_YES=true
            ;;
        --help|-h)
            echo "Usage: ./scripts/uninstall.sh [OPTIONS] [VENV_DIR]"
            echo ""
            echo "Options:"
            echo "  --remove-data    Permanently remove application configuration, reports, and logs."
            echo "  --dry-run        Simulate uninstallation actions without modifying the filesystem."
            echo "  --yes, -y        Bypass interactive confirmation prompt."
            echo "  --help, -h       Show this help message."
            exit 0
            ;;
    esac
done

echo -e "${CYAN}${BOLD}=== SystemScan Safe Uninstaller (Linux & macOS) ===${NC}"

# Identify paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_PATH="${REPO_ROOT}/${TARGET_VENV}"

OS_TYPE="$(uname -s)"
if [ "$OS_TYPE" = "Darwin" ]; then
    APP_CONFIG_DIR="${HOME}/Library/Application Support/systemscan"
    APP_DATA_DIR="${HOME}/Library/Application Support/systemscan"
    APP_CACHE_DIR="${HOME}/Library/Caches/systemscan"
    APP_LOG_DIR="${HOME}/Library/Logs/systemscan"
else
    # Linux XDG conventions
    APP_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemscan"
    APP_DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/systemscan"
    APP_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/systemscan"
    APP_LOG_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/systemscan/logs"
fi

echo "Environment Target: ${VENV_PATH}"
if [ "$REMOVE_DATA" = true ]; then
    echo -e "Data Removal:       ${RED}${BOLD}PURGE ALL APPLICATION DATA${NC}"
else
    echo -e "Data Removal:       ${GREEN}${BOLD}PRESERVE CONFIGURATION & REPORTS${NC}"
fi

if [ "$DRY_RUN" = true ]; then
    echo -e "\n${YELLOW}[DRY-RUN] Uninstallation Plan:${NC}"
    if [ -d "$VENV_PATH" ]; then
        echo "  • Would delete virtual environment: ${VENV_PATH}"
    else
        echo "  • Virtual environment absent (skipped): ${VENV_PATH}"
    fi
    if [ "$REMOVE_DATA" = true ]; then
        echo "  • Would delete configuration: ${APP_CONFIG_DIR}"
        echo "  • Would delete scan data:     ${APP_DATA_DIR}"
        echo "  • Would delete cache:         ${APP_CACHE_DIR}"
        echo "  • Would delete logs:          ${APP_LOG_DIR}"
    else
        echo "  • Preserving configuration:   ${APP_CONFIG_DIR}"
        echo "  • Preserving scan data:       ${APP_DATA_DIR}"
    fi
    exit 0
fi

# Confirmation prompt
if [ "$ASSUME_YES" = false ]; then
    echo ""
    if [ "$REMOVE_DATA" = true ]; then
        read -r -p "Are you sure you want to uninstall systemscan AND permanently delete all scan reports/history? [y/N]: " confirm
    else
        read -r -p "Proceed with removing the systemscan virtual environment? (Data will be preserved) [y/N]: " confirm
    fi
    case "$confirm" in
        [yY][eE][sS]|[yY])
            ;;
        *)
            echo "Uninstallation cancelled by user."
            exit 0
            ;;
    esac
fi

# 1. Remove virtual environment
if [ -d "$VENV_PATH" ]; then
    echo "Removing virtual environment: ${VENV_PATH}..."
    rm -rf "$VENV_PATH"
    echo -e "${GREEN}Virtual environment removed.${NC}"
else
    echo "Virtual environment not found at ${VENV_PATH} (skipping)."
fi

# Remove global launcher symlinks pointing to this repo
for link in "${PREFIX:-}/bin/systemscan" "/usr/local/bin/systemscan" "$HOME/.local/bin/systemscan"; do
    if [ -L "$link" ]; then
        target="$(readlink "$link" 2>/dev/null || true)"
        if [[ "$target" == *"$REPO_ROOT"* ]]; then
            rm -f "$link" 2>/dev/null || true
            echo "Removed global command link: $link"
        fi
    fi
done

# 2. Optionally purge user data
if [ "$REMOVE_DATA" = true ]; then
    echo -e "\n${RED}Purging application configuration and data...${NC}"
    for d in "$APP_CACHE_DIR" "$APP_LOG_DIR" "$APP_CONFIG_DIR" "$APP_DATA_DIR"; do
        if [ -d "$d" ]; then
            # Safety check: Never delete root or entire home
            if [ "$d" != "/" ] && [ "$d" != "$HOME" ]; then
                rm -rf "$d"
                echo "  Deleted: $d"
            fi
        fi
    done
    echo -e "${GREEN}Application data successfully removed.${NC}"
else
    echo -e "\n${GREEN}User configuration, scan history, and reports preserved.${NC}"
fi

echo -e "\n${GREEN}${BOLD}SystemScan uninstallation completed.${NC}"

