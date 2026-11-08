"""Execution and application environment inspection module for systemscan."""

from __future__ import annotations

import getpass
import os
import shutil
import sys

from systemscan.modules.models import (
    ApplicationEnvironmentModel,
    ExecutionEnvironmentModel,
)
from systemscan.platform.base import PlatformInterface
from systemscan.platform.detector import (
    detect_installation_type,
    detect_platform,
)
from systemscan.utils.paths import AppPaths, paths
from systemscan.version import __version__

# Sensitive environment variable keys to exclude
EXCLUDE_ENV_PATTERNS = {
    "SECRET",
    "TOKEN",
    "KEY",
    "PASS",
    "AUTH",
    "CREDENTIAL",
    "PRIVATE",
    "PWD",
    "SIGNATURE",
}

# Safe environment variables to surface for diagnostic triage
RELEVANT_SAFE_ENV_VARS = [
    "OS",
    "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
    "SHELL",
    "TERM",
    "LANG",
    "LC_ALL",
    "USER",
    "LOGNAME",
    "USERNAME",
    "PATHEXT",
    "VIRTUAL_ENV",
    "CONDA_DEFAULT_ENV",
    "WSL_DISTRO_NAME",
    "XDG_CURRENT_DESKTOP",
    "XDG_SESSION_TYPE",
]


def collect_safe_environment_vars() -> dict[str, str]:
    """Extract relevant, non-sensitive environment variables for platform diagnostics."""
    safe_vars: dict[str, str] = {}
    for var in RELEVANT_SAFE_ENV_VARS:
        if var in os.environ:
            val = os.environ[var]
            # Ensure no secret leaked even if key matched relevant list
            if not any(pat in var.upper() for pat in EXCLUDE_ENV_PATTERNS):
                safe_vars[var] = val
    return safe_vars


def collect_execution_environment(
    platform_handler: PlatformInterface | None = None,
) -> ExecutionEnvironmentModel:
    """Collect host execution environment metadata."""
    handler = platform_handler or detect_platform()

    try:
        username = getpass.getuser()
    except Exception:
        username = os.environ.get("USER") or os.environ.get("USERNAME") or "Unknown"

    uid: str | None = None
    if hasattr(os, "getuid"):
        try:
            uid = str(os.getuid())
        except OSError:
            pass

    # Terminal capabilities
    is_interactive = sys.stdin.isatty() and sys.stdout.isatty()
    term_size = shutil.get_terminal_size(fallback=(80, 24))

    # Virtual environment
    venv_path = os.environ.get("VIRTUAL_ENV") or (
        sys.prefix if sys.prefix != getattr(sys, "base_prefix", sys.prefix) else None
    )

    return ExecutionEnvironmentModel(
        username=username,
        user_id=uid,
        is_elevated=handler.is_elevated(),
        virtual_env=venv_path,
        python_executable=sys.executable,
        working_directory=os.getcwd(),
        is_interactive=is_interactive,
        terminal_columns=term_size.columns,
        terminal_lines=term_size.lines,
        safe_environment_vars=collect_safe_environment_vars(),
    )


def collect_application_environment(
    app_paths: AppPaths | None = None,
) -> ApplicationEnvironmentModel:
    """Collect application deployment directories and packaging metadata."""
    active_paths = app_paths or paths
    return ApplicationEnvironmentModel(
        version=__version__,
        install_type=detect_installation_type(),
        config_dir=str(active_paths.config_dir),
        data_dir=str(active_paths.data_dir),
        log_dir=str(active_paths.log_dir),
        report_dir=str(active_paths.report_dir),
    )
