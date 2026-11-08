"""Centralized path management and resolution for systemscan.

Handles cross-platform paths according to OS conventions:
- Linux: XDG Base Directory specification (~/.config, ~/.local/share, ~/.cache)
- Windows: %APPDATA%, %LOCALAPPDATA%
- macOS: ~/Library/Application Support, ~/Library/Caches, ~/Library/Logs
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from platformdirs import PlatformDirs

from systemscan.core.constants import APP_DIR_NAME


class AppPaths:
    """Provides centralized, cross-platform path resolution."""

    def __init__(
        self,
        base_dir: Path | str | None = None,
        custom_report_dir: Path | str | None = None,
    ) -> None:
        self._base_dir = Path(base_dir) if base_dir else None
        self._dirs = PlatformDirs(appname=APP_DIR_NAME, appauthor=False, roaming=True)
        self._custom_report_dir = Path(custom_report_dir) if custom_report_dir else None

    @property
    def install_dir(self) -> Path:
        """Directory containing the installed package/module."""
        # Resolves to src/systemscan or site-packages/systemscan
        return Path(__file__).resolve().parent.parent

    @property
    def config_dir(self) -> Path:
        """User configuration directory."""
        if self._base_dir:
            return self._base_dir / "config"
        return Path(self._dirs.user_config_dir)

    @property
    def data_dir(self) -> Path:
        """User data directory."""
        if self._base_dir:
            return self._base_dir / "data"
        return Path(self._dirs.user_data_dir)

    @property
    def cache_dir(self) -> Path:
        """User cache directory."""
        if self._base_dir:
            return self._base_dir / "cache"
        return Path(self._dirs.user_cache_dir)

    @property
    def log_dir(self) -> Path:
        """User log directory."""
        if self._base_dir:
            return self._base_dir / "logs"
        return Path(self._dirs.user_log_dir)

    @property
    def report_dir(self) -> Path:
        """Directory where scan reports are stored."""
        if self._custom_report_dir:
            return self._custom_report_dir
        return self.data_dir / "reports"

    @property
    def backup_dir(self) -> Path:
        """Directory where configuration and data backups are stored."""
        return self.data_dir / "backups"

    @property
    def quarantine_dir(self) -> Path:
        """Directory reserved for quarantined files in future phases."""
        return self.data_dir / "quarantine"

    @property
    def config_file(self) -> Path:
        """Path to the main configuration JSON file."""
        return self.config_dir / "config.json"

    def ensure_directories(self) -> None:
        """Create all required application directories with secure permissions."""
        dirs_to_create = [
            self.config_dir,
            self.data_dir,
            self.cache_dir,
            self.log_dir,
            self.report_dir,
            self.backup_dir,
            self.quarantine_dir,
        ]

        for directory in dirs_to_create:
            directory.mkdir(parents=True, exist_ok=True)
            # Secure permissions on POSIX systems (owner read/write/execute only)
            if sys.platform != "win32":
                try:
                    os.chmod(directory, 0o700)
                except OSError:
                    pass

    def as_dict(self) -> dict[str, str]:
        """Return all resolved paths as strings for inspection/debugging."""
        return {
            "install_dir": str(self.install_dir),
            "config_dir": str(self.config_dir),
            "data_dir": str(self.data_dir),
            "cache_dir": str(self.cache_dir),
            "log_dir": str(self.log_dir),
            "report_dir": str(self.report_dir),
            "backup_dir": str(self.backup_dir),
            "quarantine_dir": str(self.quarantine_dir),
            "config_file": str(self.config_file),
        }


# Global path resolver instance
paths = AppPaths()
