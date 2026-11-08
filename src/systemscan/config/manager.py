"""Centralized configuration manager for systemscan."""

from __future__ import annotations

import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from systemscan.config.defaults import get_default_config
from systemscan.config.schema import SystemScanConfig
from systemscan.config.validator import ConfigValidator
from systemscan.core.constants import DEFAULT_CONFIG_BACKUP_SUFFIX
from systemscan.core.exceptions import (
    ConfigMalformedError,
    ConfigNotFoundError,
    ConfigurationError,
)
from systemscan.utils.paths import AppPaths, paths


class ConfigManager:
    """Manages loading, validating, persisting, backing up, and resetting configuration."""

    def __init__(self, app_paths: AppPaths | None = None) -> None:
        self._paths = app_paths or paths
        self._config: SystemScanConfig | None = None

    @property
    def config_path(self) -> Path:
        """Absolute path to the active configuration file."""
        return self._paths.config_file

    @property
    def is_initialized(self) -> bool:
        """Check if configuration file exists on disk."""
        return self.config_path.is_file()

    @property
    def current(self) -> SystemScanConfig:
        """Return the current active configuration, loading if necessary."""
        if self._config is None:
            self.load_or_initialize()
        assert self._config is not None
        return self._config

    def initialize_default(self, force: bool = False) -> SystemScanConfig:
        """Create and write the default configuration file."""
        if self.is_initialized and not force:
            return self.load()

        self._paths.ensure_directories()
        default_cfg = get_default_config()
        self.save(default_cfg)
        self._config = default_cfg
        return default_cfg

    def load(self) -> SystemScanConfig:
        """Load and validate the existing configuration file."""
        if not self.config_path.is_file():
            raise ConfigNotFoundError(f"Configuration file not found: {self.config_path}")

        try:
            content = self.config_path.read_text(encoding="utf-8")
        except OSError as e:
            raise ConfigurationError(
                f"Failed to read configuration file: {e}",
                details={"path": str(self.config_path)},
            ) from e

        try:
            raw_data = json.loads(content)
        except json.JSONDecodeError as e:
            # Handle malformed configuration file by creating a backup before failing
            corrupt_backup = self.create_corrupt_backup()
            raise ConfigMalformedError(
                f"Configuration file is malformed JSON (line {e.lineno}, col {e.colno}): {e.msg}. "
                f"Corrupted file backed up to: {corrupt_backup.name}",
                details={"path": str(self.config_path), "backup": str(corrupt_backup)},
            ) from e

        validated_config = ConfigValidator.validate_dict(raw_data)
        self._config = validated_config
        return validated_config

    def load_or_initialize(self) -> SystemScanConfig:
        """Load configuration if it exists, or generate default on first launch."""
        if not self.is_initialized:
            return self.initialize_default()
        return self.load()

    def load_config(self) -> SystemScanConfig:
        """Alias for load_or_initialize."""
        return self.load_or_initialize()

    def save(self, config: SystemScanConfig) -> None:
        """Atomically persist configuration to disk formatted as human-readable JSON."""
        self._paths.ensure_directories()
        data = config.model_dump(mode="json")
        json_text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"

        # Write to a temporary file in the same directory first for atomic replace
        target_dir = self.config_path.parent
        temp_file = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target_dir,
            delete=False,
        )
        try:
            temp_file.write(json_text)
            temp_file.flush()
            temp_file.close()
            # Atomically replace target file
            shutil.move(temp_file.name, self.config_path)
        except Exception as e:
            # Clean up temp file on failure
            Path(temp_file.name).unlink(missing_ok=True)
            raise ConfigurationError(f"Failed to atomically write configuration: {e}") from e

        self._config = config

    def create_backup(self, custom_name: str | None = None) -> Path:
        """Create a timestamped backup of the current configuration file."""
        if not self.is_initialized:
            raise ConfigNotFoundError("Cannot backup configuration: file does not exist.")

        self._paths.backup_dir.mkdir(parents=True, exist_ok=True)
        if custom_name:
            filename = custom_name
        else:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"config_backup_{ts}{DEFAULT_CONFIG_BACKUP_SUFFIX}"

        dest_path = self._paths.backup_dir / filename
        shutil.copy2(self.config_path, dest_path)
        return dest_path

    def create_corrupt_backup(self) -> Path:
        """Backup a corrupt configuration file safely."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"config_corrupted_{ts}.json"
        dest_path = self._paths.backup_dir / filename
        self._paths.backup_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.config_path, dest_path)
        return dest_path

    def reset(self, create_backup_first: bool = True) -> SystemScanConfig:
        """Reset configuration to default values, creating a backup by default."""
        if self.is_initialized and create_backup_first:
            self.create_backup()

        return self.initialize_default(force=True)

    def update_field(self, section: str, field: str, value: Any) -> SystemScanConfig:
        """Update a specific configuration field and persist changes."""
        current = self.current
        dumped = current.model_dump()

        if section in dumped and isinstance(dumped[section], dict):
            dumped[section][field] = value
        elif section == "root":
            dumped[field] = value
        else:
            raise ConfigurationError(f"Unknown configuration section: '{section}'")

        validated = ConfigValidator.validate_dict(dumped)
        self.save(validated)
        return validated
