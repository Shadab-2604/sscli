"""Configuration migration engine for preserving user settings across versions."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from systemscan.config.schema import SystemScanConfig
from systemscan.logging.logger import get_logger
from systemscan.utils.paths import AppPaths

logger = get_logger("update.migrations")


class MigrationError(Exception):
    """Raised when configuration migration fails."""


class ConfigMigrationManager:
    """Manages versioned configuration migrations, validations, and rollbacks."""

    def __init__(
        self,
        config_path: Path | None = None,
        backup_dir: Path | None = None,
    ) -> None:
        self.config_path = config_path or AppPaths().config_file
        self.backup_dir = backup_dir or (AppPaths().backup_dir / "config_migrations")
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def backup_config(self) -> Path | None:
        """Create a pre-migration snapshot of current config file."""
        if not self.config_path.exists():
            return None

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        snapshot_path = self.backup_dir / f"config_pre_migration_{timestamp}.json"
        shutil.copy2(self.config_path, snapshot_path)
        logger.info(f"Created pre-migration config snapshot at '{snapshot_path}'")
        return snapshot_path

    def rollback_config(self, snapshot_path: Path) -> tuple[bool, str]:
        """Restore configuration file from pre-migration snapshot."""
        if not snapshot_path.exists():
            msg = f"Config snapshot '{snapshot_path}' not found."
            logger.error(msg)
            return False, msg

        try:
            shutil.copy2(snapshot_path, self.config_path)
            logger.info(f"Restored configuration from snapshot '{snapshot_path}'")
            return True, f"Successfully restored config from '{snapshot_path.name}'."
        except Exception as e:
            msg = f"Failed to restore config snapshot: {e}"
            logger.error(msg)
            return False, msg

    def migrate(self, dry_run: bool = False) -> tuple[bool, str, list[str]]:
        """Migrate configuration file to match current SystemScanConfig schema.

        Returns:
            Tuple of (success, status_message, list_of_applied_changes).
        """
        if not self.config_path.exists():
            # Nothing to migrate; default config will be created on demand
            return True, "Configuration file does not exist yet; migration skipped.", []

        try:
            raw_text = self.config_path.read_text(encoding="utf-8")
            data = json.loads(raw_text)
            if not isinstance(data, dict):
                return False, "Config file does not contain a JSON object.", []
        except Exception as e:
            return False, f"Failed to read configuration file: {e}", []

        # Snapshot before any mutation
        snapshot = self.backup_config()

        changes: list[str] = []
        migrated_data = dict(data)

        # 1. Ensure core sections exist
        default_model = SystemScanConfig()
        default_dict = default_model.model_dump(mode="json")

        for section_name, section_default in default_dict.items():
            if isinstance(section_default, dict):
                if section_name not in migrated_data or not isinstance(
                    migrated_data[section_name], dict
                ):
                    migrated_data[section_name] = section_default
                    changes.append(f"Added missing section '[{section_name}]' with defaults.")
                else:
                    # Merge individual keys within section
                    current_section = migrated_data[section_name]
                    for k, v in section_default.items():
                        if k not in current_section:
                            current_section[k] = v
                            changes.append(
                                f"Added missing key '{k}' to '[{section_name}]' with default: {v}"
                            )
            else:
                # Top-level scalar property (e.g. log_level, custom_report_dir)
                if section_name not in migrated_data:
                    migrated_data[section_name] = section_default
                    changes.append(f"Added missing configuration key '{section_name}'.")

        # 2. Validate migrated config with Pydantic
        try:
            validated = SystemScanConfig.model_validate(migrated_data)
        except Exception as e:
            logger.error(f"Migrated configuration failed schema validation: {e}")
            if snapshot:
                self.rollback_config(snapshot)
            return False, f"Configuration validation failed: {e}", changes

        if dry_run:
            return True, f"Dry-run migration calculated {len(changes)} change(s).", changes

        # 3. Write back migrated config atomically
        try:
            tmp_path = self.config_path.with_suffix(".tmp")
            tmp_path.write_text(
                json.dumps(validated.model_dump(mode="json"), indent=2),
                encoding="utf-8",
            )
            tmp_path.replace(self.config_path)
            logger.info(f"Successfully migrated configuration with {len(changes)} change(s)")
            return True, f"Successfully migrated config ({len(changes)} changes applied).", changes
        except Exception as e:
            logger.error(f"Failed to write migrated configuration: {e}")
            if snapshot:
                self.rollback_config(snapshot)
            return False, f"Failed to write migrated configuration: {e}", changes
