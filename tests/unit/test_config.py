"""Unit tests for configuration manager, defaults, and validation."""

from pathlib import Path

import pytest
from tests.fixtures.sample_configs import (
    INVALID_CONFIG_DATA,
    MALFORMED_JSON_STRING,
    VALID_CONFIG_DATA,
)

from systemscan.config.defaults import get_default_config, get_default_config_dict
from systemscan.config.manager import ConfigManager
from systemscan.config.validator import ConfigValidator
from systemscan.core.exceptions import ConfigMalformedError, ConfigValidationError
from systemscan.utils.paths import AppPaths


def test_default_config_generation() -> None:
    cfg = get_default_config()
    assert cfg.schema_version == 1
    assert cfg.scanner.worker_count == 4
    assert cfg.preferences.debug is False

    d = get_default_config_dict()
    assert isinstance(d, dict)
    assert d["schema_version"] == 1


def test_validator_valid() -> None:
    model = ConfigValidator.validate_dict(VALID_CONFIG_DATA)
    assert model.scanner.worker_count == 8
    assert model.scanner.removable_device_policy == "scan"
    assert model.update.channel == "beta"


def test_validator_invalid() -> None:
    with pytest.raises(ConfigValidationError) as exc_info:
        ConfigValidator.validate_dict(INVALID_CONFIG_DATA)
    assert "validation failed" in str(exc_info.value).lower()


def test_config_manager_lifecycle(tmp_path: Path) -> None:
    custom_paths = AppPaths(base_dir=tmp_path)
    manager = ConfigManager(custom_paths)
    assert not manager.is_initialized

    # 1. Initialize default
    cfg = manager.initialize_default()
    assert manager.is_initialized
    assert cfg.scanner.worker_count == 4

    # 2. Load existing
    loaded = manager.load()
    assert loaded.schema_version == 1

    # 3. Create backup
    backup_file = manager.create_backup()
    assert backup_file.is_file()

    # 4. Update field
    updated = manager.update_field("scanner", "worker_count", 16)
    assert updated.scanner.worker_count == 16
    assert manager.load().scanner.worker_count == 16

    # 5. Reset config
    reset_cfg = manager.reset()
    assert reset_cfg.scanner.worker_count == 4


def test_config_manager_malformed_handling(tmp_path: Path) -> None:
    custom_paths = AppPaths(base_dir=tmp_path)
    custom_paths.config_dir.mkdir(parents=True, exist_ok=True)
    bad_file = custom_paths.config_file
    bad_file.write_text(MALFORMED_JSON_STRING, encoding="utf-8")

    manager = ConfigManager(custom_paths)
    with pytest.raises(ConfigMalformedError) as exc_info:
        manager.load()

    assert "malformed json" in str(exc_info.value).lower()
    # Ensure backup was generated
    backups = list(custom_paths.backup_dir.glob("config_corrupted_*.json"))
    assert len(backups) == 1
