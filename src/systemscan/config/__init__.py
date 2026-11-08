"""Configuration management package for systemscan."""

from systemscan.config.defaults import get_default_config, get_default_config_dict
from systemscan.config.manager import ConfigManager
from systemscan.config.schema import (
    AppPreferences,
    ScannerConfig,
    SystemScanConfig,
    UpdateConfig,
)
from systemscan.config.validator import ConfigValidator

__all__ = [
    "AppPreferences",
    "ConfigManager",
    "ConfigValidator",
    "ScannerConfig",
    "SystemScanConfig",
    "UpdateConfig",
    "get_default_config",
    "get_default_config_dict",
]
