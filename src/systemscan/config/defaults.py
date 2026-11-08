"""Default configuration templates and values for systemscan."""

from systemscan.config.schema import SystemScanConfig


def get_default_config() -> SystemScanConfig:
    """Return a pristine instance of the default configuration."""
    return SystemScanConfig()


def get_default_config_dict() -> dict[str, object]:
    """Return the default configuration as a Python dictionary."""
    return get_default_config().model_dump(mode="json")
