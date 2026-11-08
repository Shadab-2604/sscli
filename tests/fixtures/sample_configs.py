"""Test fixtures and mock configurations for unit and integration testing."""

VALID_CONFIG_DATA = {
    "schema_version": 1,
    "preferences": {
        "debug": True,
        "verbose": True,
        "color_output": False,
        "interactive_banner": False,
    },
    "log_level": "DEBUG",
    "custom_report_dir": "/custom/reports",
    "scanner": {
        "worker_count": 8,
        "max_file_size_mb": 50,
        "timeout_seconds": 120,
        "removable_device_policy": "scan",
        "exclusions": ["/tmp", "C:\\Temp"],
    },
    "update": {
        "channel": "beta",
        "update_source": "https://custom.repo/releases",
        "auto_check": True,
    },
    "modules": {
        "test_module": {"enabled": True, "key": "value"},
    },
}

INVALID_CONFIG_DATA = {
    "schema_version": 1,
    "preferences": "not-a-dict",
    "log_level": "INVALID_LEVEL",
    "scanner": {
        "worker_count": -5,  # Invalid: ge=1
        "removable_device_policy": "invalid_policy",
    },
}

MALFORMED_JSON_STRING = '{"schema_version": 1, "preferences": { broken json ...'
