"""Central constants for Universal System Security & Intelligence CLI."""

from enum import Enum, IntEnum


class ExitCode(IntEnum):
    """Standard application exit codes."""

    SUCCESS = 0
    GENERAL_ERROR = 1
    CONFIG_ERROR = 2
    DEPENDENCY_ERROR = 3
    PERMISSION_ERROR = 4
    PLATFORM_ERROR = 5
    KEYBOARD_INTERRUPT = 130


class UpdateChannel(str, Enum):
    """Update release channels."""

    STABLE = "stable"
    BETA = "beta"
    NIGHTLY = "nightly"


class LogLevel(str, Enum):
    """Supported logging levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


# Configuration constants
DEFAULT_CONFIG_FILENAME = "config.json"
DEFAULT_CONFIG_BACKUP_SUFFIX = ".bak"
CONFIG_SCHEMA_VERSION = 1

# Logging constants
DEFAULT_LOG_FILENAME = "systemscan.log"
DEFAULT_MAX_LOG_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
DEFAULT_LOG_BACKUP_COUNT = 5

# Scanner defaults (placeholders for future phases)
DEFAULT_WORKER_COUNT = 4
DEFAULT_MAX_FILE_SIZE_MB = 100
DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_REMOVABLE_POLICY = "prompt"  # prompt, ignore, scan

# Application identifiers
APP_DIR_NAME = "systemscan"
