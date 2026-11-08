"""Core application framework for systemscan."""

from systemscan.core.constants import (
    ExitCode,
    LogLevel,
    UpdateChannel,
)
from systemscan.core.exceptions import (
    ConfigMalformedError,
    ConfigNotFoundError,
    ConfigurationError,
    ConfigValidationError,
    DependencyError,
    IncompatibleDependencyError,
    LifecycleError,
    MissingDependencyError,
    PlatformError,
    PlatformOperationError,
    ReportError,
    ScanError,
    SecurityPermissionError,
    SystemScanError,
    UnsupportedPlatformError,
    UpdateError,
)

__all__ = [
    "Application",
    "ConfigMalformedError",
    "ConfigNotFoundError",
    "ConfigValidationError",
    "ConfigurationError",
    "DependencyError",
    "DependencyRegistry",
    "DependencySpec",
    "DependencyStatus",
    "DependencyType",
    "ErrorHandler",
    "ExitCode",
    "IncompatibleDependencyError",
    "LifecycleError",
    "LifecycleManager",
    "LifecycleState",
    "LogLevel",
    "MissingDependencyError",
    "PlatformError",
    "PlatformOperationError",
    "ReportError",
    "ScanError",
    "SecurityPermissionError",
    "SystemScanError",
    "UnsupportedPlatformError",
    "UpdateChannel",
    "UpdateError",
    "app_instance",
    "dependency_registry",
    "error_handler",
]


def __getattr__(name: str) -> object:
    if name in ("Application", "app_instance"):
        from systemscan.core.application import Application, app_instance

        return Application if name == "Application" else app_instance
    if name in ("ErrorHandler", "error_handler"):
        from systemscan.core.error_handler import ErrorHandler, error_handler

        return ErrorHandler if name == "ErrorHandler" else error_handler
    if name in ("LifecycleManager", "LifecycleState"):
        from systemscan.core.lifecycle import LifecycleManager, LifecycleState

        return LifecycleManager if name == "LifecycleManager" else LifecycleState
    if name in (
        "DependencyRegistry",
        "DependencySpec",
        "DependencyStatus",
        "DependencyType",
        "dependency_registry",
    ):
        import systemscan.core.dependencies as d

        return getattr(d, name)
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
