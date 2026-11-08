"""Centralized exception hierarchy for Universal System Security & Intelligence CLI."""

from typing import Any

from systemscan.core.constants import ExitCode


class SystemScanError(Exception):
    """Base exception for all systemscan errors."""

    def __init__(
        self,
        message: str,
        *,
        exit_code: ExitCode = ExitCode.GENERAL_ERROR,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code
        self.details = details or {}

    def __str__(self) -> str:
        return self.message


class ConfigurationError(SystemScanError):
    """Raised when configuration operations fail."""

    def __init__(
        self,
        message: str,
        *,
        exit_code: ExitCode = ExitCode.CONFIG_ERROR,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, exit_code=exit_code, details=details)


class ConfigNotFoundError(ConfigurationError):
    """Raised when expected configuration file cannot be found."""


class ConfigValidationError(ConfigurationError):
    """Raised when configuration validation fails against schema."""


class ConfigMalformedError(ConfigurationError):
    """Raised when configuration file cannot be parsed (e.g. invalid JSON)."""


class DependencyError(SystemScanError):
    """Raised when dependency checks or requirements fail."""

    def __init__(
        self,
        message: str,
        *,
        exit_code: ExitCode = ExitCode.DEPENDENCY_ERROR,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, exit_code=exit_code, details=details)


class MissingDependencyError(DependencyError):
    """Raised when a required external dependency is missing."""


class IncompatibleDependencyError(DependencyError):
    """Raised when an installed dependency version does not satisfy requirements."""


class SecurityPermissionError(SystemScanError):
    """Raised when an operation lacks necessary filesystem or system permissions."""

    def __init__(
        self,
        message: str,
        *,
        exit_code: ExitCode = ExitCode.PERMISSION_ERROR,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, exit_code=exit_code, details=details)


class PlatformError(SystemScanError):
    """Raised when platform-specific operations fail or platform is unsupported."""

    def __init__(
        self,
        message: str,
        *,
        exit_code: ExitCode = ExitCode.PLATFORM_ERROR,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, exit_code=exit_code, details=details)


class UnsupportedPlatformError(PlatformError):
    """Raised when running on an unsupported OS or architecture."""


class PlatformOperationError(PlatformError):
    """Raised when an OS-level operation fails."""


class ScanError(SystemScanError):
    """Base error for scanner operations (foundation for future phases)."""


class UpdateError(SystemScanError):
    """Base error for application update operations."""


class ReportError(SystemScanError):
    """Base error for report generation and management."""


class LifecycleError(SystemScanError):
    """Raised when application transitions through invalid lifecycle states."""
