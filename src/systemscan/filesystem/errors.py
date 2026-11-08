"""Filesystem domain exceptions for systemscan."""

from __future__ import annotations

from systemscan.core.constants import ExitCode
from systemscan.core.exceptions import SystemScanError


class FilesystemError(SystemScanError):
    """Base exception for all filesystem-related operational errors."""

    def __init__(self, message: str, exit_code: ExitCode = ExitCode.GENERAL_ERROR) -> None:
        super().__init__(message, exit_code=exit_code)


class PathValidationError(FilesystemError):
    """Raised when a user-supplied filesystem path fails syntax or validation checks."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=ExitCode.GENERAL_ERROR)


class ScanCancelledError(FilesystemError):
    """Raised when a filesystem scan traversal is aborted by user or cancellation token."""

    def __init__(self, message: str = "Filesystem scan was cancelled by operator.") -> None:
        super().__init__(message, exit_code=ExitCode.KEYBOARD_INTERRUPT)


class SymlinkRecursionError(FilesystemError):
    """Raised when a cyclic symbolic link structure or boundary violation is detected."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=ExitCode.GENERAL_ERROR)


class FilesystemAccessDeniedError(FilesystemError):
    """Raised when critical root path cannot be accessed due to OS permission denial."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=ExitCode.PERMISSION_ERROR)
