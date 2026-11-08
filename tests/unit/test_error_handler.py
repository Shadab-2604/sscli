"""Unit tests for centralized error handler."""

from io import StringIO

from rich.console import Console

from systemscan.core.constants import ExitCode
from systemscan.core.error_handler import ErrorHandler
from systemscan.core.exceptions import (
    ConfigurationError,
    DependencyError,
    PlatformError,
    SecurityPermissionError,
)


def test_error_handler_domain_exceptions() -> None:
    buf = StringIO()
    console = Console(file=buf, color_system=None)
    handler = ErrorHandler(console=console, debug=False)

    # ConfigurationError -> EXIT_CONFIG_ERROR (2)
    code = handler.handle_exception(ConfigurationError("Config missing"))
    assert code == ExitCode.CONFIG_ERROR
    assert "Config missing" in buf.getvalue()

    # DependencyError -> EXIT_DEPENDENCY_ERROR (3)
    code = handler.handle_exception(DependencyError("Missing package"))
    assert code == ExitCode.DEPENDENCY_ERROR

    # SecurityPermissionError -> EXIT_PERMISSION_ERROR (4)
    code = handler.handle_exception(SecurityPermissionError("Access denied"))
    assert code == ExitCode.PERMISSION_ERROR

    # PlatformError -> EXIT_PLATFORM_ERROR (5)
    code = handler.handle_exception(PlatformError("Unsupported OS"))
    assert code == ExitCode.PLATFORM_ERROR

    # KeyboardInterrupt -> EXIT_KEYBOARD_INTERRUPT (130)
    code = handler.handle_exception(KeyboardInterrupt())
    assert code == ExitCode.KEYBOARD_INTERRUPT


def test_error_handler_unexpected_exception() -> None:
    buf = StringIO()
    console = Console(file=buf, color_system=None)
    handler = ErrorHandler(console=console, debug=False)

    code = handler.handle_exception(RuntimeError("Unexpected bug"))
    assert code == ExitCode.GENERAL_ERROR
    assert "Critical Internal Error" in buf.getvalue()
