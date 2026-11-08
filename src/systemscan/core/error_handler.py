"""Centralized error handling and reporting for systemscan."""

from __future__ import annotations

import sys
from typing import NoReturn

from rich.console import Console
from rich.panel import Panel

from systemscan.core.constants import ExitCode
from systemscan.core.exceptions import (
    ConfigurationError,
    DependencyError,
    PlatformError,
    SecurityPermissionError,
    SystemScanError,
)
from systemscan.logging.logger import get_logger

logger = get_logger("error_handler")


class ErrorHandler:
    """Centralized handler for managing uncaught errors and application exits."""

    def __init__(self, console: Console | None = None, debug: bool = False) -> None:
        self.console = console or Console(stderr=True)
        self.debug = debug

    def set_debug(self, debug: bool) -> None:
        """Enable or disable debug traceback presentation."""
        self.debug = debug

    def handle_exception(self, exc: BaseException) -> int:
        """Handle any exception, log diagnostic details, display formatted message, and return exit code."""
        if isinstance(exc, KeyboardInterrupt):
            self.console.print("\n[yellow]Operation cancelled by user (Ctrl+C).[/yellow]")
            logger.info("Application execution cancelled by user via SIGINT/KeyboardInterrupt.")
            return ExitCode.KEYBOARD_INTERRUPT

        if isinstance(exc, SystemScanError):
            logger.error(f"{type(exc).__name__}: {exc.message}", exc_info=self.debug)
            self._render_known_error(exc)
            return exc.exit_code

        # Unhandled unexpected exceptions
        logger.critical(f"Unhandled unexpected exception: {exc}", exc_info=True)
        self._render_unexpected_error(exc)
        return ExitCode.GENERAL_ERROR

    def _render_known_error(self, exc: SystemScanError) -> None:
        """Render a formatted, user-friendly panel for known domain errors."""
        category_title = self._categorize_error(exc)

        body = f"[bold red]{exc.message}[/bold red]"
        if exc.details:
            body += "\n\n[dim]Additional Details:[/dim]"
            for k, v in exc.details.items():
                body += f"\n  [cyan]{k}:[/cyan] {v}"

        if not self.debug:
            body += "\n\n[dim]Run with '--debug' for complete diagnostic traceback.[/dim]"

        panel = Panel(
            body,
            title=f"[red]Error: {category_title}[/red]",
            border_style="red",
            expand=False,
        )
        self.console.print(panel)

        if self.debug:
            self.console.print_exception(show_locals=True)

    def _render_unexpected_error(self, exc: BaseException) -> None:
        """Render an alert for unexpected internal failures."""
        msg = (
            f"[bold red]An unexpected internal error occurred: {exc}[/bold red]\n\n"
            "This may be an issue with systemscan or your environment.\n"
            "Diagnostic logs have been captured in the application log directory."
        )
        if not self.debug:
            msg += "\n[dim]Run with '--debug' to inspect full diagnostic trace.[/dim]"

        panel = Panel(
            msg,
            title="[bold red]Critical Internal Error[/bold red]",
            border_style="bright_red",
            expand=False,
        )
        self.console.print(panel)

        if self.debug:
            self.console.print_exception(show_locals=True)

    @staticmethod
    def _categorize_error(exc: SystemScanError) -> str:
        """Categorize exception into a human-readable title."""
        if isinstance(exc, ConfigurationError):
            return "Configuration Error"
        if isinstance(exc, DependencyError):
            return "Dependency Error"
        if isinstance(exc, SecurityPermissionError):
            return "Permission Error"
        if isinstance(exc, PlatformError):
            return "Platform Compatibility Error"
        return "Application Error"

    def exit_with_exception(self, exc: BaseException) -> NoReturn:
        """Handle exception and immediately terminate process with corresponding exit code."""
        code = self.handle_exception(exc)
        sys.exit(code)


# Global default error handler
error_handler = ErrorHandler()
