"""Centralized logging infrastructure for systemscan."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.logging import RichHandler

from systemscan.core.constants import (
    DEFAULT_LOG_BACKUP_COUNT,
    DEFAULT_LOG_FILENAME,
    DEFAULT_MAX_LOG_SIZE_BYTES,
    LogLevel,
)
from systemscan.logging.formatter import (
    SensitiveDataScrubber,
    StructuredFileFormatter,
)

if TYPE_CHECKING:
    from systemscan.utils.paths import AppPaths

_INITIALIZED = False
_ROOT_LOGGER_NAME = "systemscan"


def init_logging(
    level: LogLevel | str = LogLevel.INFO,
    *,
    log_dir: Path | None = None,
    console_enabled: bool = True,
    file_enabled: bool = True,
    debug: bool = False,
    app_paths: AppPaths | None = None,
) -> logging.Logger:
    """Initialize the application logging infrastructure."""
    global _INITIALIZED

    if log_dir is not None:
        target_log_dir = log_dir
    elif app_paths is not None:
        target_log_dir = app_paths.log_dir
    else:
        from systemscan.utils.paths import paths

        target_log_dir = paths.log_dir

    if debug:
        effective_level = logging.DEBUG
    elif isinstance(level, str):
        effective_level = getattr(logging, level.upper(), logging.INFO)
    else:
        effective_level = getattr(logging, level.value, logging.INFO)

    logger = logging.getLogger(_ROOT_LOGGER_NAME)
    logger.setLevel(logging.DEBUG)  # Root catches all; handlers filter
    logger.propagate = False

    # Clear existing handlers if re-initializing
    if logger.handlers:
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)

    scrubber = SensitiveDataScrubber()

    # 1. Console Handler (Rich-based)
    if console_enabled:
        console = Console(stderr=True)
        console_handler = RichHandler(
            console=console,
            show_time=False,
            show_path=debug,
            rich_tracebacks=debug,
            tracebacks_show_locals=False,
            markup=True,
        )
        console_handler.setLevel(effective_level)
        console_handler.addFilter(scrubber)
        logger.addHandler(console_handler)

    # 2. Rotating File Handler
    if file_enabled:
        try:
            target_log_dir.mkdir(parents=True, exist_ok=True)
            log_file = target_log_dir / DEFAULT_LOG_FILENAME

            file_handler = RotatingFileHandler(
                filename=log_file,
                maxBytes=DEFAULT_MAX_LOG_SIZE_BYTES,
                backupCount=DEFAULT_LOG_BACKUP_COUNT,
                encoding="utf-8",
                delay=True,
            )
            # File handler always logs DEBUG when available for deep forensics
            file_handler.setLevel(logging.DEBUG if debug else logging.INFO)
            file_handler.setFormatter(StructuredFileFormatter())
            file_handler.addFilter(scrubber)
            logger.addHandler(file_handler)
        except OSError as e:
            # If log directory isn't writable, report to stderr without crashing
            logging.getLogger().warning(
                f"Could not initialize file logging in {target_log_dir}: {e}"
            )

    _INITIALIZED = True
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Get a scoped logger under the systemscan namespace."""
    if not name or name == _ROOT_LOGGER_NAME:
        return logging.getLogger(_ROOT_LOGGER_NAME)
    if not name.startswith(f"{_ROOT_LOGGER_NAME}."):
        return logging.getLogger(f"{_ROOT_LOGGER_NAME}.{name}")
    return logging.getLogger(name)


def set_log_level(level: LogLevel | str) -> None:
    """Dynamically adjust console log level."""
    logger = logging.getLogger(_ROOT_LOGGER_NAME)
    if isinstance(level, str):
        effective_level = getattr(logging, level.upper(), logging.INFO)
    else:
        effective_level = getattr(logging, level.value, logging.INFO)

    for handler in logger.handlers:
        if isinstance(handler, RichHandler):
            handler.setLevel(effective_level)
