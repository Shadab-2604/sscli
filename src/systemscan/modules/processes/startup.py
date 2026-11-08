"""Startup and persistence application discovery module for systemscan."""

from __future__ import annotations

from systemscan.logging.logger import get_logger
from systemscan.modules.models import StartupEntry
from systemscan.platform.base import PlatformInterface
from systemscan.platform.detector import detect_platform

logger = get_logger("processes.startup")


def collect_startup_entries(
    platform_handler: PlatformInterface | None = None,
) -> list[StartupEntry]:
    """Discover host startup and persistence applications."""
    handler = platform_handler or detect_platform()
    try:
        return handler.get_startup_entries()
    except Exception as e:
        logger.debug(f"Failed to query startup entries: {e}")
        return []
