"""Service and daemon inspection module for systemscan."""

from __future__ import annotations

from systemscan.logging.logger import get_logger
from systemscan.modules.models import ServiceInformation
from systemscan.platform.base import PlatformInterface
from systemscan.platform.detector import detect_platform

logger = get_logger("processes.services")


def collect_services(
    status_filter: str | None = None,
    platform_handler: PlatformInterface | None = None,
) -> list[ServiceInformation]:
    """Query host system services via platform adapter."""
    handler = platform_handler or detect_platform()
    try:
        return handler.get_services(status_filter=status_filter)
    except Exception as e:
        logger.debug(f"Failed to query system services: {e}")
        return []
