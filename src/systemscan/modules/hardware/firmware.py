"""Motherboard, BIOS, and UEFI firmware inspection module for systemscan."""

from __future__ import annotations

from systemscan.logging.logger import get_logger
from systemscan.modules.models import FirmwareInformation
from systemscan.platform.base import PlatformInterface
from systemscan.platform.detector import detect_platform

logger = get_logger("hardware.firmware")


def collect_firmware_info(
    include_serials: bool = False,
    platform_handler: PlatformInterface | None = None,
) -> FirmwareInformation:
    """Collect motherboard, BIOS, and firmware metadata."""
    handler = platform_handler or detect_platform()
    try:
        return handler.get_firmware_info(include_serials=include_serials)
    except Exception as e:
        logger.debug(f"Failed to query firmware info: {e}")
        return FirmwareInformation()
