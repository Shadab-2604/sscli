"""GPU inspection module for systemscan."""

from __future__ import annotations

from systemscan.logging.logger import get_logger
from systemscan.modules.models import GPUInformation
from systemscan.platform.base import PlatformInterface
from systemscan.platform.detector import detect_platform

logger = get_logger("hardware.gpu")


def collect_gpu_info(platform_handler: PlatformInterface | None = None) -> list[GPUInformation]:
    """Collect detected graphics adapter hardware specifications."""
    handler = platform_handler or detect_platform()
    try:
        gpus = handler.get_gpus()
        if not gpus:
            logger.debug("No discrete or integrated GPUs were returned by platform adapter.")
        return gpus
    except Exception as e:
        logger.debug(f"Failed to query GPUs from platform: {e}")
        return []
