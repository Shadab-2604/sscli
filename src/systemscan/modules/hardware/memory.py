"""Memory and swap telemetry inspection module for systemscan."""

from __future__ import annotations

import psutil

from systemscan.logging.logger import get_logger
from systemscan.modules.models import MemoryInformation

logger = get_logger("hardware.memory")


def collect_memory_info() -> MemoryInformation:
    """Collect accurate physical RAM and swap space memory telemetry."""
    # Virtual RAM
    vmem = psutil.virtual_memory()
    total_ram = int(vmem.total)
    available_ram = int(vmem.available)
    used_ram = int(vmem.used)
    free_ram = int(vmem.free)
    ram_percentage = float(vmem.percent)

    # Cached memory (Linux/BSD/macOS; on Windows, cached is not distinct in standard vmem)
    cached_val = getattr(vmem, "cached", None)
    buffers_val = getattr(vmem, "buffers", None)
    cached_ram: int | None = None
    if cached_val is not None:
        cached_ram = int(cached_val)
    elif buffers_val is not None and buffers_val:
        cached_ram = int(buffers_val)

    # Swap Memory
    try:
        swap = psutil.swap_memory()
        swap_total = int(swap.total)
        swap_used = int(swap.used)
        swap_free = int(swap.free)
        swap_percentage = float(swap.percent)
    except Exception as e:
        logger.debug(f"Could not read swap memory: {e}")
        swap_total = 0
        swap_used = 0
        swap_free = 0
        swap_percentage = 0.0

    return MemoryInformation(
        total_bytes=total_ram,
        available_bytes=available_ram,
        used_bytes=used_ram,
        free_bytes=free_ram,
        percentage=ram_percentage,
        cached_bytes=cached_ram,
        swap_total_bytes=swap_total,
        swap_used_bytes=swap_used,
        swap_free_bytes=swap_free,
        swap_percentage=swap_percentage,
    )
