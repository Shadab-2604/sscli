"""Hardware device inventory and asset categorization module for systemscan."""

from __future__ import annotations

import psutil

from systemscan.logging.logger import get_logger
from systemscan.modules.hardware.gpu import collect_gpu_info
from systemscan.modules.hardware.storage import collect_storage_info
from systemscan.modules.models import DeviceInformation
from systemscan.platform.base import PlatformInterface
from systemscan.platform.detector import detect_platform

logger = get_logger("hardware.devices")


def collect_device_inventory(
    platform_handler: PlatformInterface | None = None,
) -> list[DeviceInformation]:
    """Collect an inventory of host hardware devices."""
    handler = platform_handler or detect_platform()
    devices: list[DeviceInformation] = []

    # 1. Storage devices (Physical & Removable)
    _, disks = collect_storage_info(handler)
    for disk in disks:
        dtype = "removable_disk" if disk.is_removable else "internal_disk"
        devices.append(
            DeviceInformation(
                device_type=dtype,
                name=disk.name,
                description=disk.model,
                vendor=None,
                status="active",
                is_removable=disk.is_removable,
                metadata={
                    "size_bytes": disk.size_bytes,
                    "is_physical": disk.is_physical,
                },
            )
        )

    # 2. Graphics Adapters (GPUs)
    gpus = collect_gpu_info(handler)
    for gpu in gpus:
        devices.append(
            DeviceInformation(
                device_type="gpu",
                name=gpu.model,
                description=f"Graphics Adapter ({gpu.vendor})",
                vendor=gpu.vendor,
                status=gpu.status,
                is_removable=False,
                metadata={
                    "driver_version": gpu.driver_version,
                    "memory_total_bytes": gpu.memory_total_bytes,
                },
            )
        )

    # 3. Network Adapters
    try:
        net_stats = psutil.net_if_stats()
        for iface_name, stat in net_stats.items():
            devices.append(
                DeviceInformation(
                    device_type="network_interface",
                    name=iface_name,
                    description=f"Network Adapter (speed: {stat.speed} Mbps)",
                    status="up" if stat.isup else "down",
                    is_removable=False,
                    metadata={"speed_mbps": stat.speed, "duplex": str(stat.duplex)},
                )
            )
    except Exception as e:
        logger.debug(f"Could not read net_if_stats for device inventory: {e}")

    return devices
