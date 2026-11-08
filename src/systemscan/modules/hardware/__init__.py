"""Hardware telemetry and asset inspection package for systemscan."""

from systemscan.modules.hardware.cpu import collect_cpu_info, get_static_cpu_info
from systemscan.modules.hardware.devices import collect_device_inventory
from systemscan.modules.hardware.firmware import collect_firmware_info
from systemscan.modules.hardware.gpu import collect_gpu_info
from systemscan.modules.hardware.memory import collect_memory_info
from systemscan.modules.hardware.storage import (
    collect_partition_info,
    collect_storage_info,
)

__all__ = [
    "collect_cpu_info",
    "collect_device_inventory",
    "collect_firmware_info",
    "collect_gpu_info",
    "collect_memory_info",
    "collect_partition_info",
    "collect_storage_info",
    "get_static_cpu_info",
]
