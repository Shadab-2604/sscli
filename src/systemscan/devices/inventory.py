"""Thread-safe device inventory cache and query interface."""

from __future__ import annotations

import logging
import threading

from systemscan.devices.metadata import sanitize_device_metadata
from systemscan.devices.models import (
    DeviceCategory,
    DeviceMetadata,
    DeviceScanningPolicy,
)

logger = logging.getLogger("systemscan.devices.inventory")


class DeviceInventory:
    """Maintains an in-memory thread-safe registry of connected devices."""

    def __init__(self, policy: DeviceScanningPolicy | None = None) -> None:
        self.policy = policy or DeviceScanningPolicy()
        self._devices: dict[str, DeviceMetadata] = {}
        self._lock = threading.RLock()

    def update_snapshot(self, devices: list[DeviceMetadata]) -> None:
        """Replace or update the active inventory snapshot."""
        with self._lock:
            new_map: dict[str, DeviceMetadata] = {}
            for d in devices:
                sanitized = sanitize_device_metadata(
                    d, redact_serial=self.policy.redact_serial_numbers
                )
                new_map[sanitized.device_id] = sanitized
            self._devices = new_map
            logger.debug(
                f"Device inventory updated: {len(self._devices)} active devices registered."
            )

    def get_all(self) -> list[DeviceMetadata]:
        """Return all registered devices."""
        with self._lock:
            return list(self._devices.values())

    def get_by_id(self, device_id: str) -> DeviceMetadata | None:
        """Look up a device by unique device_id."""
        with self._lock:
            return self._devices.get(device_id)

    def get_removable_storage(self) -> list[DeviceMetadata]:
        """Return all removable storage devices."""
        with self._lock:
            return [
                d
                for d in self._devices.values()
                if d.is_storage and (d.is_removable or d.bus_type.value == "usb")
            ]

    def get_storage_devices(self) -> list[DeviceMetadata]:
        """Return all storage devices (internal and external)."""
        with self._lock:
            return [d for d in self._devices.values() if d.is_storage]

    def get_by_mount_point(self, mount_point: str) -> DeviceMetadata | None:
        """Find the device hosting a specific mount point or path."""
        target = mount_point.lower().rstrip("\\/")
        with self._lock:
            for dev in self._devices.values():
                for mp in dev.mount_points:
                    if mp.lower().rstrip("\\/") == target:
                        return dev
                    # Prefix match for nested mounts
                    if target.startswith(mp.lower().rstrip("\\/")):
                        return dev
        return None

    def get_by_category(self, category: DeviceCategory) -> list[DeviceMetadata]:
        """Filter registered devices by category."""
        with self._lock:
            return [d for d in self._devices.values() if d.category == category]
