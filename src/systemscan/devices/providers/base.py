"""Base abstraction for platform-specific device discovery providers."""

from __future__ import annotations

import abc

from systemscan.devices.models import DeviceMetadata


class DeviceProvider(abc.ABC):
    """Abstract interface for platform-specific device enumeration."""

    @abc.abstractmethod
    def discover_devices(self) -> list[DeviceMetadata]:
        """Enumerate all connected hardware devices (USB, storage, peripherals)."""
        pass

    def get_removable_storage(self) -> list[DeviceMetadata]:
        """Convenience query returning only removable storage devices."""
        all_devs = self.discover_devices()
        return [
            d for d in all_devs if d.is_storage and (d.is_removable or d.bus_type.value == "usb")
        ]
