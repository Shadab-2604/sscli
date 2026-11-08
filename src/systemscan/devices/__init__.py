"""Public exports for the devices subsystem."""

from __future__ import annotations

from systemscan.devices.classifier import DeviceClassifier
from systemscan.devices.events import DeviceEventDispatcher
from systemscan.devices.inventory import DeviceInventory
from systemscan.devices.manager import DeviceManager
from systemscan.devices.models import (
    BusType,
    DeviceCategory,
    DeviceConnectionStatus,
    DeviceEvent,
    DeviceEventType,
    DeviceMetadata,
    DeviceScanningPolicy,
    PartitionMetadata,
)
from systemscan.devices.monitor import DeviceMonitor
from systemscan.devices.policies import PolicyManager
from systemscan.devices.providers import get_device_provider

__all__ = [
    "BusType",
    "DeviceCategory",
    "DeviceClassifier",
    "DeviceConnectionStatus",
    "DeviceEvent",
    "DeviceEventDispatcher",
    "DeviceEventType",
    "DeviceInventory",
    "DeviceManager",
    "DeviceMetadata",
    "DeviceMonitor",
    "DeviceScanningPolicy",
    "PartitionMetadata",
    "PolicyManager",
    "get_device_provider",
]
