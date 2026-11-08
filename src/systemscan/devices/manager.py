"""Device subsystem coordinator integrating discovery, inventory, monitoring, and events."""

from __future__ import annotations

import logging

from systemscan.devices.events import DeviceEventDispatcher, EventCallback
from systemscan.devices.inventory import DeviceInventory
from systemscan.devices.models import (
    DeviceEventType,
    DeviceMetadata,
    DeviceScanningPolicy,
)
from systemscan.devices.monitor import DeviceMonitor
from systemscan.devices.policies import PolicyManager
from systemscan.devices.providers import get_device_provider
from systemscan.devices.providers.base import DeviceProvider

logger = logging.getLogger("systemscan.devices.manager")


class DeviceManager:
    """Unified entry point for device discovery, inventory queries, policies, and real-time monitoring."""

    def __init__(
        self,
        provider: DeviceProvider | None = None,
        policy: DeviceScanningPolicy | None = None,
    ) -> None:
        self.policy = policy or DeviceScanningPolicy()
        self.policy_manager = PolicyManager(self.policy)
        self.provider = provider or get_device_provider()
        self.inventory = DeviceInventory(self.policy)
        self.dispatcher = DeviceEventDispatcher()
        self.monitor = DeviceMonitor(
            provider=self.provider,
            inventory=self.inventory,
            dispatcher=self.dispatcher,
            policy=self.policy,
        )

    def discover_all(self) -> list[DeviceMetadata]:
        """Perform a fresh discovery sweep and update the inventory snapshot."""
        devices = self.provider.discover_devices()
        self.inventory.update_snapshot(devices)
        return self.inventory.get_all()

    def get_removable_storage(self) -> list[DeviceMetadata]:
        """Retrieve all currently registered removable storage devices."""
        # Ensure inventory is populated if empty
        if not self.inventory.get_all():
            self.discover_all()
        return self.inventory.get_removable_storage()

    def get_device_info(self, device_id: str) -> DeviceMetadata | None:
        """Fetch details for a specific device identifier."""
        if not self.inventory.get_all():
            self.discover_all()
        return self.inventory.get_by_id(device_id)

    def start_monitoring(self, poll_interval: float = 2.0) -> None:
        """Start the background device monitor loop."""
        self.monitor.poll_interval = poll_interval
        self.monitor.start()

    def stop_monitoring(self) -> None:
        """Stop the background device monitor loop."""
        self.monitor.stop()

    def is_monitoring(self) -> bool:
        """Check whether monitor loop is running."""
        return self.monitor.is_running()

    def subscribe_events(
        self, callback: EventCallback, event_type: DeviceEventType | None = None
    ) -> None:
        """Subscribe to device hardware or mount events."""
        self.dispatcher.subscribe(callback, event_type)

    def unsubscribe_events(
        self, callback: EventCallback, event_type: DeviceEventType | None = None
    ) -> None:
        """Unsubscribe from device events."""
        self.dispatcher.unsubscribe(callback, event_type)
