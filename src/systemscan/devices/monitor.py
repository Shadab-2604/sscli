"""Real-time device monitoring loop with polling delta diffing and event dispatching."""

from __future__ import annotations

import logging
import threading
import uuid

from systemscan.devices.events import DeviceEventDispatcher
from systemscan.devices.inventory import DeviceInventory
from systemscan.devices.models import (
    DeviceEvent,
    DeviceEventType,
    DeviceMetadata,
    DeviceScanningPolicy,
)
from systemscan.devices.providers.base import DeviceProvider

logger = logging.getLogger("systemscan.devices.monitor")


class DeviceMonitor:
    """Monitors device connections, disconnections, and volume mounts in the background."""

    def __init__(
        self,
        provider: DeviceProvider,
        inventory: DeviceInventory,
        dispatcher: DeviceEventDispatcher,
        policy: DeviceScanningPolicy | None = None,
        poll_interval: float = 2.0,
    ) -> None:
        self.provider = provider
        self.inventory = inventory
        self.dispatcher = dispatcher
        self.policy = policy or DeviceScanningPolicy()
        self.poll_interval = poll_interval

        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._last_snapshot: dict[str, DeviceMetadata] = {}
        self._lock = threading.RLock()

    def start(self) -> None:
        """Start the background device monitor thread."""
        with self._lock:
            if self._running:
                logger.warning("DeviceMonitor is already running.")
                return

            self._running = True
            self._stop_event.clear()

            # Take initial snapshot
            try:
                initial_devices = self.provider.discover_devices()
                self.inventory.update_snapshot(initial_devices)
                self._last_snapshot = {
                    d.device_id: d.model_copy(deep=True) for d in initial_devices
                }
            except Exception as e:
                logger.error(f"Failed to capture initial device snapshot: {e}")
                self._last_snapshot = {}

            self._thread = threading.Thread(
                target=self._monitor_loop,
                name="systemscan-device-monitor",
                daemon=True,
            )
            self._thread.start()
            logger.info(f"DeviceMonitor started with poll_interval={self.poll_interval}s")

    def stop(self, timeout: float = 5.0) -> None:
        """Signal monitor to stop and wait for thread to terminate."""
        with self._lock:
            if not self._running:
                return

            self._running = False
            self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            logger.info("DeviceMonitor thread stopped successfully.")

    def is_running(self) -> bool:
        """Check whether monitoring loop is actively executing."""
        return self._running

    def _monitor_loop(self) -> None:
        """Background thread loop polling provider and diffing snapshots."""
        while not self._stop_event.is_set():
            # Wait for poll interval or early stop signal
            if self._stop_event.wait(timeout=self.poll_interval):
                break

            try:
                current_devices = self.provider.discover_devices()
                self._diff_and_dispatch(current_devices)
                self.inventory.update_snapshot(current_devices)
            except Exception as e:
                logger.error(f"Error in device monitoring loop: {e}", exc_info=True)

    def _diff_and_dispatch(self, current_devices: list[DeviceMetadata]) -> None:
        """Compare current device inventory against previous snapshot and dispatch events."""
        current_map = {d.device_id: d for d in current_devices}
        prev_map = self._last_snapshot

        # 1. Detect Newly Connected Devices
        for dev_id, dev in current_map.items():
            if dev_id not in prev_map:
                # Filter non-storage if policy says so
                if self.policy.ignore_non_storage and not dev.is_storage:
                    continue
                # Filter excluded devices
                if dev_id in self.policy.excluded_device_ids:
                    continue

                event = DeviceEvent(
                    event_id=str(uuid.uuid4()),
                    event_type=DeviceEventType.DEVICE_CONNECTED,
                    device_id=dev.device_id,
                    device_name=dev.name,
                    category=dev.category,
                    is_removable=dev.is_removable,
                    is_storage=dev.is_storage,
                    mount_point=dev.primary_mount_point,
                    details={
                        "capacity_bytes": dev.capacity_bytes,
                        "mount_points": dev.mount_points,
                        "bus_type": dev.bus_type.value,
                        "filesystem_types": dev.filesystem_types,
                    },
                )
                logger.info(f"Detected new device connection: {dev.name} ({dev_id})")
                self.dispatcher.emit(event)

            else:
                # 2. Check for mount point changes / new mounts
                prev_dev = prev_map[dev_id]
                new_mounts = set(dev.mount_points) - set(prev_dev.mount_points)
                unmounted = set(prev_dev.mount_points) - set(dev.mount_points)

                for mp in new_mounts:
                    if mp in self.policy.excluded_mount_points:
                        continue
                    m_event = DeviceEvent(
                        event_id=str(uuid.uuid4()),
                        event_type=DeviceEventType.VOLUME_MOUNTED,
                        device_id=dev.device_id,
                        device_name=dev.name,
                        category=dev.category,
                        is_removable=dev.is_removable,
                        is_storage=dev.is_storage,
                        mount_point=mp,
                        details={"device_id": dev.device_id, "capacity_bytes": dev.capacity_bytes},
                    )
                    logger.info(f"Detected newly mounted volume: {mp} on {dev.name}")
                    self.dispatcher.emit(m_event)

                for mp in unmounted:
                    um_event = DeviceEvent(
                        event_id=str(uuid.uuid4()),
                        event_type=DeviceEventType.VOLUME_UNMOUNTED,
                        device_id=dev.device_id,
                        device_name=dev.name,
                        category=dev.category,
                        is_removable=dev.is_removable,
                        is_storage=dev.is_storage,
                        mount_point=mp,
                        details={"device_id": dev.device_id},
                    )
                    logger.info(f"Detected unmounted volume: {mp} from {dev.name}")
                    self.dispatcher.emit(um_event)

        # 3. Detect Disconnected Devices
        for dev_id, prev_dev in prev_map.items():
            if dev_id not in current_map:
                if self.policy.ignore_non_storage and not prev_dev.is_storage:
                    continue

                d_event = DeviceEvent(
                    event_id=str(uuid.uuid4()),
                    event_type=DeviceEventType.DEVICE_DISCONNECTED,
                    device_id=prev_dev.device_id,
                    device_name=prev_dev.name,
                    category=prev_dev.category,
                    is_removable=prev_dev.is_removable,
                    is_storage=prev_dev.is_storage,
                    mount_point=prev_dev.primary_mount_point,
                    details={"previous_mounts": prev_dev.mount_points},
                )
                logger.info(f"Detected device disconnection: {prev_dev.name} ({dev_id})")
                self.dispatcher.emit(d_event)

        self._last_snapshot = {k: v.model_copy(deep=True) for k, v in current_map.items()}
