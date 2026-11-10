"""Integration tests for Phase 4: Device monitoring, event dispatching, CLI, and dynamic scanning."""

from __future__ import annotations

import time
from pathlib import Path

from typer.testing import CliRunner

from systemscan.cli import app
from systemscan.devices.events import DeviceEventDispatcher
from systemscan.devices.inventory import DeviceInventory
from systemscan.devices.manager import DeviceManager
from systemscan.devices.models import (
    BusType,
    DeviceCategory,
    DeviceEvent,
    DeviceEventType,
    DeviceMetadata,
    DeviceScanningPolicy,
)
from systemscan.devices.monitor import DeviceMonitor
from systemscan.devices.providers.base import DeviceProvider
from systemscan.filesystem.engine import FilesystemScanner
from systemscan.filesystem.models import ScanConfig


class SimulatedDeviceProvider(DeviceProvider):
    """Simulates dynamic hardware events for test isolation."""

    def __init__(self, initial_devices: list[DeviceMetadata] | None = None) -> None:
        self.devices: list[DeviceMetadata] = list(initial_devices or [])

    def discover_devices(self) -> list[DeviceMetadata]:
        return list(self.devices)

    def attach_device(self, dev: DeviceMetadata) -> None:
        self.devices.append(dev)

    def detach_device(self, device_id: str) -> None:
        self.devices = [d for d in self.devices if d.device_id != device_id]

    def mount_volume(self, device_id: str, mount_point: str) -> None:
        for d in self.devices:
            if d.device_id == device_id:
                if mount_point not in d.mount_points:
                    d.mount_points.append(mount_point)
                d.is_mounted = True


def test_device_monitor_delta_diff_and_events() -> None:
    """Verify monitor loop detects new devices, mounts, and disconnections."""
    base_dev = DeviceMetadata(
        device_id="disk-0",
        name="Internal NVMe",
        category=DeviceCategory.INTERNAL_STORAGE,
        bus_type=BusType.NVME,
        capacity_bytes=1000,
        is_storage=True,
        is_removable=False,
        is_mounted=True,
        mount_points=["/dev/nvme0n1p1"],
    )

    provider = SimulatedDeviceProvider([base_dev])
    inv = DeviceInventory()
    dispatcher = DeviceEventDispatcher()

    received_events: list[DeviceEvent] = []
    dispatcher.subscribe(lambda e: received_events.append(e))

    monitor = DeviceMonitor(
        provider=provider,
        inventory=inv,
        dispatcher=dispatcher,
        policy=DeviceScanningPolicy(ignore_non_storage=False),
        poll_interval=0.1,
    )

    monitor.start()
    assert monitor.is_running()
    time.sleep(0.15)

    # 1. Attach new USB drive
    usb_drive = DeviceMetadata(
        device_id="usb-flash-001",
        name="SanDisk Cruzer",
        category=DeviceCategory.USB_FLASH_DRIVE,
        bus_type=BusType.USB,
        capacity_bytes=32000000000,
        is_storage=True,
        is_removable=True,
        is_mounted=False,
        mount_points=[],
    )
    provider.attach_device(usb_drive.model_copy())
    time.sleep(0.3)

    assert any(
        e.event_type == DeviceEventType.DEVICE_CONNECTED and e.device_id == "usb-flash-001"
        for e in received_events
    )

    # 2. Mount partition on the USB drive
    provider.mount_volume("usb-flash-001", "/mnt/usb1")
    time.sleep(0.3)

    assert any(
        e.event_type == DeviceEventType.VOLUME_MOUNTED and e.mount_point == "/mnt/usb1"
        for e in received_events
    )

    # 3. Detach device
    provider.detach_device("usb-flash-001")
    time.sleep(0.3)

    assert any(
        e.event_type == DeviceEventType.DEVICE_DISCONNECTED and e.device_id == "usb-flash-001"
        for e in received_events
    )

    monitor.stop()
    assert not monitor.is_running()


def test_dynamic_scan_root_injection(tmp_path: Path) -> None:
    """Verify FilesystemScanner dynamically queues newly attached roots during traversal."""
    root_dir_1 = tmp_path / "root1"
    root_dir_1.mkdir()
    (root_dir_1 / "file1.txt").write_text("Hello Root 1")

    root_dir_2 = tmp_path / "root2_removable"
    root_dir_2.mkdir()
    (root_dir_2 / "usb_file.txt").write_text("Hello Removable USB")

    scanner = FilesystemScanner()

    # Dynamic roots provider simulates adding root_dir_2 after scan starts
    added = False

    def dynamic_provider() -> list[str]:
        nonlocal added
        if not added:
            added = True
            return [str(root_dir_2)]
        return []

    discovered_files: list[str] = []

    summary = scanner.scan_paths(
        roots=[str(root_dir_1)],
        config=ScanConfig(roots=[str(root_dir_1)]),
        on_item=lambda it: discovered_files.append(it.name),
        dynamic_roots_provider=dynamic_provider,
    )

    assert summary.status.value == "completed"
    assert "file1.txt" in discovered_files
    assert "usb_file.txt" in discovered_files
    assert summary.statistics.files_scanned >= 2
    assert str(root_dir_2) in summary.roots


def test_cli_devices_commands() -> None:
    """Test `systemscan devices` CLI commands."""
    runner = CliRunner()

    # 1. list text
    res = runner.invoke(app, ["devices", "list"])
    assert res.exit_code == 0
    assert "Connected Devices Inventory" in res.output or "Device ID" in res.output

    # 2. list json
    res_json = runner.invoke(app, ["devices", "list", "--format", "json"])
    assert res_json.exit_code == 0
    assert "device_id" in res_json.output

    # 3. info existing
    manager = DeviceManager()
    devs = manager.discover_all()
    target_id = devs[0].device_id if devs else "disk-0"
    res_info = runner.invoke(app, ["devices", "info", target_id])
    assert res_info.exit_code == 0
    assert "DEVICE INSPECTION" in res_info.output or target_id in res_info.output

    # 4. info non-existing
    res_bad = runner.invoke(app, ["devices", "info", "non-existent-device-id-999"])
    assert res_bad.exit_code != 0
