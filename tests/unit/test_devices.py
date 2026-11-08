"""Unit tests for Phase 4: Device Models, Classifier, Inventory, and Policies."""

from __future__ import annotations

from systemscan.devices.classifier import DeviceClassifier
from systemscan.devices.inventory import DeviceInventory
from systemscan.devices.metadata import redact_serial_number, sanitize_device_metadata
from systemscan.devices.models import (
    BusType,
    DeviceCategory,
    DeviceMetadata,
    DeviceScanningPolicy,
)
from systemscan.devices.policies import PolicyManager


def test_serial_redaction() -> None:
    assert redact_serial_number(None) == "[NOT AVAILABLE]"
    assert redact_serial_number("") == "[NOT AVAILABLE]"
    assert redact_serial_number("1234") == "****"
    assert redact_serial_number("ABCDEF123456") == "AB****56"


def test_device_metadata_sanitization() -> None:
    dev = DeviceMetadata(
        device_id="test-1",
        name="Ultra Fit",
        serial_number="SANDISK12345678",
        is_storage=True,
    )
    sanitized = sanitize_device_metadata(dev, redact_serial=True)
    assert sanitized.serial_number == "SA****78"
    assert sanitized.name == "Ultra Fit"

    unsanitized = sanitize_device_metadata(dev, redact_serial=False)
    assert unsanitized.serial_number == "SANDISK12345678"


def test_device_classifier_flash_drive() -> None:
    cat, conf = DeviceClassifier.classify(
        name="SanDisk Ultra Cruzer Flash Drive",
        bus_type=BusType.USB,
        is_removable=True,
        is_storage=True,
        capacity_bytes=32 * 1024 * 1024 * 1024,
    )
    assert cat == DeviceCategory.USB_FLASH_DRIVE
    assert conf >= 0.85


def test_device_classifier_external_ssd() -> None:
    cat, conf = DeviceClassifier.classify(
        name="Samsung Portable SSD T7",
        bus_type=BusType.USB,
        is_removable=True,
        is_storage=True,
        capacity_bytes=1000 * 1024 * 1024 * 1024,
    )
    assert cat == DeviceCategory.EXTERNAL_SSD
    assert conf >= 0.85


def test_device_classifier_external_hdd() -> None:
    cat, conf = DeviceClassifier.classify(
        name="WD Elements Portable HDD",
        bus_type=BusType.USB,
        is_removable=True,
        is_storage=True,
        capacity_bytes=2000 * 1024 * 1024 * 1024,
    )
    assert cat == DeviceCategory.EXTERNAL_HDD
    assert conf >= 0.85


def test_device_classifier_peripheral() -> None:
    cat, conf = DeviceClassifier.classify(
        name="Logitech USB Optical Mouse",
        bus_type=BusType.USB,
        is_removable=True,
        is_storage=False,
    )
    assert cat == DeviceCategory.USB_PERIPHERAL
    assert conf >= 0.90


def test_device_classifier_optical_drive() -> None:
    cat, conf = DeviceClassifier.classify(
        name="HL-DT-ST DVDRAM GUE1N",
        bus_type=BusType.SATA,
        is_removable=True,
        is_storage=True,
    )
    assert cat == DeviceCategory.OPTICAL_DRIVE
    assert conf >= 0.90


def test_device_classifier_internal_storage() -> None:
    cat, conf = DeviceClassifier.classify(
        name="Samsung SSD 980 PRO 1TB",
        bus_type=BusType.NVME,
        is_removable=False,
        is_storage=True,
        capacity_bytes=1000 * 1024 * 1024 * 1024,
    )
    assert cat == DeviceCategory.INTERNAL_STORAGE
    assert conf >= 0.95


def test_device_inventory_crud_and_queries() -> None:
    inv = DeviceInventory()
    d1 = DeviceMetadata(
        device_id="disk-0",
        name="Internal NVMe",
        category=DeviceCategory.INTERNAL_STORAGE,
        bus_type=BusType.NVME,
        capacity_bytes=1000,
        is_storage=True,
        is_removable=False,
        is_mounted=True,
        mount_points=["C:\\"],
    )
    d2 = DeviceMetadata(
        device_id="usb-flash-1",
        name="USB Flash Drive",
        category=DeviceCategory.USB_FLASH_DRIVE,
        bus_type=BusType.USB,
        capacity_bytes=500,
        is_storage=True,
        is_removable=True,
        is_mounted=True,
        mount_points=["E:\\"],
    )
    d3 = DeviceMetadata(
        device_id="mouse-1",
        name="USB Mouse",
        category=DeviceCategory.USB_PERIPHERAL,
        bus_type=BusType.USB,
        is_storage=False,
        is_removable=True,
    )

    inv.update_snapshot([d1, d2, d3])

    assert len(inv.get_all()) == 3
    assert inv.get_by_id("disk-0") is not None
    assert inv.get_by_id("non-existent") is None

    removables = inv.get_removable_storage()
    assert len(removables) == 1
    assert removables[0].device_id == "usb-flash-1"

    storages = inv.get_storage_devices()
    assert len(storages) == 2

    by_mount = inv.get_by_mount_point("E:\\")
    assert by_mount is not None
    assert by_mount.device_id == "usb-flash-1"

    by_cat = inv.get_by_category(DeviceCategory.USB_PERIPHERAL)
    assert len(by_cat) == 1
    assert by_cat[0].device_id == "mouse-1"


def test_policy_manager() -> None:
    policy = DeviceScanningPolicy(
        include_removable_by_default=False,
        require_user_approval=True,
        excluded_device_ids=["disk-0"],
        excluded_mount_points=["Z:\\"],
    )
    mgr = PolicyManager(policy)
    assert mgr.is_approval_required() is True
    assert mgr.should_auto_include_removable() is False

    d_excluded = DeviceMetadata(
        device_id="disk-0",
        name="Internal NVMe",
        is_storage=True,
        is_mounted=True,
        mount_points=["C:\\"],
    )
    assert mgr.should_scan_device(d_excluded) is False

    d_valid = DeviceMetadata(
        device_id="usb-1",
        name="USB Stick",
        is_storage=True,
        is_mounted=True,
        mount_points=["E:\\"],
    )
    assert mgr.should_scan_device(d_valid) is True

    d_non_storage = DeviceMetadata(
        device_id="kbd-1",
        name="Keyboard",
        is_storage=False,
        is_mounted=False,
    )
    assert mgr.should_scan_device(d_non_storage) is False
