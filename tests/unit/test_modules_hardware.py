"""Unit tests for Hardware inspection modules."""

from systemscan.modules.hardware.cpu import collect_cpu_info
from systemscan.modules.hardware.devices import collect_device_inventory
from systemscan.modules.hardware.firmware import collect_firmware_info
from systemscan.modules.hardware.gpu import collect_gpu_info
from systemscan.modules.hardware.memory import collect_memory_info
from systemscan.modules.hardware.storage import (
    collect_partition_info,
    collect_storage_info,
)
from systemscan.modules.models import (
    CPUInformation,
    FirmwareInformation,
    MemoryInformation,
)
from systemscan.utils.formatting import format_bytes, format_duration


def test_cpu_collection() -> None:
    cpu = collect_cpu_info(interval=None)
    assert isinstance(cpu, CPUInformation)
    assert len(cpu.model) > 0
    assert len(cpu.architecture) > 0
    assert cpu.logical_cores is None or cpu.logical_cores >= 1
    assert cpu.utilization_percent >= 0.0
    assert isinstance(cpu.per_core_utilization, list)


def test_memory_collection() -> None:
    mem = collect_memory_info()
    assert isinstance(mem, MemoryInformation)
    assert mem.total_bytes > 0
    assert mem.used_bytes >= 0
    assert mem.available_bytes >= 0
    assert 0.0 <= mem.percentage <= 100.0

    # Test human-readable formatted getters
    assert "GB" in mem.total_formatted or "MB" in mem.total_formatted
    assert "GB" in mem.used_formatted or "MB" in mem.used_formatted


def test_gpu_collection() -> None:
    gpus = collect_gpu_info()
    assert isinstance(gpus, list)
    for g in gpus:
        assert len(g.vendor) > 0
        assert len(g.model) > 0


def test_firmware_collection_redaction() -> None:
    # 1. By default, serial numbers must be redacted
    fw_redacted = collect_firmware_info(include_serials=False)
    assert isinstance(fw_redacted, FirmwareInformation)
    if fw_redacted.serial_number:
        assert "[REDACTED]" in fw_redacted.serial_number

    # 2. When explicitly requested, redaction notice is bypassed
    fw_allowed = collect_firmware_info(include_serials=True)
    if fw_allowed.serial_number:
        assert "[REDACTED]" not in fw_allowed.serial_number


def test_storage_collection() -> None:
    partitions = collect_partition_info()
    assert isinstance(partitions, list)
    if partitions:
        p = partitions[0]
        assert len(p.device) > 0
        assert len(p.mountpoint) > 0
        assert p.total_bytes > 0

    parts, disks = collect_storage_info()
    assert isinstance(disks, list)


def test_device_inventory() -> None:
    devices = collect_device_inventory()
    assert isinstance(devices, list)
    for d in devices:
        assert len(d.device_type) > 0
        assert len(d.name) > 0


def test_formatting_helpers() -> None:
    assert format_bytes(1024) == "1.00 KB"
    assert format_bytes(1024 * 1024) == "1.00 MB"
    assert format_bytes(1024 * 1024 * 1024) == "1.00 GB"
    assert format_bytes(None) == "N/A"

    assert format_duration(65) == "1m 5s"
    assert format_duration(3665) == "1h 1m 5s"
    assert format_duration(90065) == "1d 1h 1m 5s"
