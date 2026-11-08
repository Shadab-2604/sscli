"""Pydantic data models and enumerations for Device Management & Monitoring (Phase 4)."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DeviceCategory(str, Enum):
    """Categorization of detected devices."""

    USB_FLASH_DRIVE = "usb_flash_drive"
    EXTERNAL_HDD = "external_hdd"
    EXTERNAL_SSD = "external_ssd"
    USB_STORAGE = "usb_storage"
    SD_CARD = "sd_card"
    OPTICAL_DRIVE = "optical_drive"
    INTERNAL_STORAGE = "internal_storage"
    USB_PERIPHERAL = "usb_peripheral"
    NETWORK_DEVICE = "network_device"
    UNKNOWN = "unknown"


class BusType(str, Enum):
    """Hardware interconnect / bus protocol."""

    USB = "usb"
    SATA = "sata"
    NVME = "nvme"
    SCSI = "scsi"
    THUNDERBOLT = "thunderbolt"
    SDIO = "sdio"
    PCI = "pci"
    VIRTUAL = "virtual"
    UNKNOWN = "unknown"


class DeviceConnectionStatus(str, Enum):
    """Lifecycle connection status of a device."""

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    MOUNTED = "mounted"
    UNMOUNTED = "unmounted"
    UNKNOWN = "unknown"


class DeviceEventType(str, Enum):
    """Events emitted by the device monitoring subsystem."""

    DEVICE_CONNECTED = "device_connected"
    DEVICE_DISCONNECTED = "device_disconnected"
    VOLUME_MOUNTED = "volume_mounted"
    VOLUME_UNMOUNTED = "volume_unmounted"
    DEVICE_CHANGED = "device_changed"
    DEVICE_DISCOVERED = "device_discovered"
    DEVICE_DISCOVERY_FAILED = "device_discovery_failed"


class PartitionMetadata(BaseModel):
    """Logical partition residing on a physical or virtual storage device."""

    partition_id: str = Field(
        description="Unique partition identifier (e.g., Disk #1, Partition #0 or /dev/sdb1)"
    )
    name: str = Field(default="", description="Partition name or label")
    mount_point: str | None = Field(
        default=None, description="Filesystem mount path or Windows drive letter"
    )
    filesystem_type: str = Field(
        default="unknown", description="Filesystem format (NTFS, FAT32, ext4, APFS, etc.)"
    )
    capacity_bytes: int = Field(default=0, ge=0, description="Total partition capacity in bytes")
    used_bytes: int = Field(default=0, ge=0, description="Used space in bytes")
    free_bytes: int = Field(default=0, ge=0, description="Available free space in bytes")
    is_mounted: bool = Field(
        default=False, description="Whether partition is currently mounted in OS"
    )
    is_readonly: bool = Field(default=False, description="Whether partition is mounted read-only")


class DeviceMetadata(BaseModel):
    """Comprehensive device descriptor for inventory, classification, and scanning."""

    device_id: str = Field(description="Canonical unique hardware/system device identifier")
    name: str = Field(description="Display name or product string")
    category: DeviceCategory = Field(
        default=DeviceCategory.UNKNOWN, description="Classified device role"
    )
    vendor: str = Field(default="Unknown", description="Device vendor / manufacturer name")
    manufacturer: str = Field(default="Unknown", description="Reported hardware manufacturer")
    product_name: str = Field(default="", description="Model name or product string")
    vendor_id: str | None = Field(
        default=None, description="USB VID (e.g., '0781') where available"
    )
    product_id: str | None = Field(
        default=None, description="USB PID (e.g., '5567') where available"
    )
    bus_type: BusType = Field(default=BusType.UNKNOWN, description="Connection bus protocol")
    serial_number: str | None = Field(
        default=None, description="Serial number (redacted if requested)"
    )
    capacity_bytes: int = Field(
        default=0, ge=0, description="Total storage capacity in bytes (0 for non-storage)"
    )
    is_removable: bool = Field(default=False, description="Whether OS flags device as removable")
    is_storage: bool = Field(default=False, description="Whether device is a storage disk/volume")
    is_readonly: bool = Field(
        default=False, description="Whether hardware or volume is write-protected"
    )
    is_mounted: bool = Field(
        default=False, description="Whether at least one partition is actively mounted"
    )
    mount_points: list[str] = Field(
        default_factory=list, description="All active mount points for this device"
    )
    primary_mount_point: str | None = Field(
        default=None, description="Primary mount directory or drive root"
    )
    filesystem_types: list[str] = Field(
        default_factory=list, description="Filesystem formats on this device"
    )
    partitions: list[PartitionMetadata] = Field(
        default_factory=list, description="Associated logical partitions"
    )
    status: DeviceConnectionStatus = Field(
        default=DeviceConnectionStatus.CONNECTED, description="Current connection state"
    )
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="UTC timestamp of discovery"
    )
    confidence_score: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Classification confidence (0.0 to 1.0)"
    )
    raw_attributes: dict[str, Any] = Field(
        default_factory=dict, description="Platform-specific raw device attributes"
    )

    @property
    def capacity_formatted(self) -> str:
        """Human-readable size format."""
        if self.capacity_bytes <= 0:
            return "N/A"
        units = ["B", "KB", "MB", "GB", "TB", "PB"]
        val = float(self.capacity_bytes)
        idx = 0
        while val >= 1024.0 and idx < len(units) - 1:
            val /= 1024.0
            idx += 1
        return f"{val:.1f} {units[idx]}"


class DeviceEvent(BaseModel):
    """An event emitted when a hardware change, attachment, or volume mount occurs."""

    event_id: str = Field(description="Unique UUID for this event occurrence")
    event_type: DeviceEventType = Field(description="Type of device event")
    device_id: str = Field(description="Target device identifier")
    device_name: str = Field(default="", description="Target device display name")
    category: DeviceCategory = Field(
        default=DeviceCategory.UNKNOWN, description="Device classification"
    )
    is_removable: bool = Field(default=False, description="Whether target is a removable device")
    is_storage: bool = Field(default=False, description="Whether target provides storage")
    mount_point: str | None = Field(
        default=None, description="Associated mount point if applicable"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp event was detected",
    )
    details: dict[str, Any] = Field(
        default_factory=dict, description="Additional context or state delta"
    )


class DeviceScanningPolicy(BaseModel):
    """Security and traversal policy governing removable storage handling."""

    include_removable_by_default: bool = Field(
        default=False,
        description="Whether full system scans automatically traverse removable drives without asking",
    )
    monitor_new_attachments_during_scan: bool = Field(
        default=True,
        description="Whether active scans monitor for and detect newly attached storage devices",
    )
    require_user_approval: bool = Field(
        default=True,
        description="Whether the user must explicitly approve scanning a newly attached storage device",
    )
    non_interactive_action: str = Field(
        default="ignore",
        description="Action for newly attached devices in non-interactive mode ('ignore' or 'scan')",
    )
    ignore_non_storage: bool = Field(
        default=True,
        description="Ignore keyboards, mice, and non-storage peripherals during storage monitoring",
    )
    redact_serial_numbers: bool = Field(
        default=True,
        description="Redact hardware serial numbers in inventory reports and displays",
    )
    excluded_device_ids: list[str] = Field(
        default_factory=list,
        description="Explicit device IDs to ignore",
    )
    excluded_mount_points: list[str] = Field(
        default_factory=list,
        description="Explicit mount points to ignore",
    )
