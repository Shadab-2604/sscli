"""macOS device provider parsing diskutil list -plist and system_profiler SPUSBDataType."""

from __future__ import annotations

import logging
import plistlib
import subprocess
from typing import Any

import psutil

from systemscan.devices.classifier import DeviceClassifier
from systemscan.devices.models import (
    BusType,
    DeviceConnectionStatus,
    DeviceMetadata,
    PartitionMetadata,
)
from systemscan.devices.providers.base import DeviceProvider

logger = logging.getLogger("systemscan.devices.providers.macos")


class MacOSDeviceProvider(DeviceProvider):
    """Enumerates macOS storage devices and USB tree via diskutil and system_profiler."""

    def discover_devices(self) -> list[DeviceMetadata]:
        devices: list[DeviceMetadata] = []
        try:
            storage = self._discover_diskutil_storage()
            devices.extend(storage)
        except Exception as e:
            logger.warning(f"Error enumerating macOS storage via diskutil: {e}")

        try:
            usb_peripherals = self._discover_system_profiler_usb()
            devices.extend(usb_peripherals)
        except Exception as e:
            logger.warning(f"Error enumerating macOS USB via system_profiler: {e}")

        if not devices:
            devices = self._fallback_psutil()

        return devices

    def _discover_diskutil_storage(self) -> list[DeviceMetadata]:
        """Query diskutil list -plist and diskutil info -plist."""
        result = subprocess.run(["diskutil", "list", "-plist"], capture_output=True, timeout=10)
        if result.returncode != 0:
            return []

        try:
            plist_data = plistlib.loads(result.stdout)
        except Exception as e:
            logger.warning(f"Failed to parse diskutil plist: {e}")
            return []

        all_disks = plist_data.get("AllDisksAndPartitions") or []
        devices: list[DeviceMetadata] = []

        for disk_entry in all_disks:
            dev_id = disk_entry.get("DeviceIdentifier") or ""
            # Inspect details via diskutil info -plist <dev_id>
            info_res = subprocess.run(
                ["diskutil", "info", "-plist", dev_id],
                capture_output=True,
                timeout=5,
            )
            disk_info: dict[str, Any] = {}
            if info_res.returncode == 0:
                try:
                    disk_info = plistlib.loads(info_res.stdout)
                except Exception:
                    pass

            name = disk_info.get("MediaName") or dev_id
            bus_raw = str(disk_info.get("BusProtocol") or "").lower()
            is_removable = bool(disk_info.get("RemovableMedia") or disk_info.get("Ejectable"))
            is_readonly = bool(disk_info.get("Writable") is False)
            total_size = disk_info.get("TotalSize") or disk_entry.get("Size") or 0

            bus_type = BusType.UNKNOWN
            if "usb" in bus_raw:
                bus_type = BusType.USB
            elif "pci" in bus_raw or "nvme" in bus_raw or "apple fabric" in bus_raw:
                bus_type = BusType.NVME
            elif "sata" in bus_raw:
                bus_type = BusType.SATA
            elif "thunderbolt" in bus_raw:
                bus_type = BusType.THUNDERBOLT

            # Partitions
            raw_parts = disk_entry.get("Partitions") or []
            partitions: list[PartitionMetadata] = []
            mount_points: list[str] = []
            fs_types: list[str] = []

            for p in raw_parts:
                p_id = p.get("DeviceIdentifier") or ""
                p_mp = p.get("MountPoint")
                p_size = p.get("Size") or 0
                p_fs = p.get("Content") or "unknown"

                if p_mp:
                    mount_points.append(p_mp)
                if p_fs and p_fs not in fs_types:
                    fs_types.append(p_fs)

                partitions.append(
                    PartitionMetadata(
                        partition_id=f"/dev/{p_id}",
                        name=p.get("VolumeName") or p_id,
                        mount_point=p_mp,
                        filesystem_type=p_fs,
                        capacity_bytes=p_size,
                        is_mounted=bool(p_mp),
                        is_readonly=is_readonly,
                    )
                )

            category, confidence = DeviceClassifier.classify(
                name=name,
                bus_type=bus_type,
                is_removable=is_removable,
                is_storage=True,
                capacity_bytes=total_size,
                interface_type=bus_raw,
            )

            devices.append(
                DeviceMetadata(
                    device_id=f"/dev/{dev_id}",
                    name=name,
                    category=category,
                    vendor=disk_info.get("DeviceVendor") or "Apple",
                    product_name=name,
                    bus_type=bus_type,
                    serial_number=disk_info.get("MediaUUID"),
                    capacity_bytes=total_size,
                    is_removable=is_removable,
                    is_storage=True,
                    is_readonly=is_readonly,
                    is_mounted=bool(mount_points),
                    mount_points=mount_points,
                    primary_mount_point=mount_points[0] if mount_points else None,
                    filesystem_types=fs_types,
                    partitions=partitions,
                    status=DeviceConnectionStatus.CONNECTED,
                    confidence_score=confidence,
                    raw_attributes=disk_info,
                )
            )

        return devices

    def _discover_system_profiler_usb(self) -> list[DeviceMetadata]:
        """Query system_profiler SPUSBDataType -xml to find USB peripherals."""
        result = subprocess.run(
            ["system_profiler", "SPUSBDataType", "-xml"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            return []

        try:
            plist_data = plistlib.loads(result.stdout)
        except Exception:
            return []

        peripherals: list[DeviceMetadata] = []

        def traverse_items(items: list[dict[str, Any]]) -> None:
            for item in items:
                name = item.get("_name") or "USB Device"
                mfg = item.get("manufacturer") or "Apple"
                serial = item.get("serial_num")

                # If it has sub-items, traverse recursively
                if "_items" in item:
                    traverse_items(item["_items"])

                # Skip root hub
                if "hub" in name.lower() or "host controller" in name.lower():
                    continue

                category, confidence = DeviceClassifier.classify(
                    name=f"{mfg} {name}".strip(),
                    bus_type=BusType.USB,
                    is_removable=True,
                    is_storage=False,
                )

                peripherals.append(
                    DeviceMetadata(
                        device_id=f"usb-{name.replace(' ', '_')}",
                        name=f"{mfg} {name}".strip(),
                        category=category,
                        vendor=mfg,
                        product_name=name,
                        bus_type=BusType.USB,
                        serial_number=serial,
                        is_removable=True,
                        is_storage=False,
                        status=DeviceConnectionStatus.CONNECTED,
                        confidence_score=confidence,
                    )
                )

        if isinstance(plist_data, list) and plist_data:
            usb_tree = plist_data[0].get("_items") or []
            traverse_items(usb_tree)

        return peripherals

    def _fallback_psutil(self) -> list[DeviceMetadata]:
        devices: list[DeviceMetadata] = []
        for idx, part in enumerate(psutil.disk_partitions(all=True)):
            is_removable = "removable" in part.opts.lower()
            try:
                usage = psutil.disk_usage(part.mountpoint)
                cap = usage.total
                used = usage.used
                free = usage.free
            except (PermissionError, OSError):
                cap = 0
                used = 0
                free = 0

            cat, conf = DeviceClassifier.classify(
                name=part.device,
                bus_type=BusType.UNKNOWN,
                is_removable=is_removable,
                is_storage=True,
                capacity_bytes=cap,
            )

            pm = PartitionMetadata(
                partition_id=part.device,
                name=part.device,
                mount_point=part.mountpoint,
                filesystem_type=part.fstype or "unknown",
                capacity_bytes=cap,
                used_bytes=used,
                free_bytes=free,
                is_mounted=True,
            )

            devices.append(
                DeviceMetadata(
                    device_id=f"disk-fallback-{idx}",
                    name=part.device,
                    category=cat,
                    vendor="Apple",
                    product_name=part.device,
                    bus_type=BusType.UNKNOWN,
                    capacity_bytes=cap,
                    is_removable=is_removable,
                    is_storage=True,
                    is_mounted=True,
                    mount_points=[part.mountpoint],
                    primary_mount_point=part.mountpoint,
                    filesystem_types=[part.fstype] if part.fstype else [],
                    partitions=[pm],
                    status=DeviceConnectionStatus.CONNECTED,
                    confidence_score=conf,
                )
            )
        return devices
