"""Windows device provider querying Get-Disk, Get-Partition, Get-Volume, and Win32_USBHub."""

from __future__ import annotations

import json
import logging
import re
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

logger = logging.getLogger("systemscan.devices.providers.windows")


class WindowsDeviceProvider(DeviceProvider):
    """Enumerates Windows storage disks, partitions, mounted volumes, and USB hubs/controllers."""

    def discover_devices(self) -> list[DeviceMetadata]:
        devices: list[DeviceMetadata] = []
        try:
            storage_devices = self._discover_storage_devices()
            devices.extend(storage_devices)
        except Exception as e:
            logger.warning(f"Error enumerating Windows storage devices: {e}")

        try:
            usb_peripherals = self._discover_usb_peripherals()
            devices.extend(usb_peripherals)
        except Exception as e:
            logger.warning(f"Error enumerating Windows USB peripherals: {e}")

        # If PowerShell failed or returned empty storage, fallback to psutil disk partitions
        if not devices:
            devices = self._fallback_psutil()

        return devices

    def _discover_storage_devices(self) -> list[DeviceMetadata]:
        """Query Get-Disk, Get-Partition, and Get-Volume to construct complete storage topology."""
        ps_script = """
        $disks = @(Get-Disk | Select-Object Number, FriendlyName, BusType, MediaType, Size, IsRemovable, IsReadOnly, SerialNumber)
        $parts = @(Get-Partition | Select-Object DiskNumber, PartitionNumber, DriveLetter, Size, Type)
        $vols = @(Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, DriveType, Size, SizeRemaining)
        @{ Disks = $disks; Partitions = $parts; Volumes = $vols } | ConvertTo-Json -Depth 4
        """
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            logger.warning(f"PowerShell storage query failed: {result.stderr.strip()}")
            return self._fallback_psutil()

        try:
            data = json.loads(result.stdout)
        except Exception as e:
            logger.warning(f"Failed to parse PowerShell JSON: {e}")
            return self._fallback_psutil()

        raw_disks = data.get("Disks") or []
        if isinstance(raw_disks, dict):
            raw_disks = [raw_disks]
        raw_parts = data.get("Partitions") or []
        if isinstance(raw_parts, dict):
            raw_parts = [raw_parts]
        raw_vols = data.get("Volumes") or []
        if isinstance(raw_vols, dict):
            raw_vols = [raw_vols]

        # Index volumes by drive letter (e.g., "C")
        vol_by_letter: dict[str, dict[str, Any]] = {}
        for v in raw_vols:
            dl = v.get("DriveLetter")
            if dl:
                vol_by_letter[str(dl).upper().strip()] = v

        # Group partitions by disk number
        parts_by_disk: dict[int, list[dict[str, Any]]] = {}
        for p in raw_parts:
            dn = p.get("DiskNumber")
            if dn is not None:
                parts_by_disk.setdefault(int(dn), []).append(p)

        discovered: list[DeviceMetadata] = []
        for disk in raw_disks:
            disk_num = disk.get("Number")
            friendly_name = disk.get("FriendlyName") or f"Disk {disk_num}"
            bus_raw = str(disk.get("BusType") or "").upper()
            size = disk.get("Size") or 0
            is_removable = bool(disk.get("IsRemovable"))
            is_readonly = bool(disk.get("IsReadOnly"))
            serial = disk.get("SerialNumber") or ""

            # Map bus type
            bus_type = BusType.UNKNOWN
            if "USB" in bus_raw:
                bus_type = BusType.USB
            elif "NVME" in bus_raw:
                bus_type = BusType.NVME
            elif "SATA" in bus_raw or "ATA" in bus_raw:
                bus_type = BusType.SATA
            elif "SCSI" in bus_raw:
                bus_type = BusType.SCSI
            elif "SD" in bus_raw:
                bus_type = BusType.SDIO

            # Build partition models
            disk_parts = parts_by_disk.get(disk_num, [])
            partition_models: list[PartitionMetadata] = []
            mount_points: list[str] = []
            fs_types: list[str] = []

            for dp in disk_parts:
                p_num = dp.get("PartitionNumber")
                p_dl = dp.get("DriveLetter")
                p_size = dp.get("Size") or 0
                mount_path = f"{p_dl}:\\" if p_dl else None

                fs_type = "unknown"
                used = 0
                free = 0
                if p_dl and str(p_dl).upper() in vol_by_letter:
                    vol = vol_by_letter[str(p_dl).upper()]
                    fs_type = vol.get("FileSystem") or "unknown"
                    total_vol = vol.get("Size") or p_size
                    free_vol = vol.get("SizeRemaining") or 0
                    used = max(0, total_vol - free_vol)
                    free = free_vol
                    if fs_type not in fs_types:
                        fs_types.append(fs_type)

                if mount_path:
                    mount_points.append(mount_path)

                partition_models.append(
                    PartitionMetadata(
                        partition_id=f"Disk #{disk_num}, Partition #{p_num}",
                        name=f"Partition {p_num}",
                        mount_point=mount_path,
                        filesystem_type=fs_type,
                        capacity_bytes=p_size,
                        used_bytes=used,
                        free_bytes=free,
                        is_mounted=bool(mount_path),
                        is_readonly=is_readonly,
                    )
                )

            # Classify device
            category, confidence = DeviceClassifier.classify(
                name=friendly_name,
                bus_type=bus_type,
                is_removable=is_removable,
                is_storage=True,
                capacity_bytes=size,
                media_type=str(disk.get("MediaType") or ""),
                interface_type=bus_raw,
            )

            primary_mount = mount_points[0] if mount_points else None
            device_id = f"disk-{disk_num}"

            discovered.append(
                DeviceMetadata(
                    device_id=device_id,
                    name=friendly_name,
                    category=category,
                    vendor=friendly_name.split()[0] if friendly_name else "Unknown",
                    product_name=friendly_name,
                    bus_type=bus_type,
                    serial_number=serial if serial else None,
                    capacity_bytes=size,
                    is_removable=is_removable,
                    is_storage=True,
                    is_readonly=is_readonly,
                    is_mounted=bool(mount_points),
                    mount_points=mount_points,
                    primary_mount_point=primary_mount,
                    filesystem_types=fs_types,
                    partitions=partition_models,
                    status=DeviceConnectionStatus.CONNECTED,
                    confidence_score=confidence,
                    raw_attributes=disk,
                )
            )

        return discovered

    def _discover_usb_peripherals(self) -> list[DeviceMetadata]:
        """Discover attached USB controllers/peripherals using Win32_USBHub."""
        ps_script = """
        Get-CimInstance Win32_USBHub | Select-Object DeviceID, Name, PNPDeviceID | ConvertTo-Json
        """
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=8,
        )
        if result.returncode != 0:
            return []

        try:
            raw_hubs = json.loads(result.stdout)
        except Exception:
            return []

        if isinstance(raw_hubs, dict):
            raw_hubs = [raw_hubs]

        peripherals: list[DeviceMetadata] = []
        for hub in raw_hubs:
            dev_id = hub.get("DeviceID") or ""
            name = hub.get("Name") or "USB Device"
            # Ignore root hub
            if "ROOT_HUB" in dev_id.upper():
                continue

            # Extract VID and PID: USB\VID_xxxx&PID_yyyy\...
            vid = None
            pid = None
            vid_match = re.search(r"VID_([0-9A-Fa-f]{4})", dev_id)
            pid_match = re.search(r"PID_([0-9A-Fa-f]{4})", dev_id)
            if vid_match:
                vid = vid_match.group(1).upper()
            if pid_match:
                pid = pid_match.group(1).upper()

            category, confidence = DeviceClassifier.classify(
                name=name,
                bus_type=BusType.USB,
                is_removable=True,
                is_storage=False,
            )

            peripherals.append(
                DeviceMetadata(
                    device_id=dev_id,
                    name=name,
                    category=category,
                    vendor="USB Device",
                    product_name=name,
                    vendor_id=vid,
                    product_id=pid,
                    bus_type=BusType.USB,
                    is_removable=True,
                    is_storage=False,
                    is_readonly=False,
                    is_mounted=False,
                    status=DeviceConnectionStatus.CONNECTED,
                    confidence_score=confidence,
                    raw_attributes=hub,
                )
            )

        return peripherals

    def _fallback_psutil(self) -> list[DeviceMetadata]:
        """Pure Python fallback using psutil.disk_partitions."""
        devices: list[DeviceMetadata] = []
        for idx, part in enumerate(psutil.disk_partitions(all=True)):
            is_removable = "removable" in part.opts.lower() or "cdrom" in part.opts.lower()
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
                    vendor="Generic",
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
