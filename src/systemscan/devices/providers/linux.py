"""Linux device provider parsing lsblk JSON, /sys/bus/usb/devices, and /proc/mounts."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

import psutil

from systemscan.devices.classifier import DeviceClassifier
from systemscan.devices.models import (
    BusType,
    DeviceConnectionStatus,
    DeviceMetadata,
    PartitionMetadata,
)
from systemscan.devices.providers.base import DeviceProvider

logger = logging.getLogger("systemscan.devices.providers.linux")


class LinuxDeviceProvider(DeviceProvider):
    """Enumerates Linux storage devices and USB topology via lsblk, /sys/block, and /sys/bus/usb."""

    def discover_devices(self) -> list[DeviceMetadata]:
        devices: list[DeviceMetadata] = []
        try:
            storage = self._discover_lsblk_storage()
            devices.extend(storage)
        except Exception as e:
            logger.warning(f"Error enumerating Linux storage via lsblk: {e}")

        try:
            usb_peripherals = self._discover_sys_usb()
            devices.extend(usb_peripherals)
        except Exception as e:
            logger.warning(f"Error enumerating Linux USB peripherals via sysfs: {e}")

        if not devices:
            devices = self._fallback_psutil()

        return devices

    def _discover_lsblk_storage(self) -> list[DeviceMetadata]:
        """Query lsblk in JSON format for complete block device and partition hierarchy."""
        cmd = [
            "lsblk",
            "-J",
            "-b",  # raw bytes
            "-o",
            "NAME,KNAME,PATH,TYPE,SIZE,RO,RM,HOTPLUG,MODEL,VENDOR,TRAN,SERIAL,FSTYPE,MOUNTPOINT,MOUNTPOINTS,LABEL",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            logger.warning(f"lsblk execution failed: {result.stderr.strip()}")
            return []

        try:
            data = json.loads(result.stdout)
        except Exception as e:
            logger.warning(f"Failed to parse lsblk output as JSON: {e}")
            return []

        blockdevices = data.get("blockdevices") or []
        devices: list[DeviceMetadata] = []

        for blk in blockdevices:
            # We typically process disks or loop devices
            blk_type = (blk.get("type") or "").lower()
            if blk_type in ("rom", "optical"):
                is_optical = True
            else:
                is_optical = False

            name = blk.get("model") or blk.get("name") or "Storage Disk"
            vendor = blk.get("vendor") or "Unknown"
            tran = (blk.get("tran") or "").lower()
            serial = blk.get("serial") or None
            size = blk.get("size") or 0
            if isinstance(size, str) and size.isdigit():
                size = int(size)

            is_removable = bool(blk.get("rm")) or bool(blk.get("hotplug"))
            is_readonly = bool(blk.get("ro"))

            # Determine bus type
            bus_type = BusType.UNKNOWN
            if tran == "usb":
                bus_type = BusType.USB
            elif tran == "nvme":
                bus_type = BusType.NVME
            elif tran == "sata" or tran == "ata":
                bus_type = BusType.SATA
            elif tran == "scsi":
                bus_type = BusType.SCSI

            # Parse children/partitions
            children = blk.get("children") or []
            partitions: list[PartitionMetadata] = []
            mount_points: list[str] = []
            fs_types: list[str] = []

            # If top-level disk itself has a mountpoint (unpartitioned filesystem)
            top_mp = blk.get("mountpoint")
            if top_mp:
                mount_points.append(top_mp)
                top_fs = blk.get("fstype") or "unknown"
                fs_types.append(top_fs)
                partitions.append(
                    PartitionMetadata(
                        partition_id=blk.get("path") or blk.get("name"),
                        name=blk.get("label") or blk.get("name"),
                        mount_point=top_mp,
                        filesystem_type=top_fs,
                        capacity_bytes=size,
                        is_mounted=True,
                        is_readonly=is_readonly,
                    )
                )

            for child in children:
                c_name = child.get("name") or ""
                c_path = child.get("path") or f"/dev/{c_name}"
                c_size = child.get("size") or 0
                if isinstance(c_size, str) and c_size.isdigit():
                    c_size = int(c_size)
                c_mp = child.get("mountpoint")
                c_mps = child.get("mountpoints") or []
                c_fs = child.get("fstype") or "unknown"
                c_ro = bool(child.get("ro"))

                active_mps: list[str] = []
                if c_mp:
                    active_mps.append(c_mp)
                for mp in c_mps:
                    if mp and mp not in active_mps:
                        active_mps.append(mp)

                for mp in active_mps:
                    if mp not in mount_points:
                        mount_points.append(mp)
                if c_fs and c_fs not in fs_types:
                    fs_types.append(c_fs)

                partitions.append(
                    PartitionMetadata(
                        partition_id=c_path,
                        name=child.get("label") or c_name,
                        mount_point=active_mps[0] if active_mps else None,
                        filesystem_type=c_fs,
                        capacity_bytes=c_size,
                        is_mounted=bool(active_mps),
                        is_readonly=c_ro,
                    )
                )

            # Classify
            category, confidence = DeviceClassifier.classify(
                name=f"{vendor} {name}".strip(),
                bus_type=bus_type,
                is_removable=is_removable,
                is_storage=True,
                capacity_bytes=size,
                media_type="optical" if is_optical else "",
                interface_type=tran,
            )

            dev_id = blk.get("path") or f"/dev/{blk.get('name')}"

            devices.append(
                DeviceMetadata(
                    device_id=dev_id,
                    name=f"{vendor} {name}".strip(),
                    category=category,
                    vendor=vendor.strip() if vendor else "Unknown",
                    product_name=name.strip(),
                    bus_type=bus_type,
                    serial_number=serial.strip() if serial else None,
                    capacity_bytes=size,
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
                    raw_attributes=blk,
                )
            )

        return devices

    def _discover_sys_usb(self) -> list[DeviceMetadata]:
        """Inspect /sys/bus/usb/devices/ for connected USB controllers and peripherals."""
        usb_dir = Path("/sys/bus/usb/devices")
        if not usb_dir.exists() or not usb_dir.is_dir():
            return []

        peripherals: list[DeviceMetadata] = []
        for dev_path in usb_dir.iterdir():
            # Skip USB interface entries (e.g. 1-1:1.0)
            if ":" in dev_path.name:
                continue

            # Read product, manufacturer, idVendor, idProduct
            try:
                prod_file = dev_path / "product"
                product = prod_file.read_text().strip() if prod_file.exists() else ""

                mfg_file = dev_path / "manufacturer"
                mfg = mfg_file.read_text().strip() if mfg_file.exists() else "USB Device"

                vid_file = dev_path / "idVendor"
                vid = vid_file.read_text().strip() if vid_file.exists() else None

                pid_file = dev_path / "idProduct"
                pid = pid_file.read_text().strip() if pid_file.exists() else None

                serial_file = dev_path / "serial"
                serial = serial_file.read_text().strip() if serial_file.exists() else None

                # Check if it's already a mass storage device represented in block devices
                # Ignore Linux root hubs
                if (
                    "root hub" in product.lower()
                    or "linux" in mfg.lower()
                    and "hub" in product.lower()
                ):
                    continue

                display_name = f"{mfg} {product}".strip() or f"USB Device {dev_path.name}"
                category, confidence = DeviceClassifier.classify(
                    name=display_name,
                    bus_type=BusType.USB,
                    is_removable=True,
                    is_storage=False,
                )

                peripherals.append(
                    DeviceMetadata(
                        device_id=f"usb-{dev_path.name}",
                        name=display_name,
                        category=category,
                        vendor=mfg,
                        product_name=product,
                        vendor_id=vid,
                        product_id=pid,
                        bus_type=BusType.USB,
                        serial_number=serial,
                        is_removable=True,
                        is_storage=False,
                        is_readonly=False,
                        is_mounted=False,
                        status=DeviceConnectionStatus.CONNECTED,
                        confidence_score=confidence,
                    )
                )
            except (OSError, PermissionError):
                continue

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
