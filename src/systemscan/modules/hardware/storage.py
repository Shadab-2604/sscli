"""Storage and filesystem inspection module for systemscan."""

from __future__ import annotations

import psutil

from systemscan.logging.logger import get_logger
from systemscan.modules.models import DiskInformation, PartitionInformation
from systemscan.platform.base import PlatformInterface
from systemscan.platform.detector import detect_platform

logger = get_logger("hardware.storage")

# Common pseudo-filesystems to ignore when inspecting physical volumes
VIRTUAL_FILESYSTEMS = {
    "tmpfs",
    "devtmpfs",
    "squashfs",
    "overlay",
    "proc",
    "sysfs",
    "securityfs",
    "cgroup",
    "cgroup2",
    "pstore",
    "bpf",
    "autofs",
    "mqueue",
    "hugetlbfs",
    "debugfs",
    "tracefs",
    "configfs",
    "fusectl",
    "binfmt_misc",
}


def collect_partition_info() -> list[PartitionInformation]:
    """Collect mounted logical partitions and filesystem capacity telemetry."""
    partitions: list[PartitionInformation] = []

    try:
        parts = psutil.disk_partitions(all=False)
    except Exception as e:
        logger.debug(f"Could not enumerate disk partitions: {e}")
        return []

    for part in parts:
        fstype = part.fstype.lower()
        if fstype in VIRTUAL_FILESYSTEMS or not part.mountpoint:
            continue

        try:
            usage = psutil.disk_usage(part.mountpoint)
            is_ro = "ro" in part.opts.split(",")
            is_rm = "removable" in part.opts.lower() or "cdrom" in fstype

            partitions.append(
                PartitionInformation(
                    device=part.device,
                    mountpoint=part.mountpoint,
                    filesystem_type=part.fstype,
                    options=part.opts,
                    total_bytes=int(usage.total),
                    used_bytes=int(usage.used),
                    free_bytes=int(usage.free),
                    percentage=float(usage.percent),
                    is_readonly=is_ro,
                    is_removable=is_rm,
                )
            )
        except (PermissionError, OSError) as e:
            logger.debug(f"Could not read disk usage for {part.mountpoint}: {e}")
            continue

    return partitions


def collect_storage_info(
    platform_handler: PlatformInterface | None = None,
) -> tuple[list[PartitionInformation], list[DiskInformation]]:
    """Collect both mounted partitions and underlying physical disk drives."""
    handler = platform_handler or detect_platform()
    partitions = collect_partition_info()

    try:
        physical_disks = handler.get_physical_disks()
    except Exception as e:
        logger.debug(f"Failed to query physical disks: {e}")
        physical_disks = []

    # Map partitions to physical disks where possible
    for p in partitions:
        for d in physical_disks:
            if d.name in p.device:
                d.partitions.append(p)
                break

    return partitions, physical_disks
