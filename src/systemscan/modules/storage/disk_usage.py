"""Disk usage analysis and mounted volume capacity evaluation."""

from __future__ import annotations

import logging
from pathlib import Path

import psutil

from systemscan.modules.storage.models import DiskVolumeOverview

logger = logging.getLogger("systemscan.storage.disk_usage")

# Default warning threshold for low disk space (10% remaining)
LOW_SPACE_THRESHOLD_PERCENT = 10.0


class DiskUsageAnalyzer:
    """Queries and evaluates capacity and utilization across all mounted storage volumes."""

    @classmethod
    def analyze_volumes(
        cls, warning_threshold_pct: float = LOW_SPACE_THRESHOLD_PERCENT
    ) -> list[DiskVolumeOverview]:
        """Enumerate all physical and logical mounted volumes and calculate usage."""
        volumes: list[DiskVolumeOverview] = []
        partitions = psutil.disk_partitions(all=False)

        for p in partitions:
            mp = p.mountpoint
            # Filter virtual/pseudo filesystems on Linux
            if p.fstype.lower() in (
                "proc",
                "sysfs",
                "devtmpfs",
                "tmpfs",
                "cgroup",
                "overlay",
                "squashfs",
            ):
                continue

            try:
                usage = psutil.disk_usage(mp)
            except (PermissionError, OSError) as e:
                logger.debug(f"Unable to read disk usage for {mp}: {e}")
                continue

            is_removable = "removable" in p.opts.lower() or "cdrom" in p.opts.lower()
            is_readonly = "ro" in p.opts.lower()
            free_pct = (usage.free / usage.total * 100.0) if usage.total > 0 else 0.0
            is_low = free_pct < warning_threshold_pct

            volumes.append(
                DiskVolumeOverview(
                    mount_point=mp,
                    device=p.device,
                    filesystem_type=p.fstype or "unknown",
                    total_bytes=usage.total,
                    used_bytes=usage.used,
                    free_bytes=usage.free,
                    usage_percent=round(usage.percent, 1),
                    is_removable=is_removable,
                    is_readonly=is_readonly,
                    is_low_space=is_low,
                )
            )

        return volumes

    @classmethod
    def get_volume_for_path(cls, path: str | Path) -> DiskVolumeOverview | None:
        """Find the mounted volume hosting a specific filesystem path."""
        p_str = str(Path(path).resolve()).lower()
        all_vols = cls.analyze_volumes()

        best_match: DiskVolumeOverview | None = None
        best_match_len = -1

        for v in all_vols:
            v_mp = v.mount_point.lower().rstrip("\\/")
            if p_str.startswith(v_mp) and len(v_mp) > best_match_len:
                best_match = v
                best_match_len = len(v_mp)

        return best_match
