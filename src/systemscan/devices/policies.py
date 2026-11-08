"""Policy management and enforcement for device monitoring and scan integration."""

from __future__ import annotations

from systemscan.devices.models import DeviceMetadata, DeviceScanningPolicy


class PolicyManager:
    """Evaluates security rules and traversal policies for devices and volumes."""

    def __init__(self, policy: DeviceScanningPolicy | None = None) -> None:
        self.policy = policy or DeviceScanningPolicy()

    def should_scan_device(self, device: DeviceMetadata) -> bool:
        """Determine whether a device is eligible for filesystem scanning."""
        if not device.is_storage:
            return False
        if not device.is_mounted or not device.mount_points:
            return False
        if device.device_id in self.policy.excluded_device_ids:
            return False
        for mp in device.mount_points:
            if mp in self.policy.excluded_mount_points:
                return False
        return True

    def should_auto_include_removable(self) -> bool:
        """Check whether removable storage should be included in scans without prompting."""
        return self.policy.include_removable_by_default

    def is_approval_required(self) -> bool:
        """Check whether user prompt/approval is mandatory before scanning newly attached devices."""
        return self.policy.require_user_approval
