"""Rule-based heuristic classifier for physical devices and volumes."""

from __future__ import annotations

import re
from typing import Any

from systemscan.devices.models import BusType, DeviceCategory

# Keywords indicative of flash drives / thumb drives
FLASH_KEYWORDS = [
    "flash",
    "thumb",
    "cruzer",
    "sandisk ultra",
    "kingston datatraveler",
    "transcend jetflash",
    "corsair voyager",
    "lexar jumpdrive",
    "pen drive",
    "mass storage",
    "usb disk",
    "flash disk",
    "microsd",
    "sd card",
]

# Keywords indicative of external SSDs
SSD_KEYWORDS = [
    "ssd",
    "solid state",
    "nvme",
    "t5",
    "t7",
    "extreme portable",
    "sandisk extreme",
    "crucial x",
    "wd my passport ssd",
    "kingston xs",
]

# Keywords indicative of external HDDs
HDD_KEYWORDS = [
    "hdd",
    "hard drive",
    "harddisk",
    "passport",
    "elements",
    "backup plus",
    "expansion",
    "canvio",
    "my book",
    "touro",
    "desktop storage",
]

# Keywords indicative of non-storage peripherals
PERIPHERAL_KEYWORDS = [
    "keyboard",
    "mouse",
    "pointer",
    "trackpad",
    "webcam",
    "camera",
    "headset",
    "microphone",
    "audio",
    "bluetooth",
    "dongle",
    "receiver",
    "yubikey",
    "token",
    "hub",
    "controller",
    "touchpad",
    "scanner",
]

# Keywords indicative of optical media
OPTICAL_KEYWORDS = ["cd-rom", "dvd", "optical", "bd-rom", "blu-ray", "cdrom", "cd/dvd"]


class DeviceClassifier:
    """Classifies devices into semantic categories using hardware attributes, bus type, and OS heuristics."""

    @classmethod
    def classify(
        cls,
        name: str,
        bus_type: BusType,
        is_removable: bool,
        is_storage: bool,
        capacity_bytes: int = 0,
        media_type: str = "",
        interface_type: str = "",
        extra_attrs: dict[str, Any] | None = None,
    ) -> tuple[DeviceCategory, float]:
        """Classify a device and return (DeviceCategory, confidence_score [0.0 - 1.0])."""
        name_lower = (name or "").lower()
        media_lower = (media_type or "").lower()
        attrs = extra_attrs or {}

        # 1. Non-storage peripherals check
        if not is_storage:
            for kw in PERIPHERAL_KEYWORDS:
                if kw in name_lower:
                    return DeviceCategory.USB_PERIPHERAL, 0.95
            if bus_type == BusType.USB:
                return DeviceCategory.USB_PERIPHERAL, 0.85
            return DeviceCategory.UNKNOWN, 0.60

        # 2. Optical drive check (for storage devices)
        for kw in OPTICAL_KEYWORDS:
            if kw in name_lower or kw in media_lower:
                return DeviceCategory.OPTICAL_DRIVE, 0.95

        # If it is marked as storage:
        # Check SD Card
        if (
            "sd card" in name_lower
            or "sdxc" in name_lower
            or "sdhc" in name_lower
            or bus_type == BusType.SDIO
        ):
            return DeviceCategory.SD_CARD, 0.90

        # If it is NOT removable and connected via internal SATA/NVME/PCI -> Internal Storage
        if not is_removable and bus_type in (BusType.NVME, BusType.SATA, BusType.PCI):
            return DeviceCategory.INTERNAL_STORAGE, 0.98

        # Removable or USB storage:
        if bus_type == BusType.USB or is_removable:
            # Check SSD keywords first
            for kw in SSD_KEYWORDS:
                if re.search(r"\b" + re.escape(kw) + r"\b", name_lower):
                    return DeviceCategory.EXTERNAL_SSD, 0.90

            # Check Flash drive keywords
            for kw in FLASH_KEYWORDS:
                if kw in name_lower:
                    return DeviceCategory.USB_FLASH_DRIVE, 0.88

            # Check HDD keywords
            for kw in HDD_KEYWORDS:
                if kw in name_lower:
                    return DeviceCategory.EXTERNAL_HDD, 0.88

            # Heuristics based on capacity:
            # Flash drives are commonly <= 256GB, while HDDs are commonly >= 500GB (spinners)
            # But let's check media_type or rot speed if available
            if "solid state" in media_lower or attrs.get("is_ssd") is True:
                return DeviceCategory.EXTERNAL_SSD, 0.85
            if "rotational" in media_lower or attrs.get("rotational") == 1:
                return DeviceCategory.EXTERNAL_HDD, 0.85

            # Default for removable USB disk
            if capacity_bytes > 0 and capacity_bytes <= 256 * 1024 * 1024 * 1024:
                # <= 256 GB likely flash drive
                return DeviceCategory.USB_FLASH_DRIVE, 0.75
            elif capacity_bytes > 256 * 1024 * 1024 * 1024:
                # > 256 GB likely external HDD / SSD
                return DeviceCategory.USB_STORAGE, 0.70

            return DeviceCategory.USB_STORAGE, 0.80

        # If internal without specific bus markers
        return DeviceCategory.INTERNAL_STORAGE, 0.70
