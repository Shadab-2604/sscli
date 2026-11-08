"""Provider factory for platform device enumeration."""

from __future__ import annotations

import sys

from systemscan.devices.providers.base import DeviceProvider
from systemscan.devices.providers.linux import LinuxDeviceProvider
from systemscan.devices.providers.macos import MacOSDeviceProvider
from systemscan.devices.providers.windows import WindowsDeviceProvider


def get_device_provider() -> DeviceProvider:
    """Return platform-appropriate device provider."""
    if sys.platform.startswith("win"):
        return WindowsDeviceProvider()
    elif sys.platform.startswith("darwin"):
        return MacOSDeviceProvider()
    elif sys.platform.startswith("linux"):
        return LinuxDeviceProvider()
    else:
        # Default fallback to Linux (psutil fallback inside)
        return LinuxDeviceProvider()
