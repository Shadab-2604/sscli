"""Windows native platform providers and capability adapters."""

from __future__ import annotations

from systemscan.platform.windows.devices import WindowsDeviceProvider
from systemscan.platform.windows.filesystem import WindowsFilesystemProvider
from systemscan.platform.windows.network import WindowsNetworkProvider
from systemscan.platform.windows.platform import WindowsPlatform
from systemscan.platform.windows.security import WindowsSecurityProvider
from systemscan.platform.windows.system import WindowsSystemProvider

__all__ = [
    "WindowsDeviceProvider",
    "WindowsFilesystemProvider",
    "WindowsNetworkProvider",
    "WindowsPlatform",
    "WindowsSecurityProvider",
    "WindowsSystemProvider",
]
