"""macOS native platform providers and capability adapters."""

from __future__ import annotations

from systemscan.platform.macos.devices import MacOSDeviceProvider
from systemscan.platform.macos.filesystem import MacOSFilesystemProvider
from systemscan.platform.macos.network import MacOSNetworkProvider
from systemscan.platform.macos.platform import MacOSPlatform
from systemscan.platform.macos.security import MacOSSecurityProvider
from systemscan.platform.macos.system import MacOSSystemProvider

__all__ = [
    "MacOSDeviceProvider",
    "MacOSFilesystemProvider",
    "MacOSNetworkProvider",
    "MacOSPlatform",
    "MacOSSecurityProvider",
    "MacOSSystemProvider",
]
