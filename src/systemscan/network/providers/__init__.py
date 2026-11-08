"""Platform provider factory for network inspection."""

from __future__ import annotations

import sys

from systemscan.network.providers.base import NetworkPlatformProvider
from systemscan.network.providers.linux import LinuxNetworkProvider
from systemscan.network.providers.macos import MacOSNetworkProvider
from systemscan.network.providers.windows import WindowsNetworkProvider

_cached_provider: NetworkPlatformProvider | None = None


def get_network_provider() -> NetworkPlatformProvider:
    """Return the singleton network provider appropriate for host platform."""
    global _cached_provider
    if _cached_provider is not None:
        return _cached_provider

    if sys.platform.startswith("win"):
        _cached_provider = WindowsNetworkProvider()
    elif sys.platform.startswith("darwin"):
        _cached_provider = MacOSNetworkProvider()
    else:
        _cached_provider = LinuxNetworkProvider()

    return _cached_provider
