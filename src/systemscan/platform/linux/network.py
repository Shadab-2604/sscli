"""Linux native network provider integrating /proc/net, routing, and DNS configuration."""

from __future__ import annotations

from systemscan.network.providers.linux import LinuxNetworkProvider

__all__ = ["LinuxNetworkProvider"]
