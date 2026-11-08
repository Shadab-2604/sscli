"""Abstract base provider interface for platform-specific network intelligence."""

from __future__ import annotations

from abc import ABC, abstractmethod

from systemscan.network.models import (
    FirewallStatus,
    InterfaceType,
    WirelessConnectionInfo,
)


class NetworkPlatformProvider(ABC):
    """Abstract interface for platform-specific network data extraction."""

    @abstractmethod
    def get_default_gateway(self) -> str | None:
        """Discover the default network gateway IPv4 address."""
        raise NotImplementedError

    @abstractmethod
    def get_dns_servers(self) -> list[str]:
        """Discover configured DNS resolver server IP addresses."""
        raise NotImplementedError

    @abstractmethod
    def get_interface_types(self) -> dict[str, InterfaceType]:
        """Classify interface names into InterfaceType categories."""
        raise NotImplementedError

    @abstractmethod
    def get_wireless_info(self) -> WirelessConnectionInfo | None:
        """Inspect active Wi-Fi connection and security configuration."""
        raise NotImplementedError

    @abstractmethod
    def get_firewall_status(self) -> FirewallStatus:
        """Inspect host firewall state, profiles, and basic rule counts."""
        raise NotImplementedError

    @abstractmethod
    def get_arp_table(self) -> list[tuple[str, str]]:
        """Query kernel ARP cache returning list of (ip_address, mac_address) tuples."""
        raise NotImplementedError
