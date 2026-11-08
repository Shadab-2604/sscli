"""Network interfaces inventory module for systemscan."""

from __future__ import annotations

import socket

import psutil

from systemscan.logging.logger import get_logger
from systemscan.modules.models import NetworkInterface

logger = get_logger("system_info.network")


def collect_network_interfaces() -> list[NetworkInterface]:
    """Collect network adapter hardware, status, and addressing inventory."""
    interfaces: list[NetworkInterface] = []

    try:
        addrs_map = psutil.net_if_addrs()
        stats_map = psutil.net_if_stats()
    except Exception as e:
        logger.debug(f"Failed to query network interfaces: {e}")
        return []

    for name, addrs in addrs_map.items():
        mac: str | None = None
        ipv4_list: list[str] = []
        ipv6_list: list[str] = []
        netmask_list: list[str] = []
        broadcast_list: list[str] = []

        for addr in addrs:
            # AF_LINK / MAC
            if addr.family == psutil.AF_LINK or getattr(addr.family, "name", "") in (
                "AF_LINK",
                "AF_PACKET",
            ):
                if addr.address:
                    mac = addr.address

            # IPv4
            elif addr.family == socket.AF_INET:
                if addr.address:
                    ipv4_list.append(addr.address)
                if addr.netmask:
                    netmask_list.append(addr.netmask)
                if addr.broadcast:
                    broadcast_list.append(addr.broadcast)

            # IPv6
            elif addr.family == socket.AF_INET6:
                if addr.address:
                    # Strip scope id if present
                    clean_ipv6 = addr.address.split("%")[0]
                    ipv6_list.append(clean_ipv6)

        # Operational status and link speed
        stat = stats_map.get(name)
        is_up = stat.isup if stat else True
        speed = stat.speed if stat and stat.speed > 0 else None

        interfaces.append(
            NetworkInterface(
                name=name,
                description=None,
                mac_address=mac,
                ipv4_addresses=ipv4_list,
                ipv6_addresses=ipv6_list,
                netmasks=netmask_list,
                broadcast_addresses=broadcast_list,
                is_up=is_up,
                speed_mbps=speed,
                interface_type=None,
            )
        )

    return interfaces
