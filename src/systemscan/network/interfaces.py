"""Comprehensive network interface discovery and telemetry inspection."""

from __future__ import annotations

import ipaddress
import socket

import psutil

from systemscan.logging.logger import get_logger
from systemscan.network.models import InterfaceType, NetworkInterfaceDetail
from systemscan.network.providers import get_network_provider

logger = get_logger("network.interfaces")


class NetworkInterfaceInspector:
    """Discovers, audits, and normalizes network interface devices across platforms."""

    def __init__(self) -> None:
        self.provider = get_network_provider()

    def inspect_all(self) -> list[NetworkInterfaceDetail]:
        """Collect enriched telemetry for all active and inactive network interfaces."""
        details: list[NetworkInterfaceDetail] = []
        try:
            addrs_map = psutil.net_if_addrs()
            stats_map = psutil.net_if_stats()
        except Exception as e:
            logger.debug(f"Failed to query psutil network interface maps: {e}")
            return []

        default_gw = self.provider.get_default_gateway()
        dns_servers = self.provider.get_dns_servers()
        type_overrides = self.provider.get_interface_types()
        wifi_info = self.provider.get_wireless_info()

        for name, addrs in addrs_map.items():
            mac: str | None = None
            ipv4_list: list[str] = []
            ipv6_list: list[str] = []
            subnets: list[str] = []

            for addr in addrs:
                # AF_LINK (MAC)
                if addr.family == psutil.AF_LINK or getattr(addr.family, "name", "") in (
                    "AF_LINK",
                    "AF_PACKET",
                ):
                    if addr.address:
                        mac = addr.address.lower()

                # IPv4
                elif addr.family == socket.AF_INET:
                    if addr.address:
                        ipv4_list.append(addr.address)
                        if addr.netmask:
                            try:
                                net = ipaddress.IPv4Network(
                                    f"{addr.address}/{addr.netmask}", strict=False
                                )
                                subnets.append(str(net))
                            except ValueError:
                                pass

                # IPv6
                elif addr.family == socket.AF_INET6:
                    if addr.address:
                        clean_v6 = addr.address.split("%")[0]
                        ipv6_list.append(clean_v6)

            # Link statistics
            stat = stats_map.get(name)
            is_up = stat.isup if stat else False
            speed_mbps = stat.speed if stat and stat.speed > 0 else None
            mtu = stat.mtu if stat and stat.mtu > 0 else None

            # Classification heuristics
            name_lower = name.lower()
            if name in type_overrides and type_overrides[name] != InterfaceType.UNKNOWN:
                iface_type = type_overrides[name]
            elif name_lower in ("lo", "loopback") or any(ip.startswith("127.") for ip in ipv4_list):
                iface_type = InterfaceType.LOOPBACK
            elif any(k in name_lower for k in ("wlan", "wi-fi", "wireless", "airport")):
                iface_type = InterfaceType.WIFI
            elif any(
                k in name_lower for k in ("docker", "virbr", "veth", "vethernet", "vmnet", "vbox")
            ):
                iface_type = InterfaceType.VIRTUAL
            elif any(k in name_lower for k in ("tun", "tap", "wg", "vpn", "ppp")):
                iface_type = InterfaceType.VPN
            elif any(k in name_lower for k in ("br-", "bridge")):
                iface_type = InterfaceType.BRIDGE
            elif any(k in name_lower for k in ("eth", "en", "ethernet", "local area")):
                iface_type = InterfaceType.ETHERNET
            else:
                iface_type = InterfaceType.UNKNOWN

            is_loopback = iface_type == InterfaceType.LOOPBACK
            is_virtual = iface_type in (InterfaceType.VIRTUAL, InterfaceType.BRIDGE)
            is_vpn = iface_type == InterfaceType.VPN

            # Correlate gateway & SSID if interface is active and carries default route
            iface_gw = (
                default_gw
                if (
                    default_gw
                    and any(default_gw.startswith(".".join(ip.split(".")[:3])) for ip in ipv4_list)
                )
                else None
            )
            ssid = (
                wifi_info.ssid
                if (wifi_info and iface_type == InterfaceType.WIFI and wifi_info.is_connected)
                else None
            )

            details.append(
                NetworkInterfaceDetail(
                    name=name,
                    description=f"{iface_type.value} adapter",
                    interface_type=iface_type,
                    mac_address=mac,
                    ipv4_addresses=ipv4_list,
                    ipv6_addresses=ipv6_list,
                    subnets=subnets,
                    gateway=iface_gw,
                    dns_servers=dns_servers if (is_up and ipv4_list) else [],
                    is_up=is_up,
                    mtu=mtu,
                    speed_mbps=speed_mbps,
                    ssid=ssid,
                    is_loopback=is_loopback,
                    is_virtual=is_virtual,
                    is_vpn=is_vpn,
                )
            )

        return details
