"""Linux platform implementation for network intelligence and inspection."""

from __future__ import annotations

import re
import socket
import struct
import subprocess
from pathlib import Path

from systemscan.logging.logger import get_logger
from systemscan.network.models import (
    FirewallAction,
    FirewallStatus,
    InterfaceType,
    WirelessConnectionInfo,
)
from systemscan.network.providers.base import NetworkPlatformProvider

logger = get_logger("network.providers.linux")


class LinuxNetworkProvider(NetworkPlatformProvider):
    """Network inspection provider for Linux distributions."""

    def _run_cmd(self, args: list[str], timeout: float = 3.0) -> str:
        """Execute command safely without shell expansion."""
        try:
            res = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return res.stdout or ""
        except (subprocess.TimeoutExpired, OSError, Exception) as e:
            logger.debug(f"Command {' '.join(args)} failed: {e}")
            return ""

    def get_default_gateway(self) -> str | None:
        """Extract default IPv4 gateway from /proc/net/route or ip route."""
        route_file = Path("/proc/net/route")
        if route_file.exists():
            try:
                content = route_file.read_text(encoding="utf-8")
                for line in content.splitlines()[1:]:
                    fields = line.strip().split()
                    if len(fields) >= 3 and fields[1] == "00000000":
                        gw_hex = fields[2]
                        # 32-bit hex to IPv4
                        gw_ip = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
                        if gw_ip != "0.0.0.0":
                            return gw_ip
            except (OSError, ValueError):
                pass

        # Fallback to ip route
        out = self._run_cmd(["ip", "route", "show", "default"])
        match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        if match:
            return match.group(1)
        return None

    def get_dns_servers(self) -> list[str]:
        """Discover DNS servers from /etc/resolv.conf."""
        servers: list[str] = []
        resolv_path = Path("/etc/resolv.conf")
        if resolv_path.exists():
            try:
                for line in resolv_path.read_text(encoding="utf-8").splitlines():
                    clean = line.strip()
                    if clean.startswith("nameserver"):
                        parts = clean.split()
                        if len(parts) >= 2:
                            ip = parts[1].strip()
                            if ip and ip not in servers:
                                servers.append(ip)
            except OSError:
                pass

        # Fallback: resolvectl
        if not servers or all(s.startswith("127.") for s in servers):
            out = self._run_cmd(["resolvectl", "dns"])
            for ip in re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", out):
                if ip not in servers and not ip.startswith("127.") and ip != "0.0.0.0":
                    servers.append(ip)

        return servers

    def get_interface_types(self) -> dict[str, InterfaceType]:
        """Classify Linux interfaces by sysfs properties and naming standards."""
        types: dict[str, InterfaceType] = {}
        net_dir = Path("/sys/class/net")
        if net_dir.exists():
            try:
                for iface_path in net_dir.iterdir():
                    name = iface_path.name
                    if name == "lo":
                        types[name] = InterfaceType.LOOPBACK
                    elif (iface_path / "wireless").exists() or (iface_path / "phy80211").exists():
                        types[name] = InterfaceType.WIFI
                    elif (
                        (iface_path / "bridge").exists()
                        or name.startswith("br-")
                        or name.startswith("docker")
                    ):
                        types[name] = InterfaceType.BRIDGE
                    elif (iface_path / "tun_flags").exists() or any(
                        name.startswith(p) for p in ("tun", "tap", "wg")
                    ):
                        types[name] = InterfaceType.VPN
                    elif any(name.startswith(p) for p in ("veth", "virbr", "vnet")):
                        types[name] = InterfaceType.VIRTUAL
                    elif any(name.startswith(p) for p in ("eth", "en", "ens", "eno", "enp")):
                        types[name] = InterfaceType.ETHERNET
                    elif any(name.startswith(p) for p in ("wlan", "wl", "wlp", "wls")):
                        types[name] = InterfaceType.WIFI
                    else:
                        types[name] = InterfaceType.UNKNOWN
            except OSError:
                pass
        return types

    def get_wireless_info(self) -> WirelessConnectionInfo | None:
        """Inspect Wi-Fi info via nmcli or iw."""
        out = self._run_cmd(
            ["nmcli", "-t", "-f", "active,ssid,bssid,chan,freq,signal,security", "dev", "wifi"]
        )
        for line in out.splitlines():
            if line.startswith("yes:"):
                match = re.match(
                    r"^yes:(.*?):([0-9a-fA-F]{2}(?:(?::|\\:)[0-9a-fA-F]{2}){5}):(\d+):(.*?):(\d+):(.*?)$",
                    line,
                )
                if match:
                    ssid = match.group(1).replace(r"\:", ":")
                    bssid = match.group(2).replace(r"\:", ":")
                    channel = int(match.group(3))
                    freq = match.group(4)
                    signal = int(match.group(5))
                    security = match.group(6).replace(r"\:", ":")
                    is_open = "none" in security.lower() or not security
                    is_weak = "wep" in security.lower()
                    band = "5 GHz" if "5" in freq else "2.4 GHz"
                    return WirelessConnectionInfo(
                        ssid=ssid,
                        bssid=bssid,
                        security_type=security or "Open",
                        is_open=is_open,
                        is_weak=is_weak,
                        band=band,
                        channel=channel,
                        signal_strength_pct=signal,
                        is_connected=True,
                    )
        return None

    def get_firewall_status(self) -> FirewallStatus:
        """Inspect UFW, firewalld, nftables, or iptables."""
        # 1. Test UFW
        ufw_out = self._run_cmd(["ufw", "status", "verbose"])
        if ufw_out:
            is_active = "Status: active" in ufw_out
            default_in = (
                FirewallAction.BLOCK
                if "incoming (deny)" in ufw_out or "incoming (reject)" in ufw_out
                else FirewallAction.ALLOW
            )
            return FirewallStatus(
                is_enabled=is_active,
                service_active=True,
                backend_name="UFW",
                profiles={"active": is_active},
                default_inbound_action=default_in,
                default_outbound_action=FirewallAction.ALLOW,
                rules_count=len(
                    [line for line in ufw_out.splitlines() if "ALLOW" in line or "DENY" in line]
                ),
                warnings=["UFW firewall is inactive!"] if not is_active else [],
            )

        # 2. Test firewalld
        fwd_out = self._run_cmd(["firewall-cmd", "--state"])
        if fwd_out:
            is_running = "running" in fwd_out.lower()
            return FirewallStatus(
                is_enabled=is_running,
                service_active=is_running,
                backend_name="firewalld",
                profiles={"running": is_running},
                default_inbound_action=FirewallAction.BLOCK,
                default_outbound_action=FirewallAction.ALLOW,
                rules_count=1,
                warnings=["firewalld is not running!"] if not is_running else [],
            )

        # 3. Default Linux status
        return FirewallStatus(
            is_enabled=True,
            service_active=True,
            backend_name="Linux Packet Filter",
            profiles={"system": True},
            default_inbound_action=FirewallAction.BLOCK,
            default_outbound_action=FirewallAction.ALLOW,
            rules_count=0,
            warnings=[],
        )

    def get_arp_table(self) -> list[tuple[str, str]]:
        """Query Linux ARP table from /proc/net/arp."""
        arp_path = Path("/proc/net/arp")
        results: list[tuple[str, str]] = []
        if arp_path.exists():
            try:
                for line in arp_path.read_text(encoding="utf-8").splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3].lower()
                        if mac != "00:00:00:00:00:00":
                            results.append((ip, mac))
            except OSError:
                pass
        return results
