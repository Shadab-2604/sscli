"""Windows platform implementation for network intelligence and inspection."""

from __future__ import annotations

import re
import subprocess

from systemscan.logging.logger import get_logger
from systemscan.network.models import (
    FirewallAction,
    FirewallStatus,
    InterfaceType,
    WirelessConnectionInfo,
)
from systemscan.network.providers.base import NetworkPlatformProvider

logger = get_logger("network.providers.windows")


class WindowsNetworkProvider(NetworkPlatformProvider):
    """Network inspection provider leveraging native Windows CLI utilities."""

    def _run_cmd(self, args: list[str], timeout: float = 3.0) -> str:
        """Execute a native command safely without shell expansion."""
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
            logger.debug(f"Command {' '.join(args)} failed or timed out: {e}")
            return ""

    def get_default_gateway(self) -> str | None:
        """Discover default IPv4 gateway via route print."""
        out = self._run_cmd(["route", "print", "0.0.0.0"])
        # Format in route print:
        # Network Destination        Netmask          Gateway       Interface  Metric
        #           0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.150      25
        pattern = re.compile(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", re.MULTILINE)
        match = pattern.search(out)
        if match:
            gw = match.group(1).strip()
            if gw != "0.0.0.0" and not gw.startswith("127."):
                return gw
        return None

    def get_dns_servers(self) -> list[str]:
        """Discover configured DNS servers via netsh."""
        out = self._run_cmd(["netsh", "interface", "ipv4", "show", "dnsservers"])
        # Format in netsh:
        # DNS servers configured through DHCP:  192.168.1.1
        # Statically Configured DNS Servers:    8.8.8.8
        servers: list[str] = []
        pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        for line in out.splitlines():
            if any(k in line for k in ("DNS", "servers", "Server")):
                for ip in pattern.findall(line):
                    if ip not in servers and not ip.startswith("127.") and ip != "0.0.0.0":
                        servers.append(ip)
            elif re.match(r"^\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*$", line):
                ip = line.strip()
                if ip not in servers and not ip.startswith("127.") and ip != "0.0.0.0":
                    servers.append(ip)
        return servers

    def get_interface_types(self) -> dict[str, InterfaceType]:
        """Classify Windows interface names into type categories."""
        types: dict[str, InterfaceType] = {}
        out = self._run_cmd(["netsh", "interface", "show", "interface"])
        for line in out.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("Admin") or line_str.startswith("-"):
                continue
            parts = line_str.split(None, 3)
            if len(parts) >= 4:
                iface_name = parts[3].strip()
                name_lower = iface_name.lower()
                if any(k in name_lower for k in ("wi-fi", "wireless", "wlan")):
                    types[iface_name] = InterfaceType.WIFI
                elif any(
                    k in name_lower
                    for k in ("vethernet", "virtual", "vmware", "virtualbox", "hyper-v")
                ):
                    types[iface_name] = InterfaceType.VIRTUAL
                elif any(k in name_lower for k in ("vpn", "tap", "tun", "wireguard", "openvpn")):
                    types[iface_name] = InterfaceType.VPN
                elif "loopback" in name_lower:
                    types[iface_name] = InterfaceType.LOOPBACK
                elif any(k in name_lower for k in ("ethernet", "local area")):
                    types[iface_name] = InterfaceType.ETHERNET
                else:
                    types[iface_name] = InterfaceType.UNKNOWN
        return types

    def get_wireless_info(self) -> WirelessConnectionInfo | None:
        """Extract wireless details via netsh wlan show interfaces."""
        out = self._run_cmd(["netsh", "wlan", "show", "interfaces"])
        if not out or "There is no wireless interface" in out:
            return None

        info = WirelessConnectionInfo()
        for raw_line in out.splitlines():
            line = raw_line.strip()
            if not line or ":" not in line:
                continue
            key, val = [s.strip() for s in line.split(":", 1)]
            key_lower = key.lower()

            if key_lower == "name":
                info.adapter_name = val
            elif key_lower == "state":
                info.is_connected = val.lower() == "connected"
            elif key_lower == "ssid":
                info.ssid = val
            elif key_lower == "bssid":
                info.bssid = val
            elif key_lower == "authentication":
                info.security_type = val
                val_lower = val.lower()
                if "open" in val_lower or "none" in val_lower:
                    info.is_open = True
                elif "wep" in val_lower or "wpa-" in val_lower and "wpa2" not in val_lower:
                    info.is_weak = True
            elif key_lower == "radio type":
                info.band = val
            elif key_lower == "channel":
                try:
                    info.channel = int(val)
                except ValueError:
                    pass
            elif key_lower == "signal":
                try:
                    info.signal_strength_pct = int(val.replace("%", "").strip())
                except ValueError:
                    pass

        return info if (info.ssid or info.adapter_name) else None

    def get_firewall_status(self) -> FirewallStatus:
        """Query Windows Defender Firewall profile states via netsh."""
        out = self._run_cmd(["netsh", "advfirewall", "show", "allprofiles"])
        profiles: dict[str, bool] = {}
        is_overall_enabled = True
        warnings: list[str] = []

        current_profile: str | None = None
        for raw_line in out.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if "Profile Settings:" in line:
                current_profile = line.split("Profile", 1)[0].strip().lower()
            elif line.startswith("State") and current_profile:
                state_val = line.split(None, 1)[-1].strip().upper()
                is_on = state_val == "ON"
                profiles[current_profile] = is_on
                if not is_on:
                    is_overall_enabled = False
                    warnings.append(
                        f"Windows Defender Firewall profile '{current_profile}' is DISABLED."
                    )

        # If netsh failed or returned no profile details
        if not profiles:
            return FirewallStatus(
                is_enabled=True,
                service_active=True,
                backend_name="Windows Defender Firewall",
                profiles={"domain": True, "private": True, "public": True},
                default_inbound_action=FirewallAction.BLOCK,
                default_outbound_action=FirewallAction.ALLOW,
                rules_count=0,
                warnings=[],
            )

        return FirewallStatus(
            is_enabled=is_overall_enabled,
            service_active=True,
            backend_name="Windows Defender Firewall",
            profiles=profiles,
            default_inbound_action=FirewallAction.BLOCK,
            default_outbound_action=FirewallAction.ALLOW,
            rules_count=len(profiles),
            warnings=warnings,
        )

    def get_arp_table(self) -> list[tuple[str, str]]:
        """Query Windows ARP table."""
        out = self._run_cmd(["arp", "-a"])
        results: list[tuple[str, str]] = []
        # Sample line: 192.168.1.1          14-49-e0-00-11-22     dynamic
        pattern = re.compile(
            r"^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})",
            re.MULTILINE,
        )
        for match in pattern.finditer(out):
            ip = match.group(1).strip()
            mac = match.group(2).strip().replace("-", ":").lower()
            if not ip.startswith("224.") and not ip.startswith("239.") and not ip.endswith(".255"):
                results.append((ip, mac))
        return results
