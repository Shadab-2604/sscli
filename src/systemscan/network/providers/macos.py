"""macOS platform implementation for network intelligence and inspection."""

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

logger = get_logger("network.providers.macos")


class MacOSNetworkProvider(NetworkPlatformProvider):
    """Network inspection provider for Apple macOS."""

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
        """Discover default gateway via route -n get default."""
        out = self._run_cmd(["route", "-n", "get", "default"])
        match = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
        if match:
            return match.group(1)
        return None

    def get_dns_servers(self) -> list[str]:
        """Discover DNS servers via scutil --dns."""
        servers: list[str] = []
        out = self._run_cmd(["scutil", "--dns"])
        pattern = re.compile(r"nameserver\[\d+\]\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        for match in pattern.finditer(out):
            ip = match.group(1).strip()
            if ip not in servers and not ip.startswith("127.") and ip != "0.0.0.0":
                servers.append(ip)
        return servers

    def get_interface_types(self) -> dict[str, InterfaceType]:
        """Classify macOS interfaces via networksetup."""
        types: dict[str, InterfaceType] = {}
        out = self._run_cmd(["networksetup", "-listallhardwareports"])
        # Format:
        # Hardware Port: Wi-Fi
        # Device: en0
        current_port: str | None = None
        for line in out.splitlines():
            clean = line.strip()
            if clean.startswith("Hardware Port:"):
                current_port = clean.split(":", 1)[1].strip()
            elif clean.startswith("Device:") and current_port:
                device = clean.split(":", 1)[1].strip()
                port_lower = current_port.lower()
                if "wi-fi" in port_lower or "airport" in port_lower:
                    types[device] = InterfaceType.WIFI
                elif "ethernet" in port_lower:
                    types[device] = InterfaceType.ETHERNET
                elif "thunderbolt" in port_lower:
                    types[device] = InterfaceType.ETHERNET
                elif "bridge" in port_lower:
                    types[device] = InterfaceType.BRIDGE
                current_port = None

        return types

    def get_wireless_info(self) -> WirelessConnectionInfo | None:
        """Inspect Wi-Fi info via airport command."""
        airport_bin = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        out = self._run_cmd([airport_bin, "-I"])
        if not out:
            return None

        info = WirelessConnectionInfo(is_connected=False)
        for line in out.splitlines():
            clean = line.strip()
            if ":" not in clean:
                continue
            k, v = [s.strip() for s in clean.split(":", 1)]
            k_lower = k.lower()
            if k_lower == "ssid":
                info.ssid = v
                info.is_connected = True
            elif k_lower == "bssid":
                info.bssid = v
            elif k_lower in ("link auth", "security"):
                info.security_type = v
                val_lower = v.lower()
                if "none" in val_lower or "open" in val_lower:
                    info.is_open = True
                elif "wep" in val_lower:
                    info.is_weak = True
            elif k_lower == "channel":
                try:
                    info.channel = int(v.split(",")[0])
                except ValueError:
                    pass
            elif k_lower == "agrctlrssi":
                # Convert RSSI (e.g. -50 dBm) to approximate percentage
                try:
                    rssi = int(v)
                    pct = max(0, min(100, 2 * (rssi + 100)))
                    info.signal_strength_pct = pct
                except ValueError:
                    pass

        return info if info.ssid else None

    def get_firewall_status(self) -> FirewallStatus:
        """Inspect macOS Application Firewall via socketfilterfw."""
        socketfilter_bin = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        out = self._run_cmd([socketfilter_bin, "--getglobalstate"])
        is_enabled = "enabled" in out.lower()
        return FirewallStatus(
            is_enabled=is_enabled,
            service_active=True,
            backend_name="macOS Application Firewall",
            profiles={"global": is_enabled},
            default_inbound_action=FirewallAction.BLOCK,
            default_outbound_action=FirewallAction.ALLOW,
            rules_count=1,
            warnings=["macOS Application Firewall is DISABLED!"] if not is_enabled else [],
        )

    def get_arp_table(self) -> list[tuple[str, str]]:
        """Query macOS ARP cache via arp -an."""
        out = self._run_cmd(["arp", "-an"])
        results: list[tuple[str, str]] = []
        # Sample line: ? (192.168.1.1) at 14:49:e0:00:11:22 on en0 ifscope [ethernet]
        pattern = re.compile(r"\(([\d\.]+)\)\s+at\s+([0-9a-fA-F:]+)")
        for match in pattern.finditer(out):
            ip = match.group(1)
            mac = match.group(2).lower()
            if mac != "(incomplete)":
                results.append((ip, mac))
        return results
