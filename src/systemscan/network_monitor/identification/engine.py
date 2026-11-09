"""Device identification, ARP resolution, reverse DNS, and MAC OUI vendor resolution."""

from __future__ import annotations

import logging
import re
import socket
import subprocess
from datetime import datetime, timezone

from systemscan.network_monitor.models import DeviceIdentity, IdentityConfidence

logger = logging.getLogger("systemscan.network_monitor.identification")

# Common hardware vendor prefixes (OUI top prefixes for offline lookup)
WELL_KNOWN_OUIS: dict[str, str] = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1C:42": "Parallels",
    "08:00:27": "Oracle VirtualBox",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "F0:18:98": "Apple, Inc.",
    "AC:DE:48": "Apple, Inc.",
    "3C:06:30": "Apple, Inc.",
    "F4:D4:88": "Apple, Inc.",
    "70:85:C2": "Apple, Inc.",
    "B4:2E:99": "Intel Corporate",
    "00:15:5D": "Microsoft Hyper-V",
    "50:65:F3": "Samsung Electronics",
    "D8:32:14": "Samsung Electronics",
    "E8:9E:B4": "Google, Inc.",
    "3C:5A:B4": "Google, Inc.",
    "18:65:90": "Google, Inc.",
    "9C:20:7B": "ASUSTeK Computer",
    "00:1A:2B": "Cisco Systems",
}


class DeviceIdentificationEngine:
    """Resolves IP addresses to MAC, vendor, hostname, and maintains a tracked inventory."""

    def __init__(self) -> None:
        self._inventory: dict[str, DeviceIdentity] = {}
        self._arp_cache: dict[str, str] = {}
        self._refresh_arp_cache()

    def identify_host(
        self, ip: str, mac: str | None = None, interface: str = "default"
    ) -> DeviceIdentity:
        """Enrich host metadata from ARP table, reverse DNS, and OUI database."""
        now = datetime.now(timezone.utc)
        if ip in self._inventory:
            dev = self._inventory[ip]
            dev.last_seen = now
            dev.scan_count += 1
            if mac and not dev.mac_address:
                dev.mac_address = mac
                dev.vendor = self.lookup_mac_vendor(mac)
            return dev

        resolved_mac = mac or self._arp_cache.get(ip)
        resolved_host = self.resolve_hostname(ip)
        resolved_vendor = self.lookup_mac_vendor(resolved_mac) if resolved_mac else None

        # Determine confidence
        confidence = IdentityConfidence.LOW
        if resolved_mac and resolved_host:
            confidence = IdentityConfidence.HIGH
        elif resolved_mac or resolved_host:
            confidence = IdentityConfidence.MEDIUM

        device = DeviceIdentity(
            ip_address=ip,
            mac_address=resolved_mac,
            hostname=resolved_host,
            vendor=resolved_vendor,
            device_type="Workstation / Endpoint" if resolved_host else "Host",
            interface=interface,
            first_seen=now,
            last_seen=now,
            scan_count=1,
            confidence=confidence,
        )
        self._inventory[ip] = device
        return device

    def get_tracked_devices(self) -> list[DeviceIdentity]:
        """Return all observed network endpoints."""
        return list(self._inventory.values())

    @staticmethod
    def lookup_mac_vendor(mac: str | None) -> str | None:
        """Resolve vendor from MAC address IEEE OUI prefix."""
        if not mac:
            return None
        clean_mac = mac.upper().replace("-", ":")
        parts = clean_mac.split(":")
        if len(parts) >= 3:
            prefix = ":".join(parts[:3])
            if prefix in WELL_KNOWN_OUIS:
                return WELL_KNOWN_OUIS[prefix]
        return None

    @staticmethod
    def resolve_hostname(ip: str) -> str | None:
        """Perform non-blocking or cached reverse DNS resolution."""
        if ip in ("127.0.0.1", "::1", "0.0.0.0"):
            return "localhost"
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            return name
        except (socket.herror, socket.gaierror, OSError):
            return None

    def _refresh_arp_cache(self) -> None:
        """Query host operating system ARP table."""
        try:
            # Cross-platform arp -a
            res = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=3, check=False
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    # Parse standard IP ... MAC patterns
                    # Example Windows:  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic
                    # Example Linux:    ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
                    ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    mac_match = re.search(
                        r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})",
                        line,
                    )
                    if ip_match and mac_match:
                        ip = ip_match.group(1)
                        mac = mac_match.group(1).replace("-", ":").upper()
                        self._arp_cache[ip] = mac
        except Exception as e:
            logger.debug(f"Unable to read system ARP table: {e}")
