"""Wi-Fi security inspection and wireless configuration auditing."""

from __future__ import annotations

from systemscan.logging.logger import get_logger
from systemscan.network.models import (
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    NetworkFinding,
    WirelessConnectionInfo,
)
from systemscan.network.providers import get_network_provider

logger = get_logger("network.wireless")


class WirelessSecurityInspector:
    """Audits connected Wi-Fi security protocols and wireless connection metrics."""

    def __init__(self) -> None:
        self.provider = get_network_provider()

    def inspect_wifi(self) -> tuple[WirelessConnectionInfo | None, list[NetworkFinding]]:
        """Inspect active Wi-Fi connection and identify insecure configurations."""
        info = self.provider.get_wireless_info()
        findings: list[NetworkFinding] = []

        if not info or not info.is_connected or not info.ssid:
            return None, []

        # Check 1: Open unencrypted Wi-Fi network
        if info.is_open:
            findings.append(
                NetworkFinding(
                    finding_id="NET-WIFI-001",
                    category=FindingCategory.WIFI_SECURITY,
                    title="Connected to Open Unencrypted Wi-Fi",
                    description=f"Active Wi-Fi connection to '{info.ssid}' transmits data without encryption.",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.CONFIRMED,
                    evidence=f"SSID: '{info.ssid}', Security: '{info.security_type}', Open: True",
                    affected_target=f"Wi-Fi SSID: {info.ssid}",
                    remediation="Disconnect from open networks or utilize a trusted VPN tunnel to encrypt traffic.",
                    source_module="network.wireless",
                )
            )

        # Check 2: Deprecated / weak encryption (WEP, WPA-TKIP)
        elif info.is_weak:
            findings.append(
                NetworkFinding(
                    finding_id="NET-WIFI-002",
                    category=FindingCategory.WIFI_SECURITY,
                    title="Deprecated Wi-Fi Encryption Protocol",
                    description=f"Active Wi-Fi network '{info.ssid}' utilizes vulnerable encryption ({info.security_type}).",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.CONFIRMED,
                    evidence=f"SSID: '{info.ssid}', Security Protocol: '{info.security_type}'",
                    affected_target=f"Wi-Fi SSID: {info.ssid}",
                    remediation="Upgrade access point configuration to WPA2-AES (CCMP) or WPA3.",
                    source_module="network.wireless",
                )
            )

        # Check 3: Degraded signal quality
        if info.signal_strength_pct is not None and info.signal_strength_pct < 25:
            findings.append(
                NetworkFinding(
                    finding_id="NET-WIFI-003",
                    category=FindingCategory.WIFI_SECURITY,
                    title="Degraded Wireless Signal Strength",
                    description=f"Signal quality is {info.signal_strength_pct}%, risking packet drops and disconnections.",
                    severity=FindingSeverity.LOW,
                    confidence=FindingConfidence.HIGH,
                    evidence=f"Signal strength: {info.signal_strength_pct}%",
                    affected_target=f"Wi-Fi SSID: {info.ssid}",
                    remediation="Relocate closer to the access point or minimize physical obstructions.",
                    source_module="network.wireless",
                )
            )

        return info, findings
