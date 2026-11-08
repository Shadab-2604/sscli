"""Read-only host firewall configuration and security posture auditor."""

from __future__ import annotations

from systemscan.logging.logger import get_logger
from systemscan.network.models import (
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    FirewallAction,
    FirewallStatus,
    NetworkFinding,
)
from systemscan.network.providers import get_network_provider

logger = get_logger("network.firewall")


class FirewallAuditor:
    """Performs non-intrusive, read-only inspection of the operating system firewall."""

    def __init__(self) -> None:
        self.provider = get_network_provider()

    def audit_firewall(self) -> tuple[FirewallStatus, list[NetworkFinding]]:
        """Inspect host firewall state and evaluate against standard security rules."""
        status = self.provider.get_firewall_status()
        findings: list[NetworkFinding] = []

        # Check 1: Overall firewall protection disabled
        if not status.is_enabled:
            findings.append(
                NetworkFinding(
                    finding_id="NET-FW-001",
                    category=FindingCategory.FIREWALL,
                    title="Host Firewall is Disabled",
                    description=f"{status.backend_name} protection is turned off or inactive.",
                    severity=FindingSeverity.CRITICAL,
                    confidence=FindingConfidence.CONFIRMED,
                    evidence=f"Backend: {status.backend_name}, Enabled: {status.is_enabled}, Profiles: {status.profiles}",
                    affected_target=status.backend_name,
                    remediation="Enable host firewall protection immediately across all profiles.",
                    source_module="network.firewall",
                )
            )

        # Check 2: Default inbound action is permissive ALLOW
        if status.default_inbound_action == FirewallAction.ALLOW:
            findings.append(
                NetworkFinding(
                    finding_id="NET-FW-002",
                    category=FindingCategory.FIREWALL,
                    title="Permissive Default Inbound Firewall Policy",
                    description="The host firewall default inbound rule allows unrequested incoming traffic.",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                    evidence=f"Default inbound action is {status.default_inbound_action.value}.",
                    affected_target="Inbound Firewall Policy",
                    remediation="Configure default inbound policy to BLOCK or DROP all unsolicited traffic.",
                    source_module="network.firewall",
                )
            )

        # Check 3: Profile warnings (e.g., individual disabled profile)
        for warning in status.warnings:
            findings.append(
                NetworkFinding(
                    finding_id="NET-FW-003",
                    category=FindingCategory.FIREWALL,
                    title="Firewall Profile Inactive",
                    description=warning,
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                    evidence=warning,
                    affected_target="Firewall Profile",
                    remediation="Verify and enable all active network profiles (Domain, Private, Public).",
                    source_module="network.firewall",
                )
            )

        return status, findings
