"""Centralized network security finding evaluation and synthesis engine."""

from __future__ import annotations

from systemscan.logging.logger import get_logger
from systemscan.network.connections import NetworkConnectionInspector
from systemscan.network.dns import DNSIntelligenceEngine
from systemscan.network.firewall import FirewallAuditor
from systemscan.network.interfaces import NetworkInterfaceInspector
from systemscan.network.models import (
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    NetworkFinding,
)
from systemscan.network.wireless import WirelessSecurityInspector

logger = get_logger("network.findings")

# Well-known sensitive ports that should rarely be bound to all interfaces
SENSITIVE_GLOBAL_PORTS = {
    21: ("FTP", FindingSeverity.MEDIUM, "Unencrypted file transfer protocol exposed."),
    23: (
        "Telnet",
        FindingSeverity.CRITICAL,
        "Insecure, cleartext remote terminal protocol exposed on all interfaces.",
    ),
    445: (
        "SMB",
        FindingSeverity.HIGH,
        "Direct SMB file sharing service exposed on all interfaces.",
    ),
    3389: ("RDP", FindingSeverity.HIGH, "Remote Desktop Protocol service listening globally."),
    5900: ("VNC", FindingSeverity.HIGH, "VNC remote framebuffer service listening globally."),
    6379: (
        "Redis",
        FindingSeverity.HIGH,
        "In-memory database service listening globally without network boundary.",
    ),
    27017: ("MongoDB", FindingSeverity.HIGH, "NoSQL database service listening on all interfaces."),
}


class NetworkFindingsEvaluator:
    """Evaluates host network posture and produces normalized, evidence-based security findings."""

    def __init__(self) -> None:
        self.conn_inspector = NetworkConnectionInspector()
        self.iface_inspector = NetworkInterfaceInspector()
        self.firewall_auditor = FirewallAuditor()
        self.dns_engine = DNSIntelligenceEngine()
        self.wifi_inspector = WirelessSecurityInspector()

    def evaluate_listening_sockets(self) -> list[NetworkFinding]:
        """Audit listening ports for globally exposed and sensitive network services."""
        findings: list[NetworkFinding] = []
        listening = self.conn_inspector.get_listening_ports()

        for conn in listening:
            if not conn.is_all_interfaces:
                continue

            # Check for known sensitive ports
            if conn.local_port in SENSITIVE_GLOBAL_PORTS:
                svc_name, severity, desc = SENSITIVE_GLOBAL_PORTS[conn.local_port]
                proc_str = (
                    f"'{conn.process_name}' (PID: {conn.pid})"
                    if conn.process_name
                    else "Unknown process"
                )
                findings.append(
                    NetworkFinding(
                        finding_id=f"NET-PORT-{conn.local_port}",
                        category=FindingCategory.EXPOSED_SERVICE,
                        title=f"Sensitive Service Exposed Globally: {svc_name} (Port {conn.local_port})",
                        description=f"{desc} Bound to {conn.local_address}:{conn.local_port} by {proc_str}.",
                        severity=severity,
                        confidence=FindingConfidence.CONFIRMED,
                        evidence=f"Protocol: {conn.protocol.value}, Address: {conn.local_address}:{conn.local_port}, PID: {conn.pid}, Process: {conn.process_name}",
                        affected_target=f"{conn.local_address}:{conn.local_port}",
                        remediation=f"Bind {svc_name} to 127.0.0.1 or configure host firewall to restrict inbound access.",
                        source_module="network.connections",
                    )
                )
            elif conn.local_port > 1024 and not conn.process_name:
                findings.append(
                    NetworkFinding(
                        finding_id=f"NET-PORT-UNIDENTIFIED-{conn.local_port}",
                        category=FindingCategory.OPEN_PORT,
                        title=f"Unidentified Service Listening Globally on Port {conn.local_port}",
                        description=f"Port {conn.local_port} is listening on all interfaces with an unidentified process.",
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.MEDIUM,
                        evidence=f"Address: {conn.local_address}:{conn.local_port}, Process PID: {conn.pid}",
                        affected_target=f"{conn.local_address}:{conn.local_port}",
                        remediation="Identify the owning application and verify if public network exposure is necessary.",
                        source_module="network.connections",
                    )
                )

        # Connection count anomalies
        anomalies = self.conn_inspector.get_high_connection_processes(threshold=60)
        for pid, name, count in anomalies:
            findings.append(
                NetworkFinding(
                    finding_id=f"NET-ANOM-PROC-{pid}",
                    category=FindingCategory.CONNECTION_ANOMALY,
                    title=f"High Connection Count Anomaly: {name}",
                    description=f"Process '{name}' (PID {pid}) holds {count} active socket connections.",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.HIGH,
                    evidence=f"Process '{name}' (PID: {pid}) has {count} open sockets.",
                    affected_target=f"Process: {name} (PID: {pid})",
                    remediation="Investigate whether application is performing legitimate network operations or experiencing a socket leak.",
                    source_module="network.connections",
                )
            )

        return findings

    def run_full_audit(self) -> list[NetworkFinding]:
        """Aggregate all security findings across firewall, DNS, Wi-Fi, and active sockets."""
        all_findings: list[NetworkFinding] = []

        # 1. Firewall findings
        _, fw_findings = self.firewall_auditor.audit_firewall()
        all_findings.extend(fw_findings)

        # 2. DNS findings
        _, _, dns_findings = self.dns_engine.audit_dns_health()
        all_findings.extend(dns_findings)

        # 3. Wi-Fi findings
        _, wifi_findings = self.wifi_inspector.inspect_wifi()
        all_findings.extend(wifi_findings)

        # 4. Socket and listening port findings
        port_findings = self.evaluate_listening_sockets()
        all_findings.extend(port_findings)

        # Sort findings descending by severity
        severity_order = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4,
        }
        all_findings.sort(key=lambda f: severity_order.get(f.severity, 5))
        return all_findings
