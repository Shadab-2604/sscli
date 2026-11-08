"""Network state baseline snapshot creation, persistence, and drift comparison."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from systemscan.logging.logger import get_logger
from systemscan.network.connections import NetworkConnectionInspector
from systemscan.network.dns import DNSIntelligenceEngine
from systemscan.network.interfaces import NetworkInterfaceInspector
from systemscan.network.models import (
    BaselineComparisonResult,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    NetworkBaseline,
    NetworkFinding,
)
from systemscan.network.providers import get_network_provider
from systemscan.utils.paths import AppPaths

logger = get_logger("network.baseline")


class NetworkBaselineManager:
    """Manages creation, persistence, and change detection for network configuration baselines."""

    def __init__(self, baseline_dir: Path | None = None) -> None:
        self.baseline_dir = baseline_dir or (AppPaths().data_dir / "network_baselines")
        self.baseline_dir.mkdir(parents=True, exist_ok=True)
        self.provider = get_network_provider()

    def _get_baseline_path(self, name: str) -> Path:
        safe_name = "".join(c for c in name if c.isalnum() or c in ("-", "_")) or "default"
        return self.baseline_dir / f"{safe_name}.json"

    def list_baselines(self) -> list[str]:
        """List names of existing saved network baseline profiles."""
        if not self.baseline_dir.exists():
            return []
        return [p.stem for p in self.baseline_dir.glob("*.json")]

    def load_baseline(self, name: str = "default") -> NetworkBaseline | None:
        """Load an existing baseline profile from disk."""
        path = self._get_baseline_path(name)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return NetworkBaseline.model_validate(data)
        except Exception as e:
            logger.warning(f"Failed to parse baseline '{name}': {e}")
            return None

    def create_baseline(self, name: str = "default", overwrite: bool = False) -> NetworkBaseline:
        """Capture current host network configuration and persist as a baseline snapshot."""
        path = self._get_baseline_path(name)
        if path.exists() and not overwrite:
            raise FileExistsError(
                f"Baseline profile '{name}' already exists. Use overwrite=True to update."
            )

        # Gather current state
        ifaces = NetworkInterfaceInspector().inspect_all()
        known_ifaces = sorted({i.mac_address or i.name for i in ifaces})

        gw = self.provider.get_default_gateway()
        known_gws = [gw] if gw else []

        dns_servers = DNSIntelligenceEngine().get_configured_dns_servers()

        wifi_info = self.provider.get_wireless_info()
        known_ssids = [wifi_info.ssid] if (wifi_info and wifi_info.ssid) else []

        listening_conns = NetworkConnectionInspector().get_listening_ports()
        known_ports = sorted({c.local_port for c in listening_conns})

        baseline = NetworkBaseline(
            name=name,
            version=1,
            created_at=datetime.now(timezone.utc),
            known_interfaces=known_ifaces,
            known_gateways=known_gws,
            known_dns_servers=dns_servers,
            known_wifi_ssids=known_ssids,
            known_listening_ports=known_ports,
            known_local_devices=[],
        )

        # Atomic file write
        tmp_path = path.with_suffix(".tmp")
        tmp_path.write_text(baseline.model_dump_json(indent=2), encoding="utf-8")
        tmp_path.replace(path)
        logger.info(f"Saved network baseline '{name}' to {path}")
        return baseline

    def compare_baseline(self, name: str = "default") -> BaselineComparisonResult:
        """Compare current network configuration against a saved baseline."""
        baseline = self.load_baseline(name)
        if not baseline:
            raise FileNotFoundError(f"Baseline profile '{name}' was not found.")

        # Active state
        ifaces = NetworkInterfaceInspector().inspect_all()
        curr_ifaces = {i.mac_address or i.name for i in ifaces}

        gw = self.provider.get_default_gateway()
        curr_gws = {gw} if gw else set()

        curr_dns = set(DNSIntelligenceEngine().get_configured_dns_servers())

        wifi_info = self.provider.get_wireless_info()
        curr_ssids = {wifi_info.ssid} if (wifi_info and wifi_info.ssid) else set()

        curr_ports = {c.local_port for c in NetworkConnectionInspector().get_listening_ports()}

        base_ifaces = set(baseline.known_interfaces)
        base_gws = set(baseline.known_gateways)
        base_dns = set(baseline.known_dns_servers)
        base_ssids = set(baseline.known_wifi_ssids)
        base_ports = set(baseline.known_listening_ports)

        added_ifaces = sorted(curr_ifaces - base_ifaces)
        removed_ifaces = sorted(base_ifaces - curr_ifaces)

        added_gws = sorted(curr_gws - base_gws)
        removed_gws = sorted(base_gws - curr_gws)

        added_dns = sorted(curr_dns - base_dns)
        removed_dns = sorted(base_dns - curr_dns)

        added_ports = sorted(curr_ports - base_ports)
        removed_ports = sorted(base_ports - curr_ports)

        new_ssids = sorted(curr_ssids - base_ssids)

        findings: list[NetworkFinding] = []

        # Check: Gateway divergence
        if added_gws and base_gws:
            findings.append(
                NetworkFinding(
                    finding_id="NET-BASE-001",
                    category=FindingCategory.NETWORK_CONFIGURATION,
                    title="Default Gateway Divergence",
                    description=f"Default gateway changed from {list(base_gws)} to {added_gws}.",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                    evidence=f"Baseline: {list(base_gws)}, Active: {added_gws}",
                    affected_target="Default Gateway",
                    remediation="Verify whether network migration or rogue DHCP gateway advertisement occurred.",
                    source_module="network.baseline",
                )
            )

        # Check: DNS servers divergence
        if added_dns and base_dns:
            findings.append(
                NetworkFinding(
                    finding_id="NET-BASE-002",
                    category=FindingCategory.DNS,
                    title="DNS Resolver Configuration Divergence",
                    description=f"New DNS servers {added_dns} configured that were not present in baseline.",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                    evidence=f"Baseline: {list(base_dns)}, Added: {added_dns}",
                    affected_target="DNS Servers",
                    remediation="Inspect system DNS settings to ensure unauthorized DNS redirection is not active.",
                    source_module="network.baseline",
                )
            )

        # Check: New listening ports
        if added_ports:
            findings.append(
                NetworkFinding(
                    finding_id="NET-BASE-003",
                    category=FindingCategory.OPEN_PORT,
                    title="New Listening Ports Discovered",
                    description=f"New listening ports {added_ports} active since baseline was established.",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.HIGH,
                    evidence=f"Baseline ports: {len(base_ports)}, New ports: {added_ports}",
                    affected_target="Listening Sockets",
                    remediation="Identify the applications associated with the newly listening ports.",
                    source_module="network.baseline",
                )
            )

        return BaselineComparisonResult(
            baseline_name=name,
            added_interfaces=added_ifaces,
            removed_interfaces=removed_ifaces,
            added_gateways=added_gws,
            removed_gateways=removed_gws,
            added_dns_servers=added_dns,
            removed_dns_servers=removed_dns,
            added_listening_ports=added_ports,
            removed_listening_ports=removed_ports,
            new_wifi_ssids=new_ssids,
            new_devices=[],
            findings=findings,
        )
