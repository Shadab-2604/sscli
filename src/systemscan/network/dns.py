"""DNS configuration analysis, record resolution, and anomaly detection."""

from __future__ import annotations

import socket
import time

from systemscan.logging.logger import get_logger
from systemscan.network.models import (
    DNSRecordType,
    DNSResolutionResult,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    NetworkFinding,
)
from systemscan.network.providers import get_network_provider

logger = get_logger("network.dns")


class DNSIntelligenceEngine:
    """Audits host DNS configuration and performs evidence-based resolution diagnostics."""

    def __init__(self) -> None:
        self.provider = get_network_provider()

    def get_configured_dns_servers(self) -> list[str]:
        """Discover active DNS resolver servers configured on the host."""
        return self.provider.get_dns_servers()

    def resolve_domain(
        self,
        domain: str = "example.com",
        record_type: DNSRecordType = DNSRecordType.A,
        timeout: float = 2.0,
    ) -> DNSResolutionResult:
        """Resolve domain records with latency measurement and graceful error capture."""
        t_start = time.perf_counter()
        records: list[str] = []
        error: str | None = None
        success = False

        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)

        try:
            if record_type == DNSRecordType.A:
                # Resolve IPv4
                addr_info = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
                records = sorted({str(info[4][0]) for info in addr_info})
                success = True

            elif record_type == DNSRecordType.AAAA:
                # Resolve IPv6
                addr_info = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
                records = sorted({str(info[4][0]) for info in addr_info})
                success = True

            elif record_type == DNSRecordType.PTR:
                # Reverse DNS
                host_info = socket.gethostbyaddr(domain)
                records = [host_info[0]]
                success = True

            else:
                # Check for optional dnspython
                try:
                    import dns.resolver  # type: ignore

                    answers = dns.resolver.resolve(domain, record_type.value, lifetime=timeout)
                    records = [str(rdata) for rdata in answers]
                    success = True
                except ImportError:
                    # Fallback to getaddrinfo if dnspython is absent
                    addr_info = socket.getaddrinfo(domain, None)
                    records = sorted({str(info[4][0]) for info in addr_info})
                    success = True

        except (TimeoutError, socket.gaierror, socket.herror, Exception) as e:
            error = str(e)
            success = False
        finally:
            socket.setdefaulttimeout(old_timeout)

        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        return DNSResolutionResult(
            query_name=domain,
            record_type=record_type,
            records=records,
            resolution_time_ms=round(elapsed_ms, 2),
            error=error,
            success=success,
        )

    def audit_dns_health(self) -> tuple[list[str], list[DNSResolutionResult], list[NetworkFinding]]:
        """Run health audit over configured DNS servers and perform test resolution."""
        servers = self.get_configured_dns_servers()
        findings: list[NetworkFinding] = []
        test_results: list[DNSResolutionResult] = []

        # Check 1: Missing DNS servers
        if not servers:
            findings.append(
                NetworkFinding(
                    finding_id="NET-DNS-001",
                    category=FindingCategory.DNS,
                    title="No DNS Servers Configured",
                    description="No active DNS resolver servers could be identified on host interfaces.",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.CONFIRMED,
                    evidence="Query to system network configuration returned empty DNS server list.",
                    affected_target="Host DNS Configuration",
                    remediation="Configure valid internal or trusted public DNS servers (e.g. 1.1.1.1 or 8.8.8.8).",
                    source_module="network.dns",
                )
            )

        # Check 2: Test resolution of canonical domain
        res_a = self.resolve_domain("example.com", DNSRecordType.A)
        test_results.append(res_a)
        if not res_a.success:
            findings.append(
                NetworkFinding(
                    finding_id="NET-DNS-002",
                    category=FindingCategory.DNS,
                    title="DNS Resolution Failure",
                    description=f"Standard DNS lookup for 'example.com' failed: {res_a.error}.",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.HIGH,
                    evidence=f"Resolution error: {res_a.error} (Latency: {res_a.resolution_time_ms} ms)",
                    affected_target="DNS Resolver",
                    remediation="Verify local network connectivity and DNS server reachability.",
                    source_module="network.dns",
                )
            )
        elif res_a.resolution_time_ms > 1500.0:
            findings.append(
                NetworkFinding(
                    finding_id="NET-DNS-003",
                    category=FindingCategory.DNS,
                    title="Degraded DNS Resolution Latency",
                    description=f"DNS resolution took {res_a.resolution_time_ms:.1f} ms, indicating high latency.",
                    severity=FindingSeverity.LOW,
                    confidence=FindingConfidence.MEDIUM,
                    evidence=f"Resolution time: {res_a.resolution_time_ms} ms exceeds 1500ms threshold.",
                    affected_target="DNS Latency",
                    remediation="Check network congestion or switch to closer DNS resolver.",
                    source_module="network.dns",
                )
            )

        return servers, test_results, findings
