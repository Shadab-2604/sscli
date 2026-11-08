"""Basic network performance, latency, and reachability diagnostics."""

from __future__ import annotations

import socket
import time

from systemscan.logging.logger import get_logger
from systemscan.network.models import DiagnosticsResult
from systemscan.network.providers import get_network_provider

logger = get_logger("network.diagnostics")


class NetworkDiagnostics:
    """Executes safe, low-overhead network connectivity and reachability diagnostics."""

    def __init__(self) -> None:
        self.provider = get_network_provider()

    def _test_tcp_latency(self, host: str, port: int, timeout: float = 1.0) -> float | None:
        """Measure TCP connection handshake latency in milliseconds."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t_start = time.perf_counter()
        try:
            res = s.connect_ex((host, port))
            if res == 0:
                return (time.perf_counter() - t_start) * 1000.0
            return None
        except OSError:
            return None
        finally:
            s.close()

    def run_diagnostics(
        self,
        internet_target: str = "1.1.1.1",
        internet_port: int = 53,
        probe_count: int = 3,
    ) -> DiagnosticsResult:
        """Run connectivity checks across local gateway, DNS, and external internet targets."""
        gateway = self.provider.get_default_gateway()

        # 1. Gateway reachability (try port 53, 80, or 443)
        gw_reachable = False
        gw_latencies: list[float] = []
        if gateway:
            for _ in range(probe_count):
                for p in (53, 80, 443):
                    lat = self._test_tcp_latency(gateway, p, timeout=0.5)
                    if lat is not None:
                        gw_latencies.append(lat)
                        gw_reachable = True
                        break

        avg_gw_lat = round(sum(gw_latencies) / len(gw_latencies), 2) if gw_latencies else None

        # 2. DNS resolution test
        dns_working = False
        dns_latencies: list[float] = []
        for _ in range(probe_count):
            t0 = time.perf_counter()
            try:
                socket.getaddrinfo("example.com", None, socket.AF_INET)
                dns_latencies.append((time.perf_counter() - t0) * 1000.0)
                dns_working = True
            except (OSError, socket.gaierror):
                pass

        avg_dns_lat = round(sum(dns_latencies) / len(dns_latencies), 2) if dns_latencies else None

        # 3. Internet connectivity test
        inet_reachable = False
        inet_latencies: list[float] = []
        lost_packets = 0
        for _ in range(probe_count):
            lat = self._test_tcp_latency(internet_target, internet_port, timeout=1.0)
            if lat is not None:
                inet_latencies.append(lat)
                inet_reachable = True
            else:
                lost_packets += 1

        avg_inet_lat = (
            round(sum(inet_latencies) / len(inet_latencies), 2) if inet_latencies else None
        )
        loss_pct = round((lost_packets / probe_count) * 100.0, 1)

        # Interpretation summary
        if gw_reachable and dns_working and inet_reachable:
            summary = "Full network connectivity operational (Local Gateway, DNS, and Internet reachable)."
        elif gw_reachable and not inet_reachable:
            summary = "Local gateway is responsive, but Internet connectivity failed (possible WAN outage or firewall block)."
        elif inet_reachable and not dns_working:
            summary = "Direct IP Internet connectivity is operational, but DNS name resolution is failing."
        elif not gw_reachable:
            summary = "Local gateway is unreachable. Check physical cable or Wi-Fi association."
        else:
            summary = "Network diagnostics completed with partial connectivity."

        return DiagnosticsResult(
            gateway_ip=gateway,
            gateway_reachable=gw_reachable,
            gateway_latency_ms=avg_gw_lat,
            dns_working=dns_working,
            dns_latency_ms=avg_dns_lat,
            internet_target=internet_target,
            internet_reachable=inet_reachable,
            internet_latency_ms=avg_inet_lat,
            packet_loss_percent=loss_pct,
            summary=summary,
        )
