"""Safe local network discovery and host enumeration engine."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import time
from collections.abc import Callable

from systemscan.filesystem.cancellation import CancellationToken
from systemscan.logging.logger import get_logger
from systemscan.network.models import DiscoveredHost, HostStatus
from systemscan.network.providers import get_network_provider

logger = get_logger("network.discovery")

# Standard non-intrusive ports for safe host responsiveness check
DEFAULT_PROBE_PORTS = [80, 443, 22, 445, 139, 53, 8080]


class LocalNetworkDiscovery:
    """Safely discovers and enumerates reachable hosts on an authorized local subnet."""

    def __init__(self) -> None:
        self.provider = get_network_provider()

    def get_default_local_subnet(self) -> str | None:
        """Infer the primary local subnet from the default gateway or active IPv4 interfaces."""
        gateway = self.provider.get_default_gateway()
        from systemscan.network.interfaces import NetworkInterfaceInspector

        interfaces = NetworkInterfaceInspector().inspect_all()
        # Find interface matching gateway or first active non-loopback with subnets
        for iface in interfaces:
            if iface.is_up and not iface.is_loopback:
                if gateway and iface.gateway == gateway and iface.subnets:
                    return iface.subnets[0]
                if iface.subnets:
                    return iface.subnets[0]
        return None

    def validate_subnet_authorization(
        self, subnet_str: str, allow_public: bool = False
    ) -> ipaddress.IPv4Network:
        """Validate that target subnet is valid and within safe private address spaces."""
        try:
            net = ipaddress.IPv4Network(subnet_str, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid IPv4 subnet format '{subnet_str}': {e}") from e

        if not allow_public and not (net.is_private or net.is_link_local or net.is_loopback):
            raise PermissionError(
                f"Scanning public IP network '{subnet_str}' is strictly forbidden by default. "
                "Network discovery is restricted to authorized private local subnets (RFC 1918)."
            )

        # Cap scan size to /24 (256 addresses) or /22 (1024 addresses) to prevent accidental massive network stalls
        if net.num_addresses > 1024 and not allow_public:
            raise ValueError(
                f"Subnet '{subnet_str}' has {net.num_addresses} addresses (exceeds safe discovery limit of 1024). "
                "Please specify a smaller range such as /24."
            )

        return net

    def _probe_host(
        self,
        ip_str: str,
        timeout: float = 0.35,
        probe_ports: list[int] | None = None,
    ) -> tuple[bool, list[int], float | None]:
        """Test host responsiveness using non-intrusive TCP connect probes across standard ports."""
        ports = probe_ports or [80, 443, 22, 445, 139]
        open_ports: list[int] = []
        best_latency: float | None = None

        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            t_start = time.perf_counter()
            try:
                res = s.connect_ex((ip_str, port))
                latency = (time.perf_counter() - t_start) * 1000.0
                if res == 0:
                    open_ports.append(port)
                    if best_latency is None or latency < best_latency:
                        best_latency = latency
            except (TimeoutError, OSError):
                pass
            finally:
                s.close()

        is_responsive = len(open_ports) > 0
        return is_responsive, open_ports, best_latency

    def _resolve_hostname(self, ip_str: str, timeout: float = 0.5) -> str | None:
        """Attempt safe reverse DNS lookup."""
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(timeout)
            try:
                host_info = socket.gethostbyaddr(ip_str)
                return host_info[0]
            finally:
                socket.setdefaulttimeout(old_timeout)
        except (TimeoutError, socket.herror, socket.gaierror, OSError):
            return None

    def discover(
        self,
        subnet_str: str | None = None,
        max_workers: int = 24,
        probe_timeout: float = 0.35,
        allow_public: bool = False,
        cancellation_token: CancellationToken | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[DiscoveredHost]:
        """Discover reachable hosts on an authorized subnet."""
        target_str = subnet_str or self.get_default_local_subnet()
        if not target_str:
            logger.warning("No local subnet could be automatically determined.")
            return []

        net = self.validate_subnet_authorization(target_str, allow_public=allow_public)
        default_gw = self.provider.get_default_gateway()

        # Step 1: Collect known ARP entries from kernel
        arp_cache = dict(self.provider.get_arp_table())

        hosts_to_scan = [str(ip) for ip in net.hosts()]
        total_hosts = len(hosts_to_scan)
        discovered: list[DiscoveredHost] = []

        # Immediately include any hosts already in kernel ARP table for this subnet
        arp_matched_ips = set()
        for ip_str, mac in arp_cache.items():
            try:
                ip_obj = ipaddress.IPv4Address(ip_str)
                if ip_obj in net:
                    arp_matched_ips.add(ip_str)
                    is_gw = bool(default_gw and ip_str == default_gw)
                    hostname = self._resolve_hostname(ip_str, timeout=0.3)
                    discovered.append(
                        DiscoveredHost(
                            ip=ip_str,
                            mac=mac,
                            hostname=hostname,
                            status=HostStatus.UP,
                            is_gateway=is_gw,
                        )
                    )
            except ValueError:
                continue

        # Step 2: Concurrently probe hosts on the subnet with bounded worker pool
        completed = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {
                executor.submit(self._probe_host, ip_str, probe_timeout): ip_str
                for ip_str in hosts_to_scan
            }

            for future in concurrent.futures.as_completed(future_to_ip):
                if cancellation_token and cancellation_token.is_cancelled:
                    logger.info("Local network discovery cancelled by operator.")
                    break

                ip_str = future_to_ip[future]
                completed += 1
                if progress_callback:
                    progress_callback(completed, total_hosts)

                try:
                    is_up, open_ports, latency = future.result()
                    if is_up:
                        host_mac = arp_cache.get(ip_str)
                        is_gw = bool(default_gw and ip_str == default_gw)
                        hostname = self._resolve_hostname(ip_str)
                        # Check if already added via ARP table
                        existing = next((h for h in discovered if h.ip == ip_str), None)
                        if existing:
                            existing.open_ports = open_ports
                            existing.latency_ms = latency
                            if hostname and not existing.hostname:
                                existing.hostname = hostname
                        else:
                            discovered.append(
                                DiscoveredHost(
                                    ip=ip_str,
                                    mac=host_mac,
                                    hostname=hostname,
                                    status=HostStatus.UP,
                                    latency_ms=latency,
                                    open_ports=open_ports,
                                    is_gateway=is_gw,
                                )
                            )
                except Exception as e:
                    logger.debug(f"Host probe error for {ip_str}: {e}")

        # Sort discovered hosts numerically by IP address
        discovered.sort(key=lambda h: ipaddress.IPv4Address(h.ip))
        return discovered
