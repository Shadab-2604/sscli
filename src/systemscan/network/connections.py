"""Active network connection and listening port inspector."""

from __future__ import annotations

from collections import Counter

import psutil

from systemscan.logging.logger import get_logger
from systemscan.network.models import ConnectionState, NetworkConnection, Protocol

logger = get_logger("network.connections")


class NetworkConnectionInspector:
    """Inspects active socket connections, listening endpoints, and owning processes."""

    def __init__(self) -> None:
        self._proc_cache: dict[int, tuple[str, str | None]] = {}

    def _resolve_process(self, pid: int | None) -> tuple[str | None, str | None]:
        """Resolve binary name and executable path for a PID with memory caching."""
        if not pid or pid <= 0:
            return None, None

        if pid in self._proc_cache:
            return self._proc_cache[pid]

        try:
            p = psutil.Process(pid)
            name = p.name()
            try:
                exe = p.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = None
            self._proc_cache[pid] = (name, exe)
            return name, exe
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            self._proc_cache[pid] = ("Unknown", None)
            return "Unknown", None

    def inspect_connections(self) -> list[NetworkConnection]:
        """Collect all active TCP and UDP sockets across the host."""
        results: list[NetworkConnection] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError) as e:
            logger.debug(
                f"Permission denied querying all inet connections: {e}. Falling back to tcp."
            )
            try:
                conns = psutil.net_connections(kind="tcp")
            except Exception:
                conns = []
        except Exception as e:
            logger.debug(f"psutil.net_connections failed: {e}")
            conns = []

        for conn in conns:
            # Protocol
            proto = Protocol.TCP if conn.type == 1 else Protocol.UDP

            # Local endpoint
            laddr = conn.laddr
            if not laddr:
                continue
            if hasattr(laddr, "ip") and hasattr(laddr, "port"):
                local_ip = str(laddr.ip)
                local_port = int(laddr.port)
            elif len(laddr) >= 2:
                local_ip = str(laddr[0])
                local_port = int(laddr[1])
            else:
                continue

            # Remote endpoint
            remote_ip: str | None = None
            remote_port: int | None = None
            raddr = conn.raddr
            if raddr:
                if hasattr(raddr, "ip") and hasattr(raddr, "port"):
                    remote_ip = str(raddr.ip)
                    remote_port = int(raddr.port)
                elif len(raddr) >= 2:
                    remote_ip = str(raddr[0])
                    remote_port = int(raddr[1])

            # State
            raw_status = (conn.status or "NONE").upper()
            try:
                state = ConnectionState[raw_status]
            except KeyError:
                state = ConnectionState.UNKNOWN

            is_listen = state == ConnectionState.LISTEN or (proto == Protocol.UDP and not remote_ip)
            is_all_ifaces = local_ip in ("0.0.0.0", "::")
            is_loopback = local_ip.startswith("127.") or local_ip in ("::1", "fe80::1")

            proc_name, proc_path = self._resolve_process(conn.pid)

            results.append(
                NetworkConnection(
                    protocol=proto,
                    local_address=local_ip,
                    local_port=local_port,
                    remote_address=remote_ip,
                    remote_port=remote_port,
                    state=state,
                    pid=conn.pid,
                    process_name=proc_name,
                    process_path=proc_path,
                    is_listening=is_listen,
                    is_all_interfaces=is_all_ifaces,
                    is_loopback=is_loopback,
                )
            )

        return results

    def get_listening_ports(self) -> list[NetworkConnection]:
        """Return only sockets currently listening for incoming connections."""
        return [c for c in self.inspect_connections() if c.is_listening]

    def get_established_connections(self) -> list[NetworkConnection]:
        """Return only active established remote connections."""
        return [c for c in self.inspect_connections() if c.state == ConnectionState.ESTABLISHED]

    def get_high_connection_processes(self, threshold: int = 50) -> list[tuple[int, str, int]]:
        """Identify processes with connection counts exceeding threshold (pid, name, count)."""
        conns = self.inspect_connections()
        pids = [c.pid for c in conns if c.pid is not None and c.pid > 0]
        counter = Counter(pids)
        anomalies: list[tuple[int, str, int]] = []
        for pid, count in counter.items():
            if count >= threshold:
                name, _ = self._resolve_process(pid)
                anomalies.append((pid, name or "Unknown", count))
        return anomalies
