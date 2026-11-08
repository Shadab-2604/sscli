"""Real-time active network connection and port monitor."""

from __future__ import annotations

import time
from collections.abc import Callable

from systemscan.filesystem.cancellation import CancellationToken
from systemscan.logging.logger import get_logger
from systemscan.network.connections import NetworkConnectionInspector
from systemscan.network.models import NetworkConnection

logger = get_logger("network.monitor")


class NetworkMonitor:
    """Non-persistent polling monitor tracking network socket transitions in real time."""

    def __init__(self, inspector: NetworkConnectionInspector | None = None) -> None:
        self.inspector = inspector or NetworkConnectionInspector()

    def monitor(
        self,
        interval: float = 2.0,
        duration: float | None = None,
        cancellation_token: CancellationToken | None = None,
        on_update: Callable[[list[NetworkConnection], list[NetworkConnection]], None] | None = None,
    ) -> None:
        """Poll active connections periodically and emit updates."""
        t_start = time.time()
        prev_conns: set[tuple[str, str, int, str | None, int | None]] = set()

        while True:
            if cancellation_token and cancellation_token.is_cancelled:
                break
            if duration and (time.time() - t_start) >= duration:
                break

            current_conns = self.inspector.inspect_connections()
            curr_set = {
                (c.protocol.value, c.local_address, c.local_port, c.remote_address, c.remote_port)
                for c in current_conns
            }

            # Identify newly observed sockets
            new_sockets: list[NetworkConnection] = []
            if prev_conns:
                new_keys = curr_set - prev_conns
                new_sockets = [
                    c
                    for c in current_conns
                    if (
                        c.protocol.value,
                        c.local_address,
                        c.local_port,
                        c.remote_address,
                        c.remote_port,
                    )
                    in new_keys
                ]

            prev_conns = curr_set

            if on_update:
                on_update(current_conns, new_sockets)

            time.sleep(interval)
