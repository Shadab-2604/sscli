"""Alert formatting, deduplication, and notification routing."""

from __future__ import annotations

import logging
from collections.abc import Callable

from rich.console import Console

from systemscan.network_monitor.models import AlertSeverity, NetworkThreatAlert

logger = logging.getLogger("systemscan.network_monitor.alerts")


class AlertManager:
    """Handles alert deduplication, formatting, and live terminal rendering."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self._handlers: list[Callable[[NetworkThreatAlert], None]] = []

    def register_handler(self, handler: Callable[[NetworkThreatAlert], None]) -> None:
        """Register custom consumer for dispatched alerts (e.g. database saver)."""
        self._handlers.append(handler)

    def dispatch_alert(self, alert: NetworkThreatAlert) -> None:
        """Render alert to terminal and notify subscribers."""
        self.render_alert(alert)
        for h in self._handlers:
            try:
                h(alert)
            except Exception as e:
                logger.debug(f"Alert handler error: {e}")

    def render_alert(self, alert: NetworkThreatAlert) -> None:
        """Render clean, high-visibility cybersecurity CLI alert box."""
        time_str = alert.timestamp.strftime("%H:%M:%S")

        sev_color = "bold red"
        if alert.severity == AlertSeverity.CRITICAL:
            sev_color = "bold red on black"
        elif alert.severity == AlertSeverity.HIGH:
            sev_color = "bold red"
        elif alert.severity == AlertSeverity.MEDIUM:
            sev_color = "bold yellow"
        elif alert.severity == AlertSeverity.LOW:
            sev_color = "bold cyan"

        self.console.print()
        self.console.print(
            f"[{sev_color}][{time_str}] {alert.severity.value:<8} {alert.alert_type}[/{sev_color}]"
        )
        self.console.print(
            f"  [dim]Source IP       :[/dim] [bold white]{alert.source_ip}[/bold white]"
        )
        if alert.source_mac:
            self.console.print(f"  [dim]Source MAC      :[/dim] [cyan]{alert.source_mac}[/cyan]")
        if alert.source_hostname:
            self.console.print(
                f"  [dim]Hostname        :[/dim] [white]{alert.source_hostname}[/white]"
            )
        if alert.source_vendor:
            self.console.print(
                f"  [dim]Vendor          :[/dim] [dim white]{alert.source_vendor}[/dim white]"
            )

        self.console.print(
            f"  [dim]Destination IP  :[/dim] [bold white]{alert.destination_ip}[/bold white]"
        )
        self.console.print(f"  [dim]Protocol        :[/dim] [cyan]{alert.protocol.value}[/cyan]")
        self.console.print(
            f"  [dim]Pattern         :[/dim] [bold yellow]{alert.pattern.value}[/bold yellow]"
        )

        if alert.unique_ports > 0:
            self.console.print(
                f"  [dim]Unique ports    :[/dim] [bold white]{alert.unique_ports}[/bold white]"
            )
        if alert.sample_ports:
            ports_preview = ", ".join(str(p) for p in alert.sample_ports[:8])
            if len(alert.sample_ports) > 8:
                ports_preview += "..."
            self.console.print(f"  [dim]Sample ports    :[/dim] [dim]{ports_preview}[/dim]")

        self.console.print(
            f"  [dim]Time window     :[/dim] {alert.time_window_seconds:.0f} seconds"
        )
        self.console.print(
            f"  [dim]Confidence      :[/dim] [bold green]{alert.confidence.value}[/bold green]"
        )
        self.console.print(f"  [dim]Evidence        :[/dim] [dim]{alert.evidence}[/dim]")
        self.console.print(
            f"  [dim]Capture source  :[/dim] [cyan]{alert.capture_source.value}[/cyan]"
        )
        self.console.print(
            f"  [dim]Event ID        :[/dim] [dim white]{alert.alert_id}[/dim white]\n"
        )
