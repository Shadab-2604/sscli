"""Central orchestrator managing dual-mode capture, detection, alerts, and state."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import datetime, timezone
from threading import Event

from rich.console import Console

from systemscan.network_monitor.alerts.manager import AlertManager
from systemscan.network_monitor.capture.local_capture import LocalPacketCaptureEngine
from systemscan.network_monitor.capture.network_capture import NetworkSensorCaptureEngine
from systemscan.network_monitor.configuration import NetworkMonitorConfig
from systemscan.network_monitor.detection.engine import NetworkScanDetectionEngine
from systemscan.network_monitor.event_bus import EventBus
from systemscan.network_monitor.identification.engine import DeviceIdentificationEngine
from systemscan.network_monitor.models import (
    DeviceIdentity,
    MonitorMode,
    NetworkThreatAlert,
    PacketMetadata,
    SensorHealthStatus,
)
from systemscan.network_monitor.monitor_status import MonitorStatusReport
from systemscan.network_monitor.storage.database import NetworkAlertDatabase

logger = logging.getLogger("systemscan.network_monitor.manager")


class NetworkThreatMonitorManager:
    """
    Coordinates local packet ingestion, network sensor feeds, scan behavioral analysis,
    device attribution, alerting, and SQLite event persistence.
    """

    def __init__(
        self,
        config: NetworkMonitorConfig | None = None,
        console: Console | None = None,
        db: NetworkAlertDatabase | None = None,
    ) -> None:
        self.config = config or NetworkMonitorConfig()
        self.console = console or Console()
        self.db = db or NetworkAlertDatabase()

        self.event_bus = EventBus()
        self.detector = NetworkScanDetectionEngine(config=self.config)
        self.ident = DeviceIdentificationEngine()
        self.alert_mgr = AlertManager(console=self.console)

        # Wire database saving as an alert handler
        self.alert_mgr.register_handler(self.db.save_alert)

        # Wire event bus topics
        self.event_bus.subscribe("packet.observed", self._on_packet_observed)
        self.event_bus.subscribe("threat.alert", self.alert_mgr.dispatch_alert)

        # Ingestion engines
        self.local_capture = LocalPacketCaptureEngine(interface=self.config.interface)
        self.network_capture = NetworkSensorCaptureEngine(
            source_url=self.config.router_api_url,
            auth_token=self.config.router_token or self.config.sensor_auth_token,
        )

        self._running = False
        self._stop_event = Event()
        self._mode = MonitorMode.BOTH
        self._total_packets_captured = 0
        self._total_alerts_generated = 0
        self._start_time: float = 0.0

    def start_monitoring(
        self,
        mode: MonitorMode = MonitorMode.BOTH,
        duration_seconds: int | None = None,
        alert_callback: Callable[[NetworkThreatAlert], None] | None = None,
    ) -> MonitorStatusReport:
        """
        Initialize and run network threat monitoring.
        If duration_seconds is provided, runs blocking until elapsed or cancelled.
        """
        self._mode = mode
        self._running = True
        self._stop_event.clear()
        self._start_time = time.time()

        if alert_callback:
            self.alert_mgr.register_handler(alert_callback)

        self.event_bus.start()

        def _on_packet(pkt: PacketMetadata) -> None:
            self.event_bus.publish("packet.observed", pkt)

        # 1. Start Local Capture if requested
        if mode in (MonitorMode.LOCAL, MonitorMode.BOTH):
            self.local_capture.start_capture(callback=_on_packet)

        # 2. Start Network-Wide Sensor Capture if requested
        if mode in (MonitorMode.NETWORK_WIDE, MonitorMode.BOTH):
            self.network_capture.start_capture(callback=_on_packet)

        report = self.get_status_report()

        if duration_seconds:
            try:
                deadline = time.time() + duration_seconds
                while time.time() < deadline and not self._stop_event.is_set():
                    time.sleep(0.5)
            except KeyboardInterrupt:
                pass
            finally:
                self.stop_monitoring()

        return report

    def stop_monitoring(self) -> None:
        """Gracefully stop capture providers, detector threads, and event bus."""
        self._running = False
        self._stop_event.set()
        self.local_capture.stop_capture()
        self.network_capture.stop_capture()
        self.event_bus.stop()

    def process_single_packet(self, meta: PacketMetadata) -> NetworkThreatAlert | None:
        """Synchronously process a single packet metadata record (for unit testing and pipeline)."""
        self._total_packets_captured += 1
        # Track device
        self.ident.identify_host(
            ip=meta.source_ip,
            mac=meta.source_mac,
            interface=meta.interface,
        )

        alert = self.detector.process_packet(meta)
        if alert:
            # Enrich alert with device identification metadata
            dev = self.ident.identify_host(alert.source_ip, alert.source_mac)
            alert.source_hostname = dev.hostname
            alert.source_vendor = dev.vendor
            self._total_alerts_generated += 1
            self.alert_mgr.dispatch_alert(alert)
        return alert

    def _on_packet_observed(self, meta: PacketMetadata) -> None:
        self.process_single_packet(meta)

    def get_status_report(self) -> MonitorStatusReport:
        """Construct real-time operational status report."""
        loc_health, loc_details = self.local_capture.get_health_status()
        net_health, net_details = self.network_capture.get_health_status()

        # Determine coverage string truthfully
        coverage = "Inactive"
        if loc_health == SensorHealthStatus.HEALTHY and net_health == SensorHealthStatus.HEALTHY:
            coverage = "Local Machine + Network-Wide Active"
        elif loc_health == SensorHealthStatus.HEALTHY:
            coverage = "Local machine traffic only"
        elif net_health == SensorHealthStatus.HEALTHY:
            coverage = "Network-wide sensor traffic only"

        return MonitorStatusReport(
            mode=self._mode,
            timestamp=datetime.now(timezone.utc),
            local_active=self.local_capture._provider._running,
            local_interface=self.local_capture.get_interface_name(),
            local_packets_captured=self.local_capture._provider._packet_count,
            local_capture_health=loc_health,
            local_details=loc_details,
            network_active=self.network_capture._running,
            network_source_name=self.network_capture.get_interface_name(),
            network_packets_captured=0,
            network_capture_health=net_health,
            network_details=net_details,
            coverage_summary=coverage,
            alerts_generated=self._total_alerts_generated,
            devices_tracked=len(self.ident.get_tracked_devices()),
        )

    def get_tracked_devices(self) -> list[DeviceIdentity]:
        """Return list of all hosts discovered during monitoring."""
        return self.ident.get_tracked_devices()
