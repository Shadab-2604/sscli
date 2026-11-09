"""SQLite persistence and historical record management for network threat alerts."""

from __future__ import annotations

import csv
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from systemscan.network_monitor.models import (
    AlertSeverity,
    CaptureSourceType,
    DetectionConfidence,
    NetworkThreatAlert,
    ScanPattern,
    ScanProtocol,
)
from systemscan.utils.paths import AppPaths

logger = logging.getLogger("systemscan.network_monitor.storage")


class NetworkAlertDatabase:
    """Stores security alerts in SQLite with JSON, CSV, and text export capabilities."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or (AppPaths().data_dir / "network_threats.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS threat_alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_mac TEXT,
                    source_hostname TEXT,
                    source_vendor TEXT,
                    destination_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    unique_ports INTEGER DEFAULT 0,
                    target_count INTEGER DEFAULT 1,
                    time_window_seconds REAL DEFAULT 10.0,
                    evidence TEXT,
                    capture_source TEXT,
                    sample_ports TEXT
                )
                """
            )
            conn.commit()

    def save_alert(self, alert: NetworkThreatAlert) -> None:
        """Persist a single threat alert."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO threat_alerts (
                    alert_id, timestamp, severity, confidence, alert_type, pattern,
                    source_ip, source_mac, source_hostname, source_vendor,
                    destination_ip, protocol, unique_ports, target_count,
                    time_window_seconds, evidence, capture_source, sample_ports
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.timestamp.isoformat(),
                    alert.severity.value,
                    alert.confidence.value,
                    alert.alert_type,
                    alert.pattern.value,
                    alert.source_ip,
                    alert.source_mac,
                    alert.source_hostname,
                    alert.source_vendor,
                    alert.destination_ip,
                    alert.protocol.value,
                    alert.unique_ports,
                    alert.target_count,
                    alert.time_window_seconds,
                    alert.evidence,
                    alert.capture_source.value,
                    json.dumps(alert.sample_ports),
                ),
            )
            conn.commit()

    def list_alerts(self, limit: int = 50) -> list[NetworkThreatAlert]:
        """Query recent stored threat alerts."""
        alerts: list[NetworkThreatAlert] = []
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM threat_alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
            for row in cursor.fetchall():
                try:
                    ts = datetime.fromisoformat(row["timestamp"])
                except Exception:
                    ts = datetime.now(timezone.utc)

                alerts.append(
                    NetworkThreatAlert(
                        alert_id=row["alert_id"],
                        timestamp=ts,
                        severity=AlertSeverity(row["severity"]),
                        confidence=DetectionConfidence(row["confidence"]),
                        alert_type=row["alert_type"],
                        pattern=ScanPattern(row["pattern"]),
                        source_ip=row["source_ip"],
                        source_mac=row["source_mac"],
                        source_hostname=row["source_hostname"],
                        source_vendor=row["source_vendor"],
                        destination_ip=row["destination_ip"],
                        protocol=ScanProtocol(row["protocol"]),
                        unique_ports=row["unique_ports"],
                        target_count=row["target_count"],
                        time_window_seconds=row["time_window_seconds"],
                        evidence=row["evidence"] or "",
                        capture_source=CaptureSourceType(row["capture_source"]),
                        sample_ports=json.loads(row["sample_ports"] or "[]"),
                    )
                )
        return alerts

    def export_alerts(self, fmt: str = "json", limit: int = 100) -> str:
        """Export stored alerts as formatted JSON, CSV, or Text."""
        alerts = self.list_alerts(limit=limit)
        fmt_clean = fmt.lower()

        if fmt_clean == "csv":
            import io

            out = io.StringIO()
            writer = csv.writer(out)
            writer.writerow(
                [
                    "alert_id",
                    "timestamp",
                    "severity",
                    "confidence",
                    "alert_type",
                    "pattern",
                    "source_ip",
                    "source_mac",
                    "source_hostname",
                    "source_vendor",
                    "destination_ip",
                    "protocol",
                    "unique_ports",
                    "evidence",
                    "capture_source",
                ]
            )
            for a in alerts:
                writer.writerow(
                    [
                        a.alert_id,
                        a.timestamp.isoformat(),
                        a.severity.value,
                        a.confidence.value,
                        a.alert_type,
                        a.pattern.value,
                        a.source_ip,
                        a.source_mac or "",
                        a.source_hostname or "",
                        a.source_vendor or "",
                        a.destination_ip,
                        a.protocol.value,
                        a.unique_ports,
                        a.evidence,
                        a.capture_source.value,
                    ]
                )
            return out.getvalue()

        if fmt_clean == "txt":
            lines = [f"=== SSCLI NETWORK THREAT ALERTS EXPORT ({len(alerts)} records) ==="]
            for a in alerts:
                lines.append(
                    f"[{a.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {a.severity.value} | {a.alert_type} ({a.pattern.value})"
                )
                lines.append(
                    f"  Source: {a.source_ip} ({a.source_hostname or 'Unknown host'}, MAC: {a.source_mac or 'N/A'}, Vendor: {a.source_vendor or 'Unknown'})"
                )
                lines.append(
                    f"  Target: {a.destination_ip} | Protocol: {a.protocol.value} | Unique Ports: {a.unique_ports}"
                )
                lines.append(f"  Evidence: {a.evidence}\n")
            return "\n".join(lines)

        # Default JSON
        return json.dumps([a.to_dict() for a in alerts], indent=2)
