"""Central report generator synthesizing system intelligence, scan telemetry, and findings."""

from __future__ import annotations

import platform
import socket
from datetime import datetime, timezone
from typing import Any

import psutil

from systemscan.engine.models import ScanCheckpoint, ScanHistoryRecord, ScanState, ScanType
from systemscan.reporting.models import (
    ErrorRecord,
    FindingRecord,
    ReportMetadata,
    ScanReport,
    ScanStatistics,
    SystemSummary,
)
from systemscan.reporting.summary import ExecutiveSummaryBuilder


class ReportGenerator:
    """Orchestrates data assembly across system info, scan sessions, findings, and errors."""

    @staticmethod
    def collect_system_summary() -> SystemSummary:
        """Capture active host platform and hardware characteristics."""
        hostname = socket.gethostname() or "unknown"
        os_name = platform.system() or "unknown"
        os_ver = platform.release() or "unknown"
        kernel = platform.version() or "unknown"
        arch = platform.machine() or "unknown"
        cpu_model = platform.processor() or "unknown"

        phys_cores = psutil.cpu_count(logical=False)
        log_cores = psutil.cpu_count(logical=True)

        ram_mb: float | None = None
        try:
            ram_mb = round(psutil.virtual_memory().total / (1024 * 1024), 1)
        except Exception:
            pass

        return SystemSummary(
            hostname=hostname,
            os_name=os_name,
            os_version=os_ver,
            kernel=kernel,
            architecture=arch,
            cpu_model=cpu_model,
            cpu_physical_cores=phys_cores,
            cpu_logical_cores=log_cores,
            ram_total_mb=ram_mb,
        )

    @classmethod
    def generate_report(
        cls,
        scan_id: str,
        scan_type: ScanType,
        scan_status: ScanState,
        start_time: datetime,
        completion_time: datetime,
        duration_seconds: float,
        items_discovered: int = 0,
        items_processed: int = 0,
        items_skipped: int = 0,
        bytes_processed: int = 0,
        directories_inspected: int = 0,
        findings: list[FindingRecord] | None = None,
        errors: list[ErrorRecord] | None = None,
        modules_data: dict[str, Any] | None = None,
        system_summary: SystemSummary | None = None,
    ) -> ScanReport:
        """Construct a standardized ScanReport from direct execution metrics."""
        findings_list = findings or []
        errors_list = errors or []
        mod_data = modules_data or {}
        sys_info = system_summary or cls.collect_system_summary()

        # Compute throughput
        items_rate = round(items_processed / duration_seconds, 2) if duration_seconds > 0 else 0.0
        mb_rate = (
            round((bytes_processed / (1024 * 1024)) / duration_seconds, 2)
            if duration_seconds > 0
            else 0.0
        )

        stats = ScanStatistics(
            duration_seconds=duration_seconds,
            items_discovered=items_discovered,
            items_processed=items_processed,
            items_skipped=items_skipped,
            bytes_processed=bytes_processed,
            directories_inspected=directories_inspected,
            errors_count=len(errors_list),
            findings_count=len(findings_list),
            average_throughput_items_sec=items_rate,
            average_throughput_mb_sec=mb_rate,
        )

        exec_summary = ExecutiveSummaryBuilder.build_summary(
            scan_id=scan_id,
            scan_type=scan_type,
            scan_status=scan_status,
            system_identifier=sys_info.hostname,
            os_description=f"{sys_info.os_name} {sys_info.os_version} ({sys_info.architecture})",
            start_time=start_time,
            completion_time=completion_time,
            duration_seconds=duration_seconds,
            items_analyzed=items_processed,
            data_processed_bytes=bytes_processed,
            items_skipped=items_skipped,
            errors_count=len(errors_list),
            findings=findings_list,
            items_discovered=items_discovered,
        )

        metadata = ReportMetadata(
            scan_id=scan_id,
            scan_type=scan_type,
            scan_status=scan_status,
        )

        return ScanReport(
            metadata=metadata,
            system_info=sys_info,
            statistics=stats,
            executive_summary=exec_summary,
            findings=findings_list,
            errors=errors_list,
            modules_data=mod_data,
        )

    @classmethod
    def from_history_record(
        cls,
        record: ScanHistoryRecord,
        findings: list[FindingRecord] | None = None,
        errors: list[ErrorRecord] | None = None,
        modules_data: dict[str, Any] | None = None,
        system_summary: SystemSummary | None = None,
    ) -> ScanReport:
        """Create a report from a persisted ScanHistoryRecord."""
        completed_at = (
            record.ended_at or getattr(record, "completed_at", None) or datetime.now(timezone.utc)
        )
        return cls.generate_report(
            scan_id=record.scan_id,
            scan_type=record.scan_type,
            scan_status=record.status,
            start_time=record.started_at,
            completion_time=completed_at,
            duration_seconds=record.duration_seconds,
            items_discovered=record.items_discovered,
            items_processed=record.items_processed,
            items_skipped=record.items_skipped,
            bytes_processed=record.bytes_processed,
            findings=findings,
            errors=errors,
            modules_data=modules_data,
            system_summary=system_summary,
        )

    @classmethod
    def from_checkpoint(
        cls,
        checkpoint: ScanCheckpoint,
        findings: list[FindingRecord] | None = None,
        errors: list[ErrorRecord] | None = None,
    ) -> ScanReport:
        """Create a partial progress report from an active or paused ScanCheckpoint."""
        now = datetime.now(timezone.utc)
        prog = checkpoint.progress
        return cls.generate_report(
            scan_id=checkpoint.scan_id,
            scan_type=checkpoint.scan_type,
            scan_status=prog.state,
            start_time=checkpoint.created_at,
            completion_time=now,
            duration_seconds=prog.elapsed_seconds,
            items_discovered=prog.items_discovered or prog.items_processed,
            items_processed=prog.items_processed,
            items_skipped=prog.items_skipped,
            bytes_processed=prog.bytes_processed,
            findings=findings,
            errors=errors,
            modules_data={"current_phase": checkpoint.current_phase, "targets": checkpoint.targets},
        )
