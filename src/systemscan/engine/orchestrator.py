"""Central scan orchestrator coordinating scanner modules, lifecycle, and progress."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from systemscan.config.manager import ConfigManager
from systemscan.engine.checkpoint import ScanCheckpointManager
from systemscan.engine.concurrency import IntelligentConcurrencyManager
from systemscan.engine.deduplication import ScanDeduplicationManager
from systemscan.engine.eta import IntelligentETAEngine
from systemscan.engine.history import ScanHistoryManager
from systemscan.engine.incremental import IncrementalScanEngine
from systemscan.engine.lifecycle import ScanLifecycleCoordinator
from systemscan.engine.models import (
    ConcurrencyMode,
    IncrementalVerificationMode,
    ScanCheckpoint,
    ScanHistoryRecord,
    ScanProgressEvent,
    ScanState,
    ScanType,
)
from systemscan.engine.pause_resume import ScanPauseResumeController
from systemscan.engine.progress import ProgressEventDispatcher
from systemscan.engine.resource_monitor import SystemResourceMonitor
from systemscan.filesystem.cancellation import CancellationToken
from systemscan.filesystem.discovery import FilesystemDiscovery
from systemscan.filesystem.engine import FilesystemScanner
from systemscan.filesystem.models import FileMetadata, ScanConfig
from systemscan.logging.logger import get_logger

logger = get_logger("engine.orchestrator")


class CentralScanOrchestrator:
    """Coordinates multi-module security scans with adaptive concurrency, ETA, and persistence."""

    def __init__(
        self,
        config_manager: ConfigManager | None = None,
        progress_dispatcher: ProgressEventDispatcher | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> None:
        self.config_manager = config_manager or ConfigManager()
        app_cfg = self.config_manager.load_config()

        perf_cfg = getattr(app_cfg, "performance", None)
        mode_val = ConcurrencyMode.ADAPTIVE
        if perf_cfg and hasattr(perf_cfg, "mode"):
            try:
                mode_val = ConcurrencyMode(perf_cfg.mode.upper())
            except ValueError:
                mode_val = ConcurrencyMode.ADAPTIVE

        max_workers = getattr(perf_cfg, "max_workers", 4) if perf_cfg else 4
        max_cpu = getattr(perf_cfg, "max_cpu_percent", 85.0) if perf_cfg else 85.0
        max_mem = getattr(perf_cfg, "max_memory_percent", 75.0) if perf_cfg else 75.0

        self.concurrency = IntelligentConcurrencyManager(
            mode=mode_val,
            configured_max_workers=max_workers,
            max_cpu_percent=max_cpu,
            max_memory_percent=max_mem,
        )

        inc_cfg = getattr(app_cfg, "incremental", None)
        v_mode = IncrementalVerificationMode.BALANCED
        if inc_cfg and hasattr(inc_cfg, "verification_mode"):
            try:
                v_mode = IncrementalVerificationMode(inc_cfg.verification_mode.upper())
            except ValueError:
                v_mode = IncrementalVerificationMode.BALANCED

        self.incremental = IncrementalScanEngine(
            verification_mode=v_mode,
            periodic_hash_verification=getattr(inc_cfg, "periodic_hash_verification", True)
            if inc_cfg
            else True,
        )

        chk_cfg = getattr(app_cfg, "checkpoint", None)
        retention = getattr(chk_cfg, "retention_count", 10) if chk_cfg else 10
        self.checkpoints = ScanCheckpointManager(retention_count=retention)

        hist_cfg = getattr(app_cfg, "history", None)
        hist_ret = getattr(hist_cfg, "retention_days", 90) if hist_cfg else 90
        self.history = ScanHistoryManager(retention_days=hist_ret)

        self.dedup = ScanDeduplicationManager()
        self.lifecycle = ScanLifecycleCoordinator(initial_state=ScanState.QUEUED)
        self.pause_controller = ScanPauseResumeController(
            lifecycle=self.lifecycle,
            checkpoint_manager=self.checkpoints,
        )

        self.progress = progress_dispatcher or ProgressEventDispatcher()
        self.cancellation_token = cancellation_token or CancellationToken()
        self._malware_engine: Any = None

    @property
    def malware_engine(self) -> Any:
        """Lazily load MalwareDetectionEngine to avoid circular imports."""
        if self._malware_engine is None:
            try:
                from systemscan.modules.malware.engine import MalwareDetectionEngine

                self._malware_engine = MalwareDetectionEngine()
            except Exception as e:
                logger.debug(f"MalwareDetectionEngine unavailable: {e}")
                self._malware_engine = None
        return self._malware_engine

    def run_scan(
        self,
        scan_type: ScanType = ScanType.FILESYSTEM,
        targets: Sequence[str | Path] | None = None,
        all_volumes: bool = False,
        full_verification: bool = False,
        resume_scan_id: str | None = None,
        on_event: Callable[[ScanProgressEvent], None] | None = None,
    ) -> ScanHistoryRecord:
        """Execute an orchestrated security scan across specified modules and targets."""
        from systemscan.reporting.findings import FindingNormalizer
        from systemscan.reporting.models import ErrorRecord, FindingRecord

        scan_id = resume_scan_id or str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)
        modules_executed: list[str] = []
        collected_findings: list[FindingRecord] = []
        collected_errors: list[ErrorRecord] = []
        findings_count = 0
        errors_count = 0
        skipped_count = 0
        processed_count = 0
        discovered_count = 0
        bytes_processed = 0

        if on_event:
            self.progress.add_listener(on_event)

        # 1. Reset lifecycle for new scan session and Transition -> INITIALIZING
        self.lifecycle = ScanLifecycleCoordinator(initial_state=ScanState.QUEUED)
        self.pause_controller.lifecycle = self.lifecycle
        self.lifecycle.transition_to(ScanState.INITIALIZING)

        # 2. Resolve Targets & Deduplicate
        resolved_targets: list[Path] = []
        if all_volumes:
            resolved_targets = FilesystemDiscovery().discover_accessible_roots()
        elif targets:
            resolved_targets = self.dedup.normalize_and_prune_paths(targets)
        else:
            resolved_targets = [Path.cwd()]

        self.dedup.register_active_scan(scan_id, resolved_targets)
        target_str_list = [str(t) for t in resolved_targets]

        # 3. Check for Checkpoint Resumption
        checkpoint: ScanCheckpoint | None = None
        if resume_scan_id:
            checkpoint = self.pause_controller.prepare_resume(resume_scan_id)
            if checkpoint:
                processed_count = checkpoint.progress.items_processed
                bytes_processed = checkpoint.progress.bytes_processed
                errors_count = checkpoint.error_count

        eta_engine = IntelligentETAEngine()
        self.lifecycle.transition_to(ScanState.RUNNING)

        def emit_progress(phase: str, target: str = "") -> None:
            elapsed, remaining, pct = eta_engine.calculate_eta()
            snap = SystemResourceMonitor.get_snapshot()
            evt = ScanProgressEvent(
                scan_id=scan_id,
                state=self.lifecycle.state,
                current_phase=phase,
                current_target=target,
                items_discovered=discovered_count,
                items_processed=processed_count,
                items_skipped=skipped_count,
                items_failed=errors_count,
                bytes_processed=bytes_processed,
                processing_rate_items_sec=eta_engine.smoothed_items_per_sec,
                processing_rate_bytes_sec=eta_engine.smoothed_bytes_per_sec,
                elapsed_seconds=elapsed,
                estimated_remaining_seconds=remaining,
                completion_percent=pct,
                resource_usage=snap,
            )
            self.progress.dispatch(evt)

        final_status = ScanState.COMPLETED
        t0 = time.time()

        try:
            # Phase A: Discovery
            emit_progress("Target Discovery", target_str_list[0] if target_str_list else "")
            fs_scanner = FilesystemScanner()
            scan_cfg = ScanConfig(roots=[str(p) for p in resolved_targets])

            # Stream filesystem items
            stream = fs_scanner.stream_scan(
                config=scan_cfg,
                cancellation_token=self.cancellation_token,
            )

            for item in stream:
                if self.cancellation_token.is_cancelled:
                    self.lifecycle.transition_to(ScanState.CANCELLING)
                    final_status = ScanState.CANCELLED
                    break

                if self.pause_controller.is_pause_requested:
                    # Save checkpoint and pause
                    chk = ScanCheckpoint(
                        checkpoint_id=f"chk_{scan_id}_{int(time.time())}",
                        scan_id=scan_id,
                        scan_type=scan_type,
                        targets=target_str_list,
                        completed_phases=modules_executed,
                        current_phase="Filesystem Inspection",
                        progress=ScanProgressEvent(
                            scan_id=scan_id,
                            state=ScanState.PAUSED,
                            current_phase="Filesystem Inspection",
                            items_discovered=discovered_count,
                            items_processed=processed_count,
                            bytes_processed=bytes_processed,
                        ),
                        error_count=errors_count,
                    )
                    self.pause_controller.confirm_paused(chk)
                    final_status = ScanState.PAUSED
                    break

                discovered_count += 1

                if isinstance(item, FileMetadata):
                    # Incremental check
                    should_scan, cached_rec = self.incremental.should_scan_file(
                        path=item.path,
                        size_bytes=item.size_bytes,
                        modified_time=item.modified_time.timestamp() if item.modified_time else 0.0,
                        inode=item.inode,
                        force_thorough=full_verification,
                    )

                    if not should_scan:
                        skipped_count += 1
                        continue

                    # Execute active modules on file
                    processed_count += 1
                    bytes_processed += item.size_bytes
                    eta_engine.record_progress(items_delta=1, bytes_delta=item.size_bytes)

                    # Optional Malware Inspection
                    file_status = "CLEAN"
                    if scan_type in (ScanType.FULL, ScanType.MALWARE) and self.malware_engine:
                        try:
                            m_findings = self.malware_engine.analyze_file(
                                item.path, scan_id=scan_id
                            )
                            for mf in m_findings:
                                if not getattr(mf, "suppressed", False):
                                    findings_count += 1
                                    collected_findings.append(
                                        FindingNormalizer.from_malware_finding(mf)
                                    )
                                    file_status = "SUSPICIOUS"
                        except Exception as m_err:
                            logger.debug(f"Malware analysis error on {item.path}: {m_err}")

                    # Optional Storage Analysis (Flag files > 100 MB)
                    if (
                        scan_type in (ScanType.FULL, ScanType.STORAGE)
                        and item.size_bytes > 100 * 1024 * 1024
                    ):
                        storage_f = FindingNormalizer.create_custom_finding(
                            title=f"Large File Detected ({item.size_bytes // (1024 * 1024)} MB)",
                            category="STORAGE",
                            severity="INFO",
                            confidence="CONFIRMED",
                            description=f"File exceeds 100 MB storage threshold: {item.path}",
                            evidence=f"size={item.size_bytes} bytes",
                            target=item.path,
                            source_module="storage",
                        )
                        collected_findings.append(storage_f)
                        findings_count += 1

                    # Update incremental cache
                    self.incremental.record_scan_result(
                        path=item.path,
                        size_bytes=item.size_bytes,
                        modified_time=item.modified_time.timestamp() if item.modified_time else 0.0,
                        inode=item.inode,
                        status=file_status,
                    )

                emit_progress(f"{scan_type.value} Scanning", item.path)

            modules_executed.append("filesystem")
            if scan_type in (ScanType.FULL, ScanType.MALWARE):
                modules_executed.append("malware")
            if scan_type in (ScanType.FULL, ScanType.STORAGE):
                modules_executed.append("storage")

            # Phase B: Optional Network Audit if requested in Full Scan
            if (
                scan_type in (ScanType.FULL, ScanType.NETWORK)
                and not self.cancellation_token.is_cancelled
            ):
                try:
                    emit_progress("Network Security Audit")
                    from systemscan.network.findings import NetworkFindingsEvaluator

                    evaluator = NetworkFindingsEvaluator()
                    net_findings = evaluator.run_full_audit()
                    for nf in net_findings:
                        findings_count += 1
                        collected_findings.append(FindingNormalizer.from_network_finding(nf))
                    modules_executed.append("network")
                except Exception as e:
                    logger.error(f"Network audit module encountered error: {e}")
                    errors_count += 1
                    final_status = ScanState.PARTIAL

            # Phase C: Optional Device & Removable Storage Discovery
            if scan_type == ScanType.FULL and not self.cancellation_token.is_cancelled:
                try:
                    emit_progress("Device & Removable Storage Discovery")
                    from systemscan.devices.manager import DeviceManager

                    dev_mgr = DeviceManager()
                    _ = dev_mgr.discover_all()
                    modules_executed.append("devices")
                except Exception as d_err:
                    logger.debug(f"Device discovery note: {d_err}")

            # Mark discovery complete for ETA engine
            eta_engine.set_discovered_totals(
                discovered_count, bytes_processed, discovery_complete=True
            )

        except Exception as e:
            logger.error(f"Scan orchestration error: {e}")
            errors_count += 1
            final_status = ScanState.FAILED
            self.lifecycle.transition_to(ScanState.FAILED)
        finally:
            self.dedup.unregister_active_scan(scan_id)
            self.incremental.save_cache()

            if final_status == ScanState.COMPLETED and self.lifecycle.state == ScanState.RUNNING:
                self.lifecycle.transition_to(ScanState.COMPLETED)
            elif (
                final_status == ScanState.CANCELLED and self.lifecycle.state == ScanState.CANCELLING
            ):
                self.lifecycle.transition_to(ScanState.CANCELLED)

            # Record final history entry
            elapsed_total = time.time() - t0
            history_record = ScanHistoryRecord(
                scan_id=scan_id,
                scan_type=scan_type,
                targets=target_str_list,
                status=self.lifecycle.state,
                started_at=started_at,
                ended_at=datetime.now(timezone.utc),
                duration_seconds=round(elapsed_total, 2),
                items_discovered=discovered_count,
                items_processed=processed_count,
                items_skipped=skipped_count,
                items_failed=errors_count,
                bytes_processed=bytes_processed,
                findings_count=findings_count,
                modules_executed=modules_executed,
            )
            self.history.record_session(history_record)

            # Generate and persist formal ScanReport with SHA-256 checksum manifest
            try:
                from systemscan.reporting.generator import ReportGenerator
                from systemscan.reporting.storage import ReportStorageManager

                report = ReportGenerator.generate_report(
                    scan_id=scan_id,
                    scan_type=scan_type,
                    scan_status=self.lifecycle.state,
                    start_time=started_at,
                    completion_time=datetime.now(timezone.utc),
                    duration_seconds=round(elapsed_total, 2),
                    items_discovered=discovered_count,
                    items_processed=processed_count,
                    items_skipped=skipped_count,
                    bytes_processed=bytes_processed,
                    findings=collected_findings,
                    errors=collected_errors,
                )
                ReportStorageManager().save_report(report)
            except Exception as rep_err:
                logger.warning(f"Scan report persistence note for scan {scan_id}: {rep_err}")

            # Emit final progress event
            emit_progress("Scan Finished")

        return history_record
