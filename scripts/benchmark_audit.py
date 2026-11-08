"""Performance and resource benchmark audit suite for Phase 11.

Executes controlled, reproducible micro-benchmarks measuring:
1. Filesystem Traversal Throughput (items/sec)
2. Streaming SHA-256 Hashing Throughput (MB/sec)
3. Checkpoint Serialization / Deserialization Latency (ms)
4. Multi-Format Report Export Latency (JSON, CSV, TXT)
5. Peak Memory Allocation Delta (MB)
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

from systemscan.engine.checkpoint import ScanCheckpointManager
from systemscan.engine.models import ScanState, ScanType
from systemscan.filesystem.models import ScanConfig
from systemscan.filesystem.traversal import FilesystemTraversalEngine
from systemscan.modules.malware.hash_analyzer import HashAnalyzer
from systemscan.reporting.exporter import ReportExporter
from systemscan.reporting.models import (
    ConfidenceSummary,
    ExecutiveSummary,
    FindingConfidence,
    FindingRecord,
    FindingSeverity,
    OverallScanResult,
    ReportFormat,
    ReportMetadata,
    ScanReport,
    ScanStatistics,
    SeveritySummary,
    SystemSummary,
)
from systemscan.reporting.storage import ReportStorageManager


def benchmark_all() -> dict[str, float | str | int]:
    results: dict[str, float | str | int] = {}
    proc = psutil.Process(os.getpid())
    mem_initial_mb = proc.memory_info().rss / (1024 * 1024)

    # 1. Hashing Throughput Benchmark
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        chunk = b"A" * (1024 * 1024)  # 1 MB
        for _ in range(25):  # 25 MB file
            tf.write(chunk)
        temp_path = Path(tf.name)

    try:
        hasher = HashAnalyzer()
        t0 = time.perf_counter()
        _ = hasher.calculate_hash(temp_path)
        t_hash = time.perf_counter() - t0
        mb_per_sec = 25.0 / t_hash
        results["hashing_throughput_mb_s"] = round(mb_per_sec, 2)
        results["hashing_duration_25mb_s"] = round(t_hash, 4)
    finally:
        temp_path.unlink(missing_ok=True)

    # 2. Filesystem Traversal Benchmark
    with tempfile.TemporaryDirectory() as td:
        root_dir = Path(td)
        # Create 500 synthetic files across nested subdirectories
        for i in range(10):
            sub = root_dir / f"folder_{i}"
            sub.mkdir()
            for j in range(50):
                (sub / f"item_{j}.dat").write_bytes(b"payload")

        traversal_engine = FilesystemTraversalEngine(ScanConfig(roots=[str(root_dir)]))
        t0 = time.perf_counter()
        count = 0
        for _ in traversal_engine.traverse():
            count += 1
        t_traverse = time.perf_counter() - t0
        items_per_sec = count / max(t_traverse, 0.0001)
        results["traversal_items_count"] = count
        results["traversal_duration_s"] = round(t_traverse, 4)
        results["traversal_throughput_items_s"] = round(items_per_sec, 1)

    # 3. Checkpoint Serialization / Deserialization
    with tempfile.TemporaryDirectory() as td:
        ckpt_dir = Path(td)
        mgr = ScanCheckpointManager(checkpoint_dir=ckpt_dir)
        session_id = "bench-session-01"
        from systemscan.engine.models import ScanCheckpoint, ScanProgressEvent

        ckpt = ScanCheckpoint(
            scan_id=session_id,
            scan_type=ScanType.FULL,
            current_phase="DISCOVERY",
            progress=ScanProgressEvent(
                scan_id=session_id, state=ScanState.RUNNING, current_phase="DISCOVERY"
            ),
        )
        t0 = time.perf_counter()
        mgr.save_checkpoint(ckpt)
        t_save_ckpt = (time.perf_counter() - t0) * 1000  # ms
        results["checkpoint_save_ms"] = round(t_save_ckpt, 3)

        t0 = time.perf_counter()
        loaded = mgr.load_checkpoint(session_id)
        t_load_ckpt = (time.perf_counter() - t0) * 1000  # ms
        results["checkpoint_load_ms"] = round(t_load_ckpt, 3)
        assert loaded is not None

    # 4. Multi-Format Report Generation Latency
    with tempfile.TemporaryDirectory() as td:
        rep_dir = Path(td)
        storage = ReportStorageManager(storage_dir=rep_dir)
        exporter = ReportExporter(storage_manager=storage)

        now = datetime.now()
        report = ScanReport(
            metadata=ReportMetadata(
                report_id="bench-rep-01",
                scan_id="bench-session-01",
                scan_type=ScanType.FULL,
                scan_status=ScanState.COMPLETED,
            ),
            system_info=SystemSummary(
                hostname="bench-host",
                os_family="Windows",
                os_name="Windows 11",
                os_version="11",
                cpu_model="Bench CPU",
                total_ram_bytes=16000000000,
            ),
            statistics=ScanStatistics(
                scan_type=ScanType.FULL,
                duration_seconds=15.0,
                items_discovered=5000,
                items_processed=5000,
                bytes_processed=104857600,
            ),
            executive_summary=ExecutiveSummary(
                scan_id="bench-session-01",
                scan_type=ScanType.FULL,
                scan_status=ScanState.COMPLETED,
                system_identifier="bench-host",
                os_description="Windows 11",
                start_time=now,
                completion_time=now,
                duration_seconds=15.0,
                items_analyzed=5000,
                data_processed_bytes=104857600,
                items_skipped=0,
                errors_count=0,
                severity_summary=SeveritySummary(info=250, total=250),
                confidence_summary=ConfidenceSummary(high=250),
                overall_result=OverallScanResult.NO_HIGH_PRIORITY_FINDINGS,
            ),
            findings=[
                FindingRecord(
                    finding_id=f"f-{i}",
                    title="Large File Finding",
                    category="storage",
                    severity=FindingSeverity.INFO,
                    confidence=FindingConfidence.HIGH,
                    description="File exceeding size threshold",
                    evidence="Size: 100MB",
                    source_module="storage",
                    target=f"/path/to/file_{i}.dat",
                )
                for i in range(250)
            ],
        )

        t0 = time.perf_counter()
        exporter.export(report, fmt=ReportFormat.JSON, overwrite=True)
        results["report_export_json_ms"] = round((time.perf_counter() - t0) * 1000, 2)

        t0 = time.perf_counter()
        exporter.export(report, fmt=ReportFormat.CSV, overwrite=True)
        results["report_export_csv_ms"] = round((time.perf_counter() - t0) * 1000, 2)

        t0 = time.perf_counter()
        exporter.export(report, fmt=ReportFormat.TXT, overwrite=True)
        results["report_export_txt_ms"] = round((time.perf_counter() - t0) * 1000, 2)

    # 5. Memory Allocation Delta
    mem_final_mb = proc.memory_info().rss / (1024 * 1024)
    results["memory_initial_mb"] = round(mem_initial_mb, 2)
    results["memory_final_mb"] = round(mem_final_mb, 2)
    results["memory_delta_mb"] = round(mem_final_mb - mem_initial_mb, 2)

    return results


if __name__ == "__main__":
    data = benchmark_all()
    print(json.dumps(data, indent=2))
