"""Filesystem traversal engine throughput and memory benchmark script."""

from __future__ import annotations

import os
import shutil
import tempfile
import time
import tracemalloc
from pathlib import Path

from systemscan.filesystem.engine import FilesystemScanner
from systemscan.filesystem.models import ScanConfig
from systemscan.utils.formatting import format_bytes


def generate_benchmark_tree(root: Path, total_files: int = 5000, files_per_dir: int = 100) -> int:
    """Generate a synthetic directory hierarchy for traversal performance benchmarking."""
    num_dirs = max(1, total_files // files_per_dir)
    created = 0

    print(f"Generating synthetic benchmark tree with {total_files} files across {num_dirs} directories...")
    for d_idx in range(num_dirs):
        dir_path = root / f"bench_dir_{d_idx:04d}"
        dir_path.mkdir(parents=True, exist_ok=True)
        for f_idx in range(files_per_dir):
            file_path = dir_path / f"file_{f_idx:04d}.dat"
            # Small binary content
            file_path.write_bytes(b"A" * 64)
            created += 1

    return created


def run_benchmark(target_files: int = 5000) -> None:
    """Execute traversal benchmark measuring files/second throughput and peak RAM consumption."""
    bench_dir = Path(tempfile.mkdtemp(prefix="systemscan_bench_"))
    try:
        total_created = generate_benchmark_tree(bench_dir, total_files=target_files)

        scanner = FilesystemScanner()
        cfg = ScanConfig(roots=[str(bench_dir)])

        # Measure memory and wall-clock execution time
        tracemalloc.start()
        start_wall = time.perf_counter()

        summary = scanner.scan_paths([bench_dir], config=cfg)

        end_wall = time.perf_counter()
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        duration = max(0.0001, end_wall - start_wall)
        throughput = summary.statistics.files_scanned / duration

        print("\n" + "=" * 65)
        print("          FILESYSTEM ENGINE PERFORMANCE BENCHMARK")
        print("=" * 65)
        print(f"Total Files Scanned      : {summary.statistics.files_scanned:,}")
        print(f"Total Directories Scanned: {summary.statistics.directories_scanned:,}")
        print(f"Total Volume Size        : {summary.statistics.total_size_formatted}")
        print(f"Elapsed Time             : {duration:.4f} seconds")
        print(f"Traversal Throughput     : {throughput:,.1f} files/sec")
        print(f"Peak Traced RAM Delta    : {format_bytes(peak_mem)}")
        print(f"Terminal Status          : {summary.status.value.upper()}")
        print("=" * 65 + "\n")

    finally:
        shutil.rmtree(bench_dir, ignore_errors=True)


if __name__ == "__main__":
    run_benchmark(5000)

