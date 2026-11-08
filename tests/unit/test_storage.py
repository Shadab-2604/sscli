"""Unit tests for Phase 6: Disk Usage, Large Files, Duplicates, Age, and Cleanup Safety."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from systemscan.filesystem.models import FileMetadata
from systemscan.modules.storage.age_analyzer import AgeAnalyzer
from systemscan.modules.storage.cleanup.executor import SafeCleanupExecutor
from systemscan.modules.storage.cleanup.planner import CleanupPlanner
from systemscan.modules.storage.cleanup.safety import CleanupSafetyValidator
from systemscan.modules.storage.directory_analyzer import DirectoryAnalyzer
from systemscan.modules.storage.disk_usage import DiskUsageAnalyzer
from systemscan.modules.storage.duplicate_detector import DuplicateDetector
from systemscan.modules.storage.extension_analyzer import ExtensionAnalyzer
from systemscan.modules.storage.hidden_storage import HiddenStorageAnalyzer
from systemscan.modules.storage.large_files import LargeFileAnalyzer
from systemscan.modules.storage.models import (
    CleanupSafetyCategory,
    format_bytes,
)


def test_format_bytes() -> None:
    assert format_bytes(0) == "0 B"
    assert format_bytes(1024) == "1.0 KB"
    assert format_bytes(1024 * 1024 * 5) == "5.0 MB"
    assert format_bytes(1024 * 1024 * 1024 * 2) == "2.0 GB"


def test_disk_usage_analyzer() -> None:
    volumes = DiskUsageAnalyzer.analyze_volumes()
    assert len(volumes) >= 1
    root_vol = volumes[0]
    assert root_vol.total_bytes > 0
    assert root_vol.free_bytes >= 0
    assert 0.0 <= root_vol.usage_percent <= 100.0


def test_large_file_analyzer(tmp_path: Path) -> None:
    analyzer = LargeFileAnalyzer(min_size_bytes=1000)

    f1 = FileMetadata(
        path=str(tmp_path / "big.bin"),
        name="big.bin",
        size_bytes=5000,
        modified_time=datetime.now(timezone.utc),
        is_hidden=False,
    )
    f2 = FileMetadata(
        path=str(tmp_path / "small.txt"),
        name="small.txt",
        size_bytes=200,
        modified_time=datetime.now(timezone.utc),
        is_hidden=False,
    )

    analyzer.inspect_file(f1)
    analyzer.inspect_file(f2)

    top = analyzer.get_top_large_files()
    assert len(top) == 1
    assert top[0].name == "big.bin"
    assert top[0].size_bytes == 5000


def test_directory_analyzer(tmp_path: Path) -> None:
    analyzer = DirectoryAnalyzer()

    f1 = FileMetadata(
        path=str(tmp_path / "sub1" / "file1.txt"),
        name="file1.txt",
        size_bytes=1000,
        modified_time=datetime.now(timezone.utc),
    )
    f2 = FileMetadata(
        path=str(tmp_path / "sub1" / "file2.txt"),
        name="file2.txt",
        size_bytes=2000,
        modified_time=datetime.now(timezone.utc),
    )

    analyzer.inspect_file(f1)
    analyzer.inspect_file(f2)

    top_dirs = analyzer.get_top_directories()
    assert len(top_dirs) >= 1
    assert any(d.size_bytes == 3000 for d in top_dirs)


def test_duplicate_detector(tmp_path: Path) -> None:
    # Create 3 files: 2 identical content, 1 different
    f1 = tmp_path / "file1.dat"
    f2 = tmp_path / "file2_dup.dat"
    f3 = tmp_path / "file3_diff.dat"

    content_dup = b"EXACT_IDENTICAL_CONTENT_BYTES_12345" * 100
    content_diff = b"DIFFERENT_CONTENT_BYTES_99999999999" * 100

    f1.write_bytes(content_dup)
    f2.write_bytes(content_dup)
    f3.write_bytes(content_diff)

    detector = DuplicateDetector(min_size_bytes=10)

    for p in (f1, f2, f3):
        meta = FileMetadata(
            path=str(p),
            name=p.name,
            size_bytes=len(p.read_bytes()),
            modified_time=datetime.now(timezone.utc),
        )
        detector.inspect_file(meta)

    groups = detector.find_duplicates()
    assert len(groups) == 1
    assert groups[0].copy_count == 2
    assert str(f1) in groups[0].paths
    assert str(f2) in groups[0].paths
    assert groups[0].reclaimable_bytes == len(content_dup)


def test_extension_analyzer(tmp_path: Path) -> None:
    analyzer = ExtensionAnalyzer()

    f1 = FileMetadata(
        path=str(tmp_path / "doc.pdf"),
        name="doc.pdf",
        size_bytes=1000,
        modified_time=datetime.now(timezone.utc),
    )
    f2 = FileMetadata(
        path=str(tmp_path / "doc2.pdf"),
        name="doc2.pdf",
        size_bytes=3000,
        modified_time=datetime.now(timezone.utc),
    )
    f3 = FileMetadata(
        path=str(tmp_path / "notes.txt"),
        name="notes.txt",
        size_bytes=1000,
        modified_time=datetime.now(timezone.utc),
    )

    analyzer.inspect_file(f1)
    analyzer.inspect_file(f2)
    analyzer.inspect_file(f3)

    summary = analyzer.get_extension_summary()
    assert len(summary) == 2
    assert summary[0].extension == ".pdf"
    assert summary[0].total_bytes == 4000
    assert summary[0].percentage_of_total == 80.0


def test_age_analyzer(tmp_path: Path) -> None:
    now = datetime(2026, 11, 8, tzinfo=timezone.utc)
    analyzer = AgeAnalyzer(now=now)

    f_old = FileMetadata(
        path=str(tmp_path / "old.log"),
        name="old.log",
        size_bytes=1000,
        modified_time=now - timedelta(days=200),
    )
    f_new = FileMetadata(
        path=str(tmp_path / "new.log"),
        name="new.log",
        size_bytes=500,
        modified_time=now - timedelta(days=5),
    )

    analyzer.inspect_file(f_old)
    analyzer.inspect_file(f_new)

    brackets = analyzer.get_brackets_summary()
    assert brackets["180+ days"]["count"] == 1
    assert brackets["180+ days"]["total_bytes"] == 1000


def test_hidden_storage_analyzer(tmp_path: Path) -> None:
    analyzer = HiddenStorageAnalyzer()

    f_hidden = FileMetadata(
        path=str(tmp_path / ".hidden_file"),
        name=".hidden_file",
        size_bytes=2500,
        modified_time=datetime.now(timezone.utc),
        is_hidden=True,
    )
    f_normal = FileMetadata(
        path=str(tmp_path / "normal_file"),
        name="normal_file",
        size_bytes=1000,
        modified_time=datetime.now(timezone.utc),
        is_hidden=False,
    )

    analyzer.inspect_file(f_hidden)
    analyzer.inspect_file(f_normal)

    assert analyzer.total_hidden_files == 1
    assert analyzer.total_hidden_bytes == 2500


def test_cleanup_safety_rules(tmp_path: Path) -> None:
    # 1. User document format must be protected
    doc = tmp_path / "financial.xlsx"
    doc.write_bytes(b"DATA")
    safety, reason = CleanupSafetyValidator.evaluate_safety(doc)
    assert safety == CleanupSafetyCategory.PROTECTED
    assert "protected" in reason.lower()

    # 2. Disposable temp file
    temp_file = tmp_path / "scratch.tmp"
    temp_file.write_bytes(b"TEMP")
    safety_tmp, _ = CleanupSafetyValidator.evaluate_safety(temp_file)
    assert safety_tmp == CleanupSafetyCategory.SAFE_CANDIDATE


def test_cleanup_planner_and_executor(tmp_path: Path) -> None:
    target_dir = tmp_path / "clean_zone"
    target_dir.mkdir()

    # Create safe disposable files
    t1 = target_dir / "cache1.tmp"
    t1.write_bytes(b"A" * 100)
    t2 = target_dir / "app.log"
    t2.write_bytes(b"B" * 200)

    # Create protected file in same directory
    p1 = target_dir / "important_backup.sql"
    p1.write_bytes(b"C" * 300)

    # 1. Preview
    preview = CleanupPlanner.generate_preview(
        target_paths=[target_dir], include_browser_cache=False
    )
    assert preview.total_files == 3
    assert preview.total_reclaimable_bytes == 300
    assert preview.protected_count >= 1

    # 2. Dry run
    executor = SafeCleanupExecutor()
    dry_audit = executor.execute_cleanup(preview, dry_run=True)
    assert dry_audit.status == "DRY_RUN"
    assert dry_audit.deleted_files_count == 2
    assert t1.exists()  # Not deleted in dry run

    # 3. Real authorized execution
    audit = executor.execute_cleanup(preview, authorized=True, dry_run=False)
    assert audit.status == "COMPLETED"
    assert audit.deleted_files_count == 2
    assert audit.actual_reclaimed_bytes == 300
    assert not t1.exists()
    assert not t2.exists()
    assert p1.exists()  # Protected file remains 100% intact
