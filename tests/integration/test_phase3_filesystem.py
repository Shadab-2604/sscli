"""Integration tests for Phase 3 filesystem engine and CLI scan commands."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from systemscan.cli import app
from systemscan.filesystem.cancellation import CancellationToken
from systemscan.filesystem.engine import FilesystemScanner
from systemscan.filesystem.models import ExclusionConfig, FileMetadata, ScanConfig, ScanStatus

runner = CliRunner()


def create_synthetic_tree(base: Path) -> dict[str, int]:
    """Populate a synthetic directory hierarchy with various entry types."""
    # 1. Regular files
    (base / "file1.txt").write_text("Hello", encoding="utf-8")
    (base / "file2.log").write_text("Log entry", encoding="utf-8")
    (base / "data.csv").write_text("a,b,c", encoding="utf-8")

    # 2. Hidden files & directories
    hidden_dir = base / ".hidden_folder"
    hidden_dir.mkdir()
    (hidden_dir / "secret.key").write_text("secret_key", encoding="utf-8")
    (base / ".dotfile").write_text("hidden", encoding="utf-8")

    # 3. Unicode and spaced names
    spaced_dir = base / "Spaced Folder"
    spaced_dir.mkdir()
    (spaced_dir / "Unicode 日本語.txt").write_text("Japanese content", encoding="utf-8")

    # 4. Subdirectories
    sub1 = base / "level1"
    sub1.mkdir()
    (sub1 / "nested.dat").write_bytes(b"\x00\x01\x02\x03")

    return {
        "files": 7,
        "dirs": 3,
    }


def test_traversal_small_tree(tmp_path: Path) -> None:
    expected = create_synthetic_tree(tmp_path)
    scanner = FilesystemScanner()
    cfg = ScanConfig(roots=[str(tmp_path)], include_hidden=True)

    items = list(scanner.stream_scan(cfg))
    files = [i for i in items if isinstance(i, FileMetadata)]

    # Discovered files should match
    assert len(files) == expected["files"]
    names = {f.name for f in files}
    assert "file1.txt" in names
    assert ".dotfile" in names
    assert "Unicode 日本語.txt" in names
    assert "secret.key" in names


def test_traversal_deep_tree(tmp_path: Path) -> None:
    curr = tmp_path
    for i in range(15):
        curr = curr / f"depth_{i}"
        curr.mkdir()
        (curr / f"file_{i}.txt").write_text(f"Depth {i}", encoding="utf-8")

    scanner = FilesystemScanner()
    summary = scanner.scan_paths([tmp_path])

    assert summary.status == ScanStatus.COMPLETED
    assert summary.statistics.directories_scanned >= 15
    assert summary.statistics.files_scanned >= 15
    assert summary.statistics.max_depth_reached >= 15


def test_traversal_with_exclusions(tmp_path: Path) -> None:
    create_synthetic_tree(tmp_path)
    scanner = FilesystemScanner()

    # Exclude .log files and Spaced Folder
    excl = ExclusionConfig(
        exclude_extensions=[".log"],
        exclude_globs=["*Spaced*"],
        override_defaults=True,
    )
    cfg = ScanConfig(roots=[str(tmp_path)], exclusions=excl)

    summary = scanner.scan_paths([tmp_path], config=cfg)
    assert summary.status == ScanStatus.COMPLETED
    assert summary.statistics.excluded_paths >= 2


def test_traversal_max_depth(tmp_path: Path) -> None:
    level0 = tmp_path
    level1 = level0 / "level1"
    level2 = level1 / "level2"
    level2.mkdir(parents=True)

    (level0 / "l0.txt").write_text("0")
    (level1 / "l1.txt").write_text("1")
    (level2 / "l2.txt").write_text("2")

    scanner = FilesystemScanner()
    cfg = ScanConfig(roots=[str(tmp_path)], max_depth=1)
    summary = scanner.scan_paths([tmp_path], config=cfg)

    # Level 2 file should not have been scanned because max_depth=1
    assert summary.statistics.max_depth_reached <= 1
    assert summary.statistics.files_scanned == 2


def test_traversal_single_file_root(tmp_path: Path) -> None:
    f = tmp_path / "single.txt"
    f.write_text("Standalone file", encoding="utf-8")

    scanner = FilesystemScanner()
    summary = scanner.scan_paths([f])

    assert summary.status == ScanStatus.COMPLETED
    assert summary.statistics.files_scanned == 1
    assert summary.statistics.directories_scanned == 0


def test_traversal_cancellation(tmp_path: Path) -> None:
    # Create several files
    for i in range(20):
        (tmp_path / f"file_{i}.txt").write_text(f"Content {i}")

    scanner = FilesystemScanner()
    token = CancellationToken()

    def cancel_after_two(item):
        if isinstance(item, FileMetadata) and item.name == "file_2.txt":
            token.cancel()

    summary = scanner.scan_paths([tmp_path], on_item=cancel_after_two, cancellation_token=token)
    assert summary.status == ScanStatus.CANCELLED
    assert summary.statistics.files_scanned > 0


def test_cli_scan_custom_path_text(tmp_path: Path) -> None:
    create_synthetic_tree(tmp_path)
    res = runner.invoke(app, ["scan", "--path", str(tmp_path)])
    assert res.exit_code == 0
    assert "FILESYSTEM SCAN SUMMARY" in res.output
    assert "Status" in res.output
    assert "COMPLETED" in res.output


def test_cli_scan_custom_path_json(tmp_path: Path) -> None:
    create_synthetic_tree(tmp_path)
    res = runner.invoke(app, ["scan", "--path", str(tmp_path), "--format", "json"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert "scan_id" in data
    assert data["status"] == "completed"
    assert "statistics" in data
    assert data["statistics"]["files_scanned"] == 7
    assert data["statistics"]["directories_scanned"] >= 3


def test_cli_scan_max_depth_json(tmp_path: Path) -> None:
    create_synthetic_tree(tmp_path)
    res = runner.invoke(
        app,
        ["scan", "--path", str(tmp_path), "--max-depth", "1", "--format", "json"],
    )
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert data["statistics"]["max_depth_reached"] <= 1


def test_cli_scan_exclude_options(tmp_path: Path) -> None:
    create_synthetic_tree(tmp_path)
    res = runner.invoke(
        app,
        [
            "scan",
            "--path",
            str(tmp_path),
            "--exclude-ext",
            ".log",
            "--exclude",
            "*Spaced*",
            "--format",
            "json",
        ],
    )
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert data["statistics"]["excluded_paths"] >= 2
