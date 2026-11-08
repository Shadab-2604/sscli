"""Unit tests for Phase 3 filesystem engine components."""

from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest

from systemscan.filesystem.cancellation import CancellationToken
from systemscan.filesystem.discovery import FilesystemDiscovery
from systemscan.filesystem.errors import PathValidationError, ScanCancelledError
from systemscan.filesystem.exclusions import ExclusionManager
from systemscan.filesystem.metadata import MetadataCollector
from systemscan.filesystem.models import (
    ErrorCategory,
    ExclusionConfig,
    FileType,
    SymlinkPolicy,
)
from systemscan.filesystem.path_validator import PathValidator
from systemscan.filesystem.permissions import PermissionHandler
from systemscan.filesystem.statistics import ScanStatisticsCollector
from systemscan.filesystem.symlinks import SymlinkManager


def test_path_validation_valid(tmp_path: Path) -> None:
    test_file = tmp_path / "valid.txt"
    test_file.write_text("content", encoding="utf-8")

    resolved = PathValidator.validate_path(str(test_file))
    assert resolved == test_file.resolve()
    assert resolved.exists()


def test_path_validation_nonexistent(tmp_path: Path) -> None:
    nonexistent = tmp_path / "does_not_exist_abc123"
    with pytest.raises(PathValidationError):
        PathValidator.validate_path(str(nonexistent))


def test_path_validation_empty() -> None:
    with pytest.raises(PathValidationError):
        PathValidator.validate_path("   ")


def test_path_deduplication(tmp_path: Path) -> None:
    dir_a = tmp_path / "dir_a"
    dir_b = tmp_path / "dir_b"
    dir_a.mkdir()
    dir_b.mkdir()

    # Pass duplicates and distinct directories
    roots = [str(dir_a), str(dir_b), str(dir_a)]
    pruned = PathValidator.deduplicate_roots(roots)
    assert len(pruned) == 2
    assert dir_a.resolve() in pruned
    assert dir_b.resolve() in pruned


def test_path_deduplication_overlapping(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    child = parent / "child"
    grandchild = child / "grandchild"
    grandchild.mkdir(parents=True)

    other = tmp_path / "other"
    other.mkdir()

    # Pass parent, child, grandchild
    roots = [str(grandchild), str(parent), str(child), str(other)]
    pruned = PathValidator.deduplicate_roots(roots)

    # Child and grandchild should be pruned because parent subsumes them
    assert len(pruned) == 2
    assert parent.resolve() in pruned
    assert other.resolve() in pruned


def test_exclusion_exact_path(tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("secret", encoding="utf-8")

    config = ExclusionConfig(exclude_paths=[str(secret)], override_defaults=True)
    mgr = ExclusionManager(config)

    is_ex, reason = mgr.is_excluded(secret)
    assert is_ex is True
    assert "exact" in str(reason).lower()

    other = tmp_path / "other.txt"
    is_ex_other, _ = mgr.is_excluded(other)
    assert is_ex_other is False


def test_exclusion_directory_subtree(tmp_path: Path) -> None:
    sub = tmp_path / "vendor"
    nested_file = sub / "lib" / "module.py"
    nested_file.parent.mkdir(parents=True)
    nested_file.write_text("code", encoding="utf-8")

    config = ExclusionConfig(exclude_paths=[str(sub)], override_defaults=True)
    mgr = ExclusionManager(config)

    is_dir_ex, _ = mgr.is_excluded(sub, is_dir=True)
    assert is_dir_ex is True

    is_file_ex, _ = mgr.is_excluded(nested_file, is_dir=False)
    assert is_file_ex is True


def test_exclusion_extension(tmp_path: Path) -> None:
    config = ExclusionConfig(exclude_extensions=[".tmp", ".iso"], override_defaults=True)
    mgr = ExclusionManager(config)

    f1 = tmp_path / "image.iso"
    f2 = tmp_path / "archive.tar.gz"

    assert mgr.is_excluded(f1, is_dir=False)[0] is True
    assert mgr.is_excluded(f2, is_dir=False)[0] is False


def test_exclusion_glob(tmp_path: Path) -> None:
    config = ExclusionConfig(exclude_globs=["*.log", "backup_*"], override_defaults=True)
    mgr = ExclusionManager(config)

    assert mgr.is_excluded(tmp_path / "error.log")[0] is True
    assert mgr.is_excluded(tmp_path / "backup_2026.zip")[0] is True
    assert mgr.is_excluded(tmp_path / "document.pdf")[0] is False


def test_exclusion_size_limits(tmp_path: Path) -> None:
    config = ExclusionConfig(
        max_file_size_bytes=1000, min_file_size_bytes=10, override_defaults=True
    )
    mgr = ExclusionManager(config)

    p = tmp_path / "file.dat"
    # Too large
    assert mgr.is_excluded(p, is_dir=False, size_bytes=5000)[0] is True
    # Too small
    assert mgr.is_excluded(p, is_dir=False, size_bytes=5)[0] is True
    # In range
    assert mgr.is_excluded(p, is_dir=False, size_bytes=500)[0] is False


def test_exclusion_depth(tmp_path: Path) -> None:
    mgr = ExclusionManager()
    assert mgr.is_excluded(tmp_path, depth=6, max_depth=5)[0] is True
    assert mgr.is_excluded(tmp_path, depth=3, max_depth=5)[0] is False


def test_exclusion_hidden(tmp_path: Path) -> None:
    config = ExclusionConfig(exclude_hidden=True, override_defaults=True)
    mgr = ExclusionManager(config)

    assert mgr.is_excluded(tmp_path / ".git", is_hidden=True)[0] is True
    assert mgr.is_excluded(tmp_path / "src", is_hidden=False)[0] is False


def test_symlink_broken(tmp_path: Path) -> None:
    if sys.platform == "win32":
        # Windows requires SeCreateSymbolicLinkPrivilege unless Developer Mode is on
        try:
            target = tmp_path / "missing.txt"
            link = tmp_path / "link_broken.txt"
            link.symlink_to(target)
        except OSError:
            pytest.skip("Symlink creation not permitted in this Windows environment.")
    else:
        target = tmp_path / "missing.txt"
        link = tmp_path / "link_broken.txt"
        link.symlink_to(target)

    assert SymlinkManager.is_symlink(link) is True
    assert SymlinkManager.is_broken_link(link) is True


def test_symlink_policy_no_follow(tmp_path: Path) -> None:
    sym_mgr = SymlinkManager(policy=SymlinkPolicy.RECORD_NO_FOLLOW)
    can_follow, reason = sym_mgr.should_traverse(tmp_path, [tmp_path])
    assert can_follow is False
    assert "RECORD_NO_FOLLOW" in str(reason)


def test_permission_handler_classification(tmp_path: Path) -> None:
    perm_err = PermissionError("Access denied")
    rec_perm = PermissionHandler.classify_error(tmp_path, perm_err)
    assert rec_perm.category == ErrorCategory.PERMISSION_DENIED
    assert PermissionHandler.is_access_denied(perm_err) is True

    fnf_err = FileNotFoundError("No such file")
    rec_fnf = PermissionHandler.classify_error(tmp_path, fnf_err)
    assert rec_fnf.category == ErrorCategory.NOT_FOUND


def test_metadata_file_regular(tmp_path: Path) -> None:
    f = tmp_path / "sample.txt"
    f.write_text("Hello World", encoding="utf-8")

    meta = MetadataCollector.collect_file_metadata(f)
    assert meta.name == "sample.txt"
    assert meta.extension == ".txt"
    assert meta.size_bytes == 11
    assert meta.file_type == FileType.REGULAR_FILE
    assert meta.is_hidden is False
    assert meta.modified_time is not None


def test_metadata_hidden_detection(tmp_path: Path) -> None:
    hidden_unix = tmp_path / ".secret"
    hidden_unix.write_text("shh", encoding="utf-8")

    meta = MetadataCollector.collect_file_metadata(hidden_unix)
    assert meta.is_hidden is True


def test_metadata_file_types() -> None:
    assert (
        MetadataCollector.classify_file_type(stat.S_IFREG | 0o644, False) == FileType.REGULAR_FILE
    )
    assert MetadataCollector.classify_file_type(stat.S_IFDIR | 0o755, False) == FileType.DIRECTORY
    assert MetadataCollector.classify_file_type(stat.S_IFLNK | 0o777, True) == FileType.SYMLINK


def test_statistics_collector() -> None:
    collector = ScanStatisticsCollector()
    collector.start()

    collector.record_directory_discovered(is_hidden=False)
    collector.record_directory_discovered(is_hidden=True)
    collector.record_directory_scanned(depth=2)
    collector.record_file_discovered(
        size_bytes=1024, is_hidden=False, is_symlink=False, file_type=FileType.REGULAR_FILE
    )
    collector.record_file_scanned()
    collector.record_broken_link()
    collector.record_excluded()
    collector.record_permission_error()
    collector.finish()

    stats = collector.snapshot()
    assert stats.directories_discovered == 2
    assert stats.hidden_directories == 1
    assert stats.directories_scanned == 1
    assert stats.max_depth_reached == 2
    assert stats.files_discovered == 1
    assert stats.files_scanned == 1
    assert stats.total_accessible_bytes == 1024
    assert stats.broken_links == 1
    assert stats.excluded_paths == 1
    assert stats.permission_errors == 1
    assert stats.scan_duration_seconds >= 0.0


def test_cancellation_token() -> None:
    token = CancellationToken()
    assert token.is_cancelled is False

    cb_called = False

    def on_cancel():
        nonlocal cb_called
        cb_called = True

    token.register_callback(on_cancel)
    token.cancel()

    assert token.is_cancelled is True
    assert cb_called is True
    with pytest.raises(ScanCancelledError):
        token.raise_if_cancelled()


def test_discovery_all_roots() -> None:
    discovery = FilesystemDiscovery()
    roots = discovery.discover_all_roots()
    assert len(roots) > 0
    assert any(r.path for r in roots)

    accessible = discovery.discover_accessible_roots()
    assert len(accessible) > 0
    assert all(p.exists() for p in accessible)
