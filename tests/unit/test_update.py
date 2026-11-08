"""Unit tests for Application Self-Update System components."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from systemscan.update.backup import UpdateBackupManager
from systemscan.update.checker import UpdateChecker
from systemscan.update.history import UpdateHistoryManager
from systemscan.update.migrations import ConfigMigrationManager
from systemscan.update.models import (
    ReleaseChannel,
    ReleaseInfo,
    UpdateStage,
    UpdateTransaction,
)
from systemscan.update.rollback import UpdateRollbackManager
from systemscan.update.transaction import UpdateTransactionCoordinator
from systemscan.update.verifier import UpdateVerifier


def test_update_models_and_channels() -> None:
    rel = ReleaseInfo(
        version="2.0.0",
        channel=ReleaseChannel.STABLE,
        download_url="https://example.com/asset.zip",
        sha256="a" * 64,
        asset_name="systemscan-2.0.0.zip",
    )
    assert rel.version == "2.0.0"
    assert rel.channel == ReleaseChannel.STABLE

    txn = UpdateTransaction(
        source_version="1.0.0",
        target_version="2.0.0",
        channel=ReleaseChannel.STABLE,
        current_stage=UpdateStage.CHECKING,
    )
    assert txn.source_version == "1.0.0"
    assert txn.target_version == "2.0.0"
    assert txn.current_stage == UpdateStage.CHECKING
    assert txn.rolled_back is False


def test_update_checker_parse_and_plan() -> None:
    checker = UpdateChecker()

    # Raw GitHub release payload mock
    sample_release = {
        "tag_name": "v1.2.0",
        "published_at": "2026-11-01T12:00:00Z",
        "body": "Major improvements and bugfixes.",
        "prerelease": False,
        "assets": [
            {
                "name": "systemscan-1.2.0.zip",
                "browser_download_url": "https://example.com/systemscan-1.2.0.zip",
                "size": 10240,
            }
        ],
    }

    parsed = checker.parse_release_info(sample_release)
    assert parsed is not None
    assert parsed.version == "1.2.0"
    assert parsed.channel == ReleaseChannel.STABLE
    assert parsed.asset_name == "systemscan-1.2.0.zip"

    # Version comparison helper
    assert checker._parse_version("1.2.3") == (1, 2, 3)
    assert checker._parse_version("v2.0.0-beta1") == (2, 0, 0)

    # Insecure URL check
    with pytest.raises(ValueError, match="HTTPS is mandatory"):
        insecure_checker = UpdateChecker(update_source="http://insecure.site/releases")
        insecure_checker.fetch_remote_releases()


def test_update_verifier_hash_and_zip_safety(tmp_path: Path) -> None:
    verifier = UpdateVerifier()

    # 1. Test SHA-256 calculation
    test_file = tmp_path / "sample.txt"
    test_file.write_text("hello security update", encoding="utf-8")
    expected_hash = verifier.compute_sha256(test_file)

    ok, msg = verifier.verify_file_hash(test_file, expected_hash)
    assert ok is True

    bad_ok, bad_msg = verifier.verify_file_hash(test_file, "badhash" * 8)
    assert bad_ok is False
    assert "mismatch" in bad_msg.lower()

    # 2. Test safe zip archive
    safe_zip = tmp_path / "safe.zip"
    with zipfile.ZipFile(safe_zip, "w") as zf:
        zf.writestr("systemscan/test.py", "print('safe')")

    safe_ok, safe_msg = verifier.verify_archive_safety(safe_zip)
    assert safe_ok is True

    # 3. Test path traversal / zip-slip detection
    slip_zip = tmp_path / "slip.zip"
    with zipfile.ZipFile(slip_zip, "w") as zf:
        zf.writestr("../../../evil.py", "malicious_payload")

    slip_ok, slip_msg = verifier.verify_archive_safety(slip_zip)
    assert slip_ok is False
    assert "Path traversal detected" in slip_msg

    # 4. Safe extraction
    extract_dir = tmp_path / "extracted"
    ex_ok, ex_msg = verifier.extract_safe(safe_zip, extract_dir)
    assert ex_ok is True
    assert (extract_dir / "systemscan" / "test.py").exists()


def test_update_backup_and_retention(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    mgr = UpdateBackupManager(backup_dir=backup_dir, max_backups=2)

    # Mock source app dir
    app_dir = tmp_path / "app_source"
    app_dir.mkdir()
    (app_dir / "main.py").write_text("print('v1')", encoding="utf-8")

    # Create backup 1
    p1 = mgr.create_backup("txn-1", app_dir, metadata={"v": "1.0"})
    assert p1.exists()
    assert (p1 / "manifest.json").exists()

    # Create backup 2
    p2 = mgr.create_backup("txn-2", app_dir, metadata={"v": "1.1"})
    assert p2.exists()

    # Create backup 3 -> should prune oldest (txn-1) because max_backups=2
    p3 = mgr.create_backup("txn-3", app_dir, metadata={"v": "1.2"})
    assert p3.exists()

    backups = mgr.list_backups()
    assert len(backups) <= 2
    backup_ids = [b["transaction_id"] for b in backups]
    assert "txn-3" in backup_ids
    assert "txn-1" not in backup_ids


def test_update_rollback_manager(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    app_dir = tmp_path / "target_app"
    app_dir.mkdir()
    (app_dir / "code.py").write_text("original code", encoding="utf-8")

    mgr = UpdateBackupManager(backup_dir=backup_dir)
    mgr.create_backup("txn-rollback-test", app_dir)

    # Mutate app dir (simulate corrupted/failed update)
    (app_dir / "code.py").write_text("corrupted code", encoding="utf-8")
    assert (app_dir / "code.py").read_text(encoding="utf-8") == "corrupted code"

    # Execute rollback
    rb_mgr = UpdateRollbackManager(backup_manager=mgr)
    ok, msg = rb_mgr.rollback("txn-rollback-test")
    assert ok is True
    assert (app_dir / "code.py").read_text(encoding="utf-8") == "original code"


def test_config_migration_manager(tmp_path: Path) -> None:
    config_file = tmp_path / "config.json"
    backup_dir = tmp_path / "cfg_backups"

    # Pre-populate config with missing sections and older schema version
    initial_data = {
        "schema_version": 1,
        "log_level": "DEBUG",
        "preferences": {"color_enabled": True},
    }
    config_file.write_text(json.dumps(initial_data), encoding="utf-8")

    mgr = ConfigMigrationManager(config_path=config_file, backup_dir=backup_dir)

    # Dry run
    dry_ok, dry_msg, dry_changes = mgr.migrate(dry_run=True)
    assert dry_ok is True
    assert len(dry_changes) > 0

    # Live migration
    ok, msg, changes = mgr.migrate(dry_run=False)
    assert ok is True
    assert len(changes) > 0

    # Verify updated content
    updated = json.loads(config_file.read_text(encoding="utf-8"))
    assert "dependencies" in updated
    assert "update" in updated
    assert updated["log_level"] == "DEBUG"  # Preserved original user preference


def test_update_history_manager(tmp_path: Path) -> None:
    history_file = tmp_path / "update_history.json"
    mgr = UpdateHistoryManager(history_file=history_file)

    txn = UpdateTransaction(
        source_version="1.0.0",
        target_version="1.1.0",
        channel=ReleaseChannel.STABLE,
        current_stage=UpdateStage.COMPLETED,
    )
    txn.committed = True

    mgr.save_transaction(txn)
    records = mgr.list_transactions()
    assert len(records) == 1
    assert records[0].target_version == "1.1.0"
    assert records[0].committed is True


def test_update_transaction_dry_run() -> None:
    coordinator = UpdateTransactionCoordinator()

    release = ReleaseInfo(
        version="2.0.0",
        channel=ReleaseChannel.STABLE,
        download_url="https://example.com/asset.zip",
        sha256="0" * 64,
        asset_name="systemscan-2.0.0.zip",
    )

    txn = coordinator.execute_update(release=release, dry_run=True)
    assert txn.committed is True
    assert txn.current_stage == UpdateStage.COMPLETED
    assert txn.target_version == "2.0.0"
