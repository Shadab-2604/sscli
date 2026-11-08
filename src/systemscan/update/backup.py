"""Pre-update application snapshot and backup retention manager."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from systemscan.logging.logger import get_logger
from systemscan.utils.paths import AppPaths

logger = get_logger("update.backup")


class UpdateBackupManager:
    """Creates isolated pre-update application backups and enforces retention limits."""

    def __init__(self, backup_dir: Path | None = None, max_backups: int = 3) -> None:
        self.backup_dir = backup_dir or (AppPaths().backup_dir / "update_backups")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.max_backups = max(1, max_backups)

    def create_backup(
        self,
        transaction_id: str,
        source_app_dir: Path,
        metadata: dict[str, Any] | None = None,
    ) -> Path:
        """Create an isolated snapshot of the installed application package before updating."""
        dest_dir = self.backup_dir / transaction_id
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)

        copied_files: list[str] = []
        if source_app_dir.exists() and source_app_dir.is_dir():
            target_pkg_dir = dest_dir / source_app_dir.name
            shutil.copytree(source_app_dir, target_pkg_dir, dirs_exist_ok=True)
            for p in target_pkg_dir.rglob("*"):
                if p.is_file():
                    copied_files.append(str(p.relative_to(dest_dir)))

        manifest = {
            "transaction_id": transaction_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_dir": str(source_app_dir),
            "files_backed_up": len(copied_files),
            "metadata": metadata or {},
        }
        manifest_path = dest_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        self.prune_old_backups()
        logger.info(f"Created pre-update backup snapshot for '{transaction_id}' at '{dest_dir}'")
        return dest_dir

    def list_backups(self) -> list[dict[str, Any]]:
        """List all available pre-update backup snapshots."""
        if not self.backup_dir.exists():
            return []

        backups: list[dict[str, Any]] = []
        for d in self.backup_dir.iterdir():
            if not d.is_dir():
                continue
            manifest_file = d / "manifest.json"
            if manifest_file.exists():
                try:
                    data = json.loads(manifest_file.read_text(encoding="utf-8"))
                    data["path"] = str(d)
                    backups.append(data)
                except Exception:
                    pass

        return sorted(backups, key=lambda x: x.get("created_at", ""), reverse=True)

    def get_latest_backup(self) -> Path | None:
        """Find the path of the most recently created backup snapshot."""
        backups = self.list_backups()
        if backups:
            return Path(backups[0]["path"])
        return None

    def prune_old_backups(self) -> int:
        """Enforce maximum backup retention by deleting oldest snapshots."""
        backups = self.list_backups()
        excess = len(backups) - self.max_backups
        pruned = 0

        if excess > 0:
            for b in backups[self.max_backups :]:
                p = Path(b["path"])
                try:
                    if p.exists() and p.is_dir():
                        shutil.rmtree(p)
                        pruned += 1
                except OSError as e:
                    logger.debug(f"Failed to prune old backup '{p}': {e}")

        return pruned
