"""Persistent scan checkpoint manager with atomic serialization and integrity validation."""

from __future__ import annotations

import json
from pathlib import Path

from systemscan.engine.models import ScanCheckpoint
from systemscan.logging.logger import get_logger
from systemscan.utils.paths import AppPaths

logger = get_logger("engine.checkpoint")


class ScanCheckpointManager:
    """Manages persistent scan snapshots, validation, and retention."""

    def __init__(self, checkpoint_dir: Path | None = None, retention_count: int = 10) -> None:
        self.checkpoint_dir = checkpoint_dir or (AppPaths().data_dir / "checkpoints")
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.retention_count = max(1, retention_count)

    def _get_path(self, scan_id: str) -> Path:
        safe_id = "".join(c for c in scan_id if c.isalnum() or c in ("-", "_"))
        return self.checkpoint_dir / f"{safe_id}.json"

    def save_checkpoint(self, checkpoint: ScanCheckpoint) -> Path:
        """Atomically persist a validated checkpoint to disk."""
        target_path = self._get_path(checkpoint.scan_id)
        tmp_path = target_path.with_suffix(".tmp")

        try:
            payload = checkpoint.model_dump_json(indent=2)
            tmp_path.write_text(payload, encoding="utf-8")
            tmp_path.replace(target_path)
            logger.debug(f"Saved checkpoint for scan '{checkpoint.scan_id}' to {target_path}")
        except Exception as e:
            logger.error(f"Failed to persist checkpoint for scan '{checkpoint.scan_id}': {e}")
            if tmp_path.exists():
                tmp_path.unlink()
            raise

        self._prune_retention()
        return target_path

    def load_checkpoint(self, scan_id: str) -> ScanCheckpoint | None:
        """Load and validate a checkpoint file, handling corruption safely."""
        path = self._get_path(scan_id)
        if not path.exists():
            return None

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            checkpoint = ScanCheckpoint.model_validate(data)

            # Re-validate target paths
            for target in checkpoint.targets:
                target_p = Path(target)
                if not target_p.exists():
                    logger.warning(
                        f"Target path '{target}' referenced in checkpoint no longer exists."
                    )

            return checkpoint
        except Exception as e:
            logger.error(f"Checkpoint file '{path}' is corrupt or incompatible: {e}")
            # Safely isolate corrupt checkpoint
            corrupt_path = path.with_suffix(".corrupt")
            try:
                path.rename(corrupt_path)
            except OSError:
                pass
            return None

    def list_checkpoints(self) -> list[str]:
        """Return scan IDs of all available valid checkpoints."""
        if not self.checkpoint_dir.exists():
            return []
        return [p.stem for p in self.checkpoint_dir.glob("*.json")]

    def delete_checkpoint(self, scan_id: str) -> bool:
        """Remove a checkpoint file once a scan completes or is cancelled."""
        path = self._get_path(scan_id)
        if path.exists():
            try:
                path.unlink()
                return True
            except OSError as e:
                logger.debug(f"Failed to delete checkpoint '{scan_id}': {e}")
        return False

    def _prune_retention(self) -> None:
        """Enforce maximum retention limit by removing oldest checkpoints."""
        try:
            files = sorted(self.checkpoint_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
            excess = len(files) - self.retention_count
            if excess > 0:
                for old_file in files[:excess]:
                    try:
                        old_file.unlink()
                    except OSError:
                        pass
        except Exception as e:
            logger.debug(f"Error during checkpoint retention pruning: {e}")
