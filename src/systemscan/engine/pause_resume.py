"""Pause, resume, and interruption controller with checkpoint verification."""

from __future__ import annotations

import threading
from pathlib import Path

from systemscan.engine.checkpoint import ScanCheckpointManager
from systemscan.engine.lifecycle import ScanLifecycleCoordinator
from systemscan.engine.models import ScanCheckpoint, ScanState
from systemscan.logging.logger import get_logger

logger = get_logger("engine.pause_resume")


class ScanPauseResumeController:
    """Coordinates graceful pause requests and checkpoint-based resumption."""

    def __init__(
        self,
        lifecycle: ScanLifecycleCoordinator,
        checkpoint_manager: ScanCheckpointManager | None = None,
    ) -> None:
        self.lifecycle = lifecycle
        self.checkpoint_manager = checkpoint_manager or ScanCheckpointManager()
        self._pause_event = threading.Event()
        self._resume_lock = threading.Lock()

    @property
    def is_pause_requested(self) -> bool:
        """Return True if an operator has requested a pause."""
        return self._pause_event.is_set()

    def request_pause(self) -> None:
        """Signal active workers to halt at the next safe processing boundary."""
        if self.lifecycle.state == ScanState.RUNNING:
            self._pause_event.set()
            self.lifecycle.transition_to(ScanState.PAUSING)
            logger.info("Pause requested. Active workers will pause at the next safe boundary.")

    def confirm_paused(self, checkpoint: ScanCheckpoint) -> None:
        """Persist checkpoint and confirm transition to PAUSED state."""
        self.checkpoint_manager.save_checkpoint(checkpoint)
        self.lifecycle.transition_to(ScanState.PAUSED)
        self._pause_event.clear()
        logger.info(f"Scan '{checkpoint.scan_id}' successfully paused and checkpoint persisted.")

    def prepare_resume(self, scan_id: str) -> ScanCheckpoint:
        """Validate environment and restore state for scan resumption."""
        with self._resume_lock:
            checkpoint = self.checkpoint_manager.load_checkpoint(scan_id)
            if not checkpoint:
                raise FileNotFoundError(f"No valid checkpoint found for scan ID '{scan_id}'.")

            # Validate target paths exist
            missing_targets: list[str] = []
            for target in checkpoint.targets:
                if not Path(target).exists():
                    missing_targets.append(target)

            if missing_targets:
                logger.warning(
                    f"Resuming scan '{scan_id}' with missing targets: {missing_targets}. "
                    "These will be recorded as errors during execution."
                )

            # Signal state transition
            if self.lifecycle.state == ScanState.PAUSED:
                self.lifecycle.transition_to(ScanState.RESUMING)

            logger.info(
                f"Prepared scan '{scan_id}' for resumption from phase '{checkpoint.current_phase}'."
            )
            return checkpoint
