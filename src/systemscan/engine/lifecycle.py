"""Scan lifecycle state machine and transition validation."""

from __future__ import annotations

import threading
from collections.abc import Callable

from systemscan.engine.models import ScanState
from systemscan.logging.logger import get_logger

logger = get_logger("engine.lifecycle")

# Permitted state transition map
ALLOWED_TRANSITIONS: dict[ScanState, set[ScanState]] = {
    ScanState.QUEUED: {ScanState.INITIALIZING, ScanState.CANCELLING, ScanState.CANCELLED},
    ScanState.INITIALIZING: {
        ScanState.RUNNING,
        ScanState.CANCELLING,
        ScanState.CANCELLED,
        ScanState.FAILED,
    },
    ScanState.RUNNING: {
        ScanState.PAUSING,
        ScanState.CANCELLING,
        ScanState.COMPLETED,
        ScanState.PARTIAL,
        ScanState.FAILED,
    },
    ScanState.PAUSING: {ScanState.PAUSED, ScanState.CANCELLING, ScanState.FAILED},
    ScanState.PAUSED: {ScanState.RESUMING, ScanState.CANCELLING, ScanState.CANCELLED},
    ScanState.RESUMING: {ScanState.RUNNING, ScanState.CANCELLING, ScanState.FAILED},
    ScanState.CANCELLING: {ScanState.CANCELLED, ScanState.FAILED},
    ScanState.CANCELLED: set(),
    ScanState.COMPLETED: set(),
    ScanState.PARTIAL: set(),
    ScanState.FAILED: set(),
}


class InvalidScanStateTransitionError(Exception):
    """Raised when an invalid scan state transition is attempted."""


class ScanLifecycleCoordinator:
    """Thread-safe state coordinator enforcing deterministic scan lifecycle transitions."""

    def __init__(self, initial_state: ScanState = ScanState.QUEUED) -> None:
        self._state = initial_state
        self._lock = threading.Lock()
        self._listeners: list[Callable[[ScanState, ScanState], None]] = []

    @property
    def state(self) -> ScanState:
        """Current scan state."""
        with self._lock:
            return self._state

    def add_listener(self, callback: Callable[[ScanState, ScanState], None]) -> None:
        """Register a callback invoked upon state transition (old_state, new_state)."""
        self._listeners.append(callback)

    register_callback = add_listener

    def transition_to(self, new_state: ScanState) -> None:
        """Transition scan to a new state if permissible."""
        with self._lock:
            old_state = self._state
            if old_state == new_state:
                return

            allowed = ALLOWED_TRANSITIONS.get(old_state, set())
            if new_state not in allowed:
                raise InvalidScanStateTransitionError(
                    f"Illegal scan lifecycle transition: cannot move from {old_state.value} to {new_state.value}."
                )

            self._state = new_state
            logger.debug(f"Scan lifecycle transitioned: {old_state.value} -> {new_state.value}")

        for callback in self._listeners:
            try:
                callback(old_state, new_state)
            except Exception as e:
                logger.debug(f"Lifecycle listener error: {e}")

    def is_terminal(self) -> bool:
        """Return True if scan has reached a terminal state."""
        return self.state in (
            ScanState.COMPLETED,
            ScanState.PARTIAL,
            ScanState.CANCELLED,
            ScanState.FAILED,
        )

    def is_active(self) -> bool:
        """Return True if scan is currently running or initializing."""
        return self.state in (ScanState.INITIALIZING, ScanState.RUNNING, ScanState.RESUMING)
