"""Application lifecycle manager for systemscan."""

from __future__ import annotations

import signal
import sys
from collections.abc import Callable
from enum import Enum
from types import FrameType

from systemscan.core.constants import ExitCode
from systemscan.core.exceptions import LifecycleError
from systemscan.logging.logger import get_logger

logger = get_logger("lifecycle")

CleanupCallback = Callable[[], None]


class LifecycleState(str, Enum):
    """Application operational lifecycle states."""

    CREATED = "CREATED"
    INITIALIZING = "INITIALIZING"
    CONFIGURED = "CONFIGURED"
    READY = "READY"
    RUNNING = "RUNNING"
    SHUTTING_DOWN = "SHUTTING_DOWN"
    TERMINATED = "TERMINATED"
    FAILED = "FAILED"


class LifecycleManager:
    """Manages application state transitions, graceful shutdown, and signal traps."""

    def __init__(self) -> None:
        self._state: LifecycleState = LifecycleState.CREATED
        self._cleanup_callbacks: list[tuple[str, CleanupCallback]] = []
        self._signal_handlers_installed: bool = False

    @property
    def state(self) -> LifecycleState:
        """Current lifecycle state."""
        return self._state

    def transition_to(self, new_state: LifecycleState) -> None:
        """Transition application to a new state with validation."""
        valid_transitions: dict[LifecycleState, set[LifecycleState]] = {
            LifecycleState.CREATED: {LifecycleState.INITIALIZING, LifecycleState.FAILED},
            LifecycleState.INITIALIZING: {
                LifecycleState.CONFIGURED,
                LifecycleState.FAILED,
                LifecycleState.SHUTTING_DOWN,
            },
            LifecycleState.CONFIGURED: {
                LifecycleState.READY,
                LifecycleState.FAILED,
                LifecycleState.SHUTTING_DOWN,
            },
            LifecycleState.READY: {
                LifecycleState.RUNNING,
                LifecycleState.SHUTTING_DOWN,
                LifecycleState.FAILED,
            },
            LifecycleState.RUNNING: {
                LifecycleState.SHUTTING_DOWN,
                LifecycleState.FAILED,
            },
            LifecycleState.SHUTTING_DOWN: {
                LifecycleState.TERMINATED,
                LifecycleState.FAILED,
            },
            LifecycleState.TERMINATED: set(),
            LifecycleState.FAILED: {LifecycleState.SHUTTING_DOWN, LifecycleState.TERMINATED},
        }

        allowed = valid_transitions.get(self._state, set())
        if new_state not in allowed:
            msg = f"Invalid lifecycle state transition from '{self._state}' to '{new_state}'"
            logger.error(msg)
            raise LifecycleError(msg)

        logger.debug(f"Lifecycle state transition: {self._state} -> {new_state}")
        self._state = new_state

    def register_cleanup(self, name: str, callback: CleanupCallback) -> None:
        """Register a callback to run on application termination or shutdown."""
        self._cleanup_callbacks.append((name, callback))
        logger.debug(f"Registered cleanup hook: {name}")

    def install_signal_handlers(self) -> None:
        """Install SIGINT (Ctrl+C) and SIGTERM signal handlers."""
        if self._signal_handlers_installed:
            return

        def _handle_signal(signum: int, frame: FrameType | None) -> None:
            sig_name = "SIGINT" if signum == signal.SIGINT else f"Signal {signum}"
            logger.info(f"Received {sig_name}, initiating graceful application shutdown.")
            self.shutdown(exit_code=ExitCode.KEYBOARD_INTERRUPT)
            sys.exit(ExitCode.KEYBOARD_INTERRUPT)

        try:
            signal.signal(signal.SIGINT, _handle_signal)
            if hasattr(signal, "SIGTERM"):
                signal.signal(signal.SIGTERM, _handle_signal)
            self._signal_handlers_installed = True
            logger.debug("Signal handlers for SIGINT/SIGTERM installed successfully.")
        except (ValueError, OSError) as e:
            # Signal handling might not be supported in some embedded or secondary thread contexts
            logger.debug(f"Could not install signal handlers: {e}")

    def shutdown(self, exit_code: ExitCode = ExitCode.SUCCESS) -> None:
        """Execute all registered cleanup callbacks safely and set state to TERMINATED."""
        if self._state == LifecycleState.TERMINATED:
            return

        if self._state != LifecycleState.SHUTTING_DOWN:
            self._state = LifecycleState.SHUTTING_DOWN

        logger.info(f"Executing shutdown sequence (exit_code={int(exit_code)})...")

        # Run cleanup callbacks in reverse order of registration
        for name, callback in reversed(self._cleanup_callbacks):
            try:
                logger.debug(f"Executing cleanup handler: {name}")
                callback()
            except Exception as e:
                logger.error(f"Error during cleanup '{name}': {e}", exc_info=True)

        self._state = LifecycleState.TERMINATED
        logger.info("Application shutdown completed.")
