"""Thread-safe cooperative cancellation token for filesystem operations."""

from __future__ import annotations

import threading
from collections.abc import Callable

from systemscan.filesystem.errors import ScanCancelledError


class CancellationToken:
    """Cooperative cancellation token supporting multi-threaded or signal-triggered halts."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._callbacks: list[Callable[[], None]] = []
        self._lock = threading.Lock()

    def cancel(self) -> None:
        """Trigger cancellation across all consumers of this token."""
        self._event.set()
        with self._lock:
            callbacks = list(self._callbacks)
        for cb in callbacks:
            try:
                cb()
            except Exception:
                pass

    @property
    def is_cancelled(self) -> bool:
        """Check whether cancellation has been requested."""
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        """Raise ScanCancelledError immediately if cancellation was signaled."""
        if self._event.is_set():
            raise ScanCancelledError()

    def register_callback(self, callback: Callable[[], None]) -> None:
        """Register a cleanup or notification callback to execute upon cancellation."""
        with self._lock:
            if self._event.is_set():
                callback()
            else:
                self._callbacks.append(callback)
