"""Lightweight thread-safe in-memory publish-subscribe event bus for network monitoring."""

from __future__ import annotations

import logging
from collections.abc import Callable
from queue import Empty, Queue
from threading import Event, Thread
from typing import Any

logger = logging.getLogger("systemscan.network_monitor.event_bus")


class EventBus:
    """Decoupled asynchronous event broker for packet streams and security alerts."""

    def __init__(self, maxsize: int = 5000) -> None:
        self._queue: Queue[tuple[str, Any]] = Queue(maxsize=maxsize)
        self._subscribers: dict[str, list[Callable[[Any], None]]] = {}
        self._running = False
        self._worker_thread: Thread | None = None
        self._stop_event = Event()

    def subscribe(self, topic: str, handler: Callable[[Any], None]) -> None:
        """Register a callback handler for a specific event topic."""
        if topic not in self._subscribers:
            self._subscribers[topic] = []
        self._subscribers[topic].append(handler)

    def publish(self, topic: str, data: Any) -> bool:
        """Enqueue an event item onto the processing queue (non-blocking)."""
        try:
            self._queue.put_nowait((topic, data))
            return True
        except Exception:
            # Queue saturated: drop oldest or log drop count to protect memory
            logger.debug(f"Event bus queue full on topic '{topic}'; dropping event.")
            return False

    def start(self) -> None:
        """Start the background dispatch worker."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._worker_thread = Thread(
            target=self._process_events, daemon=True, name="NetMonEventBus"
        )
        self._worker_thread.start()

    def stop(self) -> None:
        """Signal and wait for worker thread termination."""
        self._running = False
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.0)
            self._worker_thread = None

    def _process_events(self) -> None:
        while not self._stop_event.is_set():
            try:
                topic, data = self._queue.get(timeout=0.1)
                handlers = self._subscribers.get(topic, [])
                for handler in handlers:
                    try:
                        handler(data)
                    except Exception as e:
                        logger.debug(f"Error in subscriber handler for '{topic}': {e}")
                self._queue.task_done()
            except Empty:
                continue
