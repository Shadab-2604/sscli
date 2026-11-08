"""Thread-safe publish/subscribe event dispatcher for device discovery and monitoring."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

from systemscan.devices.models import DeviceEvent, DeviceEventType

logger = logging.getLogger("systemscan.devices.events")

EventCallback = Callable[[DeviceEvent], None]


class DeviceEventDispatcher:
    """Thread-safe event dispatcher for device subsystem events."""

    def __init__(self) -> None:
        self._subscribers: dict[DeviceEventType | None, list[EventCallback]] = {}
        self._lock = threading.RLock()

    def subscribe(self, callback: EventCallback, event_type: DeviceEventType | None = None) -> None:
        """Register a subscriber callback. If event_type is None, listens to all events."""
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            if callback not in self._subscribers[event_type]:
                self._subscribers[event_type].append(callback)
            logger.debug(f"Subscribed callback {callback} to event_type={event_type}")

    def unsubscribe(
        self, callback: EventCallback, event_type: DeviceEventType | None = None
    ) -> None:
        """Unregister a subscriber callback."""
        with self._lock:
            if event_type in self._subscribers and callback in self._subscribers[event_type]:
                self._subscribers[event_type].remove(callback)
                logger.debug(f"Unsubscribed callback {callback} from event_type={event_type}")

    def emit(self, event: DeviceEvent) -> None:
        """Dispatch an event to all matching registered listeners synchronously in isolation."""
        callbacks_to_invoke: list[EventCallback] = []
        with self._lock:
            # Specific type callbacks
            if event.event_type in self._subscribers:
                callbacks_to_invoke.extend(self._subscribers[event.event_type])
            # Wildcard (None) callbacks
            if None in self._subscribers:
                callbacks_to_invoke.extend(self._subscribers[None])

        for cb in callbacks_to_invoke:
            try:
                cb(event)
            except Exception as e:
                logger.error(
                    f"Error executing device event listener callback {cb}: {e}", exc_info=True
                )

    def clear(self) -> None:
        """Clear all registered event subscribers."""
        with self._lock:
            self._subscribers.clear()
