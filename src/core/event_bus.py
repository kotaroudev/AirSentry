from collections.abc import Callable
from dataclasses import dataclass, field
from queue import Empty, Queue

from src.core.models import RawWirelessEvent

EventHandler = Callable[[RawWirelessEvent], None]


@dataclass
class EventBus:
    """
    Small in-process event bus for AirSentry.

    Collectors publish RawWirelessEvent objects.
    Consumers such as the dashboard, device registry, and exporters subscribe
    to receive those events.

    This is intentionally local and simple for the MVP.
    """

    handlers: list[EventHandler] = field(default_factory=list)
    queue: Queue[RawWirelessEvent] = field(default_factory=Queue)

    def subscribe(self, handler: EventHandler) -> None:
        self.handlers.append(handler)

    def publish(self, event: RawWirelessEvent) -> None:
        self.queue.put(event)

    def process_once(self, timeout: float = 0.1) -> bool:
        """
        Processes one event from the queue.

        Returns True if an event was processed.
        Returns False if no event was available.
        """
        try:
            event = self.queue.get(timeout=timeout)
        except Empty:
            return False

        for handler in self.handlers:
            handler(event)

        return True

    def drain(self, max_events: int = 100) -> int:
        """
        Processes up to max_events from the queue.

        Useful for dashboards that refresh periodically.
        """
        processed = 0

        while processed < max_events:
            try:
                event = self.queue.get_nowait()
            except Empty:
                break

            for handler in self.handlers:
                handler(event)

            processed += 1

        return processed
