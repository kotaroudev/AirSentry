import time
from dataclasses import dataclass, field
from threading import Event, Thread

from src.infrastructure.wifi_mode_controller import WiFiModeController

DEFAULT_24_GHZ_CHANNELS = [1, 6, 11]

DEFAULT_5_GHZ_CHANNELS = [
    36,
    40,
    44,
    48,
    149,
    153,
    157,
    161,
]

DEFAULT_WIFI_HOP_CHANNELS = DEFAULT_24_GHZ_CHANNELS + DEFAULT_5_GHZ_CHANNELS


@dataclass
class WiFiChannelHopper:
    """
    Rotates a monitor interface across WiFi channels.

    Important:
    A single WiFi adapter can only listen to one channel at a time.
    Channel hopping gives broad coverage over time, but packets may be missed
    while the adapter is listening on another channel.
    """

    controller: WiFiModeController
    channels: list[int] = field(
        default_factory=lambda: DEFAULT_WIFI_HOP_CHANNELS.copy()
    )
    dwell_seconds: float = 0.75

    def __post_init__(self) -> None:
        self._stop_event = Event()
        self._thread: Thread | None = None
        self.current_channel: int | None = None
        self.successful_channels: set[int] = set()
        self.failed_channels: set[int] = set()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = Thread(
            target=self._run,
            name="airsentry-wifi-channel-hopper",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def summary(self) -> str:
        channels = ",".join(str(channel) for channel in self.channels)

        return (
            f"channel hopping enabled; channels={channels}; dwell={self.dwell_seconds}s"
        )

    def _run(self) -> None:
        while not self._stop_event.is_set():
            for channel in self.channels:
                if self._stop_event.is_set():
                    break

                if self.controller.set_channel(channel):
                    self.current_channel = channel
                    self.successful_channels.add(channel)
                else:
                    self.failed_channels.add(channel)

                self._sleep_dwell()

    def _sleep_dwell(self) -> None:
        slept = 0.0
        interval = 0.1

        while slept < self.dwell_seconds and not self._stop_event.is_set():
            time.sleep(interval)
            slept += interval
