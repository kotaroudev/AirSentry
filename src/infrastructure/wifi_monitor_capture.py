from collections.abc import Callable
from dataclasses import dataclass
from threading import Event, Thread
from typing import Any

from scapy.sendrecv import sniff

from src.core.event_bus import EventBus
from src.infrastructure.wifi_packet_parser import WiFiPacketParser


@dataclass
class WiFiMonitorCapture:
    """
    Captures WiFi packets from an interface that is already in monitor mode.

    This class does not enable monitor mode by itself.
    Its only responsibility is:

    Scapy packet -> WiFiPacketParser -> RawWirelessEvent -> EventBus
    """

    interface: str
    event_bus: EventBus
    store_raw_bytes: bool = False
    channel_provider: Callable[[], int | None] | None = None

    def __post_init__(self) -> None:
        self._stop_event = Event()
        self._thread: Thread | None = None

        self.raw_packet_count = 0
        self.parsed_event_count = 0
        self.parser_error_count = 0
        self.last_packet_summary: str | None = None
        self.last_parser_error: str | None = None

    def start(self) -> None:
        """
        Starts packet capture in a background thread.
        """
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()

        self._thread = Thread(
            target=self._capture_loop,
            name=f"airsentry-wifi-capture-{self.interface}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """
        Requests packet capture to stop.
        """
        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _capture_loop(self) -> None:
        """
        Runs Scapy sniff loop.

        We intentionally do not pass monitor=True here because the interface
        is already placed into monitor mode by WiFiModeController.

        The loop uses timeout=1 so AirSentry can stop cleanly even when no
        packets are received.
        """
        while not self._stop_event.is_set():
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
                timeout=1,
            )

    def _handle_packet(self, packet: Any) -> None:
        """
        Converts Scapy packets into AirSentry raw events.
        """
        self.raw_packet_count += 1

        try:
            self.last_packet_summary = packet.summary()
        except Exception:
            self.last_packet_summary = "<summary unavailable>"

        try:
            events = WiFiPacketParser.parse(packet)
        except Exception as exc:
            self.parser_error_count += 1
            self.last_parser_error = str(exc)
            return

        for event in events:
            event.interface = self.interface

            if self.store_raw_bytes:
                try:
                    event.raw_bytes_hex = bytes(packet).hex()
                except Exception:
                    event.raw_bytes_hex = None

            self.parsed_event_count += 1
            observed_channel = None

            if self.channel_provider:
                try:
                    observed_channel = self.channel_provider()
                except Exception:
                    observed_channel = None

            if event.signal.channel is None and observed_channel is not None:
                event.signal.channel = observed_channel
                event.signal.frequency_mhz = WiFiPacketParser._channel_to_frequency(
                    observed_channel
                )
                event.signal.band = WiFiPacketParser._frequency_to_band(
                    event.signal.frequency_mhz
                )
                event.extra["channel_source"] = "inferred_from_channel_hopper"

            self.event_bus.publish(event)
