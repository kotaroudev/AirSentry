from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from src.core.capture_context import CaptureContext
from src.core.device_registry import DeviceRegistry
from src.presentation.context_panel import ContextPanel
from src.presentation.keyboard_reader import KeyboardReader
from src.presentation.smart_packet_stream_model import SmartPacketTrace
from src.presentation.wifi_view_model import WiFiViewModel


class LiveDashboard:
    """
    First live terminal dashboard for AirSentry.

    This is intentionally simple:
    - WiFi Air Perimeter preview
    - Smart Packet Stream preview
    - Device Intelligence mini summary

    Later this can evolve into tabs/panels/navigation.
    """

    def __init__(
        self,
        registry: DeviceRegistry,
        packet_traces: list[SmartPacketTrace],
        capture_context: CaptureContext,
        refresh_per_second: int = 4,
    ):
        self.registry = registry
        self.packet_traces = packet_traces
        self.capture_context = capture_context
        self.refresh_per_second = refresh_per_second
        self.current_view = "overview"
        self.quit_requested = False

    def run(self, should_stop):
        with KeyboardReader() as keyboard:
            with Live(
                self._render(),
                refresh_per_second=self.refresh_per_second,
                screen=True,
            ) as live:
                while not should_stop() and not self.quit_requested:
                    key = keyboard.read_key()
                    self._handle_key(key)
                    live.update(self._render())

    def _handle_key(self, key: str | None) -> None:
        if not key:
            return

        if key == "0":
            self.current_view = "overview"
        elif key == "1":
            self.current_view = "wifi"
        elif key == "2":
            self.current_view = "bluetooth"
        elif key == "3":
            self.current_view = "stream"
        elif key == "4":
            self.current_view = "devices"
        elif key.lower() == "q":
            self.quit_requested = True

    def _render(self):
        devices = self.registry.all_devices()
        wifi_rows = WiFiViewModel.build_rows(devices)

        if self.current_view == "wifi":
            return Group(
                ContextPanel.render(self.capture_context, "WiFi Air Perimeter"),
                self._render_navigation_help(),
                self._render_wifi_air_perimeter(wifi_rows, limit=24),
            )

        if self.current_view == "bluetooth":
            return Group(
                ContextPanel.render(self.capture_context, "Bluetooth Radar"),
                self._render_navigation_help(),
                self._render_bluetooth_radar_placeholder(),
            )

        if self.current_view == "stream":
            return Group(
                ContextPanel.render(self.capture_context, "Smart Packet Stream"),
                self._render_navigation_help(),
                self._render_smart_packet_stream(limit=24),
            )

        if self.current_view == "devices":
            return Group(
                ContextPanel.render(self.capture_context, "Device Intelligence"),
                self._render_navigation_help(),
                self._render_device_intelligence(devices, limit=18),
            )

        return Group(
            ContextPanel.render(self.capture_context, "Overview"),
            self._render_navigation_help(),
            self._render_wifi_air_perimeter(wifi_rows, limit=12),
            self._render_smart_packet_stream(limit=8),
            self._render_device_intelligence(devices, limit=6),
        )

    def _render_navigation_help(self) -> Panel:
        return Panel(
            "[bold]Navigation[/bold]: "
            "[0] Overview  [1] WiFi  [2] Bluetooth  [3] Packet Stream  "
            "[4] Devices  [q] Quit",
            title=f"Current View: {self.current_view}",
        )

    def _render_header(self) -> Panel:
        return Panel(
            "[bold]AirSentry Live Dashboard[/bold]\n"
            "Profile: Air Perimeter / 802.11 Monitor\n"
            "Visibility: WiFi beacons, probes, control frames, data-frame metadata, "
            "RSSI, channel, security metadata\n"
            "Payloads: protected WiFi payloads may be encrypted\n"
            "Exit: Ctrl+C",
            title="Session",
        )

    def _render_wifi_air_perimeter(self, wifi_rows, limit: int = 12) -> Panel:
        table = Table(expand=True)

        table.add_column("Role", no_wrap=True)
        table.add_column("SSID")
        table.add_column("MAC", no_wrap=True)
        table.add_column("RSSI", justify="right")
        table.add_column("CH", justify="right")
        table.add_column("Band")
        table.add_column("Security")
        table.add_column("Pkts", justify="right")

        for row in wifi_rows[:limit]:
            rssi = f"{row.rssi:.1f}" if row.rssi is not None else "-"
            channel = str(row.channel) if row.channel is not None else "-"
            band = row.band or "-"
            ssid = row.ssid or "-"
            security = row.security or "unknown"

            table.add_row(
                row.role,
                ssid,
                row.mac,
                rssi,
                channel,
                band,
                security,
                str(row.packet_count),
            )

        return Panel(table, title="WiFi Air Perimeter")

    def _render_bluetooth_radar_placeholder(self) -> Panel:
        table = Table(expand=True)

        table.add_column("Status")
        table.add_column("Interface")
        table.add_column("Mode")
        table.add_column("Visibility")
        table.add_column("Notes")

        table.add_row(
            "Pending",
            "hci0",
            "Basic BLE / HCI",
            "BLE advertisements and local HCI metadata when implemented",
            "Bluetooth collector is planned after WiFi live navigation.",
        )

        return Panel(table, title="Bluetooth Radar")

    def _render_smart_packet_stream(self, limit: int = 12) -> Panel:
        table = Table(expand=True)

        table.add_column("Time", no_wrap=True)
        table.add_column("Proto", no_wrap=True)
        table.add_column("Type")
        table.add_column("Src MAC", no_wrap=True)
        table.add_column("Src IP", no_wrap=True)
        table.add_column("Dst MAC", no_wrap=True)
        table.add_column("Dst IP", no_wrap=True)
        table.add_column("Len", justify="right")
        table.add_column("RSSI", justify="right")
        table.add_column("CH/Band", justify="right")
        table.add_column("Flags")
        table.add_column("Device")
        table.add_column("Summary")

        for trace in self.packet_traces[-limit:]:
            channel_band = "-"

            if trace.channel is not None and trace.band:
                channel_band = f"{trace.channel}/{trace.band}"
            elif trace.channel is not None:
                channel_band = str(trace.channel)
            elif trace.band:
                channel_band = trace.band

            table.add_row(
                trace.timestamp,
                trace.protocol,
                trace.event_type[:18],
                trace.src_mac or "-",
                trace.src_ip or "-",
                trace.dst_mac or "-",
                trace.dst_ip or "-",
                str(trace.length) if trace.length is not None else "-",
                str(trace.rssi) if trace.rssi is not None else "-",
                channel_band,
                trace.flags[:24] if trace.flags else "-",
                trace.device_key[:18],
                trace.summary[:90],
            )

        return Panel(table, title="Smart Packet Stream")

    def _render_device_intelligence(self, devices, limit: int = 8) -> Panel:
        table = Table(expand=True)

        table.add_column("Device", no_wrap=True)
        table.add_column("Type")
        table.add_column("Pkts", justify="right")
        table.add_column("RSSI", justify="right")
        table.add_column("Last Behavior")

        sorted_devices = sorted(
            devices,
            key=lambda device: device.packet_count,
            reverse=True,
        )

        for device in sorted_devices[:limit]:
            rssi = device.avg_wifi_rssi()
            behavior = "-"

            if device.last_behavior:
                behavior = (
                    f"[{device.last_behavior.category}] {device.last_behavior.title}"
                )

            table.add_row(
                device.identity.primary_mac or device.device_id,
                device.identity.suspected_device_type or "unknown",
                str(device.packet_count),
                f"{rssi:.1f}" if rssi is not None else "-",
                behavior[:90],
            )

        return Panel(table, title="Device Intelligence Preview")
