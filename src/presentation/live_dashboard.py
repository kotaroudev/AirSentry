from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from src.core.capture_context import CaptureContext
from src.core.device_registry import DeviceRegistry
from src.presentation.context_panel import ContextPanel
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

    def run(self, should_stop):
        with Live(
            self._render(),
            refresh_per_second=self.refresh_per_second,
            screen=True,
        ) as live:
            while not should_stop():
                live.update(self._render())

    def _render(self):
        devices = self.registry.all_devices()
        wifi_rows = WiFiViewModel.build_rows(devices)

        return Group(
            ContextPanel.render(self.capture_context, "Overview"),
            self._render_wifi_air_perimeter(wifi_rows),
            self._render_smart_packet_stream(),
            self._render_device_intelligence(devices),
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

    def _render_wifi_air_perimeter(self, wifi_rows) -> Panel:
        table = Table(expand=True)

        table.add_column("Role", no_wrap=True)
        table.add_column("SSID")
        table.add_column("MAC", no_wrap=True)
        table.add_column("RSSI", justify="right")
        table.add_column("CH", justify="right")
        table.add_column("Band")
        table.add_column("Security")
        table.add_column("Pkts", justify="right")

        for row in wifi_rows[:12]:
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

    def _render_smart_packet_stream(self) -> Panel:
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

        for trace in self.packet_traces[-12:]:
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

    def _render_device_intelligence(self, devices) -> Panel:
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

        for device in sorted_devices[:8]:
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
