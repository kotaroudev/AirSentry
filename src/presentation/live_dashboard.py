import textwrap

from rich import box
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from src.core.capture_context import CaptureContext
from src.core.device_registry import DeviceRegistry
from src.presentation.bluetooth_view_model import BluetoothViewModel
from src.presentation.context_panel import ContextPanel
from src.presentation.device_intelligence_view_model import DeviceIntelligenceViewModel
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
        self.device_page = 0
        self.devices_per_page = 8
        self.selected_device_index = 0
        self.expanded_device_id = None

        self.stream_page = 0
        self.stream_page_size = 20

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
        elif key.lower() == "n":
            self._next_page()
        elif key.lower() == "p":
            self._previous_page()
        elif key.lower() == "j":
            self._move_device_selection(1)
        elif key.lower() == "k":
            self._move_device_selection(-1)
        elif key.lower() in {"e", "\n", "\r"}:
            self._toggle_selected_device()
        elif key.lower() == "r":
            self.device_page = 0
            self.stream_page = 0
            self.selected_device_index = 0
            self.expanded_device_id = None
        elif key.lower() == "q":
            self.quit_requested = True

    def _current_device_items(self):
        devices = self.registry.all_devices()
        return DeviceIntelligenceViewModel.build_items(devices)

    def _current_visible_device_items(self):
        items = self._current_device_items()
        start = self.device_page * self.devices_per_page
        end = start + self.devices_per_page
        return items[start:end]

    def _move_device_selection(self, direction: int) -> None:
        if self.current_view != "devices":
            return

        visible_items = self._current_visible_device_items()

        if not visible_items:
            self.selected_device_index = 0
            return

        max_index = len(visible_items) - 1
        self.selected_device_index = max(
            0,
            min(self.selected_device_index + direction, max_index),
        )

    def _toggle_selected_device(self) -> None:
        if self.current_view != "devices":
            return

        visible_items = self._current_visible_device_items()

        if not visible_items:
            return

        selected_item = visible_items[self.selected_device_index]

        if self.expanded_device_id == selected_item.device_id:
            self.expanded_device_id = None
        else:
            self.expanded_device_id = selected_item.device_id

    def _next_page(self) -> None:
        if self.current_view == "devices":
            devices = self.registry.all_devices()
            max_page = max(0, (len(devices) - 1) // self.devices_per_page)
            self.device_page = min(self.device_page + 1, max_page)
            self.selected_device_index = 0
            self.expanded_device_id = None

        elif self.current_view == "stream":
            total = len(self.packet_traces)
            max_page = max(0, (total - 1) // self.stream_page_size)
            self.stream_page = min(self.stream_page + 1, max_page)

    def _previous_page(self) -> None:
        if self.current_view == "devices":
            self.device_page = max(0, self.device_page - 1)
            self.selected_device_index = 0
            self.expanded_device_id = None

        elif self.current_view == "stream":
            self.stream_page = max(0, self.stream_page - 1)

    def _context_for_view(self, view_name: str) -> CaptureContext:
        if view_name == "Bluetooth Radar":
            return CaptureContext(
                profile_name="Bluetooth Radar / Basic BLE Scan",
                profile_description=(
                    "Discovers nearby BLE devices from advertised Bluetooth Low Energy "
                    "metadata using the local adapter when available."
                ),
                bluetooth_interface=self.capture_context.bluetooth_interface,
                capture_metadata=[
                    "Bluetooth interface",
                    "BLE address",
                    "advertised name when available",
                    "RSSI when available",
                    "service UUIDs when advertised",
                    "manufacturer data when advertised",
                    "advertising timestamp",
                ],
                network_layers=[
                    "Bluetooth radio observation layer",
                    "BLE advertising layer",
                ],
                observed_protocols=[
                    "BLE advertisements",
                    "BLE scan responses when available",
                ],
                frame_families=[
                    "BLE advertisements",
                    "BLE scan responses",
                ],
                limitations=[
                    "Basic BLE scanning does not capture all Bluetooth traffic.",
                    "Connected BLE payloads may be encrypted or unavailable.",
                    "Many BLE devices use random/private addresses.",
                    "RSSI, advertised name and manufacturer data may appear intermittently.",
                    "External BLE hardware can significantly improve passive Bluetooth spectrum visibility.",
                ],
                active_storage="memory-only",
                channel_strategy="controller-managed BLE scanning",
                payload_visibility=(
                    "advertising metadata only; connection payloads may be encrypted or unavailable"
                ),
            )

        if view_name == "Smart Packet Stream":
            context = self.capture_context
            context.profile_description = (
                "Shows the most complete technical trace view for every normalized event "
                "seen by the active collectors."
            )
            return context

        if view_name == "Device Intelligence":
            return CaptureContext(
                profile_name="Device Intelligence / Correlation View",
                profile_description=(
                    "Correlates observed signals into device profiles, behaviors, "
                    "evidence, identity notes and confidence hints."
                ),
                base_wifi_interface=self.capture_context.base_wifi_interface,
                capture_wifi_interface=self.capture_context.capture_wifi_interface,
                bluetooth_interface=self.capture_context.bluetooth_interface,
                capture_metadata=[
                    "normalized events",
                    "RSSI samples",
                    "MAC addresses",
                    "OUI/vendor evidence",
                    "SSID probes",
                    "frame/message types",
                    "behavior timeline",
                ],
                network_layers=[
                    "Depends on active collectors",
                    "Current Air Perimeter evidence: OSI L2 / IEEE 802.11 wireless link",
                    "Future Local Visibility: OSI L2/L3/L4/L7 local network protocols",
                ],
                observed_protocols=[
                    "IEEE 802.11 from Air Perimeter",
                    "BLE/HCI when Bluetooth Radar is active",
                    "ARP, DHCP, mDNS, SSDP, DNS, LLMNR, NetBIOS when Local Visibility is active",
                ],
                frame_families=[
                    "Behaviors",
                    "Evidence",
                    "Identity notes",
                    "Risk notes",
                    "Related devices",
                ],
                limitations=[
                    "Unknown means activity was observed but identity evidence is incomplete.",
                    "Vendor/OUI is soft evidence and may be wrong with randomized MACs.",
                    "Use Smart Packet Stream to validate raw technical traces.",
                    "Local Network Visibility, BLE collection and persistence improve confidence.",
                ],
                active_storage="memory-only",
                channel_strategy="uses evidence from active collectors",
                payload_visibility="shows interpreted evidence, not raw payload decoding",
            )

        return self.capture_context

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
            bluetooth_rows = BluetoothViewModel.build_rows(devices)

            return Group(
                ContextPanel.render(
                    self._context_for_view("Bluetooth Radar"),
                    "Bluetooth Radar",
                ),
                self._render_navigation_help(),
                self._render_bluetooth_radar(bluetooth_rows, limit=24),
            )

        if self.current_view == "stream":
            return Group(
                ContextPanel.render(
                    self._context_for_view("Smart Packet Stream"), "Smart Packet Stream"
                ),
                self._render_navigation_help(),
                self._render_smart_packet_stream(limit=24),
            )

        if self.current_view == "devices":
            return Group(
                ContextPanel.render(
                    self._context_for_view("Device Intelligence"), "Device Intelligence"
                ),
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
            "[4] Devices  [n] Next  [p] Previous  "
            "[j/k] Select  [e] Expand  [r] Reset  [q] Quit",
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

    def _render_bluetooth_radar(self, bluetooth_rows, limit: int = 12) -> Panel:
        table = Table(expand=True)

        table.add_column("Role", no_wrap=True, width=4)
        table.add_column("Name", ratio=2, overflow="ellipsis")
        table.add_column("Address", no_wrap=True, width=17)
        table.add_column("RSSI", justify="right", width=6)
        table.add_column("Proximity", width=10, overflow="ellipsis")
        table.add_column("Vendor", ratio=2, overflow="ellipsis")
        table.add_column("Addr Type", width=9, overflow="ellipsis")
        table.add_column("Services", ratio=2, overflow="ellipsis")
        table.add_column("Events", justify="right", width=6, no_wrap=True)
        table.add_column("Last Seen", no_wrap=True, width=8)

        for row in bluetooth_rows[:limit]:
            table.add_row(
                row.role,
                row.name,
                row.address,
                f"{row.rssi:.1f}" if row.rssi is not None else "-",
                row.proximity,
                row.vendor,
                row.address_type,
                self._clip_text(row.services, 28),
                str(row.events),
                row.last_seen,
            )

        if not bluetooth_rows:
            return Panel(
                "No BLE devices observed yet.\n\n"
                "Basic BLE scanning depends on nearby devices advertising. "
                "Many devices rotate private addresses or advertise intermittently.",
                title="Bluetooth Radar",
            )

        return Panel(table, title="Bluetooth Radar")

    def _render_smart_packet_stream(self, limit: int = 12) -> Panel:
        table = Table(expand=True)

        table.add_column("Time", no_wrap=True)
        table.add_column("Radio", no_wrap=True, width=5)
        table.add_column("Proto", no_wrap=True)
        table.add_column("Type", overflow="ellipsis")
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

        traces = self.packet_traces

        if self.current_view == "stream":
            reversed_traces = list(reversed(traces))
            start = self.stream_page * self.stream_page_size
            end = start + self.stream_page_size
            visible_traces = list(reversed(reversed_traces[start:end]))
        else:
            visible_traces = traces[-limit:]

        for trace in visible_traces:
            channel_band = "-"

            if trace.channel is not None and trace.band:
                channel_band = f"{trace.channel}/{trace.band}"
            elif trace.channel is not None:
                channel_band = str(trace.channel)
            elif trace.band:
                channel_band = trace.band

            radio = trace.radio

            table.add_row(
                trace.timestamp,
                radio,
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

        title = "Smart Packet Stream"

        if self.current_view == "stream":
            total_pages = max(
                1,
                (len(self.packet_traces) + self.stream_page_size - 1)
                // self.stream_page_size,
            )
            title = (
                f"Smart Packet Stream | Page {self.stream_page + 1}/{total_pages} "
                f"| Buffer {len(self.packet_traces)} traces"
            )

        return Panel(table, title=title)

    def _render_device_intelligence_overview(self, items, limit: int = 4) -> Panel:
        table = Table(expand=True)
        table.add_column("Device")
        table.add_column("Role", no_wrap=True)
        table.add_column("Vendor")
        table.add_column("Signal", no_wrap=True)
        table.add_column("Last Behavior")

        for item in items[:limit]:
            table.add_row(
                item.title,
                item.role,
                ", ".join(item.vendors) if item.vendors else "unknown",
                f"{item.avg_wifi_rssi:.1f} dBm"
                if item.avg_wifi_rssi is not None
                else "-",
                self._last_behavior_label(item),
            )

        return Panel(table, title="Device Intelligence Preview")

    def _render_device_intelligence_interactive(self, items) -> Panel:
        start = self.device_page * self.devices_per_page
        end = start + self.devices_per_page
        visible_items = items[start:end]

        total_pages = max(
            1, (len(items) + self.devices_per_page - 1) // self.devices_per_page
        )

        if not visible_items:
            return Panel("No devices on this page.", title="Device Intelligence")

        selected_item = visible_items[
            min(self.selected_device_index, len(visible_items) - 1)
        ]

        if self.expanded_device_id == selected_item.device_id:
            return Panel(
                self._render_device_detail_card(selected_item),
                title=(
                    f"Device Intelligence | Page {self.device_page + 1}/{total_pages} "
                    f"| Expanded {self.selected_device_index + 1}/{len(visible_items)}"
                ),
            )

        table = Table(expand=True)
        table.add_column("Sel", no_wrap=True)
        table.add_column("Device")
        table.add_column("Role", no_wrap=True)
        table.add_column("Vendor")
        table.add_column("Signal", no_wrap=True)
        table.add_column("Packets", justify="right")
        table.add_column("Last Behavior")

        for index, item in enumerate(visible_items):
            marker = ">" if index == self.selected_device_index else " "
            tag = self._device_status_tag(item)

            table.add_row(
                marker,
                f"{item.title} {tag}".strip(),
                item.role,
                ", ".join(item.vendors) if item.vendors else "unknown",
                f"{item.avg_wifi_rssi:.1f} dBm"
                if item.avg_wifi_rssi is not None
                else "-",
                str(item.packet_count),
                self._last_behavior_label(item),
            )

        return Panel(
            table,
            title=(
                f"Device Intelligence | Page {self.device_page + 1}/{total_pages} "
                f"| Showing {len(visible_items)} of {len(items)} devices"
            ),
        )

    def _render_device_intelligence(self, devices, limit: int = 4) -> Panel:
        items = DeviceIntelligenceViewModel.build_items(devices)

        if not items:
            return Panel(
                "No devices have been identified yet.",
                title="Device Intelligence",
            )

        if self.current_view == "devices":
            return self._render_device_intelligence_interactive(items)

        return self._render_device_intelligence_overview(items, limit=limit)

    def _clip_text(self, value: str, max_length: int = 120) -> str:
        if len(value) <= max_length:
            return value

        return value[: max_length - 3] + "..."

    def _wrap_text(self, value: str, width: int = 120) -> str:
        return "\n".join(
            textwrap.wrap(
                value,
                width=width,
                break_long_words=False,
                break_on_hyphens=False,
            )
        )

    def _format_recent_behaviors(self, behaviors) -> list[str]:
        """
        Compacts repeated behaviors for Device Intelligence.

        Raw events are still preserved in memory/exporters. This method only
        prevents the intelligence view from becoming noisy with repeated beacons,
        ACKs, protected frames or retry observations.
        """
        if not behaviors:
            return []

        grouped = {}

        for behavior in behaviors:
            key = (
                behavior.category,
                behavior.title,
                behavior.description,
            )

            if key not in grouped:
                grouped[key] = {
                    "behavior": behavior,
                    "count": 0,
                }

            grouped[key]["count"] += 1

        lines = []

        for entry in list(grouped.values())[-3:]:
            behavior = entry["behavior"]
            count = entry["count"]

            suffix = f" Seen {count} times." if count > 1 else ""

            line = (
                f"[{behavior.category}] {behavior.title}: "
                f"{behavior.description}{suffix}"
            )

            lines.append(self._wrap_text(line, 120))

        return lines

    def _device_status_tag(self, item) -> str:
        categories = {behavior.category for behavior in item.recent_behaviors}

        if "RISK" in categories:
            return "[RISK]"

        if "SUSPICIOUS" in categories:
            return "[SUSPICIOUS]"

        if "NOTICE" in categories:
            return "[NOTICE]"

        return ""

    def _last_behavior_label(self, item) -> str:
        if not item.recent_behaviors:
            return "-"

        behavior = item.recent_behaviors[-1]
        return self._clip_text(
            f"[{behavior.category}] {behavior.title}",
            70,
        )

    def _render_device_detail_card(self, item):
        table = Table(
            expand=True,
            show_header=False,
            show_lines=True,
            box=box.HORIZONTALS,
            padding=(0, 1),
        )

        table.add_column("Property", ratio=1, style="bold", no_wrap=True)
        table.add_column("Value", ratio=3)

        vendor_text = ", ".join(item.vendors) if item.vendors else "unknown"

        identity_line = (
            f"Role={item.role} | MAC={item.mac or 'unknown'} | Vendor={vendor_text}"
        )

        network_line = (
            f"IP={', '.join(item.ip_addresses) if item.ip_addresses else 'not observed'} | "
            f"Hostnames={', '.join(item.hostnames) if item.hostnames else 'not observed'}"
        )

        signal_line = (
            f"{item.avg_wifi_rssi:.1f} dBm ({item.proximity})"
            if item.avg_wifi_rssi is not None
            else "unknown / not exposed by driver yet"
        )

        protocol_line = ", ".join(item.protocols) if item.protocols else "unknown"

        layer_line = (
            ", ".join(item.network_layers_seen)
            if item.network_layers_seen
            else "unknown"
        )

        metadata_line = (
            ", ".join(item.capture_metadata_used)
            if item.capture_metadata_used
            else "unknown"
        )

        frame_family_line = (
            ", ".join(item.frame_families_seen)
            if item.frame_families_seen
            else "unknown"
        )

        frame_type_line = (
            ", ".join(item.frame_types_seen[:6]) if item.frame_types_seen else "unknown"
        )

        table.add_row("[bold]Device[/bold]", self._clip_text(item.title, 130))
        table.add_row("[bold]Identity[/bold]", self._clip_text(identity_line, 130))
        table.add_row("[bold]Network[/bold]", self._clip_text(network_line, 130))
        table.add_row("[bold]Signal[/bold]", signal_line)
        table.add_row("[bold]Packets[/bold]", str(item.packet_count))

        behavior_lines = self._format_recent_behaviors(item.recent_behaviors)

        if not behavior_lines:
            behavior_lines.append("No behavior timeline yet.")

        table.add_row("[bold]Recent behaviors[/bold]", "\n".join(behavior_lines))

        table.add_row(
            "[bold]Protocols seen[/bold]", self._clip_text(protocol_line, 130)
        )
        table.add_row("[bold]Network layers[/bold]", self._clip_text(layer_line, 130))
        table.add_row(
            "[bold]Capture metadata[/bold]", self._clip_text(metadata_line, 130)
        )
        table.add_row(
            "[bold]Frame families[/bold]", self._clip_text(frame_family_line, 130)
        )
        table.add_row("[bold]Frame types[/bold]", self._clip_text(frame_type_line, 130))

        if item.ssids_probed:
            table.add_row(
                "[bold]SSIDs probed[/bold]",
                self._clip_text(", ".join(item.ssids_probed), 130),
            )

        if item.services:
            table.add_row(
                "[bold]Services[/bold]",
                self._clip_text(", ".join(item.services), 130),
            )

        if item.related_devices:
            table.add_row(
                "[bold]Related devices[/bold]",
                self._clip_text(", ".join(item.related_devices), 130),
            )

        if item.risk_notes:
            table.add_row(
                "[bold]Risk notes[/bold]",
                "\n".join(self._clip_text(note, 110) for note in item.risk_notes[:2]),
            )

        if item.identity_notes:
            table.add_row(
                "[bold]Identity notes[/bold]",
                "\n".join(
                    self._wrap_text(note, 120) for note in item.identity_notes[:2]
                ),
            )

        return table
