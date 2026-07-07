import textwrap
import time

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
        self.show_context_help = False
        self._device_items_cache = []
        self._device_items_cache_at = 0.0
        self._device_items_cache_ttl = 0.75
        self.stream_radio_filter = None

        self.stream_page = 0
        self.stream_page_size = 20
        self.device_search_query = ""
        self.device_search_mode = False

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

    def _current_stream_traces(self):
        if not self.stream_radio_filter:
            return self.packet_traces

        return [
            trace
            for trace in self.packet_traces
            if trace.radio == self.stream_radio_filter
        ]

    def _handle_key(self, key: str | None) -> None:
        if not key:
            return

        if self.device_search_mode:
            if key in {"\n", "\r"}:
                self.device_search_mode = False
                self.device_page = 0
                self.selected_device_index = 0
                self.expanded_device_id = None
                return

            if key == "\x1b":  # ESC
                self.device_search_mode = False
                return

            if key in {"\x7f", "\b"}:  # Backspace
                self.device_search_query = self.device_search_query[:-1]
                self.device_page = 0
                self.selected_device_index = 0
                self.expanded_device_id = None
                return

            if len(key) == 1 and key.isprintable():
                self.device_search_query += key
                self.device_page = 0
                self.selected_device_index = 0
                self.expanded_device_id = None
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
            self.device_search_query = ""
            self.device_search_mode = False
            self.stream_radio_filter = None
        elif key.lower() == "q":
            self.quit_requested = True
        elif key.lower() == "h":
            self.show_context_help = not self.show_context_help
        elif key == "/":
            if self.current_view == "devices":
                self.device_search_mode = True
        elif key.lower() == "l":
            if self.current_view == "stream":
                self.stream_radio_filter = (
                    None if self.stream_radio_filter == "LOCAL" else "LOCAL"
                )
                self.stream_page = 0

    def _current_device_items(self):
        now = time.monotonic()

        if now - self._device_items_cache_at >= self._device_items_cache_ttl:
            devices = self.registry.all_devices()
            self._device_items_cache = DeviceIntelligenceViewModel.build_items(devices)
            self._device_items_cache_at = now

        items = self._device_items_cache

        if self.device_search_query:
            items = [
                item
                for item in items
                if self._device_matches_search(item, self.device_search_query)
            ]

        return items

    def _device_matches_search(self, item, query: str) -> bool:
        needle = query.strip().lower()

        if not needle:
            return True

        values = [
            item.title,
            item.role,
            item.mac,
            item.bluetooth_name,
            item.bluetooth_address,
            item.bluetooth_address_type,
            item.signal_summary,
            item.events_summary,
        ]

        values.extend(item.ip_addresses)
        values.extend(item.hostnames)
        values.extend(item.vendors)
        values.extend(item.radios_seen)
        values.extend(item.protocols)
        values.extend(item.network_layers_seen)
        values.extend(item.capture_metadata_used)
        values.extend(item.frame_families_seen)
        values.extend(item.frame_types_seen)
        values.extend(item.ssids_probed)
        values.extend(item.services)
        values.extend(item.bluetooth_services)
        values.extend(item.related_devices)
        values.extend(item.risk_notes)
        values.extend(item.identity_notes)
        values.extend(item.security_evidence)

        for behavior in item.recent_behaviors:
            values.extend(
                [
                    behavior.category,
                    behavior.title,
                    behavior.description,
                    behavior.protocol,
                    behavior.event_type,
                ]
            )

        haystack = " ".join(str(value).lower() for value in values if value)

        normalized_haystack = haystack.replace("-", ":")
        normalized_needle = needle.replace("-", ":")

        return needle in haystack or normalized_needle in normalized_haystack

    def _is_local_visibility_profile(self) -> bool:
        profile_name = (self.capture_context.profile_name or "").lower()
        return "local network visibility" in profile_name

    def _active_hardware_label(self) -> str:
        base_wifi = self._interface_name(
            getattr(self.capture_context, "base_wifi_interface", None),
            "local interface",
        )
        capture_wifi_context = getattr(
            self.capture_context, "capture_wifi_interface", None
        )
        capture_wifi = self._interface_name(capture_wifi_context, "")

        bluetooth_context = getattr(self.capture_context, "bluetooth_interface", None)
        bluetooth = self._interface_name(bluetooth_context, "")

        parts = []

        if capture_wifi:
            parts.append(capture_wifi)
        elif base_wifi:
            parts.append(base_wifi)

        if bluetooth:
            parts.append(bluetooth)

        return " + ".join(parts) if parts else "unknown hardware"

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
            items = self._current_device_items()
            max_page = max(0, (len(items) - 1) // self.devices_per_page)
            self.device_page = min(self.device_page + 1, max_page)
            self.selected_device_index = 0
            self.expanded_device_id = None

        elif self.current_view == "stream":
            total = len(self._current_stream_traces())
            max_page = max(0, (total - 1) // self.stream_page_size)
            self.stream_page = min(self.stream_page + 1, max_page)

    def _previous_page(self) -> None:
        if self.current_view == "devices":
            self.device_page = max(0, self.device_page - 1)
            self.selected_device_index = 0
            self.expanded_device_id = None

        elif self.current_view == "stream":
            self.stream_page = max(0, self.stream_page - 1)

    def _last_behavior_full_label(self, item) -> str:
        if not item.recent_behaviors:
            return "-"

        behavior = item.recent_behaviors[-1]

        return self._wrap_text(
            f"[{behavior.category}] {behavior.title}: {behavior.description}",
            90,
        )

    def _render_local_network_visibility(self, devices, limit: int = 12) -> Panel:
        table = Table(expand=True, show_lines=True)

        table.add_column("Device", overflow="fold", no_wrap=False, ratio=3)
        table.add_column("MAC", overflow="fold", no_wrap=False, width=18)
        table.add_column("Vendor", overflow="fold", no_wrap=False, ratio=2)
        table.add_column("IP", overflow="fold", no_wrap=False, ratio=2)
        table.add_column("Names", overflow="fold", no_wrap=False, ratio=3)
        table.add_column("Protocols", overflow="fold", no_wrap=False, ratio=3)
        table.add_column("Services", overflow="fold", no_wrap=False, ratio=4)
        table.add_column("Events", justify="right", width=7)
        table.add_column("Last Behavior", overflow="fold", no_wrap=False, ratio=4)

        local_protocols = {
            "ARP",
            "DHCP",
            "DNS",
            "MDNS",
            "SSDP",
            "UPNP",
            "LLMNR",
            "NETBIOS",
            "NDP",
            "ICMPV6",
            "DHCPV6",
            "WS_DISCOVERY",
        }

        rows = []

        items = DeviceIntelligenceViewModel.build_items(devices)
        item_by_id = {item.device_id: item for item in items}

        for device in devices:
            protocols = device.identity.protocols_seen

            if not protocols & local_protocols:
                continue

            item = item_by_id.get(device.device_id)

            if not item:
                continue

            rows.append(
                (
                    item.event_count,
                    item,
                )
            )

        rows.sort(key=lambda entry: entry[0], reverse=True)

        for _, item in rows[:limit]:
            table.add_row(
                item.title,
                item.mac or "-",
                ", ".join(item.vendors) if item.vendors else "-",
                "\n".join(item.ip_addresses) if item.ip_addresses else "-",
                "\n".join(item.hostnames) if item.hostnames else "-",
                "\n".join(item.protocols) if item.protocols else "-",
                "\n".join(item.services) if item.services else "-",
                str(item.event_count),
                self._last_behavior_full_label(item),
            )

        if not rows:
            return Panel(
                "No local network visibility events observed yet.\n\n"
                "This profile listens for ARP, DHCP, DNS, mDNS, SSDP/UPnP, "
                "LLMNR and NetBIOS visible to this host. Managed mode sees host, "
                "broadcast and multicast traffic. Promiscuous mode is best effort.",
                title="Local Network Visibility",
            )

        return Panel(table, title="Local Network Visibility")

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
                    "behavior timeline",
                    "related devices",
                    *self.capture_context.capture_metadata,
                ],
                network_layers=[
                    "Depends on active collectors",
                    *self.capture_context.network_layers,
                ],
                observed_protocols=[
                    *self.capture_context.observed_protocols,
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
                    *self.capture_context.limitations,
                ],
                active_storage="memory-only",
                channel_strategy="uses evidence from active collectors",
                payload_visibility="shows interpreted evidence, not raw payload decoding",
            )

        return self.capture_context

    def _render(self):
        if self.show_context_help:
            return Group(
                self._render_navigation_help(),
                ContextPanel.render(
                    self._context_for_current_view(),
                    f"{self.current_view.title()} Context",
                ),
            )

        if self.current_view == "wifi":
            devices = self.registry.all_devices()

            if self._is_local_visibility_profile():
                return Group(
                    self._render_navigation_help(),
                    self._render_local_network_visibility(devices, limit=24),
                )

            wifi_rows = WiFiViewModel.build_rows(devices)

            return Group(
                self._render_navigation_help(),
                self._render_wifi_air_perimeter(wifi_rows, limit=24),
            )

        if self.current_view == "bluetooth":
            devices = self.registry.all_devices()
            bluetooth_rows = BluetoothViewModel.build_rows(devices)

            return Group(
                self._render_navigation_help(),
                self._render_bluetooth_radar(bluetooth_rows, limit=24),
            )

        if self.current_view == "stream":
            return Group(
                self._render_navigation_help(),
                self._render_smart_packet_stream(limit=24),
            )

        if self.current_view == "devices":
            devices = self.registry.all_devices()

            return Group(
                self._render_navigation_help(),
                self._render_device_intelligence(devices, limit=18),
            )

        devices = self.registry.all_devices()
        bluetooth_rows = BluetoothViewModel.build_rows(devices)

        primary_panel = (
            self._render_local_network_visibility(devices, limit=5)
            if self._is_local_visibility_profile()
            else self._render_wifi_air_perimeter(
                WiFiViewModel.build_rows(devices), limit=5
            )
        )

        return Group(
            self._render_navigation_help(),
            primary_panel,
            self._render_bluetooth_radar(bluetooth_rows, limit=5),
            self._render_smart_packet_stream(limit=5),
            self._render_device_intelligence(devices, limit=5),
        )

    def _render_navigation_help(self) -> Panel:
        return Panel(
            "[bold]Navigation[/bold]: "
            f"[0] Overview  [1] {'Local' if self._is_local_visibility_profile() else 'WiFi'}  "
            "[2] Bluetooth  [3] Packet Stream  "
            "[4] Devices  [n] Next  [p] Previous  [l] Local filter  "
            "[j/k] Select  [e] Expand [/] Search  [r] Reset  "
            "[bold]h[/bold] Help  [q] Quit\n"
            f"[bold]Context[/bold]: {self._compact_context_line()}",
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

    def _compact_context_line(self) -> str:
        base_wifi = self._interface_name(
            getattr(self.capture_context, "base_wifi_interface", None),
            "local interface",
        )
        capture_wifi_context = getattr(
            self.capture_context, "capture_wifi_interface", None
        )
        capture_wifi = self._interface_name(capture_wifi_context, "")
        bluetooth = self._interface_name(
            getattr(self.capture_context, "bluetooth_interface", None),
            "",
        )

        active_hardware = self._active_hardware_label()

        if self.current_view == "wifi":
            if self._is_local_visibility_profile():
                return (
                    "Local Network Visibility | "
                    f"Hardware: {base_wifi} | "
                    "Mode: managed/promiscuous local capture | "
                    "Visible: ARP, DHCP, DNS, mDNS, SSDP/UPnP, LLMNR, NetBIOS | "
                    "Press h for details"
                )

            return (
                "WiFi Air Perimeter | "
                f"Hardware: {base_wifi} -> {capture_wifi} | "
                "Mode: 802.11 monitor + channel hopping | "
                "Press h for details"
            )

        if self.current_view == "bluetooth":
            return (
                "Bluetooth Radar | "
                f"Hardware: {bluetooth} | "
                "Mode: Basic BLE Scan | "
                "Press h for details"
            )

        if self.current_view == "stream":
            return (
                "Smart Packet Stream | "
                f"Hardware: {active_hardware} | "
                "Mode: normalized multi-source event stream | "
                "Press h for details"
            )

        if self.current_view == "devices":
            search_text = (
                f" | Search: {self.device_search_query}"
                if self.device_search_query
                else ""
            )

            mode_text = " | Typing search..." if self.device_search_mode else ""

            return (
                "Device Intelligence | "
                f"Hardware: {active_hardware} | "
                "Mode: multi-source device correlation | "
                "Press / to search | Press h for details"
                f"{search_text}{mode_text}"
            )

        if self._is_local_visibility_profile():
            return (
                "Overview | "
                f"Hardware: {active_hardware} | "
                "Mode: Local Network Visibility / managed-promiscuous | "
                "Press h for details"
            )

        return (
            "Overview | "
            f"Hardware: {active_hardware} | "
            "Mode: Air Perimeter live monitoring | "
            "Press h for details"
        )

    def _context_for_current_view(self) -> CaptureContext:
        if self.current_view == "bluetooth":
            return self._context_for_view("Bluetooth Radar")

        if self.current_view == "stream":
            return self._context_for_view("Smart Packet Stream")

        if self.current_view == "devices":
            return self._context_for_view("Device Intelligence")

        if self.current_view == "wifi":
            return self.capture_context

        return self.capture_context

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

        table.add_column("Time", no_wrap=True, width=8)
        table.add_column("Radio", no_wrap=True, width=5)
        table.add_column("Proto", no_wrap=True, width=7)
        table.add_column("Type", overflow="ellipsis", no_wrap=True, width=18)
        table.add_column("Device", overflow="fold", no_wrap=False, ratio=3)
        table.add_column("Src", overflow="fold", no_wrap=False, ratio=3)
        table.add_column("Dst", overflow="fold", no_wrap=False, ratio=3)
        table.add_column("Len", justify="right", width=5)
        table.add_column("RSSI", justify="right", width=5)
        table.add_column("CH/Band", justify="right", width=9)
        table.add_column("Flags", overflow="ellipsis", no_wrap=True, width=18)

        summary_full_mode = self.current_view == "stream"

        table.add_column(
            "Summary",
            ratio=5,
            overflow="fold" if summary_full_mode else "ellipsis",
            no_wrap=not summary_full_mode,
        )

        traces = self._current_stream_traces()

        if self.current_view == "stream":
            reversed_traces = list(reversed(traces))
            start = self.stream_page * self.stream_page_size
            end = start + self.stream_page_size
            visible_traces = list(reversed(reversed_traces[start:end]))
        else:
            visible_traces = traces[-limit:]

        devices = self.registry.all_devices()
        device_title_index = self._device_title_index(devices)

        for trace in visible_traces:
            channel_band = "-"

            if trace.channel is not None and trace.band:
                channel_band = f"{trace.channel}/{trace.band}"
            elif trace.channel is not None:
                channel_band = str(trace.channel)
            elif trace.band:
                channel_band = trace.band

            device_name = self._trace_device_name(trace, device_title_index)
            src = self._endpoint_label(trace.src_mac, trace.src_ip)
            dst = self._endpoint_label(trace.dst_mac, trace.dst_ip)

            table.add_row(
                trace.timestamp,
                trace.radio,
                trace.protocol,
                trace.event_type,
                device_name,
                src,
                dst,
                str(trace.length) if trace.length is not None else "-",
                str(trace.rssi) if trace.rssi is not None else "-",
                channel_band,
                trace.flags[:18] if trace.flags else "-",
                trace.summary
                if summary_full_mode
                else self._clip_text(trace.summary, 90),
            )
        title = "Smart Packet Stream"

        if self.current_view == "stream":
            total_pages = max(
                1,
                (len(traces) + self.stream_page_size - 1) // self.stream_page_size,
            )
            filter_text = (
                f" | Filter {self.stream_radio_filter}"
                if self.stream_radio_filter
                else ""
            )
            title = (
                f"Smart Packet Stream | Page {self.stream_page + 1}/{total_pages} "
                f"| Buffer {len(traces)} traces{filter_text}"
            )

        return Panel(table, title=title)

    def _render_device_intelligence_overview(self, items, limit: int = 4) -> Panel:
        table = Table(expand=True)

        table.add_column("Device", overflow="ellipsis", no_wrap=True, ratio=3)
        table.add_column("Radios", no_wrap=True, width=9)
        table.add_column("Role", no_wrap=True, width=10)
        table.add_column("Signal", overflow="ellipsis", no_wrap=True, ratio=3)
        table.add_column("Events", overflow="ellipsis", no_wrap=True, ratio=2)
        table.add_column("Last Behavior", overflow="ellipsis", no_wrap=True, ratio=3)

        for item in items[:limit]:
            table.add_row(
                item.title,
                ", ".join(item.radios_seen) if item.radios_seen else "-",
                item.role,
                item.signal_summary,
                item.events_summary,
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
        table.add_column("Sel", no_wrap=True, width=3)
        table.add_column("Device", overflow="ellipsis", no_wrap=True, ratio=3)
        table.add_column("Radios", no_wrap=True, width=9)
        table.add_column("Role", no_wrap=True, width=10)
        table.add_column("Vendor", overflow="ellipsis", no_wrap=True, ratio=2)
        table.add_column("Signal", overflow="ellipsis", no_wrap=True, ratio=3)
        table.add_column("Events", overflow="ellipsis", no_wrap=True, ratio=2)
        table.add_column("Last Behavior", overflow="ellipsis", no_wrap=True, ratio=3)

        for index, item in enumerate(visible_items):
            marker = ">" if index == self.selected_device_index else " "
            tag = self._device_status_tag(item)

            table.add_row(
                marker,
                f"{item.title} {tag}".strip(),
                ", ".join(item.radios_seen) if item.radios_seen else "-",
                item.role,
                ", ".join(item.vendors) if item.vendors else "unknown",
                item.signal_summary,
                item.events_summary,
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
        items = self._current_device_items()

        if not items:
            return Panel(
                "No devices have been identified yet.",
                title="Device Intelligence",
            )

        if self.current_view == "devices":
            return self._render_device_intelligence_interactive(items)

        return self._render_device_intelligence_overview(items, limit=limit)

    def _endpoint_label(self, mac: str | None, ip: str | None) -> str:
        if mac and ip:
            return f"{mac}/{ip}"

        if mac:
            return mac

        if ip:
            return ip

        return "-"

    def _device_title_index(self, devices) -> dict[str, str]:
        index = {}

        items = DeviceIntelligenceViewModel.build_items(devices)
        item_by_id = {item.device_id: item for item in items}

        for device in devices:
            item = item_by_id.get(device.device_id)

            if not item:
                continue

            title = item.title
            identity = device.identity

            candidates = [
                device.device_id,
                identity.primary_mac,
                getattr(identity, "bluetooth_address", None),
                device.extra.get("bluetooth_address"),
                device.extra.get("ble_address"),
            ]

            candidates.extend(identity.ip_addresses)
            candidates.extend(identity.hostnames)

            for value in candidates:
                if value:
                    index[str(value).lower()] = title

        return index

    def _trace_device_name(
        self,
        trace: SmartPacketTrace,
        device_title_index: dict[str, str],
    ) -> str:
        candidates = [
            trace.device_key,
            trace.src_mac,
            trace.src_ip,
            trace.dst_mac,
            trace.dst_ip,
        ]

        for value in candidates:
            if not value:
                continue

            title = device_title_index.get(str(value).lower())

            if title:
                return title

        return trace.device_key or "unknown"

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

        identity_parts = [
            f"Role={item.role}",
        ]

        if item.mac:
            identity_parts.append(f"MAC={item.mac}")

        if item.bluetooth_address:
            identity_parts.append(f"BLE={item.bluetooth_address}")

        if item.bluetooth_name:
            identity_parts.append(f"BLE Name={item.bluetooth_name}")

        if item.bluetooth_address_type:
            identity_parts.append(f"BLE Type={item.bluetooth_address_type}")

        identity_parts.append(f"Vendor={vendor_text}")

        identity_line = " | ".join(identity_parts)

        network_parts = [
            f"IP={', '.join(item.ip_addresses) if item.ip_addresses else 'not observed'}",
            f"Hostnames={', '.join(item.hostnames) if item.hostnames else 'not observed'}",
        ]

        if item.bluetooth_name:
            network_parts.append(f"BLE Name={item.bluetooth_name}")

        if item.bluetooth_services:
            network_parts.append(
                f"BLE Services={len(item.bluetooth_services)} observed"
            )

        network_line = " | ".join(network_parts)

        signal_line = item.signal_summary

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
        table.add_row("[bold]Identity[/bold]", self._wrap_text(identity_line, 120))
        table.add_row(
            "[bold]Radios[/bold]",
            ", ".join(item.radios_seen) if item.radios_seen else "unknown",
        )
        table.add_row(
            "[bold]Network / Names[/bold]",
            self._wrap_text(network_line, 120),
        )
        table.add_row("[bold]Signal[/bold]", signal_line)
        table.add_row("[bold]Events[/bold]", item.events_summary)

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

        if item.security_evidence:
            table.add_row(
                "[bold]Security evidence[/bold]",
                "\n".join(
                    self._wrap_text(evidence, 120)
                    for evidence in item.security_evidence[:4]
                ),
            )

        if item.ssids_probed:
            table.add_row(
                "[bold]SSIDs probed[/bold]",
                self._clip_text(", ".join(item.ssids_probed), 130),
            )

        if item.bluetooth_services:
            table.add_row(
                "[bold]Bluetooth services[/bold]",
                self._clip_text(", ".join(item.bluetooth_services[:6]), 130),
            )

        if item.services:
            table.add_row(
                "[bold]Services[/bold]",
                self._clip_text(", ".join(item.services), 130),
            )

        if item.related_devices:
            table.add_row(
                "[bold]Related devices[/bold]",
                self._wrap_text(", ".join(item.related_devices), 120),
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

    def _interface_name(self, interface_value, fallback: str) -> str:
        if not interface_value:
            return fallback

        if isinstance(interface_value, str):
            return interface_value

        name = getattr(interface_value, "name", None)

        if name:
            return name

        return str(interface_value)
