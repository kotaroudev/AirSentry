from rich.panel import Panel
from rich.table import Table

from src.core.capture_context import CaptureContext


class ContextPanel:
    """
    Renders capture/session context for every AirSentry view.

    Every view should tell the user:
    - what capture profile is active
    - which chip/interface is being used
    - what AirSentry can observe
    - what AirSentry cannot observe in this mode
    - whether data is persistent or memory-only
    """

    @staticmethod
    def render(context: CaptureContext, view_name: str) -> Panel:
        table = Table.grid(expand=True)
        table.add_column(ratio=1)
        table.add_column(ratio=1)

        left = ContextPanel._render_capture_side(context, view_name)
        right = ContextPanel._render_visibility_side(context)

        table.add_row(left, right)

        return Panel(table, title=f"{view_name} Context")

    @staticmethod
    def _render_capture_side(context: CaptureContext, view_name: str) -> str:
        lines = [
            f"[bold]View[/bold]: {view_name}",
            f"[bold]Profile[/bold]: {context.profile_name}",
            f"[bold]Profile Goal[/bold]: {context.profile_description}",
            f"[bold]Storage[/bold]: {context.active_storage}",
            f"[bold]Channel Strategy[/bold]: {context.channel_strategy}",
            f"[bold]Payload Visibility[/bold]: {context.payload_visibility}",
        ]

        if context.base_wifi_interface:
            iface = context.base_wifi_interface
            lines.extend(
                [
                    "",
                    "[bold]Base WiFi Interface[/bold]",
                    f"Name: {iface.name}",
                    f"Role: {iface.role}",
                    f"Mode: {iface.mode or 'unknown'}",
                    f"Driver: {iface.driver or 'unknown'}",
                    f"MAC: {iface.mac_address or 'unknown'}",
                ]
            )

        if context.capture_wifi_interface:
            iface = context.capture_wifi_interface
            lines.extend(
                [
                    "",
                    "[bold]Capture WiFi Interface[/bold]",
                    f"Name: {iface.name}",
                    f"Role: {iface.role}",
                    f"Mode: {iface.mode or 'unknown'}",
                    f"MAC: {iface.mac_address or 'temporary/unknown'}",
                    f"Signal Power: {iface.signal_power or 'per-device RSSI'}",
                    f"Approx Range: {iface.approximate_range or 'RSSI-based estimate only'}",
                ]
            )

        if context.bluetooth_interface:
            iface = context.bluetooth_interface
            lines.extend(
                [
                    "",
                    "[bold]Bluetooth Interface[/bold]",
                    f"Name: {iface.name}",
                    f"Role: {iface.role}",
                    f"Mode: {iface.mode or 'unknown'}",
                    f"MAC: {iface.mac_address or 'unknown'}",
                ]
            )

        return "\n".join(lines)

    @staticmethod
    def _render_visibility_side(context: CaptureContext) -> str:
        capture_metadata = (
            ", ".join(context.capture_metadata)
            or ", ".join(context.visible_layers)
            or "unknown"
        )

        network_layers = ", ".join(context.network_layers) or "unknown"

        observed_protocols = (
            ", ".join(context.observed_protocols)
            or ", ".join(context.visible_protocols)
            or "unknown"
        )

        frame_families = ", ".join(context.frame_families) or "not applicable"

        lines = [
            "[bold]Capture Metadata[/bold]",
            capture_metadata,
            "",
            "[bold]Network Layers Observed[/bold]",
            network_layers,
            "",
            "[bold]Observed Protocols / Standards[/bold]",
            observed_protocols,
            "",
            "[bold]Observed Frame / Message Families[/bold]",
            frame_families,
            "",
            "[bold]Limitations[/bold]",
        ]

        if context.limitations:
            lines.extend(f"- {limitation}" for limitation in context.limitations)
        else:
            lines.append("- none documented")

        # lines.extend(
        #     [
        #         "",
        #         "[bold]Memory Policy[/bold]",
        #         context.memory_policy,
        #         "",
        #         "[bold]Persistence[/bold]",
        #         context.persistence_hint,
        #     ]
        # )

        return "\n".join(lines)
