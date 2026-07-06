from dataclasses import dataclass

from src.core.models import RawWirelessEvent


@dataclass
class SmartPacketTrace:
    timestamp: str
    radio: str
    protocol: str
    event_type: str
    src_mac: str | None
    src_ip: str | None
    dst_mac: str | None
    dst_ip: str | None
    length: int | None
    rssi: int | None
    channel: int | None
    band: str | None
    flags: str
    device_key: str
    summary: str
    source: str


class SmartPacketStreamModel:
    """
    Builds trace rows for the Smart Packet Stream view.

    This is AirSentry's readable tcpdump-like view.
    It should preserve technical details while staying searchable and readable.
    """

    @staticmethod
    def from_event(event: RawWirelessEvent) -> SmartPacketTrace:
        parsed_fields = event.parsed_fields or {}
        dot11 = parsed_fields.get("dot11", {})
        flags = dot11.get("flags", {})
        size_hints = parsed_fields.get("size_hints", {})

        return SmartPacketTrace(
            timestamp=event.timestamp.strftime("%H:%M:%S"),
            radio=SmartPacketStreamModel._radio_from_event(event),
            source=event.source,
            protocol=SmartPacketStreamModel._display_protocol(event),
            event_type=SmartPacketStreamModel._display_event_type(event),
            src_mac=event.src_mac,
            src_ip=event.src_ip,
            dst_mac=event.dst_mac,
            dst_ip=event.dst_ip,
            length=size_hints.get("total_length"),
            rssi=event.signal.rssi,
            channel=event.signal.channel,
            band=event.signal.band,
            flags=SmartPacketStreamModel._format_flags(flags),
            device_key=SmartPacketStreamModel._device_key(event),
            summary=SmartPacketStreamModel._summary(event),
        )

    @staticmethod
    def _format_flags(flags: dict) -> str:
        if not flags:
            return ""

        active = [name for name, enabled in flags.items() if enabled]
        return ",".join(active)

    @staticmethod
    def _radio_from_event(event: RawWirelessEvent) -> str:
        protocol = (event.protocol or "").upper()
        source = (event.source or "").upper()
        capture_mode = (event.capture_mode or "").upper()

        if protocol in {"BLE", "BT", "BT_HCI", "BLUETOOTH"}:
            return "BT"

        if source.startswith("BLE") or capture_mode.startswith("BT_"):
            return "BT"

        if protocol in {"WIFI", "802.11", "IEEE 802.11"}:
            return "WIFI"

        if source == "WIFI_MONITOR" or capture_mode == "WIFI_MONITOR":
            return "WIFI"

        return "-"

    @staticmethod
    def _device_key(event: RawWirelessEvent) -> str:
        return (
            event.src_mac
            or event.src_ip
            or event.bssid
            or event.extra.get("bluetooth_address")
            or "unknown"
        )

    @staticmethod
    def _summary(event: RawWirelessEvent) -> str:
        if event.event_type == "beacon" and event.ssid:
            security = event.parsed_fields.get("security_profile", {}).get(
                "security", []
            )
            security_text = ", ".join(security) or "unknown security"
            return f'AP beacon SSID="{event.ssid}" security={security_text}'

        if event.event_type == "probe_request":
            return f'Device searched SSID="{event.ssid or "<hidden/wildcard>"}"'

        if event.raw_summary:
            return event.raw_summary

        return event.event_type

    @staticmethod
    def _display_protocol(event: RawWirelessEvent) -> str:
        """
        User-facing protocol.

        Do not display 'WIFI' as a protocol. In Air Perimeter mode,
        the observed wireless frame protocol/standard is IEEE 802.11.
        """
        if event.source == "WIFI_MONITOR" or event.capture_mode == "WIFI_MONITOR":
            return "802.11"

        protocol_map = {
            "MDNS": "mDNS",
            "SSDP": "SSDP",
            "UPNP": "UPnP",
            "NETBIOS": "NetBIOS",
            "LLMNR": "LLMNR",
            "BLE": "BLE",
        }

        return protocol_map.get(event.protocol, event.protocol)

    @staticmethod
    def _display_event_type(event: RawWirelessEvent) -> str:
        """
        User-facing event/frame type.

        For 802.11 monitor-mode events, convert numeric subtype labels into
        human-readable WiFi frame names.
        """
        if event.source == "WIFI_MONITOR" or event.capture_mode == "WIFI_MONITOR":
            return SmartPacketStreamModel._display_80211_type(event)

        return event.event_type

    @staticmethod
    def _display_80211_type(event: RawWirelessEvent) -> str:
        dot11 = event.parsed_fields.get("dot11", {})
        frame_type = dot11.get("frame_type")
        frame_subtype = dot11.get("frame_subtype")

        management_subtypes = {
            0: "Association Request",
            1: "Association Response",
            2: "Reassociation Request",
            3: "Reassociation Response",
            4: "Probe Request",
            5: "Probe Response",
            8: "Beacon",
            9: "ATIM",
            10: "Disassociation",
            11: "Authentication",
            12: "Deauthentication",
            13: "Action",
            14: "Action No Ack",
        }

        control_subtypes = {
            7: "Control Wrapper",
            8: "Block ACK Request",
            9: "Block ACK",
            10: "PS-Poll",
            11: "RTS",
            12: "CTS",
            13: "ACK",
            14: "CF-End",
            15: "CF-End + CF-ACK",
        }

        data_subtypes = {
            0: "Data",
            1: "Data + CF-ACK",
            2: "Data + CF-Poll",
            3: "Data + CF-ACK + CF-Poll",
            4: "Null Data",
            5: "CF-ACK",
            6: "CF-Poll",
            7: "CF-ACK + CF-Poll",
            8: "QoS Data",
            9: "QoS Data + CF-ACK",
            10: "QoS Data + CF-Poll",
            11: "QoS Data + CF-ACK + CF-Poll",
            12: "QoS Null",
            14: "QoS CF-Poll",
            15: "QoS CF-ACK + CF-Poll",
        }

        if frame_type == 0:
            return management_subtypes.get(
                frame_subtype,
                f"Management subtype {frame_subtype}",
            )

        if frame_type == 1:
            return control_subtypes.get(
                frame_subtype,
                f"Control subtype {frame_subtype}",
            )

        if frame_type == 2:
            return data_subtypes.get(
                frame_subtype,
                f"Data subtype {frame_subtype}",
            )

        return event.event_type
