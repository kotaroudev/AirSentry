from dataclasses import dataclass, field

from src.core.models import DeviceBehavior, DeviceProfile


@dataclass
class DeviceIntelligenceItem:
    title: str
    device_id: str
    role: str
    mac: str | None
    ip_addresses: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    vendors: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    network_layers_seen: list[str] = field(default_factory=list)
    capture_metadata_used: list[str] = field(default_factory=list)
    frame_families_seen: list[str] = field(default_factory=list)
    frame_types_seen: list[str] = field(default_factory=list)
    ssids_probed: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    related_devices: list[str] = field(default_factory=list)
    packet_count: int = 0
    event_count: int = 0
    avg_wifi_rssi: float | None = None
    avg_bluetooth_rssi: float | None = None
    proximity: str = "unknown"
    confidence: float = 0.0
    risk_notes: list[str] = field(default_factory=list)
    recent_behaviors: list[DeviceBehavior] = field(default_factory=list)
    identity_notes: list[str] = field(default_factory=list)


class DeviceIntelligenceViewModel:
    """
    Builds human-readable device intelligence cards from DeviceProfile data.

    This view is not a raw packet table. It is the correlated, interpreted,
    device-centric view of AirSentry.
    """

    @staticmethod
    def build_items(devices: list[DeviceProfile]) -> list[DeviceIntelligenceItem]:
        items = []

        for device in devices:
            items.append(DeviceIntelligenceViewModel._build_item(device))

        return sorted(
            items,
            key=lambda item: (
                DeviceIntelligenceViewModel._role_priority(item.role),
                -item.packet_count,
            ),
        )

    @staticmethod
    def _build_item(device: DeviceProfile) -> DeviceIntelligenceItem:
        identity = device.identity

        mac = identity.primary_mac or device.device_id
        role = DeviceIntelligenceViewModel._infer_role(device)

        title = DeviceIntelligenceViewModel._build_title(device, role, mac)
        avg_wifi_rssi = device.avg_wifi_rssi()
        avg_bluetooth_rssi = device.avg_bluetooth_rssi()

        proximity = DeviceIntelligenceViewModel._rssi_to_proximity(avg_wifi_rssi)

        recent_behaviors = device.behaviors[-30:] if device.behaviors else []

        identity_notes = DeviceIntelligenceViewModel._build_identity_notes(device)

        protocols = DeviceIntelligenceViewModel._display_protocols(
            identity.protocols_seen
        )
        network_layers_seen = DeviceIntelligenceViewModel._display_layers(
            identity.protocols_seen
        )
        capture_metadata_used = DeviceIntelligenceViewModel._display_capture_metadata(
            device
        )
        frame_families_seen = DeviceIntelligenceViewModel._display_frame_families(
            device
        )
        frame_types_seen = DeviceIntelligenceViewModel._display_frame_types(device)

        return DeviceIntelligenceItem(
            title=title,
            device_id=device.device_id,
            role=role,
            mac=mac,
            ip_addresses=sorted(identity.ip_addresses),
            hostnames=sorted(identity.hostnames),
            vendors=sorted(identity.vendors),
            protocols=protocols,
            network_layers_seen=network_layers_seen,
            capture_metadata_used=capture_metadata_used,
            frame_families_seen=frame_families_seen,
            frame_types_seen=frame_types_seen,
            ssids_probed=sorted(identity.ssids_probed),
            services=sorted(identity.services),
            related_devices=sorted(device.related_devices),
            packet_count=device.packet_count,
            event_count=device.event_count,
            avg_wifi_rssi=avg_wifi_rssi,
            avg_bluetooth_rssi=avg_bluetooth_rssi,
            proximity=proximity,
            confidence=identity.confidence,
            risk_notes=device.risk_notes[-5:],
            recent_behaviors=recent_behaviors,
            identity_notes=identity_notes,
        )

    @staticmethod
    def _build_title(device: DeviceProfile, role: str, mac: str) -> str:
        identity = device.identity

        if identity.hostnames:
            return sorted(identity.hostnames)[0]

        if role == "AP":
            wifi_air_profile = device.extra.get("wifi_air_profile") or {}
            wifi_last = device.extra.get("wifi_last") or {}
            ssid = wifi_air_profile.get("ssid") or wifi_last.get("ssid")

            if ssid:
                return f"AP {ssid}"

        if identity.ssids_probed:
            return f"WiFi client probing {sorted(identity.ssids_probed)[0]}"

        if role == "CLIENT":
            return f"WiFi client {mac}"

        if role == "STA":
            return f"WiFi station {mac}"

        return f"{role} {mac}"

    @staticmethod
    def _infer_role(device: DeviceProfile) -> str:
        suspected_type = device.identity.suspected_device_type or ""

        if suspected_type == "WiFi access point":
            return "AP"

        if suspected_type == "WiFi client device":
            return "CLIENT"

        if device.identity.bluetooth_address:
            return "BLUETOOTH"

        if device.identity.ip_addresses:
            return "LOCAL DEVICE"

        if (
            device.last_behavior
            and "Protected WiFi frame" in device.last_behavior.title
        ):
            return "STA"

        return "UNKNOWN"

    @staticmethod
    def _rssi_to_proximity(rssi: float | None) -> str:
        if rssi is None:
            return "unknown"

        if rssi >= -50:
            return "very near / excellent signal"

        if rssi >= -65:
            return "near / good signal"

        if rssi >= -75:
            return "medium range / fair signal"

        if rssi >= -85:
            return "far / weak signal"

        return "edge of reception / very weak signal"

    @staticmethod
    def _build_identity_notes(device: DeviceProfile) -> list[str]:
        notes = []

        if device.identity.suspected_device_type:
            notes.append(f"Type inferred as {device.identity.suspected_device_type}.")

        if device.identity.ssids_probed:
            notes.append("Device revealed remembered SSIDs through probe requests.")

        if not device.identity.hostnames and not device.identity.ip_addresses:
            notes.append(
                "No hostname or IP observed yet. Local Network Visibility mode "
                "may help correlate this device through ARP, DHCP, mDNS or SSDP."
            )

        if device.identity.primary_mac and not device.identity.vendors:
            notes.append(
                "Vendor is unknown from the current local OUI seed list. A full OUI database can improve identification later."
            )

        if device.identity.confidence <= 0:
            notes.append(
                "Identity is based on wireless observations only; confidence may improve "
                "with more collectors or persistent sessions."
            )

        if device.identity.extra.get("mac_randomization"):
            notes.append(
                "MAC appears locally administered/randomized. This is common on phones, "
                "laptops and privacy-focused devices, and can reduce identity confidence."
            )

        if device.identity.vendors:
            notes.append(
                "Vendor/OUI is soft evidence from the MAC prefix. It may be wrong if the "
                "device uses MAC randomization, spoofing, extenders, virtual interfaces or "
                "an incomplete local OUI database."
            )

        return notes

    @staticmethod
    def _role_priority(role: str) -> int:
        priorities = {
            "AP": 0,
            "CLIENT": 1,
            "LOCAL DEVICE": 2,
            "BLUETOOTH": 3,
            "STA": 4,
            "UNKNOWN": 5,
        }

        return priorities.get(role, 9)

    @staticmethod
    def _display_protocols(protocols: set[str]) -> list[str]:
        protocol_map = {
            "WIFI": "IEEE 802.11",
            "MDNS": "mDNS",
            "SSDP": "SSDP",
            "UPNP": "UPnP",
            "NETBIOS": "NetBIOS",
            "LLMNR": "LLMNR",
            "BLE": "BLE",
            "BT_HCI": "Bluetooth HCI",
        }

        return [protocol_map.get(protocol, protocol) for protocol in sorted(protocols)]

    @staticmethod
    def _display_layers(protocols: set[str]) -> list[str]:
        layers = set()

        for protocol in protocols:
            if protocol == "WIFI":
                layers.add("OSI L2 / IEEE 802.11 wireless link")

            elif protocol == "ARP":
                layers.add("OSI L2 / ARP")

            elif protocol in {"IP", "IPv4", "IPv6", "ICMP"}:
                layers.add("OSI L3 / network layer")

            elif protocol in {"TCP", "UDP"}:
                layers.add("OSI L4 / transport layer")

            elif protocol in {
                "MDNS",
                "DNS",
                "DHCP",
                "SSDP",
                "UPNP",
                "LLMNR",
                "NETBIOS",
            }:
                layers.add("OSI L7 / application layer")

            elif protocol in {"BLE", "BT_HCI"}:
                layers.add("Bluetooth radio/controller layer")

            else:
                layers.add("uncategorized layer")

        return sorted(layers)

    @staticmethod
    def _display_capture_metadata(device: DeviceProfile) -> list[str]:
        metadata = set()
        identity = device.identity

        if "WIFI" in identity.protocols_seen:
            metadata.add("capture timestamp")

            if identity.primary_mac:
                metadata.add("source/destination MAC")

            if device.wifi_rssi_samples:
                metadata.add("RSSI")
                metadata.add("RadioTap")

            wifi_last = device.extra.get("wifi_last", {})
            wifi_air_profile = device.extra.get("wifi_air_profile", {})

            if wifi_last.get("channel") or wifi_air_profile.get("channel"):
                metadata.add("observed channel")
                metadata.add("RadioTap")

            if wifi_last.get("band") or wifi_air_profile.get("band"):
                metadata.add("band")

            if wifi_last.get("frequency_mhz") or wifi_air_profile.get("frequency_mhz"):
                metadata.add("frequency")

        if identity.ip_addresses:
            metadata.add("source/destination IP")

        if "BLE" in identity.protocols_seen or "BT_HCI" in identity.protocols_seen:
            metadata.add("Bluetooth interface")

            if device.bluetooth_rssi_samples:
                metadata.add("Bluetooth RSSI")

        return sorted(metadata)

    @staticmethod
    def _display_frame_families(device: DeviceProfile) -> list[str]:
        families = set()

        for event_type in device.most_common_events:
            lowered = event_type.lower()

            if "beacon" in lowered or "probe" in lowered or "management" in lowered:
                families.add("802.11 management")

            elif (
                "rts" in lowered
                or "cts" in lowered
                or "ack" in lowered
                or "control" in lowered
            ):
                families.add("802.11 control")

            elif "data" in lowered or "qos" in lowered:
                families.add("802.11 data")

        return sorted(families)

    @staticmethod
    def _display_frame_types(device: DeviceProfile) -> list[str]:
        if not device.most_common_events:
            return []

        names = []

        for event_type, count in sorted(
            device.most_common_events.items(),
            key=lambda item: item[1],
            reverse=True,
        )[:8]:
            display_name = DeviceIntelligenceViewModel._display_80211_event_type(
                event_type
            )
            names.append(f"{display_name} ({count})")

        return names

    @staticmethod
    def _display_80211_event_type(event_type: str) -> str:
        type_map = {
            # Common normalized events
            "beacon": "Beacon",
            "probe_request": "Probe Request",
            "probe_response": "Probe Response",
            # 802.11 management frame subtypes
            "management_subtype_0": "Association Request",
            "management_subtype_1": "Association Response",
            "management_subtype_2": "Reassociation Request",
            "management_subtype_3": "Reassociation Response",
            "management_subtype_4": "Probe Request",
            "management_subtype_5": "Probe Response",
            "management_subtype_6": "Timing Advertisement",
            "management_subtype_7": "Reserved Management Frame",
            "management_subtype_8": "Beacon",
            "management_subtype_9": "ATIM",
            "management_subtype_10": "Disassociation",
            "management_subtype_11": "Authentication",
            "management_subtype_12": "Deauthentication",
            "management_subtype_13": "Action",
            "management_subtype_14": "Action No Ack",
            "management_subtype_15": "Reserved Management Frame",
            # 802.11 control frame subtypes
            "control_subtype_0": "Reserved Control Frame",
            "control_subtype_1": "Reserved Control Frame",
            "control_subtype_2": "Trigger",
            "control_subtype_3": "TACK",
            "control_subtype_4": "Beamforming Report Poll",
            "control_subtype_5": "VHT/HE NDP Announcement",
            "control_subtype_6": "Control Frame Extension",
            "control_subtype_7": "Control Wrapper",
            "control_subtype_8": "Block ACK Request",
            "control_subtype_9": "Block ACK",
            "control_subtype_10": "PS-Poll",
            "control_subtype_11": "RTS",
            "control_subtype_12": "CTS",
            "control_subtype_13": "ACK",
            "control_subtype_14": "CF-End",
            "control_subtype_15": "CF-End + CF-ACK",
            # 802.11 data frame subtypes
            "data_subtype_0": "Data",
            "data_subtype_1": "Data + CF-ACK",
            "data_subtype_2": "Data + CF-Poll",
            "data_subtype_3": "Data + CF-ACK + CF-Poll",
            "data_subtype_4": "Null Data",
            "data_subtype_5": "CF-ACK",
            "data_subtype_6": "CF-Poll",
            "data_subtype_7": "CF-ACK + CF-Poll",
            "data_subtype_8": "QoS Data",
            "data_subtype_9": "QoS Data + CF-ACK",
            "data_subtype_10": "QoS Data + CF-Poll",
            "data_subtype_11": "QoS Data + CF-ACK + CF-Poll",
            "data_subtype_12": "QoS Null",
            "data_subtype_13": "Reserved Data Frame",
            "data_subtype_14": "QoS CF-Poll",
            "data_subtype_15": "QoS CF-ACK + CF-Poll",
        }

        return type_map.get(event_type, event_type)
