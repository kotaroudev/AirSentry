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

    radios_seen: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    network_layers_seen: list[str] = field(default_factory=list)
    capture_metadata_used: list[str] = field(default_factory=list)
    frame_families_seen: list[str] = field(default_factory=list)
    frame_types_seen: list[str] = field(default_factory=list)
    security_evidence: list[str] = field(default_factory=list)

    ssids_probed: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    bluetooth_services: list[str] = field(default_factory=list)
    related_devices: list[str] = field(default_factory=list)

    packet_count: int = 0
    event_count: int = 0
    wifi_event_count: int = 0
    bluetooth_event_count: int = 0
    events_summary: str = "0"

    avg_wifi_rssi: float | None = None
    avg_bluetooth_rssi: float | None = None
    signal_summary: str = "unknown"
    proximity: str = "unknown"

    bluetooth_name: str | None = None
    bluetooth_address: str | None = None
    bluetooth_address_type: str | None = None

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
        pairs = []

        for device in devices:
            item = DeviceIntelligenceViewModel._build_item(device)
            pairs.append((device, item))

        title_index = DeviceIntelligenceViewModel._build_title_index(pairs)

        for device, item in pairs:
            item.related_devices = DeviceIntelligenceViewModel._display_related_devices(
                device,
                title_index,
            )

        items = [item for _, item in pairs]

        return sorted(
            items,
            key=lambda item: (
                DeviceIntelligenceViewModel._role_priority(item.role),
                -item.event_count,
            ),
        )

    @staticmethod
    def _build_title_index(
        pairs: list[tuple[DeviceProfile, DeviceIntelligenceItem]],
    ) -> dict[str, str]:
        index = {}

        for device, item in pairs:
            identity = device.identity

            values = [
                device.device_id,
                identity.primary_mac,
                identity.bluetooth_address,
                device.extra.get("bluetooth_address"),
                device.extra.get("ble_address"),
            ]

            values.extend(identity.ip_addresses)
            values.extend(identity.hostnames)

            for value in values:
                if not value:
                    continue

                normalized = str(value).strip().lower()

                if normalized:
                    index[normalized] = item.title

        return index

    @staticmethod
    def _display_related_devices(
        device: DeviceProfile,
        title_index: dict[str, str],
    ) -> list[str]:
        related = []

        for value in sorted(device.related_devices):
            normalized = str(value).strip().lower()

            if not normalized:
                continue

            title = title_index.get(normalized)

            if title:
                related.append(title)
                continue

            display_value = DeviceIntelligenceViewModel._display_address_as_device_name(
                normalized
            )

            related.append(f"Observed endpoint {display_value}")

        return sorted(set(related))

    @staticmethod
    def _build_item(device: DeviceProfile) -> DeviceIntelligenceItem:
        identity = device.identity

        mac = (
            identity.primary_mac
            or identity.bluetooth_address
            or device.extra.get("bluetooth_address")
            or device.device_id
        )
        role = DeviceIntelligenceViewModel._infer_role(device)

        title = DeviceIntelligenceViewModel._build_title(device, role, mac)
        avg_wifi_rssi = device.avg_wifi_rssi()
        avg_bluetooth_rssi = device.avg_bluetooth_rssi()

        radios_seen = DeviceIntelligenceViewModel._display_radios(device)
        wifi_event_count = DeviceIntelligenceViewModel._radio_event_count(
            device, "WIFI"
        )
        bluetooth_event_count = DeviceIntelligenceViewModel._radio_event_count(
            device, "BT"
        )
        signal_summary = DeviceIntelligenceViewModel._display_signal_summary(
            avg_wifi_rssi,
            avg_bluetooth_rssi,
        )
        events_summary = DeviceIntelligenceViewModel._display_events_summary(
            device.event_count,
            wifi_event_count,
            bluetooth_event_count,
        )
        security_evidence = DeviceIntelligenceViewModel._display_security_evidence(
            device
        )

        bluetooth_name = (
            device.extra.get("bluetooth_name")
            or device.extra.get("ble_name")
            or device.extra.get("name")
        )

        bluetooth_address = (
            identity.bluetooth_address
            or device.extra.get("bluetooth_address")
            or device.extra.get("ble_address")
        )

        bluetooth_address_type = device.extra.get("address_type")

        bluetooth_services = DeviceIntelligenceViewModel._display_bluetooth_services(
            device
        )

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
            radios_seen=radios_seen,
            protocols=protocols,
            network_layers_seen=network_layers_seen,
            capture_metadata_used=capture_metadata_used,
            frame_families_seen=frame_families_seen,
            frame_types_seen=frame_types_seen,
            security_evidence=security_evidence,
            ssids_probed=sorted(identity.ssids_probed),
            services=sorted(identity.services),
            bluetooth_services=bluetooth_services,
            related_devices=sorted(device.related_devices),
            packet_count=device.packet_count,
            event_count=device.event_count,
            wifi_event_count=wifi_event_count,
            bluetooth_event_count=bluetooth_event_count,
            events_summary=events_summary,
            avg_wifi_rssi=avg_wifi_rssi,
            avg_bluetooth_rssi=avg_bluetooth_rssi,
            signal_summary=signal_summary,
            proximity=proximity,
            bluetooth_name=bluetooth_name,
            bluetooth_address=bluetooth_address,
            bluetooth_address_type=bluetooth_address_type,
            confidence=identity.confidence,
            risk_notes=device.risk_notes[-5:],
            recent_behaviors=recent_behaviors,
            identity_notes=identity_notes,
        )

    @staticmethod
    def _build_title(device: DeviceProfile, role: str, mac: str) -> str:
        identity = device.identity

        wifi_air_profile = device.extra.get("wifi_air_profile") or {}
        wifi_last = device.extra.get("wifi_last") or {}

        ssid = wifi_air_profile.get("ssid") or wifi_last.get("ssid")

        if role == "AP" and ssid:
            return f"AP {ssid}"

        bluetooth_name = (
            device.extra.get("bluetooth_name")
            or device.extra.get("ble_name")
            or device.extra.get("name")
        )

        if DeviceIntelligenceViewModel._is_meaningful_device_name(bluetooth_name):
            return bluetooth_name

        meaningful_hostnames = [
            hostname
            for hostname in sorted(identity.hostnames)
            if DeviceIntelligenceViewModel._is_meaningful_device_name(hostname)
        ]

        if meaningful_hostnames:
            return meaningful_hostnames[0]

        if identity.ssids_probed:
            return f"WiFi client probing {sorted(identity.ssids_probed)[0]}"

        bluetooth_address = (
            identity.bluetooth_address
            or device.extra.get("bluetooth_address")
            or device.extra.get("ble_address")
        )

        if role == "BLUETOOTH" and bluetooth_address:
            return DeviceIntelligenceViewModel._display_address_as_device_name(
                bluetooth_address
            )

        if role == "CLIENT":
            return f"WiFi client {mac}"

        if role == "STA":
            return f"WiFi station {mac}"

        if bluetooth_address:
            return DeviceIntelligenceViewModel._display_address_as_device_name(
                bluetooth_address
            )

        return f"{role} {mac}"

    @staticmethod
    def _is_meaningful_device_name(value: str | None) -> bool:
        if not value:
            return False

        normalized = value.strip()

        if not normalized:
            return False

        lowered = normalized.lower()

        bad_prefixes = (
            "addresstype:",
            "address type:",
            "rssi:",
            "txpower:",
            "legacypairing:",
            "manufacturerdata",
            "manufacturerdata.value",
            "uuids:",
            "uuid:",
            "paired:",
            "connected:",
            "trusted:",
            "blocked:",
            "icon:",
            "class:",
            "modalias:",
        )

        if lowered.startswith(bad_prefixes):
            return False

        return True

    @staticmethod
    def _display_address_as_device_name(address: str) -> str:
        return address.replace(":", "-").upper()

    @staticmethod
    def _display_radios(device: DeviceProfile) -> list[str]:
        radios = set()
        protocols = device.identity.protocols_seen
        counts = device.extra.get("radio_event_counts", {})

        if "WIFI" in protocols or counts.get("WIFI"):
            radios.add("WIFI")

        if "BLE" in protocols or "BT_HCI" in protocols or counts.get("BT"):
            radios.add("BT")

        return sorted(radios)

    @staticmethod
    def _radio_event_count(device: DeviceProfile, radio: str) -> int:
        counts = device.extra.get("radio_event_counts", {})

        if radio in counts:
            return int(counts.get(radio) or 0)

        if radio == "WIFI" and "WIFI" in device.identity.protocols_seen:
            return device.event_count

        if radio == "BT" and (
            "BLE" in device.identity.protocols_seen
            or "BT_HCI" in device.identity.protocols_seen
        ):
            return device.event_count

        return 0

    @staticmethod
    def _display_signal_summary(
        avg_wifi_rssi: float | None,
        avg_bluetooth_rssi: float | None,
    ) -> str:
        parts = []

        if avg_wifi_rssi is not None:
            parts.append(
                "WiFi "
                f"{avg_wifi_rssi:.1f} dBm "
                f"({DeviceIntelligenceViewModel._rssi_to_proximity(avg_wifi_rssi)})"
            )

        if avg_bluetooth_rssi is not None:
            parts.append(
                "BT "
                f"{avg_bluetooth_rssi:.1f} dBm "
                f"({DeviceIntelligenceViewModel._rssi_to_proximity(avg_bluetooth_rssi)})"
            )

        return " | ".join(parts) if parts else "unknown"

    @staticmethod
    def _display_events_summary(
        total_events: int,
        wifi_events: int,
        bluetooth_events: int,
    ) -> str:
        parts = [f"Total {total_events}"]

        if wifi_events:
            parts.append(f"WiFi {wifi_events}")

        if bluetooth_events:
            parts.append(f"BT {bluetooth_events}")

        return " | ".join(parts)

    @staticmethod
    def _display_bluetooth_services(device: DeviceProfile) -> list[str]:
        services = device.extra.get("service_uuids") or []

        if isinstance(services, set):
            services = sorted(services)

        if not isinstance(services, list):
            return []

        return [str(service) for service in services if service]

    @staticmethod
    def _display_security_evidence(device: DeviceProfile) -> list[str]:
        evidence = []
        identity = device.identity

        wifi_air_profile = device.extra.get("wifi_air_profile") or {}
        wifi_last = device.extra.get("wifi_last") or {}

        security_profile = (
            wifi_air_profile.get("security")
            or wifi_last.get("security")
            or device.extra.get("wifi_security")
        )

        if isinstance(security_profile, dict):
            security_labels = security_profile.get("security") or security_profile.get(
                "security_labels"
            )
            akm_suites = security_profile.get("akm_suites")
            pairwise_ciphers = security_profile.get("pairwise_ciphers")
            group_cipher = security_profile.get("group_cipher")
            is_open = security_profile.get("is_open")

            if security_labels:
                evidence.append(
                    "WiFi security: "
                    + ", ".join(str(value) for value in security_labels)
                )

            if akm_suites:
                evidence.append(
                    "WiFi AKM: " + ", ".join(str(value) for value in akm_suites)
                )

            if pairwise_ciphers:
                evidence.append(
                    "WiFi pairwise cipher: "
                    + ", ".join(str(value) for value in pairwise_ciphers)
                )

            if group_cipher:
                evidence.append(f"WiFi group cipher: {group_cipher}")

            if is_open is True:
                evidence.append("Open WiFi network advertised")

        elif isinstance(security_profile, list):
            evidence.append(
                "WiFi security: " + ", ".join(str(value) for value in security_profile)
            )

        elif security_profile:
            evidence.append(f"WiFi security: {security_profile}")

        if "WIFI" in identity.protocols_seen:
            for behavior in device.behaviors[-20:]:
                text = f"{behavior.title} {behavior.description}".lower()

                if "protected" in text or "encrypted" in text:
                    evidence.append("Protected 802.11 frame metadata observed")
                    break

        if "BLE" in identity.protocols_seen or "BT_HCI" in identity.protocols_seen:
            address_type = device.extra.get("address_type")

            if address_type:
                evidence.append(f"BLE address type: {address_type}")

            evidence.append(
                "BLE advertising metadata observed; connected payload security is not visible in Basic BLE Scan"
            )

        return sorted(set(evidence))

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
            metadata.add("BLE address")
            metadata.add("advertising timestamp")

            if device.extra.get("bluetooth_name"):
                metadata.add("advertised BLE name")

            if device.extra.get("service_uuids"):
                metadata.add("service UUIDs")

            if device.extra.get("manufacturer_data"):
                metadata.add("manufacturer data")

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

        if "BLE" in device.identity.protocols_seen:
            families.add("BLE advertisements")

        return sorted(families)

    @staticmethod
    def _display_event_type(event_type: str) -> str:
        event_map = {
            "ble_advertisement": "BLE Advertisement",
            "ble_scan_response": "BLE Scan Response",
            "ble_device_seen": "BLE Device Seen",
        }

        if event_type in event_map:
            return event_map[event_type]

        return DeviceIntelligenceViewModel._display_80211_event_type(event_type)

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
            display_name = DeviceIntelligenceViewModel._display_event_type(event_type)
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
