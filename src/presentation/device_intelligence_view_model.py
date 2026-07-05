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

        recent_behaviors = device.behaviors[-5:] if device.behaviors else []

        identity_notes = DeviceIntelligenceViewModel._build_identity_notes(device)

        return DeviceIntelligenceItem(
            title=title,
            device_id=device.device_id,
            role=role,
            mac=mac,
            ip_addresses=sorted(identity.ip_addresses),
            hostnames=sorted(identity.hostnames),
            vendors=sorted(identity.vendors),
            protocols=sorted(identity.protocols_seen),
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
