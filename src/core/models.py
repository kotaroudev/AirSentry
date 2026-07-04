from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class SignalSample:
    """
    Represents signal/proximity data observed from WiFi or Bluetooth.

    RSSI is usually negative. Example: -35 is strong/near, -85 is weak/far.
    """

    rssi: int | None = None
    channel: int | None = None
    frequency_mhz: int | None = None
    band: str | None = None
    noise: int | None = None
    rate: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class PacketEvidence:
    """
    A single piece of evidence extracted from an observed packet or event.

    This is important because AirSentry should explain why it believes something.
    """

    source: str
    evidence_type: str
    description: str
    confidence: float = 0.0
    timestamp: datetime = field(default_factory=utc_now)
    raw_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class DeviceBehavior:
    """
    Human-readable behavior observed or inferred from packets.

    This is the core of the Device Intelligence Summary view.
    AirSentry should separate direct evidence from suspicious or inferred behavior.
    """

    category: str
    title: str
    description: str
    confidence: float = 0.0
    severity: str = "info"
    timestamp: datetime = field(default_factory=utc_now)
    protocol: str | None = None
    event_type: str | None = None
    raw_event_id: str | None = None
    raw_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class RawWirelessEvent:
    """
    Lowest-level event AirSentry stores after receiving data from any collector.

    This model is intentionally flexible. WiFi, BLE, ARP, DHCP, mDNS, SSDP,
    UPnP, NetBIOS, LLMNR, and future protocols can all fit here.

    The goal is to avoid losing information, even if the MVP does not process
    all fields yet.
    """

    event_id: str
    timestamp: datetime
    source: str

    # Examples:
    # WIFI_MONITOR, WIFI_PROMISCUOUS, WIFI_MANAGED, BT_HCI, BT_BLE
    capture_mode: str

    # Examples:
    # WIFI, BLE, ARP, DHCP, MDNS, SSDP, UPNP, NETBIOS, LLMNR, UNKNOWN
    protocol: str

    # Examples:
    # beacon, probe_request, probe_response, data, arp_request, mdns_response
    event_type: str

    interface: str | None = None

    src_mac: str | None = None
    dst_mac: str | None = None
    bssid: str | None = None

    src_ip: str | None = None
    dst_ip: str | None = None

    ssid: str | None = None
    hostname: str | None = None
    service_name: str | None = None
    vendor: str | None = None

    signal: SignalSample = field(default_factory=SignalSample)

    # Parsed packet fields. This should hold all useful decoded headers/fields.
    parsed_fields: dict[str, Any] = field(default_factory=dict)

    # Protocol-specific fields that do not have first-class columns yet.
    extra: dict[str, Any] = field(default_factory=dict)

    # Optional forensic fields. Keep disabled or minimized by default if needed.
    raw_summary: str | None = None
    raw_layers: list[str] = field(default_factory=list)
    raw_bytes_hex: str | None = None


@dataclass
class NormalizedDeviceEvent:
    """
    Human-readable event derived from RawWirelessEvent.

    This is what powers the Smart Packet Stream.
    """

    timestamp: datetime
    device_key: str
    protocol: str
    event_type: str
    title: str
    description: str
    severity: str = "info"

    related_mac: str | None = None
    related_ip: str | None = None
    evidence: list[PacketEvidence] = field(default_factory=list)
    raw_event_id: str | None = None


@dataclass
class DeviceIdentity:
    """
    Identity hints collected from multiple protocols.

    Nothing here should be treated as absolute truth unless confidence is high
    and evidence supports it.
    """

    primary_mac: str | None = None
    bluetooth_address: str | None = None
    ip_addresses: set[str] = field(default_factory=set)

    hostnames: set[str] = field(default_factory=set)
    vendors: set[str] = field(default_factory=set)
    ssids_probed: set[str] = field(default_factory=set)
    services: set[str] = field(default_factory=set)
    protocols_seen: set[str] = field(default_factory=set)

    suspected_device_type: str | None = None
    confidence: float = 0.0

    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class DeviceProfile:
    """
    Aggregated device-centric profile.

    This is the backbone of the future Device Intelligence Summary view.
    """

    device_id: str
    identity: DeviceIdentity = field(default_factory=DeviceIdentity)

    first_seen: datetime = field(default_factory=utc_now)
    last_seen: datetime = field(default_factory=utc_now)

    packet_count: int = 0
    event_count: int = 0

    wifi_rssi_samples: list[int] = field(default_factory=list)
    bluetooth_rssi_samples: list[int] = field(default_factory=list)

    most_common_events: dict[str, int] = field(default_factory=dict)
    risk_notes: list[str] = field(default_factory=list)
    evidence: list[PacketEvidence] = field(default_factory=list)

    behaviors: list[DeviceBehavior] = field(default_factory=list)
    last_behavior: DeviceBehavior | None = None

    related_devices: set[str] = field(default_factory=set)

    # Future-proof storage for fields not modeled yet.
    extra: dict[str, Any] = field(default_factory=dict)

    def update_seen_time(self, timestamp: datetime) -> None:
        if timestamp < self.first_seen:
            self.first_seen = timestamp

        if timestamp > self.last_seen:
            self.last_seen = timestamp

    def add_protocol(self, protocol: str) -> None:
        if protocol:
            self.identity.protocols_seen.add(protocol)

    def add_rssi(self, source: str, rssi: int | None) -> None:
        if rssi is None:
            return

        if source.startswith("WIFI"):
            self.wifi_rssi_samples.append(rssi)
        elif source.startswith("BT"):
            self.bluetooth_rssi_samples.append(rssi)

    def add_event_type(self, event_type: str) -> None:
        if not event_type:
            return

        self.most_common_events[event_type] = (
            self.most_common_events.get(event_type, 0) + 1
        )

    def add_behavior(self, behavior: DeviceBehavior, max_items: int = 100) -> None:
        self.behaviors.append(behavior)
        self.last_behavior = behavior

        if len(self.behaviors) > max_items:
            self.behaviors = self.behaviors[-max_items:]

    def avg_wifi_rssi(self) -> float | None:
        if not self.wifi_rssi_samples:
            return None

        return sum(self.wifi_rssi_samples) / len(self.wifi_rssi_samples)

    def avg_bluetooth_rssi(self) -> float | None:
        if not self.bluetooth_rssi_samples:
            return None

        return sum(self.bluetooth_rssi_samples) / len(self.bluetooth_rssi_samples)
