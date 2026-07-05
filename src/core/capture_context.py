from dataclasses import dataclass, field


@dataclass
class CaptureInterfaceContext:
    name: str
    role: str
    mode: str | None = None
    driver: str | None = None
    mac_address: str | None = None
    signal_power: str | None = None
    approximate_range: str | None = None


@dataclass
class CaptureContext:
    profile_name: str
    profile_description: str
    base_wifi_interface: CaptureInterfaceContext | None = None
    capture_wifi_interface: CaptureInterfaceContext | None = None
    bluetooth_interface: CaptureInterfaceContext | None = None
    visible_layers: list[str] = field(default_factory=list)
    visible_protocols: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    memory_policy: str = (
        "Live mode keeps only a rolling in-memory buffer. "
        "Old traces are discarded unless persistence is enabled."
    )
    persistence_hint: str = (
        "Future persistent storage: run AirSentry with --db <path> "
        "to store events in SQLite."
    )
    active_storage: str = "memory-only"
    channel_strategy: str = "fixed channel"
    payload_visibility: str = "protected WiFi payloads may be encrypted"
