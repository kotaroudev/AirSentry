from dataclasses import dataclass, field

from src.core.models import (
    DeviceBehavior,
    DeviceProfile,
    PacketEvidence,
    RawWirelessEvent,
)


@dataclass
class DeviceRegistry:
    """
    Central in-memory registry for all observed devices.

    This is the backbone of AirSentry's Device Intelligence Summary view.

    Every RawWirelessEvent updates one or more DeviceProfile objects.
    The registry does not decide if something is an attack yet.
    It collects evidence, enriches identities, and prepares data for
    dashboards, exporters, and future correlation engines.
    """

    devices: dict[str, DeviceProfile] = field(default_factory=dict)

    def ingest(self, event: RawWirelessEvent) -> None:
        """
        Ingests one raw event and updates the related device profile.
        """
        device_key = self._resolve_device_key(event)

        if not device_key:
            return

        profile = self._get_or_create_device(device_key)

        profile.update_seen_time(event.timestamp)
        profile.packet_count += 1
        profile.event_count += 1

        profile.add_protocol(event.protocol)
        profile.add_event_type(event.event_type)
        profile.add_rssi(event.source, event.signal.rssi)

        self._update_identity(profile, event)
        self._add_basic_evidence(profile, event)
        self._add_basic_risk_notes(profile, event)
        self._add_behavior(profile, event)

    def all_devices(self) -> list[DeviceProfile]:
        """
        Returns all known device profiles.
        """
        return list(self.devices.values())

    def get_device(self, device_id: str) -> DeviceProfile | None:
        """
        Returns one device profile by ID.
        """
        return self.devices.get(device_id)

    def _get_or_create_device(self, device_key: str) -> DeviceProfile:
        if device_key not in self.devices:
            self.devices[device_key] = DeviceProfile(device_id=device_key)

        return self.devices[device_key]

    def _resolve_device_key(self, event: RawWirelessEvent) -> str | None:
        """
        Chooses the best available identity key for the event.

        Priority:
        1. Source MAC
        2. Bluetooth address from extra fields
        3. Source IP
        4. BSSID
        """
        if event.src_mac:
            return self._normalize_key(event.src_mac)

        bluetooth_address = event.extra.get("bluetooth_address")
        if bluetooth_address:
            return self._normalize_key(bluetooth_address)

        if event.src_ip:
            return event.src_ip

        if event.bssid:
            return self._normalize_key(event.bssid)

        return None

    def _normalize_key(self, value: str) -> str:
        return value.strip().lower()

    def _update_identity(self, profile: DeviceProfile, event: RawWirelessEvent) -> None:
        """
        Updates identity hints from a raw event.
        """
        if event.src_mac and not profile.identity.primary_mac:
            profile.identity.primary_mac = event.src_mac

        bluetooth_address = event.extra.get("bluetooth_address")
        if bluetooth_address and not profile.identity.bluetooth_address:
            profile.identity.bluetooth_address = bluetooth_address

        if event.src_ip:
            profile.identity.ip_addresses.add(event.src_ip)

        if event.dst_ip:
            profile.identity.ip_addresses.add(event.dst_ip)

        if event.hostname:
            profile.identity.hostnames.add(event.hostname)

        if event.vendor:
            profile.identity.vendors.add(event.vendor)

        if event.ssid and event.event_type == "probe_request":
            profile.identity.ssids_probed.add(event.ssid)

        if event.service_name:
            profile.identity.services.add(event.service_name)

        security_profile = event.parsed_fields.get("security_profile")

        if event.event_type == "beacon" and security_profile:
            profile.extra["wifi_security"] = security_profile

        if event.protocol == "WIFI":
            wifi_last = profile.extra.get("wifi_last", {})

            profile.extra["wifi_last"] = {
                "ssid": event.ssid or wifi_last.get("ssid"),
                "channel": event.signal.channel
                if event.signal.channel is not None
                else wifi_last.get("channel"),
                "band": event.signal.band or wifi_last.get("band"),
                "rssi": event.signal.rssi
                if event.signal.rssi is not None
                else wifi_last.get("rssi"),
                "event_type": event.event_type or wifi_last.get("event_type"),
            }

        if event.event_type in {"beacon", "probe_response"}:
            wifi_air_profile = profile.extra.get("wifi_air_profile", {})

            profile.extra["wifi_air_profile"] = {
                "ssid": event.ssid or wifi_air_profile.get("ssid"),
                "channel": event.signal.channel
                if event.signal.channel is not None
                else wifi_air_profile.get("channel"),
                "band": event.signal.band or wifi_air_profile.get("band"),
                "rssi": event.signal.rssi
                if event.signal.rssi is not None
                else wifi_air_profile.get("rssi"),
                "security": event.parsed_fields.get("security_profile")
                or wifi_air_profile.get("security"),
                "last_event_type": event.event_type,
            }

        self._infer_basic_device_type(profile, event)

    def _infer_basic_device_type(
        self,
        profile: DeviceProfile,
        event: RawWirelessEvent,
    ) -> None:
        """
        Very early MVP-level device type inference.

        This should stay conservative.
        """
        if event.protocol == "BLE":
            profile.identity.suspected_device_type = (
                profile.identity.suspected_device_type or "BLE-capable device"
            )
            profile.identity.confidence = max(profile.identity.confidence, 0.35)

        if event.event_type == "probe_request":
            profile.identity.suspected_device_type = (
                profile.identity.suspected_device_type or "WiFi client device"
            )
            profile.identity.confidence = max(profile.identity.confidence, 0.45)

        if event.event_type == "beacon":
            profile.identity.suspected_device_type = (
                profile.identity.suspected_device_type or "WiFi access point"
            )
            profile.identity.confidence = max(profile.identity.confidence, 0.50)

        if event.protocol in {"MDNS", "SSDP", "UPNP"}:
            profile.identity.confidence = max(profile.identity.confidence, 0.60)

    def _add_basic_evidence(
        self, profile: DeviceProfile, event: RawWirelessEvent
    ) -> None:
        """
        Stores explainable evidence for future dashboard views.
        """
        description = self._build_evidence_description(event)

        if not description:
            return

        profile.evidence.append(
            PacketEvidence(
                source=event.source,
                evidence_type=event.event_type,
                description=description,
                confidence=0.50,
                raw_fields={
                    "protocol": event.protocol,
                    "src_mac": event.src_mac,
                    "dst_mac": event.dst_mac,
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "ssid": event.ssid,
                    "hostname": event.hostname,
                    "service_name": event.service_name,
                },
            )
        )

    def _build_evidence_description(self, event: RawWirelessEvent) -> str | None:
        if event.event_type == "probe_request" and event.ssid:
            return f"Device searched for WiFi network '{event.ssid}'."

        if event.event_type == "beacon" and event.ssid:
            return f"Access point advertised SSID '{event.ssid}'."

        if event.protocol == "MDNS" and event.hostname:
            return f"Device announced hostname '{event.hostname}' through mDNS."

        if event.protocol in {"SSDP", "UPNP"} and event.service_name:
            return f"Device used local discovery for service '{event.service_name}'."

        if event.protocol == "ARP" and event.src_ip:
            return f"Device was associated with local IP address {event.src_ip}."

        if event.protocol == "BLE":
            return "Bluetooth Low Energy activity was observed for this device."

        return None

    def _add_basic_risk_notes(
        self, profile: DeviceProfile, event: RawWirelessEvent
    ) -> None:
        """
        Adds conservative risk notes.

        These are not attack claims. They are signals worth showing.
        """
        note = None

        if event.protocol in {"SSDP", "UPNP"}:
            service = (event.service_name or "").lower()

            if "internetgatewaydevice" in service:
                note = "UPnP Internet Gateway discovery observed."

            elif "upnp" in service:
                note = "UPnP activity observed."

        if event.event_type == "probe_request" and event.ssid:
            note = "WiFi probe request observed. Device may be revealing trusted network names."

        if note and note not in profile.risk_notes:
            profile.risk_notes.append(note)

    def _add_behavior(self, profile: DeviceProfile, event: RawWirelessEvent) -> None:
        behavior = self._build_behavior(event)

        if not behavior:
            return

        profile.add_behavior(behavior)

    def _build_behavior(self, event: RawWirelessEvent) -> DeviceBehavior | None:
        security_profile = event.parsed_fields.get("security_profile", {})
        dot11 = event.parsed_fields.get("dot11", {})
        flags = dot11.get("flags", {})
        size_hints = event.parsed_fields.get("size_hints", {})

        raw_fields = {
            "src_mac": event.src_mac,
            "dst_mac": event.dst_mac,
            "bssid": event.bssid,
            "ssid": event.ssid,
            "hostname": event.hostname,
            "service_name": event.service_name,
            "rssi": event.signal.rssi,
            "channel": event.signal.channel,
            "band": event.signal.band,
            "security_profile": security_profile,
            "dot11_flags": flags,
            "size_hints": size_hints,
        }

        if event.event_type == "beacon" and event.ssid:
            security = ", ".join(security_profile.get("security", [])) or "unknown"
            akm = ", ".join(security_profile.get("akm_suites", [])) or "unknown"
            pairwise = (
                ", ".join(security_profile.get("pairwise_ciphers", [])) or "unknown"
            )

            return DeviceBehavior(
                category="EVIDENCE",
                severity="info",
                protocol=event.protocol,
                event_type=event.event_type,
                raw_event_id=event.event_id,
                title="Access point beacon observed",
                description=(
                    f"AP advertised SSID '{event.ssid}' "
                    f"with security '{security}', AKM '{akm}', "
                    f"pairwise cipher '{pairwise}'."
                ),
                confidence=0.95,
                raw_fields=raw_fields,
            )

        if event.event_type == "probe_request":
            ssid = event.ssid or "<wildcard/hidden>"

            return DeviceBehavior(
                category="EVIDENCE",
                severity="notice",
                protocol=event.protocol,
                event_type=event.event_type,
                raw_event_id=event.event_id,
                title="WiFi probe request observed",
                description=f"Device searched for SSID '{ssid}'.",
                confidence=0.90,
                raw_fields=raw_fields,
            )

        if event.protocol == "WIFI" and flags.get("retry"):
            return DeviceBehavior(
                category="NOTICE",
                severity="info",
                protocol=event.protocol,
                event_type=event.event_type,
                raw_event_id=event.event_id,
                title="WiFi retry frame observed",
                description=(
                    "A retry flag was observed in this device's traffic. "
                    "This may indicate normal retransmission, weak signal, or congestion."
                ),
                confidence=0.60,
                raw_fields=raw_fields,
            )

        if event.protocol == "WIFI" and flags.get("protected"):
            return DeviceBehavior(
                category="INFO",
                severity="info",
                protocol=event.protocol,
                event_type=event.event_type,
                raw_event_id=event.event_id,
                title="Protected WiFi frame observed",
                description=(
                    "Protected 802.11 traffic was observed. Payload content may be encrypted."
                ),
                confidence=0.80,
                raw_fields=raw_fields,
            )

        if event.protocol == "SSDP" or event.protocol == "UPNP":
            return DeviceBehavior(
                category="EVIDENCE",
                severity="notice",
                protocol=event.protocol,
                event_type=event.event_type,
                raw_event_id=event.event_id,
                title="Local discovery protocol observed",
                description=(
                    f"Device used {event.protocol} for service discovery"
                    + (
                        f" involving '{event.service_name}'."
                        if event.service_name
                        else "."
                    )
                ),
                confidence=0.85,
                raw_fields=raw_fields,
            )

        if event.protocol == "MDNS":
            return DeviceBehavior(
                category="EVIDENCE",
                severity="info",
                protocol=event.protocol,
                event_type=event.event_type,
                raw_event_id=event.event_id,
                title="mDNS activity observed",
                description=(
                    "Device announced or queried local identity/service data"
                    + (f" for hostname '{event.hostname}'." if event.hostname else ".")
                ),
                confidence=0.85,
                raw_fields=raw_fields,
            )

        return None
