from dataclasses import dataclass

from src.core.models import DeviceProfile


@dataclass
class BluetoothRadarRow:
    role: str
    name: str
    address: str
    rssi: float | None
    proximity: str
    vendor: str
    address_type: str
    services: str
    events: int
    last_seen: str


class BluetoothViewModel:
    @staticmethod
    def build_rows(devices: list[DeviceProfile]) -> list[BluetoothRadarRow]:
        rows = []

        for device in devices:
            if not BluetoothViewModel._has_bluetooth_evidence(device):
                continue

            rows.append(BluetoothViewModel._build_row(device))

        return sorted(
            rows,
            key=lambda row: (
                row.rssi is None,
                -(row.rssi or -999),
                -row.events,
            ),
        )

    @staticmethod
    def _has_bluetooth_evidence(device: DeviceProfile) -> bool:
        identity = device.identity

        return (
            bool(identity.bluetooth_address)
            or "BLE" in identity.protocols_seen
            or bool(device.extra.get("bluetooth_address"))
        )

    @staticmethod
    def _build_row(device: DeviceProfile) -> BluetoothRadarRow:
        identity = device.identity
        extra = device.extra

        address = (
            identity.bluetooth_address
            or extra.get("bluetooth_address")
            or identity.primary_mac
            or device.device_id
        )

        name = (
            extra.get("bluetooth_name") or next(iter(identity.hostnames), None) or "-"
        )

        rssi = device.avg_bluetooth_rssi()

        if rssi is None and device.bluetooth_rssi_samples:
            rssi = device.bluetooth_rssi_samples[-1]

        vendor = ", ".join(sorted(identity.vendors)) if identity.vendors else "unknown"

        services = extra.get("service_uuids") or []

        if isinstance(services, list):
            services = [str(service) for service in services if service]

            if not services:
                services_text = "-"
            elif len(services) == 1:
                services_text = BluetoothViewModel._display_service_uuid(services[0])
            else:
                first_service = BluetoothViewModel._display_service_uuid(services[0])
                services_text = f"{first_service} +{len(services) - 1}"
        else:
            services_text = "-"

        return BluetoothRadarRow(
            role="BLE",
            name=name,
            address=address,
            rssi=rssi,
            proximity=BluetoothViewModel._rssi_to_proximity(rssi),
            vendor=vendor,
            address_type=extra.get("address_type") or "unknown",
            services=services_text,
            events=int(extra.get("event_count") or device.event_count),
            last_seen=device.last_seen.strftime("%H:%M:%S"),
        )

    @staticmethod
    def _display_service_uuid(service_uuid: str) -> str:
        known_services = {
            "0000110a-0000-1000-8000-00805f9b34fb": "A2DP Audio Source",
            "0000110b-0000-1000-8000-00805f9b34fb": "A2DP Audio Sink",
            "0000110c-0000-1000-8000-00805f9b34fb": "AVRCP Target",
            "0000110e-0000-1000-8000-00805f9b34fb": "AVRCP Controller",
            "00001112-0000-1000-8000-00805f9b34fb": "Headset Audio Gateway",
            "0000111e-0000-1000-8000-00805f9b34fb": "Handsfree",
            "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
            "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
            "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
            "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
        }

        normalized = service_uuid.lower()

        if normalized in known_services:
            return known_services[normalized]

        return normalized[:8]

    @staticmethod
    def _rssi_to_proximity(rssi: float | None) -> str:
        if rssi is None:
            return "unknown"

        if rssi >= -50:
            return "very near"

        if rssi >= -65:
            return "near"

        if rssi >= -75:
            return "medium"

        if rssi >= -85:
            return "far"

        return "very weak"
