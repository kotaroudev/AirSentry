from dataclasses import dataclass

from src.core.models import DeviceProfile


@dataclass
class WiFiDeviceRow:
    role: str
    mac: str
    ssid: str | None
    rssi: float | None
    channel: int | None
    band: str | None
    security: str
    akm: str
    cipher: str
    wps: str
    packet_count: int
    last_behavior: str | None


class WiFiViewModel:
    """
    Builds clean WiFi Air Perimeter rows from DeviceRegistry profiles.

    This does not render the UI.
    It only prepares data for terminal dashboards, exporters, or future web UI.
    """

    @staticmethod
    def build_rows(devices: list[DeviceProfile]) -> list[WiFiDeviceRow]:
        rows = []

        for device in devices:
            if "WIFI" not in device.identity.protocols_seen:
                continue

            row = WiFiViewModel._build_row(device)
            rows.append(row)

        return sorted(
            rows,
            key=lambda row: (
                WiFiViewModel._role_priority(row.role),
                -(row.packet_count or 0),
            ),
        )

    @staticmethod
    def _build_row(device: DeviceProfile) -> WiFiDeviceRow:
        identity = device.identity

        wifi_security = device.extra.get("wifi_security") or {}
        wifi_last = device.extra.get("wifi_last") or {}

        security = ", ".join(wifi_security.get("security", [])) or "unknown"
        akm = ", ".join(wifi_security.get("akm_suites", [])) or "unknown"
        cipher = ", ".join(wifi_security.get("pairwise_ciphers", [])) or "unknown"

        ssid = WiFiViewModel._best_ssid(device)
        role = WiFiViewModel._infer_role(device)

        last_behavior = None
        if device.last_behavior:
            last_behavior = (
                f"[{device.last_behavior.category}] {device.last_behavior.title}"
            )

        return WiFiDeviceRow(
            role=role,
            mac=identity.primary_mac or device.device_id,
            ssid=ssid,
            rssi=device.avg_wifi_rssi(),
            channel=wifi_last.get("channel"),
            band=wifi_last.get("band"),
            security=security,
            akm=akm,
            cipher=cipher,
            wps=str(wifi_security.get("wps", "unknown")),
            packet_count=device.packet_count,
            last_behavior=last_behavior,
        )

    @staticmethod
    def _best_ssid(device: DeviceProfile) -> str | None:
        wifi_last = device.extra.get("wifi_last") or {}

        if wifi_last.get("ssid"):
            return wifi_last.get("ssid")

        if device.identity.ssids_probed:
            return "Probing: " + ", ".join(sorted(device.identity.ssids_probed))

        return None

    @staticmethod
    def _infer_role(device: DeviceProfile) -> str:
        suspected_type = device.identity.suspected_device_type or ""

        if suspected_type == "WiFi access point":
            return "AP"

        if suspected_type == "WiFi client device":
            return "CLIENT"

        if device.identity.ssids_probed:
            return "CLIENT"

        if device.extra.get("wifi_security"):
            return "AP"

        if (
            device.last_behavior
            and "Protected WiFi frame" in device.last_behavior.title
        ):
            return "STA"

        return "UNKNOWN"

    @staticmethod
    def _role_priority(role: str) -> int:
        priorities = {
            "AP": 0,
            "CLIENT": 1,
            "STA": 2,
            "UNKNOWN": 3,
        }

        return priorities.get(role, 9)
