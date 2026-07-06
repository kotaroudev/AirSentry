import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Event, Thread
from uuid import uuid4

from src.core.event_bus import EventBus
from src.core.models import RawWirelessEvent, SignalSample

BLE_ADDRESS_PATTERN = re.compile(
    r"Device\s+((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})(?:\s+(.+))?"
)


@dataclass
class BluetoothBasicScanner:
    """
    Basic BLE scanner using bluetoothctl.

    This is the MVP Bluetooth Radar collector.

    It observes nearby BLE advertisements through the local HCI adapter.
    It is not a full passive BLE sniffer.
    """

    event_bus: EventBus
    interface: str = "hci0"
    scan_window_seconds: int = 8
    scan_pause_seconds: float = 1.0

    def __post_init__(self) -> None:
        self._stop_event = Event()
        self._thread: Thread | None = None
        self._devices: dict[str, dict] = {}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        if not shutil.which("bluetoothctl"):
            return

        self._stop_event.clear()
        self._thread = Thread(
            target=self._run,
            name="airsentry-bluetooth-basic-scanner",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

        try:
            subprocess.run(
                ["bluetoothctl", "scan", "off"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except Exception:
            pass

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self._scan_once()

            slept = 0.0
            while slept < self.scan_pause_seconds and not self._stop_event.is_set():
                time.sleep(0.1)
                slept += 0.1

    def _scan_once(self) -> None:
        try:
            result = subprocess.run(
                [
                    "bluetoothctl",
                    "--timeout",
                    str(self.scan_window_seconds),
                    "scan",
                    "on",
                ],
                capture_output=True,
                text=True,
                timeout=self.scan_window_seconds + 5,
                check=False,
            )
        except Exception:
            return

        output = "\n".join([result.stdout or "", result.stderr or ""])

        for line in output.splitlines():
            self._parse_line(line.strip())

    def _parse_line(self, line: str) -> None:
        if not line:
            return

        match = BLE_ADDRESS_PATTERN.search(line)

        if not match:
            return

        address = match.group(1).lower()
        trailing_value = (match.group(2) or "").strip()

        device = self._devices.setdefault(
            address,
            {
                "address": address,
                "name": None,
                "rssi": None,
                "manufacturer_data": None,
                "service_uuids": set(),
                "address_type": "unknown",
                "event_count": 0,
                "last_raw_line": None,
            },
        )

        device["event_count"] += 1
        device["last_raw_line"] = line

        normalized = trailing_value.strip()
        lowered = normalized.lower()

        property_prefixes = (
            "addresstype:",
            "rssi:",
            "txpower:",
            "legacypairing:",
            "manufacturerdata",
            "uuids:",
            "uuid:",
            "name:",
            "alias:",
            "paired:",
            "connected:",
            "trusted:",
            "blocked:",
            "icon:",
            "class:",
        )

        if lowered.startswith("name:"):
            device["name"] = normalized.split(":", maxsplit=1)[1].strip()

        elif lowered.startswith("alias:"):
            device["name"] = normalized.split(":", maxsplit=1)[1].strip()

        elif lowered.startswith("addresstype:"):
            value = normalized.split(":", maxsplit=1)[1].strip().lower()
            if value in {"public", "random"}:
                device["address_type"] = value

        elif lowered.startswith("rssi:"):
            value = normalized.split(":", maxsplit=1)[1].strip()
            try:
                device["rssi"] = int(value)
            except ValueError:
                pass

        elif lowered.startswith("txpower:"):
            device["tx_power"] = normalized.split(":", maxsplit=1)[1].strip()

        elif lowered.startswith("manufacturerdata"):
            device["manufacturer_data"] = normalized

        elif lowered.startswith(("uuids:", "uuid:")):
            for service_uuid in self._extract_service_uuids(normalized):
                device["service_uuids"].add(service_uuid)

        elif normalized and not lowered.startswith(property_prefixes):
            # Usually the initial "[NEW] Device <addr> <name>" line.
            device["name"] = normalized

        self._publish_device_event(device)

    def _extract_service_uuids(self, value: str) -> list[str]:
        uuid_pattern = re.compile(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        )

        return [match.group(0).lower() for match in uuid_pattern.finditer(value)]

    def _publish_device_event(self, device: dict) -> None:
        name = device.get("name")
        address = device["address"]
        rssi = device.get("rssi")
        service_uuids = sorted(device.get("service_uuids") or [])

        summary_name = f' name="{name}"' if name else ""
        summary_rssi = f" RSSI={rssi}" if rssi is not None else ""

        event = RawWirelessEvent(
            event_id=str(uuid4()),
            timestamp=datetime.now(timezone.utc),
            source="BLE_SCAN",
            capture_mode="BT_BLE_BASIC",
            protocol="BLE",
            event_type="ble_advertisement",
            interface=self.interface,
            src_mac=address,
            dst_mac=None,
            vendor=None,
            signal=SignalSample(
                rssi=rssi,
                channel=None,
                frequency_mhz=2400,
                band="2.4GHz",
            ),
            parsed_fields={
                "ble": {
                    "address": address,
                    "address_type": device.get("address_type"),
                    "name": name,
                    "manufacturer_data": device.get("manufacturer_data"),
                    "service_uuids": service_uuids,
                    "event_count": device.get("event_count", 0),
                }
            },
            extra={
                "bluetooth_address": address,
                "bluetooth_name": name,
                "address_type": device.get("address_type"),
                "manufacturer_data": device.get("manufacturer_data"),
                "service_uuids": service_uuids,
                "event_count": device.get("event_count", 0),
            },
            raw_summary=(
                f"BLE advertisement from {address}{summary_name}{summary_rssi}"
            ),
            raw_layers=["Bluetooth", "BLE", "Advertisement"],
        )

        self.event_bus.publish(event)
