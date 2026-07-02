import os
import shutil
import subprocess


class HardwareReader:
    CAP_YES = "yes"
    CAP_NO = "no"
    CAP_UNKNOWN = "unknown"

    @staticmethod
    def _path_exists(path: str) -> bool:
        return os.path.exists(path)

    @staticmethod
    def _read_text_file(path: str) -> str | None:
        try:
            with open(path, "r", encoding="utf-8") as file:
                return file.read().strip()
        except Exception:
            return None

    @staticmethod
    def _command_exists(command: str) -> bool:
        return shutil.which(command) is not None

    @staticmethod
    def _run_optional_command(command: list[str]) -> subprocess.CompletedProcess | None:
        """
        Runs an optional external command.

        AirSentry must never depend on this to start.
        If the command does not exist or fails, return None.
        """
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=3,
            )
        except Exception:
            return None

    @staticmethod
    def check_recommended_tools() -> dict:
        """
        Checks whether recommended system tools are available.
        These tools improve detection accuracy but are not required to start AirSentry.
        """
        return {
            "iw": HardwareReader._command_exists("iw"),
            "bluetoothctl": HardwareReader._command_exists("bluetoothctl"),
            "btmon": HardwareReader._command_exists("btmon"),
            "ip": HardwareReader._command_exists("ip"),
        }

    @staticmethod
    def list_wifi_interfaces() -> dict:
        """
        Detects Wi-Fi interfaces using Linux kernel filesystem data first.
        External tools are optional and only improve accuracy.
        """
        wifi_interfaces = {}
        default_interface = HardwareReader.get_default_interface_from_proc_route()

        try:
            all_interfaces = os.listdir("/sys/class/net/")
        except Exception:
            return {}

        for interface in all_interfaces:
            if not HardwareReader.is_wireless_interface(interface):
                continue

            wifi_interfaces[interface] = {
                "interface": interface,
                "is_default": interface == default_interface,
                "mac_address": HardwareReader.get_interface_mac(interface),
                "state": HardwareReader.get_interface_operstate(interface),
                "driver": HardwareReader.get_interface_driver(interface),
                "managed": HardwareReader.CAP_YES,
                "promiscuous": HardwareReader.supports_promiscuous_mode(interface),
                "monitor": HardwareReader.supports_monitor_mode(interface),
                "monitor_detection_method": HardwareReader.get_monitor_detection_method(),
            }

        return wifi_interfaces

    @staticmethod
    def is_wireless_interface(interface: str) -> bool:
        """
        Detects whether an interface is wireless using kernel-exposed paths.
        """
        return os.path.exists(f"/sys/class/net/{interface}/wireless") or os.path.exists(
            f"/sys/class/net/{interface}/phy80211"
        )

    @staticmethod
    def get_interface_mac(interface: str) -> str | None:
        return HardwareReader._read_text_file(f"/sys/class/net/{interface}/address")

    @staticmethod
    def get_interface_operstate(interface: str) -> str | None:
        return HardwareReader._read_text_file(f"/sys/class/net/{interface}/operstate")

    @staticmethod
    def get_interface_driver(interface: str) -> str | None:
        """
        Attempts to resolve the kernel driver backing the interface.
        """
        driver_path = f"/sys/class/net/{interface}/device/driver"

        try:
            if os.path.islink(driver_path):
                return os.path.basename(os.readlink(driver_path))
        except Exception:
            pass

        return None

    @staticmethod
    def get_default_interface_from_proc_route() -> str | None:
        """
        Detects the default network interface using /proc/net/route.

        This avoids depending on `ip route` and does not require internet access.
        """
        try:
            with open("/proc/net/route", "r", encoding="utf-8") as route_file:
                lines = route_file.readlines()

            for line in lines[1:]:
                fields = line.strip().split()

                if len(fields) < 2:
                    continue

                interface = fields[0]
                destination = fields[1]

                # Destination 00000000 means default route.
                if destination == "00000000":
                    return interface

        except Exception:
            pass

        return None

    @staticmethod
    def supports_promiscuous_mode(interface: str) -> str:
        """
        Most Linux network interfaces can be placed into promiscuous mode.

        This checks whether the interface exists. Later, the actual activation
        step can confirm whether setting IFF_PROMISC succeeds.
        """
        if not os.path.exists(f"/sys/class/net/{interface}"):
            return HardwareReader.CAP_NO

        return HardwareReader.CAP_YES

    @staticmethod
    def supports_monitor_mode(interface: str) -> str:
        """
        Detects monitor mode support.

        Low-level /sys data can identify wireless interfaces, but it usually
        cannot reliably prove monitor-mode support. For precise detection,
        AirSentry can optionally use `iw`, which talks to nl80211.

        If `iw` is unavailable, return UNKNOWN instead of lying.
        """
        if not HardwareReader.is_wireless_interface(interface):
            return HardwareReader.CAP_NO

        if not HardwareReader._command_exists("iw"):
            return HardwareReader.CAP_UNKNOWN

        result = HardwareReader._run_optional_command(["iw", "phy"])

        if result is None or result.returncode != 0:
            return HardwareReader.CAP_UNKNOWN

        if "* monitor" in result.stdout:
            return HardwareReader.CAP_YES

        return HardwareReader.CAP_NO

    @staticmethod
    def get_monitor_detection_method() -> str:
        if HardwareReader._command_exists("iw"):
            return "iw/nl80211"
        return "kernel_sysfs_only_limited"

    @staticmethod
    def check_bluetooth_status() -> dict:
        """
        Detects Bluetooth HCI interfaces using Linux sysfs.

        BLE capability is reported conservatively because full BLE sniffing
        requires deeper probing or dedicated hardware.
        """
        result = {
            "available": False,
            "interfaces": [],
            "interface": None,
            "default_interface": None,
            "hci": HardwareReader.CAP_NO,
            "ble_scan": HardwareReader.CAP_NO,
            "external_ble": HardwareReader.CAP_NO,
            "ble_mode": None,
            "detection_method": "sysfs",
        }

        bluetooth_path = "/sys/class/bluetooth/"

        if not os.path.exists(bluetooth_path):
            return result

        try:
            devices = os.listdir(bluetooth_path)
            hcis = [
                device
                for device in devices
                if device.startswith("hci") and ":" not in device
            ]

            if not hcis:
                return result

            result["available"] = True
            result["interfaces"] = hcis
            result["interface"] = hcis[0]
            result["default_interface"] = hcis[0]
            result["hci"] = HardwareReader.CAP_YES

            # First practical version:
            # If a Linux HCI interface exists, AirSentry can attempt basic BLE discovery later.
            # This does NOT mean full BLE connection sniffing.
            result["ble_scan"] = HardwareReader.CAP_YES
            result["ble_mode"] = "basic_hci_ble_scan"

        except Exception:
            pass

        return result

    @staticmethod
    def get_default_wifi_interface() -> str | None:
        """
        Backward-compatible method for current run.py.
        """
        default_interface = HardwareReader.get_default_interface_from_proc_route()

        if default_interface and HardwareReader.is_wireless_interface(
            default_interface
        ):
            return default_interface

        wifi_interfaces = HardwareReader.list_wifi_interfaces()

        if wifi_interfaces:
            return next(iter(wifi_interfaces.keys()))

        return None
