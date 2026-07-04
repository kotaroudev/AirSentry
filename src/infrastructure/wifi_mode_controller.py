import subprocess
from dataclasses import dataclass


@dataclass
class WiFiMonitorInterface:
    """
    Represents a temporary monitor interface created by AirSentry.
    """

    base_interface: str
    monitor_interface: str


class WiFiModeController:
    """
    Safely creates and removes a dedicated WiFi monitor interface.

    Instead of converting wlan0 directly into monitor mode, AirSentry creates
    a temporary monitor interface such as airsentrymon0.

    This is safer for capture and easier to clean up.
    """

    def __init__(self, interface: str, monitor_interface: str = "airsentrymon0"):
        self.interface = interface
        self.monitor_interface = monitor_interface

    def create_monitor_interface(self) -> bool:
        """
        Creates a dedicated monitor interface.

        Example:
            wlan0 -> airsentrymon0
        """
        self.delete_monitor_interface()

        commands = [
            [
                "iw",
                "dev",
                self.interface,
                "interface",
                "add",
                self.monitor_interface,
                "type",
                "monitor",
            ],
            ["ip", "link", "set", self.monitor_interface, "up"],
        ]

        for command in commands:
            result = self._run(command)
            if result.returncode != 0:
                return False

        return self.get_interface_type(self.monitor_interface) == "monitor"

    def delete_monitor_interface(self) -> bool:
        """
        Deletes the temporary monitor interface if it exists.
        """
        if not self.interface_exists(self.monitor_interface):
            return True

        result = self._run(["iw", "dev", self.monitor_interface, "del"])

        return result.returncode == 0 or not self.interface_exists(
            self.monitor_interface
        )

    def set_channel(self, channel: int) -> bool:
        """
        Sets the monitor interface to a specific WiFi channel.
        """
        result = self._run(
            ["iw", "dev", self.monitor_interface, "set", "channel", str(channel)]
        )
        return result.returncode == 0

    def get_interface_type(self, interface: str | None = None) -> str | None:
        """
        Reads current WiFi interface type using `iw dev <iface> info`.
        """
        target_interface = interface or self.interface
        result = self._run(["iw", "dev", target_interface, "info"])

        if result.returncode != 0:
            return None

        for line in result.stdout.splitlines():
            line = line.strip()

            if line.startswith("type "):
                return line.replace("type ", "").strip()

        return None

    def interface_exists(self, interface: str) -> bool:
        result = self._run(["iw", "dev", interface, "info"])
        return result.returncode == 0

    def get_interface_operstate(self, interface: str | None = None) -> str | None:
        """
        Reads Linux interface state from sysfs.
        """
        target_interface = interface or self.interface

        try:
            with open(
                f"/sys/class/net/{target_interface}/operstate",
                "r",
                encoding="utf-8",
            ) as file:
                return file.read().strip()
        except Exception:
            return None

    def _run(self, command: list[str]) -> subprocess.CompletedProcess:
        """
        Runs a system command and captures output.
        """
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
