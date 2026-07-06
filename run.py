import argparse
import os
from threading import Event, Thread

from src.core.capture_context import CaptureContext, CaptureInterfaceContext
from src.core.device_registry import DeviceRegistry
from src.core.event_bus import EventBus
from src.infrastructure.bluetooth_basic_scanner import BluetoothBasicScanner
from src.infrastructure.hardware_reader import HardwareReader
from src.infrastructure.local_network_visibility import LocalNetworkVisibilityCollector
from src.infrastructure.wifi_channel_hopper import WiFiChannelHopper
from src.infrastructure.wifi_mode_controller import WiFiModeController
from src.infrastructure.wifi_monitor_capture import WiFiMonitorCapture
from src.presentation.live_dashboard import LiveDashboard
from src.presentation.smart_packet_stream_model import SmartPacketStreamModel

# 🎨 ANSI Terminal Color Palette
CLR_RED = "\033[31m"
CLR_GREEN = "\033[32m"
CLR_YELLOW = "\033[33m"
CLR_BLUE = "\033[34m"
CLR_RESET = "\033[0m"


def get_wifi_interface_context_data(interface: str) -> dict:
    wifi_interfaces = HardwareReader.list_wifi_interfaces()
    return wifi_interfaces.get(interface, {})


def get_default_bluetooth_interface() -> str | None:
    bt_info = HardwareReader.check_bluetooth_status()

    if not bt_info.get("available"):
        return None

    return (
        bt_info.get("default_interface")
        or bt_info.get("interface")
        or (bt_info.get("interfaces") or [None])[0]
    )


def get_bluetooth_interface_context(
    interface: str | None,
) -> CaptureInterfaceContext | None:
    if not interface:
        return None

    bt_info = HardwareReader.check_bluetooth_status()

    ble_scan = bt_info.get("ble_scan")
    external_ble = bt_info.get("external_ble")

    if external_ble == HardwareReader.CAP_YES:
        mode = "External BLE capable"
    elif ble_scan == HardwareReader.CAP_YES:
        mode = "Basic BLE Scan"
    else:
        mode = "HCI fallback / limited Bluetooth visibility"

    return CaptureInterfaceContext(
        name=interface,
        role="local Bluetooth adapter",
        mode=mode,
    )


def build_local_visibility_context(
    interface: str,
    bluetooth_interface: str | None,
) -> CaptureContext:
    wifi_context_data = get_wifi_interface_context_data(interface)

    return CaptureContext(
        profile_name="Local Network Visibility",
        profile_description=(
            "Captures local network identity and discovery traffic visible to this host: "
            "ARP, DHCP, DNS, mDNS, SSDP/UPnP, LLMNR and NetBIOS."
        ),
        base_wifi_interface=CaptureInterfaceContext(
            name=interface,
            role="managed/local network interface",
            mode="managed/promiscuous local visibility",
            driver=wifi_context_data.get("driver"),
            mac_address=wifi_context_data.get("mac_address"),
        ),
        bluetooth_interface=get_bluetooth_interface_context(bluetooth_interface),
        capture_metadata=[
            "Ethernet source/destination MAC",
            "source/destination IP",
            "hostnames when advertised",
            "service names when advertised",
            "DNS/mDNS/SSDP/LLMNR/NetBIOS metadata",
            "DHCP metadata",
            "BLE address/name/services when advertised",
            "timestamp",
        ],
        network_layers=[
            "OSI L2 / Ethernet and ARP",
            "OSI L3 / IPv4 and IPv6",
            "OSI L4 / UDP/TCP metadata",
            "OSI L7 / local discovery protocols",
            "Bluetooth radio observation layer",
            "BLE advertising layer",
        ],
        observed_protocols=[
            "ARP",
            "DHCP",
            "DNS",
            "mDNS",
            "SSDP/UPnP",
            "LLMNR",
            "NetBIOS",
            "BLE advertisements",
        ],
        frame_families=[
            "ARP messages",
            "DHCP messages",
            "DNS/mDNS messages",
            "SSDP discovery messages",
            "LLMNR messages",
            "NetBIOS messages",
            "BLE advertisements",
        ],
        limitations=[
            "Managed/promiscuous local capture may not see all unicast traffic between other devices.",
            "Switches and WiFi drivers may limit visibility.",
            "Encrypted application payloads are not decoded.",
            "BLE Basic Scan sees advertised metadata only; connected BLE payloads may be unavailable.",
            "Live mode keeps a rolling in-memory buffer only.",
        ],
        active_storage="memory-only",
        channel_strategy="local managed/promiscuous capture on the selected interface",
        payload_visibility=(
            "local identity/discovery metadata only; encrypted application payloads are not decoded"
        ),
    )


def build_air_perimeter_context(
    interface: str,
    controller: WiFiModeController,
    channel_hopper: WiFiChannelHopper,
    bluetooth_interface: str | None,
) -> CaptureContext:
    wifi_context_data = get_wifi_interface_context_data(interface)

    return CaptureContext(
        profile_name="Air Perimeter / 802.11 Monitor",
        profile_description=(
            "Captures nearby WiFi activity: APs, clients, probes, beacons, "
            "channels, RSSI and encryption metadata."
        ),
        base_wifi_interface=CaptureInterfaceContext(
            name=interface,
            role="physical/base WiFi interface",
            mode="managed/base",
            driver=wifi_context_data.get("driver"),
            mac_address=wifi_context_data.get("mac_address"),
        ),
        capture_wifi_interface=CaptureInterfaceContext(
            name=controller.monitor_interface,
            role="temporary AirSentry monitor capture interface",
            mode="monitor",
            signal_power="per-device RSSI",
            approximate_range="RSSI-based estimate only; exact meters are unreliable",
        ),
        bluetooth_interface=get_bluetooth_interface_context(bluetooth_interface),
        capture_metadata=[
            "RadioTap",
            "RSSI",
            "observed channel",
            "frequency",
            "capture interface",
            "timestamp",
            "BLE address/name/services when advertised",
        ],
        network_layers=[
            "OSI L2 / IEEE 802.11 wireless link",
            "Bluetooth radio observation layer",
            "BLE advertising layer",
        ],
        observed_protocols=[
            "IEEE 802.11",
            "BLE advertisements",
        ],
        frame_families=[
            "Management frames",
            "Control frames",
            "Data frames",
            "Beacon frames",
            "Probe requests",
            "WPA/WPA2/WPA3/WPS metadata",
            "BLE advertisements",
        ],
        limitations=[
            "A single WiFi adapter listens to one channel at a time.",
            "Channel hopping improves coverage over time but may miss packets.",
            "Protected WiFi payloads may be encrypted and not readable.",
            "Internet connectivity may be interrupted on single-adapter systems depending on driver support.",
            "BLE Basic Scan sees advertised metadata only.",
            "Live mode keeps a rolling in-memory buffer only.",
        ],
        active_storage="memory-only",
        channel_strategy=channel_hopper.summary(),
        payload_visibility="encrypted/protected payloads are not decoded",
    )


def build_live_runtime(capture_context: CaptureContext):
    event_bus = EventBus()
    registry = DeviceRegistry()
    packet_traces = []
    stop_event = Event()

    event_bus.subscribe(registry.ingest)

    def collect_packet_trace(event):
        trace = SmartPacketStreamModel.from_event(event)
        packet_traces.append(trace)

        if len(packet_traces) > 300:
            del packet_traces[0 : len(packet_traces) - 300]

    event_bus.subscribe(collect_packet_trace)

    def process_events_loop() -> None:
        while not stop_event.is_set():
            event_bus.drain(max_events=250)

    processor_thread = Thread(
        target=process_events_loop,
        name="airsentry-event-processor",
        daemon=True,
    )

    dashboard = LiveDashboard(
        registry=registry,
        packet_traces=packet_traces,
        capture_context=capture_context,
        refresh_per_second=4,
    )

    return event_bus, registry, packet_traces, stop_event, processor_thread, dashboard


def run_live_local_dashboard(
    interface: str,
    bluetooth_interface: str | None,
) -> bool:
    """
    Runs AirSentry Local Network Visibility.

    Default MVP profile:
    managed/promiscuous local capture + Basic BLE Scan.
    """
    print("\n=== AirSentry Local Network Visibility ===\n")

    capture_context = build_local_visibility_context(
        interface=interface,
        bluetooth_interface=bluetooth_interface,
    )

    (
        event_bus,
        _registry,
        _packet_traces,
        stop_event,
        processor_thread,
        dashboard,
    ) = build_live_runtime(capture_context)

    local_collector = LocalNetworkVisibilityCollector(
        event_bus=event_bus,
        interface=interface,
        promiscuous=True,
    )

    bluetooth_scanner = None

    if bluetooth_interface:
        bluetooth_scanner = BluetoothBasicScanner(
            event_bus=event_bus,
            interface=bluetooth_interface,
            scan_window_seconds=8,
            scan_pause_seconds=1.0,
        )

    try:
        print(f"[*] Local Interface           : {interface}")
        print("[*] Profile                   : Local Network Visibility")
        print("[*] Local Capture Mode        : managed/promiscuous")
        if bluetooth_interface:
            print(f"[*] Bluetooth Interface       : {bluetooth_interface}")
            print("[*] Bluetooth Mode            : Basic BLE Scan")
        else:
            print(
                f"{CLR_YELLOW}[INFO] No Bluetooth interface detected. BLE scan disabled.{CLR_RESET}"
            )
        print("[*] Dashboard Mode            : live")

        print(f"\n[*] Starting Local Network Visibility on {interface}...")
        local_collector.start()

        if bluetooth_scanner:
            print(
                f"[*] Starting Bluetooth Basic BLE scanner on {bluetooth_interface}..."
            )
            bluetooth_scanner.start()

        print("[*] Starting AirSentry event processor...")
        processor_thread.start()

        print("[*] Launching live dashboard. Press q to exit.")

        dashboard.run(should_stop=stop_event.is_set)

        return True

    except KeyboardInterrupt:
        print(f"\n{CLR_YELLOW}[-] Live dashboard interrupted by user.{CLR_RESET}")
        return True

    except Exception as e:
        print(f"{CLR_RED}[❌ ERROR] Local visibility failed: {e}{CLR_RESET}")
        return False

    finally:
        stop_event.set()

        print("\n[*] Stopping Local Network Visibility...")

        if bluetooth_scanner:
            bluetooth_scanner.stop()
        local_collector.stop()

        print("\n=== AirSentry Local Network Visibility Stopped ===")


def run_live_air_perimeter_dashboard(
    interface: str,
    bluetooth_interface: str | None,
) -> bool:
    """
    Runs the first real AirSentry live dashboard.

    Flow:
    base WiFi interface -> temporary monitor interface -> Scapy capture
    -> WiFiPacketParser -> EventBus -> DeviceRegistry -> LiveDashboard
    """
    print("\n=== AirSentry Air Perimeter ===\n")

    controller = WiFiModeController(interface)
    event_bus = EventBus()
    registry = DeviceRegistry()
    packet_traces = []
    stop_event = Event()
    bluetooth_scanner = None

    if bluetooth_interface:
        bluetooth_scanner = BluetoothBasicScanner(
            event_bus=event_bus,
            interface=bluetooth_interface,
            scan_window_seconds=8,
            scan_pause_seconds=1.0,
        )

    channel_hopper = WiFiChannelHopper(
        controller=controller,
        dwell_seconds=1.5,
    )

    capture_context = build_air_perimeter_context(
        interface=interface,
        controller=controller,
        channel_hopper=channel_hopper,
        bluetooth_interface=bluetooth_interface,
    )

    print(f"[*] Base WiFi Interface       : {interface}")
    print("[*] Interface Role            : physical/base WiFi interface")
    print(f"[*] Monitor Interface         : {controller.monitor_interface}")
    print("[*] Monitor Interface Role    : temporary AirSentry capture interface")
    print("[*] Dashboard Mode            : live")

    event_bus.subscribe(registry.ingest)

    def collect_packet_trace(event):
        trace = SmartPacketStreamModel.from_event(event)
        packet_traces.append(trace)

        if len(packet_traces) > 300:
            del packet_traces[0 : len(packet_traces) - 300]

    event_bus.subscribe(collect_packet_trace)

    capture = WiFiMonitorCapture(
        interface=controller.monitor_interface,
        event_bus=event_bus,
        store_raw_bytes=False,
        channel_provider=lambda: channel_hopper.current_channel,
    )

    def process_events_loop() -> None:
        while not stop_event.is_set():
            event_bus.drain(max_events=250)

    processor_thread = Thread(
        target=process_events_loop,
        name="airsentry-event-processor",
        daemon=True,
    )

    try:
        print(
            f"\n[*] Creating AirSentry monitor interface "
            f"{controller.monitor_interface} from base interface {interface}..."
        )

        if not controller.create_monitor_interface():
            print(
                f"{CLR_RED}[❌ ERROR] Failed to create monitor interface "
                f"{controller.monitor_interface} from {interface}.{CLR_RESET}"
            )
            return False

        print(
            f"{CLR_GREEN}[✓] SUCCESS: Monitor interface "
            f"{controller.monitor_interface} created successfully.{CLR_RESET}"
        )

        print(f"[*] Starting WiFi channel hopper: {channel_hopper.summary()}")
        channel_hopper.start()

        print(
            f"\n[*] Starting WiFi monitor capture on {controller.monitor_interface}..."
        )
        capture.start()

        if bluetooth_scanner:
            print(
                f"[*] Starting Bluetooth Basic BLE scanner on {bluetooth_interface}..."
            )
            bluetooth_scanner.start()
        else:
            print(
                f"{CLR_YELLOW}[INFO] No Bluetooth interface detected. BLE scan disabled.{CLR_RESET}"
            )

        print("[*] Starting AirSentry event processor...")
        processor_thread.start()

        print("[*] Launching live dashboard. Press Ctrl+C to exit.")

        dashboard = LiveDashboard(
            registry=registry,
            packet_traces=packet_traces,
            capture_context=capture_context,
            refresh_per_second=4,
        )

        dashboard.run(should_stop=stop_event.is_set)

        return True

    except KeyboardInterrupt:
        print(f"\n{CLR_YELLOW}[-] Live dashboard interrupted by user.{CLR_RESET}")
        return True

    except Exception as e:
        print(f"{CLR_RED}[❌ ERROR] Live dashboard failed: {e}{CLR_RESET}")
        return False

    finally:
        stop_event.set()

        print(
            f"\n[*] Stopping capture and removing AirSentry monitor interface "
            f"{controller.monitor_interface}..."
        )

        channel_hopper.stop()
        if bluetooth_scanner:
            bluetooth_scanner.stop()
        capture.stop()

        if controller.delete_monitor_interface():
            print(
                f"{CLR_GREEN}[✓] SUCCESS: Monitor interface "
                f"{controller.monitor_interface} removed successfully.{CLR_RESET}"
            )
        else:
            print(
                f"{CLR_RED}[❌ ERROR] Failed to remove monitor interface "
                f"{controller.monitor_interface}.{CLR_RESET}"
            )
            print(
                f"{CLR_YELLOW}[WARNING] Manual cleanup may be required:\n"
                f"  sudo iw dev {controller.monitor_interface} del{CLR_RESET}"
            )

        print("\n=== AirSentry Live Dashboard Stopped ===")


def parse_args():
    parser = argparse.ArgumentParser(
        prog="airsentry",
        description="AirSentry live wireless and local network visibility dashboard.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Profiles:
  Default:
    sudo ./venv/bin/python run.py
    Runs Local Network Visibility using the system default WiFi/local interface,
    plus Basic BLE Scan when Bluetooth is available.

  Air Perimeter:
    sudo ./venv/bin/python run.py --air-perimeter
    Runs 802.11 monitor-mode WiFi Air Perimeter using the system default WiFi
    interface, plus Basic BLE Scan when Bluetooth is available.

Dashboard keys:
  0  Overview
  1  WiFi Air Perimeter
  2  Bluetooth Radar
  3  Smart Packet Stream
  4  Device Intelligence

  n / p   Next / previous page
  j / k   Move down / up in Device Intelligence
  e       Expand/collapse selected device card
  /       Search in Device Intelligence only
  r       Reset page/search/selection
  h       Show context/help for the current view
  q       Quit dashboard
""",
    )

    parser.add_argument(
        "--air-perimeter",
        action="store_true",
        help="Run Air Perimeter profile using WiFi monitor mode plus BLE scan.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if os.getuid() != 0:
        print(
            f"{CLR_RED}[❌ EXECUTION ERROR] AirSentry requires root privileges (sudo).{CLR_RESET}"
        )
        print("Usage: sudo ./venv/bin/python run.py")
        return 1

    wifi_dict = HardwareReader.list_wifi_interfaces()
    default_wifi_interface = HardwareReader.get_default_wifi_interface()
    bluetooth_interface = get_default_bluetooth_interface()

    if not default_wifi_interface:
        print(
            f"{CLR_RED}[❌ ERROR] No default WiFi/local network interface detected. "
            f"AirSentry cannot start.{CLR_RESET}"
        )
        return 1

    if default_wifi_interface not in wifi_dict:
        print(
            f"{CLR_YELLOW}[WARNING] Default interface '{default_wifi_interface}' was not found "
            f"in hardware discovery. AirSentry will try to use it anyway.{CLR_RESET}"
        )

    if args.air_perimeter:
        if (
            wifi_dict.get(default_wifi_interface, {}).get("monitor")
            != HardwareReader.CAP_YES
        ):
            print(
                f"{CLR_RED}[❌ ERROR] {default_wifi_interface} does not report monitor mode support. "
                f"Cannot safely start Air Perimeter.{CLR_RESET}"
            )
            return 1

        ok = run_live_air_perimeter_dashboard(
            interface=default_wifi_interface,
            bluetooth_interface=bluetooth_interface,
        )
    else:
        ok = run_live_local_dashboard(
            interface=default_wifi_interface,
            bluetooth_interface=bluetooth_interface,
        )

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
