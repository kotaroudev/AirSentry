import argparse
import os
import sys
import time
import traceback
from threading import Event, Thread

from src.core.capture_context import CaptureContext, CaptureInterfaceContext
from src.core.device_registry import DeviceRegistry
from src.core.event_bus import EventBus
from src.core.mode_descriptions import MODE_DESCRIPTIONS
from src.infrastructure.hardware_reader import HardwareReader
from src.infrastructure.wifi_channel_hopper import WiFiChannelHopper
from src.infrastructure.wifi_mode_controller import WiFiModeController
from src.infrastructure.wifi_monitor_capture import WiFiMonitorCapture
from src.presentation.live_dashboard import LiveDashboard
from src.presentation.smart_packet_stream_model import SmartPacketStreamModel
from src.presentation.wifi_view_model import WiFiViewModel

# 🎨 ANSI Terminal Color Palette
CLR_RED = "\033[31m"
CLR_GREEN = "\033[32m"
CLR_YELLOW = "\033[33m"
CLR_BLUE = "\033[34m"
CLR_RESET = "\033[0m"


def print_chip_success(hardware_type, chip_name, mode):
    """Generates the structured and detailed green success message."""
    key = f"{hardware_type}_{mode}"
    info = MODE_DESCRIPTIONS.get(
        key, {"desc": mode, "auditing": "Standard auditing status."}
    )

    print(
        f"{CLR_GREEN}[✓] SUCCESS: {hardware_type} [{chip_name}] successfully initiated in {info['desc']}.{CLR_RESET}"
    )
    print(f"    -> Description: {info['desc']}")
    print(f"    -> Auditing Scope: {info['auditing']}\n")


def print_capability(value: str) -> str:
    if value == HardwareReader.CAP_YES:
        return f"{CLR_GREEN}YES{CLR_RESET}"

    if value == HardwareReader.CAP_NO:
        return f"{CLR_RED}NO{CLR_RESET}"

    return f"{CLR_YELLOW}UNKNOWN{CLR_RESET}"


def print_interfaces_report(wifi_dict: dict, bt_info: dict):
    print("\n=== AirSentry Hardware Discovery Report ===\n")

    recommended_tools = HardwareReader.check_recommended_tools()

    print("--- Recommended System Tools ---")
    for tool, available in recommended_tools.items():
        status = (
            f"{CLR_GREEN}FOUND{CLR_RESET}"
            if available
            else f"{CLR_YELLOW}MISSING{CLR_RESET}"
        )
        print(f"  {tool:<15}: {status}")

    if not recommended_tools.get("iw"):
        print(
            f"  {CLR_YELLOW}[INFO] 'iw' not found. Monitor mode detection may be UNKNOWN.{CLR_RESET}"
        )

    if not recommended_tools.get("bluetoothctl"):
        print(
            f"  {CLR_YELLOW}[INFO] 'bluetoothctl' not found. Bluetooth stack inspection will be limited.{CLR_RESET}"
        )

    print("\n--- Wi-Fi Interfaces ---")

    if not wifi_dict:
        print(f"  {CLR_RED}No Wi-Fi interfaces detected.{CLR_RESET}")
    else:
        for index, (interface, data) in enumerate(wifi_dict.items(), start=1):
            default_marker = (
                " [Current System Default]" if data.get("is_default") else ""
            )

            print(f"  [{index}] {interface}{default_marker}")
            print(f"      MAC Address       : {data.get('mac_address') or 'unknown'}")
            print(f"      State             : {data.get('state') or 'unknown'}")
            print(f"      Driver            : {data.get('driver') or 'unknown'}")
            print(f"      Managed Mode      : {print_capability(data.get('managed'))}")
            print(
                f"      Promiscuous Mode  : {print_capability(data.get('promiscuous'))}"
            )
            print(f"      Monitor Mode      : {print_capability(data.get('monitor'))}")
            print(f"      Monitor Detector  : {data.get('monitor_detection_method')}")
            print()

    print("--- Bluetooth Interfaces ---")

    if not bt_info.get("available"):
        print(f"  {CLR_RED}No Bluetooth HCI interfaces detected.{CLR_RESET}")
    else:
        for index, interface in enumerate(bt_info.get("interfaces", []), start=1):
            default_marker = (
                " [Default]" if interface == bt_info.get("default_interface") else ""
            )

            print(f"  [{index}] {interface}{default_marker}")
            print(f"      HCI Available     : {print_capability(bt_info.get('hci'))}")
            print(
                f"      BLE Basic Scan    : {print_capability(bt_info.get('ble_scan'))}"
            )
            print(
                f"      External BLE      : {print_capability(bt_info.get('external_ble'))}"
            )
            print(f"      Detection Method  : {bt_info.get('detection_method')}")

            if (
                bt_info.get("ble_scan") == HardwareReader.CAP_YES
                and bt_info.get("external_ble") != HardwareReader.CAP_YES
            ):
                print(
                    f"      {CLR_YELLOW}[INFO] Basic BLE scanning is available through the local HCI adapter, "
                    f"but full BLE sniffing requires dedicated external hardware.{CLR_RESET}"
                )

            print()

    print("=== End of Hardware Discovery Report ===\n")


def get_wifi_interface_context_data(interface: str) -> dict:
    wifi_interfaces = HardwareReader.list_wifi_interfaces()
    return wifi_interfaces.get(interface, {})


def test_wifi_monitor_mode(interface: str) -> bool:
    """
    Safely tests WiFi monitor mode activation and restoration.
    This does not start packet capture.
    """
    print("\n=== AirSentry WiFi Monitor Mode Test ===\n")
    print(f"[*] Target WiFi interface: {interface}")

    controller = WiFiModeController(interface)

    original_type = controller.get_interface_type()
    original_state = controller.get_interface_operstate()

    print(f"[*] Current interface type : {original_type or 'unknown'}")
    print(f"[*] Current interface state: {original_state or 'unknown'}")

    if original_type == "monitor":
        print(
            f"{CLR_YELLOW}[INFO] Interface is already in monitor mode. "
            f"AirSentry will still attempt to restore it to managed mode at the end.{CLR_RESET}"
        )

    print(f"\n[*] Enabling monitor mode on {interface}...")

    enabled = controller.enable_monitor_mode()

    if not enabled:
        print(
            f"{CLR_RED}[❌ ERROR] Failed to enable monitor mode on {interface}.{CLR_RESET}"
        )
        print(f"{CLR_YELLOW}[INFO] Attempting to restore managed mode...{CLR_RESET}")
        controller.restore_managed_mode()
        return False

    print(f"{CLR_GREEN}[✓] SUCCESS: {interface} is now in monitor mode.{CLR_RESET}")
    print(
        "    -> Description: Monitor Mode (Passive Air Sniffing)\n"
        "    -> Auditing Scope: Analyzes nearby WiFi frames traveling through the air, "
        "depending on hardware, driver, channel, and permissions."
    )

    input(
        f"\n{CLR_YELLOW}Press ENTER to restore {interface} back to managed mode...{CLR_RESET}"
    )

    print(f"\n[*] Restoring {interface} back to managed mode...")

    restored = controller.restore_managed_mode()

    if not restored:
        print(
            f"{CLR_RED}[❌ ERROR] Failed to restore {interface} to managed mode.{CLR_RESET}"
        )
        print(
            f"{CLR_YELLOW}[WARNING] You may need to manually reconnect WiFi or run:\n"
            f"  sudo ip link set {interface} down\n"
            f"  sudo iw dev {interface} set type managed\n"
            f"  sudo ip link set {interface} up{CLR_RESET}"
        )
        return False

    print(f"{CLR_GREEN}[✓] SUCCESS: {interface} restored to managed mode.{CLR_RESET}")
    print("\n=== Monitor Mode Test Completed ===")
    return True


def test_wifi_monitor_capture(interface: str, duration_seconds: int = 15) -> bool:
    """
    Tests the full WiFi monitor capture pipeline.

    Flow:
    monitor mode -> Scapy capture -> WiFiPacketParser -> EventBus -> DeviceRegistry
    """
    controller = WiFiModeController(interface)
    event_bus = EventBus()
    registry = DeviceRegistry()
    packet_traces = []

    event_bus.subscribe(registry.ingest)

    print("\n=== AirSentry WiFi Monitor Capture Test ===\n")
    print(f"[*] Base WiFi Interface       : {interface}")
    print("[*] Interface Role            : physical/base WiFi interface")
    print(f"[*] Monitor Interface         : {controller.monitor_interface}")
    print("[*] Monitor Interface Role    : temporary AirSentry capture interface")
    print(f"[*] Capture duration          : {duration_seconds} seconds")

    def collect_packet_trace(event):
        trace = SmartPacketStreamModel.from_event(event)
        packet_traces.append(trace)

        if len(packet_traces) > 200:
            del packet_traces[0 : len(packet_traces) - 200]

    event_bus.subscribe(collect_packet_trace)

    capture = WiFiMonitorCapture(
        interface=controller.monitor_interface,
        event_bus=event_bus,
        store_raw_bytes=False,
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

        print(
            f"\n[*] Starting WiFi monitor capture on {controller.monitor_interface}..."
        )
        capture.start()

        start_time = time.time()
        last_count = 0

        while time.time() - start_time < duration_seconds:
            processed = event_bus.drain(max_events=100)
            last_count += processed
            time.sleep(0.25)

        capture.stop()

        # Drain remaining events after stopping capture.
        last_count += event_bus.drain(max_events=500)

        devices = registry.all_devices()

        wifi_rows = WiFiViewModel.build_rows(devices)

        print("\n=== WiFi Air Perimeter Preview ===")
        print(
            f"{'ROLE':<8} {'SSID':<28} {'MAC':<18} {'RSSI':<7} "
            f"{'CH':<4} {'BAND':<6} {'SECURITY':<22} {'PKTS':<6}"
        )

        for row in wifi_rows[:20]:
            ssid = row.ssid or "-"
            rssi = round(row.rssi, 1) if row.rssi is not None else "-"
            channel = row.channel or "-"
            band = row.band or "-"
            security = row.security or "unknown"

            print(
                f"{row.role:<8} {ssid[:27]:<28} {row.mac:<18} {str(rssi):<7} "
                f"{str(channel):<4} {str(band):<6} {security[:21]:<22} {row.packet_count:<6}"
            )

        print("\n=== Smart Packet Stream Preview ===")
        print(
            f"{'TIME':<9} {'PROTO':<8} {'TYPE':<16} {'SRC MAC':<18} "
            f"{'DST MAC':<18} {'LEN':<6} {'RSSI':<7} {'CH':<4} SUMMARY"
        )

        for trace in packet_traces[-25:]:
            print(
                f"{trace.timestamp:<9} {trace.protocol:<8} {trace.event_type[:15]:<16} "
                f"{(trace.src_mac or '-'):<18} {(trace.dst_mac or '-'):<18} "
                f"{str(trace.length or '-'):<6} {str(trace.rssi or '-'):<7} "
                f"{str(trace.channel or '-'):<4} {trace.summary[:80]}"
            )

        print("\n=== Capture Summary ===")
        print(f"Raw Packets Seen : {capture.raw_packet_count}")
        print(f"Parsed Events    : {capture.parsed_event_count}")
        print(f"Bus Events       : {last_count}")
        print(f"Parser Errors    : {capture.parser_error_count}")
        print(f"Devices Seen     : {len(devices)}")

        if capture.last_packet_summary:
            print(f"Last Packet      : {capture.last_packet_summary}")

        if capture.last_parser_error:
            print(f"Last Parser Error: {capture.last_parser_error}")

        print()

        if not devices:
            print(
                f"{CLR_YELLOW}[INFO] No WiFi devices were parsed during this short capture window. "
                f"Try increasing duration, changing channel, or moving near active WiFi traffic.{CLR_RESET}"
            )
        else:
            for index, device in enumerate(devices[:20], start=1):
                identity = device.identity
                avg_wifi_rssi = device.avg_wifi_rssi()

                print(f"[{index}] Device ID      : {device.device_id}")
                print(f"    MAC              : {identity.primary_mac or 'unknown'}")
                print(
                    f"    Type             : {identity.suspected_device_type or 'unknown'}"
                )
                print(
                    f"    Protocols        : {', '.join(sorted(identity.protocols_seen)) or 'unknown'}"
                )
                print(f"    Packet Count     : {device.packet_count}")
                print(
                    f"    Avg WiFi RSSI    : "
                    f"{round(avg_wifi_rssi, 2) if avg_wifi_rssi is not None else 'unknown'}"
                )

                if identity.ssids_probed:
                    print(
                        f"    Probed SSIDs     : {', '.join(sorted(identity.ssids_probed))}"
                    )

                if device.risk_notes:
                    print(f"    Risk Notes       : {'; '.join(device.risk_notes)}")

                wifi_security = device.extra.get("wifi_security")

                if wifi_security:
                    print(
                        f"    Security         : "
                        f"{', '.join(wifi_security.get('security', [])) or 'unknown'}"
                    )
                    print(
                        f"    Pairwise Cipher  : "
                        f"{', '.join(wifi_security.get('pairwise_ciphers', [])) or 'unknown'}"
                    )
                    print(
                        f"    AKM              : "
                        f"{', '.join(wifi_security.get('akm_suites', [])) or 'unknown'}"
                    )
                    print(f"    WPS              : {wifi_security.get('wps')}")

                if device.evidence:
                    print(f"    Last Evidence    : {device.evidence[-1].description}")

                if device.last_behavior:
                    print(
                        f"    Last Behavior    : "
                        f"[{device.last_behavior.category}] {device.last_behavior.description}"
                    )

                print()

        return True

    except KeyboardInterrupt:
        print(f"\n{CLR_YELLOW}[-] Capture interrupted by user.{CLR_RESET}")
        return False

    except Exception as e:
        print(f"{CLR_RED}[❌ ERROR] WiFi capture test failed: {e}{CLR_RESET}")
        return False

    finally:
        print(
            f"\n[*] Stopping capture and removing AirSentry monitor interface "
            f"{controller.monitor_interface}..."
        )
        capture.stop()

        if controller.delete_monitor_interface():
            print(
                f"{CLR_GREEN}[✓] SUCCESS: Monitor interface "
                f"{controller.monitor_interface} removed successfully.{CLR_RESET}"
            )
        else:
            print(
                f"{CLR_RED}[❌ ERROR] Failed to restore {interface} to managed mode.{CLR_RESET}"
            )
            print(
                f"{CLR_YELLOW}[WARNING] Manual recovery may be required:\n"
                f"  sudo ip link set {interface} down\n"
                f"  sudo iw dev {interface} set type managed\n"
                f"  sudo ip link set {interface} up{CLR_RESET}"
            )

        print("\n=== WiFi Monitor Capture Test Completed ===")


def run_live_wifi_dashboard(interface: str) -> bool:
    """
    Runs the first real AirSentry live dashboard.

    Flow:
    base WiFi interface -> temporary monitor interface -> Scapy capture
    -> WiFiPacketParser -> EventBus -> DeviceRegistry -> LiveDashboard
    """
    print("\n=== AirSentry Live Dashboard ===\n")

    controller = WiFiModeController(interface)
    event_bus = EventBus()
    registry = DeviceRegistry()
    packet_traces = []
    stop_event = Event()

    channel_hopper = WiFiChannelHopper(
        controller=controller,
        dwell_seconds=1.5,
    )

    wifi_context_data = get_wifi_interface_context_data(interface)

    capture_context = CaptureContext(
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
        visible_layers=[
            "RadioTap metadata",
            "802.11 management frames",
            "802.11 control frames",
            "802.11 data-frame metadata",
        ],
        visible_protocols=[
            "IEEE 802.11",
            "Beacon frames",
            "Probe requests",
            "Control frames",
            "Data-frame metadata",
            "WPA/WPA2/WPA3/WPS metadata",
        ],
        limitations=[
            "A single WiFi adapter listens to one channel at a time.",
            "Channel hopping improves coverage over time but may miss packets.",
            "Protected WiFi payloads may be encrypted and not readable.",
            "Internet connectivity may be interrupted on single-adapter systems.",
            "Live mode keeps a rolling in-memory buffer only.",
            "Use future --db <path> mode for persistent SQLite storage.",
        ],
        active_storage="memory-only",
        channel_strategy=channel_hopper.summary(),
        payload_visibility="encrypted/protected payloads are not decoded",
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


def main():
    # 🚨 Mandatory Root/Raw Sockets Validation
    if os.getuid() != 0:
        print(
            f"{CLR_RED}[❌ EXECUTION ERROR] AirSentry requires root privileges (sudo).{CLR_RESET}"
        )
        print("Usage: sudo ./venv/bin/python run.py")
        sys.exit(1)

    # 🔧 Console Arguments Configuration (No arguments = Automatic, -i = Interactive)
    parser = argparse.ArgumentParser(
        description="AirSentry Framework - Wireless Auditing Ecosystem"
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Deploys the interactive menu to manually select interfaces and modes",
    )
    parser.add_argument(
        "-l",
        "--interfaces",
        action="store_true",
        help="Lists detected Wi-Fi and Bluetooth interfaces, capabilities, and recommended tools, then exits",
    )
    parser.add_argument(
        "--test-monitor",
        action="store_true",
        help="Tests enabling WiFi monitor mode and restoring managed mode, then exits",
    )
    parser.add_argument(
        "--test-wifi-capture",
        action="store_true",
        help="Tests WiFi monitor capture, parses packets, updates the device registry, and restores managed mode",
    )
    parser.add_argument(
        "--live-dashboard",
        action="store_true",
        help="Runs the AirSentry live dashboard using the current WiFi monitor pipeline",
    )
    args = parser.parse_args()

    print("=== AirSentry Framework Core | Initializing Environment ===")

    # Control variables for hardware infrastructure and cleanup fallback
    wifi_controller = None
    used_wifi_interface = None

    # 🔍 REAL HARDWARE SCANNING VIA KERNEL
    wifi_dict = HardwareReader.list_wifi_interfaces()
    has_wifi = len(wifi_dict) > 0
    default_wifi_interface = (
        HardwareReader.get_default_wifi_interface() if has_wifi else None
    )

    wifi_supports_monitor = (
        wifi_dict.get(default_wifi_interface, {}).get("monitor")
        == HardwareReader.CAP_YES
        if has_wifi and default_wifi_interface
        else False
    )

    wifi_supports_promiscuo = (
        wifi_dict.get(default_wifi_interface, {}).get("promiscuous")
        == HardwareReader.CAP_YES
        if has_wifi and default_wifi_interface
        else False
    )

    bt_info = HardwareReader.check_bluetooth_status()
    has_bluetooth = bt_info["available"]
    if args.interfaces:
        print_interfaces_report(wifi_dict, bt_info)

        if not has_wifi and not has_bluetooth:
            print(
                f"{CLR_RED}[❌ CRITICAL ERROR] No Bluetooth or Wi-Fi chips detected in any mode. AirSentry cannot proceed.{CLR_RESET}"
            )
            sys.exit(1)

        sys.exit(0)
    if args.test_monitor:
        if not has_wifi or not default_wifi_interface:
            print(
                f"{CLR_RED}[❌ ERROR] No WiFi interface detected. Cannot test monitor mode.{CLR_RESET}"
            )
            sys.exit(1)

        if (
            wifi_dict.get(default_wifi_interface, {}).get("monitor")
            != HardwareReader.CAP_YES
        ):
            print(
                f"{CLR_RED}[❌ ERROR] {default_wifi_interface} does not report monitor mode support. "
                f"Cannot safely continue.{CLR_RESET}"
            )
            sys.exit(1)

        success = test_wifi_monitor_mode(default_wifi_interface)
        sys.exit(0 if success else 1)

    if args.test_wifi_capture:
        if not has_wifi or not default_wifi_interface:
            print(
                f"{CLR_RED}[❌ ERROR] No WiFi interface detected. Cannot test WiFi capture.{CLR_RESET}"
            )
            sys.exit(1)

        if (
            wifi_dict.get(default_wifi_interface, {}).get("monitor")
            != HardwareReader.CAP_YES
        ):
            print(
                f"{CLR_RED}[❌ ERROR] {default_wifi_interface} does not report monitor mode support. "
                f"Cannot safely continue.{CLR_RESET}"
            )
            sys.exit(1)

        success = test_wifi_monitor_capture(default_wifi_interface)
        sys.exit(0 if success else 1)

    if args.live_dashboard:
        if not has_wifi or not default_wifi_interface:
            print(
                f"{CLR_RED}[❌ ERROR] No WiFi interface detected. "
                f"Cannot start live dashboard.{CLR_RESET}"
            )
            sys.exit(1)

        if (
            wifi_dict.get(default_wifi_interface, {}).get("monitor")
            != HardwareReader.CAP_YES
        ):
            print(
                f"{CLR_RED}[❌ ERROR] {default_wifi_interface} does not report "
                f"monitor mode support. Cannot safely continue.{CLR_RESET}"
            )
            sys.exit(1)

        success = run_live_wifi_dashboard(default_wifi_interface)
        sys.exit(0 if success else 1)

    default_bt_interface = bt_info["interface"]
    bt_supports_ble = (
        bt_info.get("external_ble") == HardwareReader.CAP_YES
        or bt_info.get("ble_scan") == HardwareReader.CAP_YES
    )
    bt_uses_limited_ble = (
        bt_info.get("ble_scan") == HardwareReader.CAP_YES
        and bt_info.get("external_ble") != HardwareReader.CAP_YES
    )

    try:
        # ❌ CRITICAL CASE 1: No compatible hardware found at all
        if not has_wifi and not has_bluetooth:
            print(
                f"{CLR_RED}[❌ CRITICAL ERROR] No Bluetooth or Wi-Fi chips detected in any mode. AirSentry cannot proceed.{CLR_RESET}"
            )
            sys.exit(1)

        # ⚠️ CRITICAL CASE 2: Partial hardware available warnings
        if has_wifi and not has_bluetooth:
            print(
                f"{CLR_YELLOW}[⚠️ WARNING] Only Wi-Fi hardware is available. AirSentry will only audit what is physically possible.{CLR_RESET}"
            )
            print(
                f"{CLR_RED}[Remember] Bluetooth packet auditing will be skipped due to missing hardware.{CLR_RESET}\n"
            )
        elif has_bluetooth and not has_wifi:
            print(
                f"{CLR_YELLOW}[⚠️ WARNING] Only Bluetooth hardware is available. AirSentry will only audit what is physically possible.{CLR_RESET}\n"
            )

        # ---------------------------------------------------------
        # 🤖 ROUTE A: DEFAULT AUTOMATIC MODE (NO ARGUMENTS)
        # ---------------------------------------------------------
        if not args.interactive:
            print(f"{CLR_YELLOW}[*] Running in Default Automatic Mode...{CLR_RESET}")

            # Optimal Wi-Fi Mode Selection
            chosen_wifi_mode = "MANAGED"
            if wifi_supports_monitor:
                chosen_wifi_mode = "MONITOR"
            elif wifi_supports_promiscuo:
                chosen_wifi_mode = "PROMISCUOUS"

            # Optimal Bluetooth Mode Selection
            chosen_bt_mode = "BLE" if bt_supports_ble else "HCI"

            print("\n[*] Provisioning hardware automatically...")
            if has_wifi:
                print_chip_success("WIFI", default_wifi_interface, chosen_wifi_mode)
            if has_bluetooth:
                print_chip_success("BT", default_bt_interface, chosen_bt_mode)

        # ---------------------------------------------------------
        # 🎯 ROUTE B: INTERACTIVE MODE (WITH -i FLAG)
        # ---------------------------------------------------------
        else:
            print(f"{CLR_BLUE}[*] Interactive Mode Activated.{CLR_RESET}")

            # 1. Wi-Fi Interface Menu Selection
            if has_wifi:
                print("\n--- Detected Wi-Fi Interfaces ---")
                print(f"  [1] {default_wifi_interface} [Current System Default]")
                print(
                    f"      > Capabilities: Monitor: {'YES' if wifi_supports_monitor else 'NO'}, Promiscuous: {'YES' if wifi_supports_promiscuo else 'NO'}, Managed: YES"
                )

                print(f"\n[*] Target interface auto-selected: {default_wifi_interface}")

                # Wi-Fi Mode Selection Menu
                print(
                    "\nSelect the operating mode for the Wi-Fi interface (Recommended: MONITOR):"
                )
                print(
                    f"  [1] MONITOR   -> {MODE_DESCRIPTIONS['WIFI_MONITOR']['auditing']}"
                )
                print(
                    f"  [2] PROMISCUOUS -> {MODE_DESCRIPTIONS['WIFI_PROMISCUOUS']['auditing']}"
                )
                print(
                    f"  [3] MANAGED   -> {MODE_DESCRIPTIONS['WIFI_MANAGED']['auditing']}"
                )

                wifi_option = (
                    input("\nEnter choice [1-3] (Default: 1): ").strip() or "1"
                )

                if wifi_option == "1" and wifi_supports_monitor:
                    final_wifi_mode = "MONITOR"
                elif wifi_option == "2":
                    final_wifi_mode = "PROMISCUOUS"
                    print(
                        f"{CLR_YELLOW}[⚠️ NOTE] Operating in Promiscuous mode requires the network password later.{CLR_RESET}"
                    )
                else:
                    final_wifi_mode = "MANAGED"
                    print(
                        f"{CLR_YELLOW}[⚠️ WARNING] In Managed mode, AirSentry will not capture packets from other devices outside of broadcast or your own host.{CLR_RESET}"
                    )

            # 2. Bluetooth Interface Menu Selection
            if has_bluetooth:
                print("\n--- Detected Bluetooth Interfaces ---")
                print(f"  [1] {default_bt_interface}")
                ble_label = "NO"
                if bt_info.get("external_ble") == HardwareReader.CAP_YES:
                    ble_label = "YES (External BLE sniffer)"
                elif bt_info.get("ble_scan") == HardwareReader.CAP_YES:
                    ble_label = "YES (Basic BLE via local HCI, limited)"

                print(
                    f"      > Capabilities: HCI Sniffing: YES, BLE Sniffing: {ble_label}"
                )

                if bt_uses_limited_ble:
                    print(
                        f"{CLR_YELLOW}[INFO] This system supports basic BLE scanning through the local HCI adapter. "
                        f"For full BLE sniffing power, dedicated external hardware is recommended.{CLR_RESET}"
                    )

                print("\nSelect the operating mode for the Bluetooth chip:")
                print(f"  [1] HCI -> {MODE_DESCRIPTIONS['BT_HCI']['auditing']}")
                print(f"  [2] BLE -> {MODE_DESCRIPTIONS['BT_BLE']['auditing']}")

                bt_option = input("\nEnter choice [1-2] (Default: 1): ").strip() or "1"

                if bt_option == "2" and bt_supports_ble:
                    final_bt_mode = "BLE"
                elif bt_option == "2" and not bt_supports_ble:
                    final_bt_mode = "HCI"
                    print(
                        f"{CLR_YELLOW}[⚠️ WARNING] BLE is not available on this system. Falling back to HCI mode.{CLR_RESET}"
                    )
                else:
                    final_bt_mode = "HCI"

            # Launching chips based on explicit user choices
            print("\n[*] Applying custom hardware profiles...")
            if has_wifi:
                print_chip_success("WIFI", default_wifi_interface, final_wifi_mode)
            if has_bluetooth:
                print_chip_success("BT", default_bt_interface, final_bt_mode)

    except KeyboardInterrupt:
        print("\n[-] Cancelled by user cleanly.")

    except Exception as e:
        # 🚨 AUTOMATIC FORENSIC FALLBACK BLOCK
        print("\n" + "!" * 60)
        print(
            f"{CLR_RED}[❌ CRITICAL FALLBACK] AN EXECUTION FAILURE WAS ENCOUNTERED{CLR_RESET}"
        )
        print("!" * 60)

        ex_type, ex_obj, ex_tb = sys.exc_info()
        stack_trace = traceback.extract_tb(ex_tb)
        last_fault = stack_trace[-1]

        print("\n📝 FORENSIC ERROR DOSSIER FOR ANALYSIS:")
        print(f"  • Exception Type : {ex_type.__name__}")
        print(f"  • Error Message  : {e}")
        print(f"  • Target File    : {last_fault.filename}")
        print(f"  • Exact Line     : {last_fault.lineno}")
        print(f"  • Inside Function: {last_fault.name}()")
        print(f"  • Source Code Bug: {last_fault.line}")
        print("\n" + "!" * 60)

    finally:
        # 🔄 ABSOLUTE HARDWARE SANITIZATION & RESTORATION
        print("\n[*] Safely tearing down AirSentry environment...")
        if wifi_controller and used_wifi_interface:
            print(
                f"[*] Restoring {used_wifi_interface} back to standard factory settings..."
            )
        print("=== AirSentry Finalized ===")


if __name__ == "__main__":
    main()
