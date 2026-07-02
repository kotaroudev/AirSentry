import os
import sys
import argparse
import traceback
from src.infrastructure.hardware_reader import HardwareReader
from src.core.mode_descriptions import MODE_DESCRIPTIONS

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

            print(f"\n[*] Provisioning hardware automatically...")
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
                print(f"\n--- Detected Wi-Fi Interfaces ---")
                print(f"  [1] {default_wifi_interface} [Current System Default]")
                print(
                    f"      > Capabilities: Monitor: {'YES' if wifi_supports_monitor else 'NO'}, Promiscuous: {'YES' if wifi_supports_promiscuo else 'NO'}, Managed: YES"
                )

                print(f"\n[*] Target interface auto-selected: {default_wifi_interface}")

                # Wi-Fi Mode Selection Menu
                print(
                    f"\nSelect the operating mode for the Wi-Fi interface (Recommended: MONITOR):"
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
                print(f"\n--- Detected Bluetooth Interfaces ---")
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

                print(f"\nSelect the operating mode for the Bluetooth chip:")
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
            print(f"\n[*] Applying custom hardware profiles...")
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

        print(f"\n📝 FORENSIC ERROR DOSSIER FOR ANALYSIS:")
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
