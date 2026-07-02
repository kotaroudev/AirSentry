# AirSentry

AirSentry is a Linux-first wireless auditing MVP focused on detecting available WiFi and Bluetooth hardware, reporting supported auditing modes, and preparing the system for safe wireless analysis.

This MVP is intentionally starting with hardware discovery because every future AirSentry feature depends on knowing what the current Linux host can actually audit.

AirSentry is intended for authorized cybersecurity research, defensive monitoring, lab environments, asset visibility, and security education.

## Current MVP Features

### Hardware Discovery

AirSentry can list available WiFi and Bluetooth interfaces without starting packet capture or changing interface modes.

Current capabilities:

* Detects WiFi interfaces from Linux kernel paths.
* Detects the current default WiFi interface.
* Shows the WiFi MAC address.
* Shows the WiFi interface state.
* Shows the WiFi driver when available.
* Reports Managed mode availability.
* Reports Promiscuous mode availability.
* Reports Monitor mode availability when `iw` is available.
* Reports Monitor mode as `UNKNOWN` when precise detection is not possible.
* Detects Bluetooth HCI interfaces.
* Filters Bluetooth aliases such as `hci0:1`.
* Reports basic BLE scan availability through the local HCI adapter.
* Warns when BLE support is limited.
* Reports when external BLE sniffing hardware is not available.
* Lists recommended system tools.

## Usage

### List Detected Interfaces

Use this command to list detected WiFi and Bluetooth interfaces:

```bash
sudo ./venv/bin/python run.py --interfaces
```

Short version:

```bash
sudo ./venv/bin/python run.py -l
```

Example output:

```text
=== AirSentry Hardware Discovery Report ===

--- Recommended System Tools ---
  iw             : FOUND
  bluetoothctl   : FOUND
  btmon          : FOUND
  ip             : FOUND

--- Wi-Fi Interfaces ---
  [1] wlan0 [Current System Default]
      MAC Address       : xx:xx:xx:xx:xx:xx
      State             : up
      Driver            : rtw88_8822ce
      Managed Mode      : YES
      Promiscuous Mode  : YES
      Monitor Mode      : YES
      Monitor Detector  : iw/nl80211

--- Bluetooth Interfaces ---
  [1] hci0 [Default]
      HCI Available     : YES
      BLE Basic Scan    : YES
      External BLE      : NO
      Detection Method  : sysfs
      [INFO] Basic BLE scanning is available through the local HCI adapter, but full BLE sniffing requires dedicated external hardware.

=== End of Hardware Discovery Report ===
```

## Auditing Modes

### WiFi Modes

#### Monitor Mode

Monitor mode analyzes nearby wireless traffic at the air/radio level.

It can observe wireless frames from nearby networks and devices, depending on hardware support, driver support, selected channel, and permissions.

AirSentry should prefer Monitor mode when it is available.

#### Promiscuous Mode

Promiscuous mode analyzes packets visible inside the current local network context.

It is useful for LAN-level inspection, but it does not provide the same air-level visibility as Monitor mode.

When using Promiscuous mode on encrypted WiFi networks, the network password may be required later depending on the capture and decoding workflow.

#### Managed Mode

Managed mode is the normal connected WiFi mode.

In this mode, AirSentry can only analyze traffic visible to the host, such as packets addressed to the local machine and broadcast traffic.

Managed mode does not capture arbitrary wireless traffic from other nearby devices.

### Bluetooth Modes

#### HCI Mode

HCI mode uses the local Bluetooth controller interface exposed by Linux.

It can inspect local Bluetooth controller activity, host-controller events, and basic Bluetooth information available through the system Bluetooth stack.

#### BLE Mode

BLE mode focuses on Bluetooth Low Energy discovery.

When only the local HCI adapter is available, AirSentry can perform basic BLE scanning, mainly useful for detecting nearby BLE advertising activity.

This local BLE mode is limited. Full BLE sniffing, especially deeper connection-level BLE analysis, generally requires dedicated external BLE sniffing hardware.

## Recommended System Tools

AirSentry uses low-level Linux interfaces first and recommended system tools only when they improve detection accuracy.

These tools are not Python packages and should be installed with the system package manager.

### Debian / Ubuntu / Kali

```bash
sudo apt update
sudo apt install -y iw bluez iproute2
```

### Fedora

```bash
sudo dnf install -y iw bluez iproute
```

### Alpine

```bash
sudo apk add iw bluez iproute2
```

Recommended tools:

* `iw`: improves WiFi capability detection, especially Monitor mode support.
* `bluez`: provides the Linux Bluetooth stack and related tools.
* `iproute2` / `iproute`: provides modern Linux networking utilities.

AirSentry should still start without these tools, but some capabilities may be reported as `UNKNOWN`.

## Python Requirements

Install Python dependencies:

```bash
./venv/bin/pip install -r requirements.txt
```

Current Python dependencies:

```text
scapy==2.7.0
ruff
```

## Development

Format Python files with Ruff:

```bash
./venv/bin/ruff format .
```

Run lint fixes:

```bash
./venv/bin/ruff check . --fix
```

## Current Project Structure

```text
.
├── README.md
├── requirements-system.md
├── requirements.txt
├── run.py
└── src
    ├── core
    │   ├── __init__.py
    │   ├── mode_descriptions.py
    │   └── models.py
    ├── infrastructure
    │   ├── bluetooth_capability_detector.py
    │   ├── hardware_reader.py
    │   ├── __init__.py
    │   └── wifi_capability_detector.py
    ├── presentation
    │   └── console_reporter.py
    └── use_cases
        ├── discover_hardware.py
        └── __init__.py
```

## Security Notice

AirSentry is designed for authorized wireless audits, defensive monitoring, lab environments, asset visibility, cybersecurity education, and research on owned or permitted networks.

Do not use AirSentry to monitor, intercept, disrupt, attack, or analyze networks or devices without authorization.

This MVP currently performs hardware discovery only. Packet capture, packet analysis, dashboard views, and device correlation will be added incrementally.
