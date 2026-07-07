# AirSentry

AirSentry is a Linux-first defensive visibility tool for local network and wireless auditing.

Its purpose is to help an analyst understand:

- What devices are visible from the current machine.
- What protocols, services, hostnames, IPs, MACs and vendors are exposed.
- What nearby WiFi and Bluetooth activity is visible.
- What raw evidence supports each device identity.
- Which devices or endpoints appear related.

AirSentry is not only a packet viewer. Its philosophy is:

```text
Collectors observe raw events.
Parsers normalize those events.
The registry correlates them into device profiles.
Smart Packet Stream preserves the technical trace.
Device Intelligence explains what was observed.
```

---

## Current MVP

AirSentry currently has two live profiles:

| Profile | Command | Purpose |
|---|---|---|
| Local Network Visibility | `sudo ./venv/bin/python run.py` | Default mode. Observes local network protocols visible to this host. |
| Air Perimeter | `sudo ./venv/bin/python run.py --air-perimeter` | Optional mode. Uses WiFi monitor mode and BLE scan to observe nearby wireless activity. |

The dashboard includes:

- Overview
- Local Visibility / WiFi Air Perimeter
- Bluetooth Radar
- Smart Packet Stream
- Device Intelligence
- Per-view context help
- Device search in Device Intelligence
- Basic related-device correlation
- OUI/vendor lookup
- WiFi channel hopping in Air Perimeter mode
- BLE Basic Scan when a Bluetooth adapter is available

---

## Installation on Kali Linux

Clone the project:

```bash
git clone https://github.com/kotaroudev/AirSentry.git
cd AirSentry
```

Create a Python virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Install recommended system tools:

```bash
sudo apt update
sudo apt install -y iw tcpdump bluez wireless-tools
```

AirSentry requires root privileges because it uses packet capture and wireless interface operations.

---

## Commands

AirSentry currently keeps the CLI minimal for the MVP.

### 1. Show help

```bash
./venv/bin/python run.py --help
```

Shows the available profiles and dashboard keys.

---

### 2. Default mode: Local Network Visibility

```bash
sudo ./venv/bin/python run.py
```

This is the default profile.

It listens on the system default local/WiFi interface in managed/promiscuous visibility mode and starts Basic BLE Scan when Bluetooth is available.

It observes local protocols visible to this host, including:

- ARP
- DHCP
- DHCPv6
- DNS
- mDNS
- SSDP / UPnP
- LLMNR
- NetBIOS
- IPv6 Neighbor Discovery
- WS-Discovery when available

### What Local Visibility can see

Local Visibility can observe:

- Traffic to/from this machine
- Broadcast traffic
- Multicast traffic
- Local discovery protocols
- Some additional traffic when promiscuous capture is effective

### What Local Visibility may not see

Local Visibility does not guarantee full discovery of every LAN device.

It may miss:

- Silent devices
- Sleeping phones
- Some unicast traffic between other clients
- Devices isolated by the access point
- Traffic hidden by switch/AP behavior
- WiFi RSSI/signal strength from local IP traffic

Signal strength is only available when a device is observed through WiFi monitor mode or Bluetooth RSSI.

---

### 3. Air Perimeter mode

```bash
sudo ./venv/bin/python run.py --air-perimeter
```

This profile creates a temporary monitor interface and observes nearby WiFi activity in the air.

It captures:

- WiFi access points
- WiFi clients/stations
- Beacons
- Probe requests
- Probe responses
- Control frames
- Data-frame metadata
- Protected frame metadata
- RSSI when available through RadioTap
- Channel and band information
- WiFi security metadata when visible
- BLE advertisements when Bluetooth is available

Air Perimeter uses channel hopping to improve coverage across common 2.4 GHz and 5 GHz channels.

### What Air Perimeter may not capture

Air Perimeter may miss packets because:

- A single adapter listens to one channel at a time
- Channel hopping improves coverage but is not perfect
- Protected WiFi payloads may be encrypted
- Some drivers may not support simultaneous managed and monitor operation
- BLE Basic Scan sees advertising metadata only, not full connected BLE payloads

---

## Dashboard navigation

Inside the dashboard:

```text
0       Overview
1       Local Visibility or WiFi Air Perimeter
2       Bluetooth Radar
3       Smart Packet Stream
4       Device Intelligence

n / p   Next / previous page
j / k   Move down / up in Device Intelligence
e       Expand/collapse selected device card
/       Search in Device Intelligence only
r       Reset page/search/selection
h       Show context/help for the current view
q       Quit dashboard
```

---

## Context help

Press:

```text
h
```

to open the context panel for the current view.

The context panel explains:

- Active profile
- Active hardware
- Capture mode
- Visible protocols
- Capture metadata
- Network layers
- Frame/event families
- Payload visibility
- Current limitations

This is important because each view has different visibility depending on the active profile.

Examples:

- Local Visibility observes local managed/promiscuous traffic.
- Air Perimeter observes 802.11 monitor-mode traffic.
- Bluetooth Radar observes BLE advertising metadata.
- Smart Packet Stream shows normalized technical events.
- Device Intelligence correlates evidence into device profiles.

---

## Search

Search is currently available only in:

```text
Device Intelligence
```

Go to view:

```text
4
```

Then press:

```text
/
```

You can search by:

- MAC address
- IP address
- hostname
- service name
- vendor
- protocol
- device title
- related device
- behavior text

Examples:

```text
/ 192.168
/ spotify
/ googlecast
/ huawei
/ mdns
/ be:42
```

---

## Main views

### Local Visibility

Shows devices inferred from visible local network traffic.

Typical data:

- Device
- MAC
- Vendor
- IPs
- Names
- Protocols
- Services
- Events
- Last behavior

Services such as:

```text
_spotify-connect._tcp.local
_googlecast._tcp.local
urn:schemas-upnp-org:...
```

are not device names. They are services, domains or discovery names observed in traffic.

A device name is shown only when AirSentry has stronger identity evidence, such as:

- DHCP hostname
- mDNS hostname
- LLMNR hostname
- NetBIOS name
- A correlated device title

Otherwise, AirSentry uses the MAC address.

---

### WiFi Air Perimeter

Shows nearby WiFi activity observed through monitor mode.

It includes:

- Access points
- Clients/stations
- SSIDs
- MAC addresses
- RSSI
- Channel
- Band
- Security metadata
- Packet/event counts

---

### Bluetooth Radar

Shows BLE devices observed through the local Bluetooth adapter.

It includes:

- BLE address
- Advertised BLE name when available
- RSSI when available
- Address type
- Services when advertised
- Event count
- Last seen

Many BLE devices use random/private addresses, so identity confidence can be limited.

---

### Smart Packet Stream

Shows the technical trace of normalized events.

It is the best view for validating what AirSentry actually observed.

Typical columns:

- Time
- Radio
- Protocol
- Event type
- Device
- Source
- Destination
- Length
- RSSI
- Channel/Band
- Flags
- Summary

Smart Packet Stream preserves raw technical summaries from parsers so the analyst can inspect the evidence behind Device Intelligence.

---

### Device Intelligence

Device Intelligence is the main correlation view.

It combines available evidence into device cards showing:

- Device title
- Identity
- Radios seen
- IPs and hostnames
- Signal summary when available
- Event counts
- Recent behaviors
- Protocols seen
- Network layers
- Capture metadata
- Frame/event types
- Security evidence
- Services
- Related devices
- Risk notes
- Identity notes

---

## Related devices and observed endpoints

Related devices are built from observed relationships such as:

- Source MAC / destination MAC
- Source IP / destination IP
- BSSID
- Local traffic endpoints
- Protocol interactions

When AirSentry can resolve the endpoint to another known device, it displays the related device name.

When it cannot resolve the endpoint yet, it displays it as an observed endpoint.

Example:

```text
Observed endpoint 77-E0-56-15-F0-11
```

This means AirSentry observed that endpoint as a destination, BSSID, or related network endpoint, but it has not collected enough evidence yet to promote it into a fully identified device card.

Observed endpoints are useful evidence, but they should not be treated as fully identified devices.

---

## Current limitations

AirSentry is passive/best-effort in the current MVP.

Important limitations:

- Local Visibility does not guarantee discovery of every LAN device.
- Managed/promiscuous capture may not see all client-to-client traffic.
- Phones and modern devices may stay quiet until an app triggers local discovery.
- WiFi RSSI is only available through monitor-mode WiFi observations.
- BLE Basic Scan only sees advertising metadata.
- Device names depend on protocols that reveal identity.
- OUI/vendor lookup is soft evidence and can be wrong with randomized MACs.
- Related devices may include unresolved observed endpoints.
- Live mode currently keeps data in memory only.

---

## Working features

Current working features include:

- Local Network Visibility profile
- Air Perimeter profile
- Live terminal dashboard
- WiFi monitor capture
- WiFi channel hopping
- BLE Basic Scan
- Smart Packet Stream
- Device Intelligence
- Local protocol parsing
- ARP, DHCP, DHCPv6, DNS, mDNS, SSDP/UPnP, LLMNR, NetBIOS and IPv6 NDP visibility
- OUI/vendor lookup
- RSSI interpretation for WiFi monitor and BLE when available
- WiFi security metadata extraction when visible
- Recent behavior timeline
- Security evidence
- Identity notes
- Related devices and observed endpoints
- Search in Device Intelligence
- Per-view context help

---

## Next milestone

The next major milestone is persistence and deeper correlation.

Planned work:

- Persistent SQLite storage
- Full filters for each view
- Better per-view layouts
- Faster render performance
- More efficient Device Intelligence caching
- Historical device timelines
- Session comparison
- Exportable reports
- Cross-profile correlation between Local Visibility and Air Perimeter

Persistence is the biggest next feature.

Once AirSentry stores observations over time, it can combine both profiles:

```text
Local Visibility:
  IPs, hostnames, services, DNS/mDNS/SSDP/DHCP evidence

Air Perimeter:
  WiFi RSSI, channels, SSIDs, BSSIDs, probes, nearby wireless behavior

Bluetooth Radar:
  BLE names, BLE addresses, advertised services, proximity hints
```

That will allow AirSentry to build a more complete report of:

- Devices on the local network
- Devices nearby in the wireless spectrum
- Relationships between local devices and observed endpoints
- Identity changes over time
- Services exposed or queried
- Wireless behavior and signal evidence

This is the foundation for a full local network and wireless environment intelligence report.