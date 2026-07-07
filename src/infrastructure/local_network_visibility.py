from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    DNS,
    IP,
    UDP,
    AsyncSniffer,
    Ether,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6ND_RA,
    ICMPv6ND_RS,
    IPv6,
    Raw,
)

from src.core.event_bus import EventBus
from src.core.models import RawWirelessEvent, SignalSample


@dataclass
class LocalNetworkVisibilityCollector:
    """
    Local Network Visibility collector.

    Captures local identity/discovery protocols visible to this host:
    ARP, DHCP, mDNS, SSDP/UPnP, DNS, LLMNR and NetBIOS.

    This is not WiFi monitor mode. It runs on the managed/local interface
    and helps correlate MAC, IP, hostnames and services.
    """

    event_bus: EventBus
    interface: str
    promiscuous: bool = True
    _sniffer: AsyncSniffer | None = field(default=None, init=False)

    def start(self) -> None:
        if self._sniffer:
            return

        self._sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._handle_packet,
            store=False,
            promisc=self.promiscuous,
            filter="arp or udp or icmp6",
        )
        self._sniffer.start()

    def stop(self) -> None:
        if not self._sniffer:
            return

        try:
            self._sniffer.stop()
        except Exception:
            pass

        self._sniffer = None

    def _parse_ipv6_ndp(self, packet) -> RawWirelessEvent | None:
        fields = self._base_fields(packet)

        if ICMPv6ND_RA in packet:
            event_type = "ndp_router_advertisement"
            summary = f"IPv6 NDP Router Advertisement {fields.get('src_ip')} -> {fields.get('dst_ip')}"
        elif ICMPv6ND_RS in packet:
            event_type = "ndp_router_solicitation"
            summary = f"IPv6 NDP Router Solicitation {fields.get('src_ip')} -> {fields.get('dst_ip')}"
        elif ICMPv6ND_NS in packet:
            event_type = "ndp_neighbor_solicitation"
            target = packet[ICMPv6ND_NS].tgt
            summary = f"IPv6 NDP Neighbor Solicitation target={target}"
        elif ICMPv6ND_NA in packet:
            event_type = "ndp_neighbor_advertisement"
            target = packet[ICMPv6ND_NA].tgt
            summary = f"IPv6 NDP Neighbor Advertisement target={target}"
        else:
            event_type = "icmpv6_activity"
            summary = (
                f"ICMPv6 activity {fields.get('src_ip')} -> {fields.get('dst_ip')}"
            )

        return RawWirelessEvent(
            **fields,
            protocol="NDP",
            event_type=event_type,
            service_name="IPv6 Neighbor Discovery",
            parsed_fields={
                "ndp": {
                    "src_ip": fields.get("src_ip"),
                    "dst_ip": fields.get("dst_ip"),
                }
            },
            extra={},
            raw_summary=summary,
            raw_layers=["Ethernet", "IPv6", "ICMPv6", "NDP"],
        )

    def _parse_dhcpv6(self, packet) -> RawWirelessEvent | None:
        fields = self._base_fields(packet)

        return RawWirelessEvent(
            **fields,
            protocol="DHCPV6",
            event_type="dhcpv6_activity",
            service_name="DHCPv6",
            parsed_fields={
                "dhcpv6": {
                    "sport": int(packet[UDP].sport),
                    "dport": int(packet[UDP].dport),
                }
            },
            extra={},
            raw_summary=f"DHCPv6 activity {fields.get('src_ip')} -> {fields.get('dst_ip')}",
            raw_layers=["Ethernet", "IPv6", "UDP", "DHCPv6"],
        )

    def _parse_ws_discovery(self, packet) -> RawWirelessEvent | None:
        fields = self._base_fields(packet)
        payload = self._raw_text(packet)

        lowered = payload.lower()

        if "probe" in lowered:
            event_type = "ws_discovery_probe"
        elif "hello" in lowered:
            event_type = "ws_discovery_hello"
        elif "resolve" in lowered:
            event_type = "ws_discovery_resolve"
        else:
            event_type = "ws_discovery"

        service_name = "WS-Discovery"

        return RawWirelessEvent(
            **fields,
            protocol="WS_DISCOVERY",
            event_type=event_type,
            service_name=service_name,
            parsed_fields={
                "ws_discovery": {
                    "payload_preview": payload[:500],
                    "sport": int(packet[UDP].sport),
                    "dport": int(packet[UDP].dport),
                }
            },
            extra={
                "payload_preview": payload[:500],
            },
            raw_summary=f"WS-Discovery {event_type} {fields.get('src_ip')} -> {fields.get('dst_ip')}",
            raw_layers=["Ethernet", "IP", "UDP", "WS-Discovery"],
        )

    def _handle_packet(self, packet) -> None:
        try:
            event = self._parse_packet(packet)

            if event:
                self.event_bus.publish(event)

        except Exception as error:
            print(f"[local-visibility parser error] {type(error).__name__}: {error}")

    def _parse_packet(self, packet) -> RawWirelessEvent | None:
        if ARP in packet:
            return self._parse_arp(packet)

        if (
            ICMPv6ND_NS in packet
            or ICMPv6ND_NA in packet
            or ICMPv6ND_RS in packet
            or ICMPv6ND_RA in packet
        ):
            return self._parse_ipv6_ndp(packet)

        if DHCP in packet or BOOTP in packet:
            return self._parse_dhcp(packet)

        if UDP in packet:
            sport = int(packet[UDP].sport)
            dport = int(packet[UDP].dport)

            if sport == 5353 or dport == 5353:
                return self._parse_dns_like(packet, protocol="MDNS", event_type="mdns")

            if sport == 53 or dport == 53:
                return self._parse_dns_like(packet, protocol="DNS", event_type="dns")

            if sport == 5355 or dport == 5355:
                return self._parse_dns_like(
                    packet,
                    protocol="LLMNR",
                    event_type="llmnr",
                )

            if sport == 1900 or dport == 1900:
                return self._parse_ssdp(packet)

            if sport in {137, 138} or dport in {137, 138}:
                return self._parse_netbios(packet)

            if sport in {546, 547} or dport in {546, 547}:
                return self._parse_dhcpv6(packet)

            if sport == 3702 or dport == 3702:
                return self._parse_ws_discovery(packet)

        return None

    def _base_fields(self, packet) -> dict:
        ether = packet[Ether] if Ether in packet else None
        ip = packet[IP] if IP in packet else None
        ipv6 = packet[IPv6] if IPv6 in packet else None

        return {
            "event_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc),
            "source": "LOCAL_NETWORK",
            "capture_mode": "LOCAL_VISIBILITY",
            "interface": self.interface,
            "src_mac": ether.src.lower() if ether and ether.src else None,
            "dst_mac": ether.dst.lower() if ether and ether.dst else None,
            "src_ip": ip.src if ip else ipv6.src if ipv6 else None,
            "dst_ip": ip.dst if ip else ipv6.dst if ipv6 else None,
            "vendor": None,
            "signal": SignalSample(
                rssi=None,
                channel=None,
                frequency_mhz=None,
                band=None,
            ),
        }

    def _parse_arp(self, packet) -> RawWirelessEvent | None:
        fields = self._base_fields(packet)
        arp = packet[ARP]

        event_type = "arp_reply" if int(arp.op) == 2 else "arp_request"

        fields["src_ip"] = arp.psrc
        fields["dst_ip"] = arp.pdst

        return RawWirelessEvent(
            **fields,
            protocol="ARP",
            event_type=event_type,
            parsed_fields={
                "arp": {
                    "op": int(arp.op),
                    "psrc": arp.psrc,
                    "pdst": arp.pdst,
                    "hwsrc": arp.hwsrc,
                    "hwdst": arp.hwdst,
                }
            },
            extra={},
            raw_summary=(
                f"ARP {event_type} {arp.psrc} ({arp.hwsrc}) -> {arp.pdst} ({arp.hwdst})"
            ),
            raw_layers=["Ethernet", "ARP"],
        )

    def _parse_dhcp(self, packet) -> RawWirelessEvent | None:
        fields = self._base_fields(packet)
        options = self._dhcp_options(packet)
        message_type = str(options.get("message-type") or "unknown").lower()

        hostname = options.get("hostname")
        requested_addr = options.get("requested_addr")
        vendor_class_id = options.get("vendor_class_id")

        event_type = f"dhcp_{message_type.replace(' ', '_')}"

        return RawWirelessEvent(
            **fields,
            protocol="DHCP",
            event_type=event_type,
            hostname=hostname,
            service_name="DHCP",
            parsed_fields={
                "dhcp": {
                    "message_type": message_type,
                    "hostname": hostname,
                    "requested_addr": requested_addr,
                    "vendor_class_id": vendor_class_id,
                    "options": options,
                }
            },
            extra={
                "hostname": hostname,
                "requested_addr": requested_addr,
                "vendor_class_id": vendor_class_id,
            },
            raw_summary=(
                f"DHCP {message_type}"
                + (f" hostname={hostname}" if hostname else "")
                + (f" requested_ip={requested_addr}" if requested_addr else "")
                + (f" vendor_class={vendor_class_id}" if vendor_class_id else "")
            ),
            raw_layers=["Ethernet", "IPv4", "UDP", "DHCP"],
        )

    def _parse_dns_like(
        self,
        packet,
        protocol: str,
        event_type: str,
    ) -> RawWirelessEvent | None:
        fields = self._base_fields(packet)

        query_name = None
        response_name = None

        if DNS in packet:
            dns = packet[DNS]

            if dns.qd:
                query_name = self._decode_dns_name(getattr(dns.qd, "qname", None))

            if dns.an:
                response_name = self._decode_dns_name(getattr(dns.an, "rrname", None))

        observed_name = response_name or query_name

        full_event_type = (
            f"{event_type}_response" if response_name else f"{event_type}_query"
        )

        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)

        return RawWirelessEvent(
            **fields,
            protocol=protocol,
            event_type=full_event_type,
            hostname=None,
            service_name=observed_name,
            parsed_fields={
                protocol.lower(): {
                    "query_name": query_name,
                    "response_name": response_name,
                    "observed_name": observed_name,
                    "sport": sport,
                    "dport": dport,
                    "scapy_decoded_dns": DNS in packet,
                }
            },
            extra={
                "query_name": query_name,
                "response_name": response_name,
                "observed_name": observed_name,
                "sport": sport,
                "dport": dport,
            },
            raw_summary=(
                f"{protocol} {full_event_type} ports={sport}->{dport}"
                + (f" name={observed_name}" if observed_name else "")
            ),
            raw_layers=["Ethernet", "IP", "UDP", protocol],
        )

    def _parse_ssdp(self, packet) -> RawWirelessEvent | None:
        fields = self._base_fields(packet)
        payload = self._raw_text(packet)

        service_name = self._extract_header(payload, "ST") or self._extract_header(
            payload,
            "NT",
        )
        usn = self._extract_header(payload, "USN")

        if payload.startswith("M-SEARCH"):
            event_type = "ssdp_m_search"
        elif payload.startswith("NOTIFY"):
            event_type = "ssdp_notify"
        else:
            event_type = "ssdp"

        return RawWirelessEvent(
            **fields,
            protocol="SSDP",
            event_type=event_type,
            service_name=service_name,
            parsed_fields={
                "ssdp": {
                    "service_name": service_name,
                    "usn": usn,
                    "payload_preview": payload[:500],
                }
            },
            extra={
                "service_name": service_name,
                "usn": usn,
            },
            raw_summary=(
                f"SSDP {event_type}"
                + (f" service={service_name}" if service_name else "")
                + (f" usn={usn}" if usn else "")
            ),
            raw_layers=["Ethernet", "IP", "UDP", "SSDP"],
        )

    def _parse_netbios(self, packet) -> RawWirelessEvent | None:
        fields = self._base_fields(packet)

        return RawWirelessEvent(
            **fields,
            protocol="NETBIOS",
            event_type="netbios_activity",
            service_name="NetBIOS",
            parsed_fields={
                "netbios": {
                    "sport": int(packet[UDP].sport),
                    "dport": int(packet[UDP].dport),
                }
            },
            extra={},
            raw_summary=(
                f"NetBIOS UDP activity {fields.get('src_ip')} -> {fields.get('dst_ip')}"
            ),
            raw_layers=["Ethernet", "IP", "UDP", "NetBIOS"],
        )

    def _dhcp_options(self, packet) -> dict:
        result = {}

        if DHCP not in packet:
            return result

        for option in packet[DHCP].options:
            if not isinstance(option, tuple) or len(option) < 2:
                continue

            key, value = option[0], option[1]

            if isinstance(value, bytes):
                value = value.decode(errors="ignore")

            result[str(key)] = value

        return result

    def _decode_dns_name(self, value) -> str | None:
        if not value:
            return None

        if isinstance(value, bytes):
            value = value.decode(errors="ignore")

        return str(value).rstrip(".")

    def _raw_text(self, packet) -> str:
        if Raw not in packet:
            return ""

        try:
            return bytes(packet[Raw]).decode(errors="ignore").strip()
        except Exception:
            return ""

    def _extract_header(self, payload: str, header_name: str) -> str | None:
        prefix = f"{header_name.lower()}:"

        for line in payload.splitlines():
            lowered = line.lower().strip()

            if lowered.startswith(prefix):
                return line.split(":", maxsplit=1)[1].strip()

        return None
