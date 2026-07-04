from datetime import datetime, timezone
from uuid import uuid4

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, RadioTap

from src.core.models import RawWirelessEvent, SignalSample


class WiFiPacketParser:
    """
    Converts Scapy WiFi packets into AirSentry RawWirelessEvent objects.

    This parser does not capture packets by itself.
    It only translates raw Scapy packets into AirSentry's internal data model.
    """

    SOURCE = "WIFI_MONITOR"

    RSN_CIPHER_SUITES = {
        0: "Use group cipher suite",
        1: "WEP-40",
        2: "TKIP",
        4: "CCMP-128/AES",
        5: "WEP-104",
        6: "BIP-CMAC-128",
        8: "GCMP-128",
        9: "GCMP-256",
        10: "CCMP-256",
        11: "BIP-GMAC-128",
        12: "BIP-GMAC-256",
        13: "BIP-CMAC-256",
    }

    RSN_AKM_SUITES = {
        1: "802.1X",
        2: "PSK",
        3: "FT-802.1X",
        4: "FT-PSK",
        5: "802.1X-SHA256",
        6: "PSK-SHA256",
        8: "SAE",
        9: "FT-SAE",
        11: "802.1X-Suite-B",
        12: "802.1X-Suite-B-192",
        13: "FT-802.1X-SHA384",
        14: "FILS-SHA256",
        15: "FILS-SHA384",
        18: "OWE",
    }

    WPA_VENDOR_OUI = b"\x00\x50\xf2"
    RSN_OUI = b"\x00\x0f\xac"

    @staticmethod
    def parse(packet) -> list[RawWirelessEvent]:
        """
        Parses one Scapy packet and returns zero or more AirSentry events.
        """
        if not packet.haslayer(Dot11):
            return []

        events = []

        if packet.haslayer(Dot11Beacon):
            event = WiFiPacketParser._parse_beacon(packet)
            if event:
                events.append(event)

        elif packet.haslayer(Dot11ProbeReq):
            event = WiFiPacketParser._parse_probe_request(packet)
            if event:
                events.append(event)

        else:
            event = WiFiPacketParser._parse_generic_dot11(packet)
            if event:
                events.append(event)

        return events

    @staticmethod
    def _parse_beacon(packet) -> RawWirelessEvent | None:
        dot11 = packet.getlayer(Dot11)

        ssid = WiFiPacketParser._extract_ssid(packet)
        channel = WiFiPacketParser._extract_channel(packet)
        frequency_mhz = WiFiPacketParser._channel_to_frequency(channel)
        band = WiFiPacketParser._frequency_to_band(frequency_mhz)
        rssi = WiFiPacketParser._extract_rssi(packet)

        return RawWirelessEvent(
            event_id=str(uuid4()),
            timestamp=WiFiPacketParser._packet_timestamp(packet),
            source=WiFiPacketParser.SOURCE,
            capture_mode="WIFI_MONITOR",
            protocol="WIFI",
            event_type="beacon",
            interface=None,
            src_mac=dot11.addr2,
            dst_mac=dot11.addr1,
            bssid=dot11.addr3,
            ssid=ssid,
            signal=SignalSample(
                rssi=rssi,
                channel=channel,
                frequency_mhz=frequency_mhz,
                band=band,
            ),
            parsed_fields=WiFiPacketParser._build_full_parsed_fields(packet, dot11),
            raw_summary=WiFiPacketParser._extract_packet_meta(packet).get("summary"),
            raw_layers=[layer.__name__ for layer in packet.layers()],
        )

    @staticmethod
    def _parse_probe_request(packet) -> RawWirelessEvent | None:
        dot11 = packet.getlayer(Dot11)

        ssid = WiFiPacketParser._extract_ssid(packet)
        rssi = WiFiPacketParser._extract_rssi(packet)

        return RawWirelessEvent(
            event_id=str(uuid4()),
            timestamp=WiFiPacketParser._packet_timestamp(packet),
            source=WiFiPacketParser.SOURCE,
            capture_mode="WIFI_MONITOR",
            protocol="WIFI",
            event_type="probe_request",
            interface=None,
            src_mac=dot11.addr2,
            dst_mac=dot11.addr1,
            bssid=dot11.addr3,
            ssid=ssid,
            signal=SignalSample(rssi=rssi),
            parsed_fields=WiFiPacketParser._build_full_parsed_fields(packet, dot11),
            raw_summary=WiFiPacketParser._extract_packet_meta(packet).get("summary"),
            raw_layers=[layer.__name__ for layer in packet.layers()],
        )

    @staticmethod
    def _parse_generic_dot11(packet) -> RawWirelessEvent | None:
        dot11 = packet.getlayer(Dot11)
        rssi = WiFiPacketParser._extract_rssi(packet)

        event_type = WiFiPacketParser._dot11_event_type(dot11)

        return RawWirelessEvent(
            event_id=str(uuid4()),
            timestamp=WiFiPacketParser._packet_timestamp(packet),
            source=WiFiPacketParser.SOURCE,
            capture_mode="WIFI_MONITOR",
            protocol="WIFI",
            event_type=event_type,
            interface=None,
            src_mac=dot11.addr2,
            dst_mac=dot11.addr1,
            bssid=dot11.addr3,
            signal=SignalSample(rssi=rssi),
            parsed_fields=WiFiPacketParser._build_full_parsed_fields(packet, dot11),
            raw_summary=WiFiPacketParser._extract_packet_meta(packet).get("summary"),
            raw_layers=[layer.__name__ for layer in packet.layers()],
        )

    @staticmethod
    def _extract_ssid(packet) -> str | None:
        element = packet.getlayer(Dot11Elt)

        while element:
            if element.ID == 0:
                try:
                    ssid = element.info.decode(errors="ignore")
                    return ssid if ssid else "<hidden>"
                except Exception:
                    return "<decode-error>"

            element = element.payload.getlayer(Dot11Elt)

        return None

    @staticmethod
    def _extract_channel(packet) -> int | None:
        element = packet.getlayer(Dot11Elt)

        while element:
            if element.ID == 3:
                try:
                    return int(element.info[0])
                except Exception:
                    return None

            element = element.payload.getlayer(Dot11Elt)

        return None

    @staticmethod
    def _extract_rssi(packet) -> int | None:
        if not packet.haslayer(RadioTap):
            return None

        radiotap = packet.getlayer(RadioTap)

        if hasattr(radiotap, "dBm_AntSignal"):
            return radiotap.dBm_AntSignal

        return None

    @staticmethod
    def _packet_timestamp(packet):
        try:
            return datetime.fromtimestamp(float(packet.time), tz=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    @staticmethod
    def _dot11_event_type(dot11: Dot11) -> str:
        if dot11.type == 0:
            return f"management_subtype_{dot11.subtype}"

        if dot11.type == 1:
            return f"control_subtype_{dot11.subtype}"

        if dot11.type == 2:
            return f"data_subtype_{dot11.subtype}"

        return "unknown_dot11"

    @staticmethod
    def _channel_to_frequency(channel: int | None) -> int | None:
        if channel is None:
            return None

        if 1 <= channel <= 14:
            return 2407 + channel * 5

        if 32 <= channel <= 177:
            return 5000 + channel * 5

        return None

    @staticmethod
    def _frequency_to_band(frequency_mhz: int | None) -> str | None:
        if frequency_mhz is None:
            return None

        if 2400 <= frequency_mhz <= 2500:
            return "2.4GHz"

        if 4900 <= frequency_mhz <= 5900:
            return "5GHz"

        if 5925 <= frequency_mhz <= 7125:
            return "6GHz"

        return "unknown"

    @staticmethod
    def _extract_dot11_fields(dot11: Dot11) -> dict:
        """
        Extracts core 802.11 header fields.

        AirSentry keeps all address fields because their meaning changes
        depending on ToDS/FromDS flags.
        """
        fields = {
            "frame_type": dot11.type,
            "frame_subtype": dot11.subtype,
            "addr1_receiver": dot11.addr1,
            "addr2_transmitter": dot11.addr2,
            "addr3_bssid_or_destination": dot11.addr3,
            "addr4_optional": getattr(dot11, "addr4", None),
            "fcfield_raw": str(dot11.FCfield),
            "id": getattr(dot11, "ID", None),
            "sequence_control": getattr(dot11, "SC", None),
            "sequence_number": None,
            "fragment_number": None,
        }

        sequence_control = getattr(dot11, "SC", None)

        if sequence_control is not None:
            try:
                fields["sequence_number"] = sequence_control >> 4
                fields["fragment_number"] = sequence_control & 0xF
            except Exception:
                fields["sequence_parse_error"] = True

        try:
            fcfield = int(dot11.FCfield)
            fields["flags"] = {
                "to_ds": bool(fcfield & 0x01),
                "from_ds": bool(fcfield & 0x02),
                "more_fragments": bool(fcfield & 0x04),
                "retry": bool(fcfield & 0x08),
                "power_management": bool(fcfield & 0x10),
                "more_data": bool(fcfield & 0x20),
                "protected": bool(fcfield & 0x40),
                "order": bool(fcfield & 0x80),
            }
        except Exception:
            fields["flags_parse_error"] = True
            fields["flags"] = {}

        return fields

    @staticmethod
    def _extract_radiotap_fields(packet) -> dict:
        """
        Extracts all RadioTap fields exposed by Scapy.

        RadioTap contains physical-layer metadata such as RSSI, channel,
        rate, antenna, noise, MCS/VHT information, and other driver-exposed
        capture details.
        """
        if not packet.haslayer(RadioTap):
            return {}

        radiotap = packet.getlayer(RadioTap)
        fields = {}

        for field_name, value in radiotap.fields.items():
            fields[field_name] = WiFiPacketParser._safe_value(value)

        return fields

    @staticmethod
    def _extract_dot11_elements(packet) -> list[dict]:
        """
        Extracts all 802.11 Information Elements from management frames.

        This is critical for AP fingerprinting, SSID discovery, RSN/WPA
        capability analysis, supported rates, vendor-specific data, and
        future evil-twin detection.
        """
        elements = []
        element = packet.getlayer(Dot11Elt)

        while element:
            info = getattr(element, "info", b"")

            try:
                info_text = (
                    info.decode(errors="ignore")
                    if isinstance(info, bytes)
                    else str(info)
                )
            except Exception:
                info_text = None

            elements.append(
                {
                    "id": getattr(element, "ID", None),
                    "id_name": WiFiPacketParser._dot11_element_name(
                        getattr(element, "ID", None)
                    ),
                    "length": len(info) if info is not None else 0,
                    "info_text": info_text,
                    "info_hex": info.hex() if isinstance(info, bytes) else None,
                }
            )

            element = element.payload.getlayer(Dot11Elt)

        return elements

    @staticmethod
    def _extract_packet_meta(packet) -> dict:
        """
        Stores generic packet metadata useful for forensic analysis,
        replay, deduplication, and future exporters.
        """
        try:
            packet_length = len(bytes(packet))
        except Exception:
            packet_length = None

        try:
            summary = packet.summary()
        except Exception:
            summary = None

        try:
            layers = [layer.__name__ for layer in packet.layers()]
        except Exception:
            layers = []

        return {
            "packet_length": packet_length,
            "summary": summary,
            "layers": layers,
        }

    @staticmethod
    def _extract_security_hints(packet) -> dict:
        """
        Extracts early security hints from beacon/probe response information.

        This does not fully classify WPA/WPA2/WPA3 yet, but preserves the
        evidence needed for deeper analysis later.
        """
        elements = WiFiPacketParser._extract_dot11_elements(packet)

        element_ids = {element.get("id") for element in elements}
        vendor_specific = [element for element in elements if element.get("id") == 221]

        return {
            "has_rsn_element": 48 in element_ids,
            "has_vendor_specific": 221 in element_ids,
            "vendor_specific_count": len(vendor_specific),
            "has_country_element": 7 in element_ids,
            "has_ht_capabilities": 45 in element_ids,
            "has_ht_operation": 61 in element_ids,
            "has_vht_capabilities": 191 in element_ids,
            "has_vht_operation": 192 in element_ids,
            "has_extended_capabilities": 127 in element_ids,
        }

    @staticmethod
    def _extract_frame_size_hints(packet) -> dict:
        """
        Stores size-related hints.

        Packet sizes are useful for behavioral analysis even when payloads
        are encrypted.
        """
        try:
            raw_bytes = bytes(packet)
            total_length = len(raw_bytes)
        except Exception:
            total_length = None

        dot11_payload_length = None

        if packet.haslayer(Dot11):
            try:
                dot11_payload_length = len(bytes(packet.getlayer(Dot11).payload))
            except Exception:
                dot11_payload_length = None

        return {
            "total_length": total_length,
            "dot11_payload_length": dot11_payload_length,
        }

    @staticmethod
    def _build_full_parsed_fields(packet, dot11: Dot11) -> dict:
        """
        Builds the complete parsed_fields structure for RawWirelessEvent.

        This should preserve as much observable WiFi metadata as possible.
        """
        return {
            "dot11": WiFiPacketParser._extract_dot11_fields(dot11),
            "radiotap": WiFiPacketParser._extract_radiotap_fields(packet),
            "dot11_elements": WiFiPacketParser._extract_dot11_elements(packet),
            "security_hints": WiFiPacketParser._extract_security_hints(packet),
            "security_profile": WiFiPacketParser._extract_security_profile(packet),
            "size_hints": WiFiPacketParser._extract_frame_size_hints(packet),
            "packet_meta": WiFiPacketParser._extract_packet_meta(packet),
        }

    @staticmethod
    def _safe_value(value):
        """
        Converts Scapy values into JSON-friendly values when possible.
        """
        if isinstance(value, bytes):
            return value.hex()

        if isinstance(value, (str, int, float, bool)) or value is None:
            return value

        if isinstance(value, list):
            return [WiFiPacketParser._safe_value(item) for item in value]

        if isinstance(value, tuple):
            return [WiFiPacketParser._safe_value(item) for item in value]

        if isinstance(value, dict):
            return {
                str(key): WiFiPacketParser._safe_value(item)
                for key, item in value.items()
            }

        return str(value)

    @staticmethod
    def _dot11_element_name(element_id: int | None) -> str:
        """
        Returns a friendly name for common 802.11 Information Elements.
        Unknown IDs are still preserved by ID and hex.
        """
        names = {
            0: "SSID",
            1: "Supported Rates",
            3: "DS Parameter Set",
            5: "TIM",
            7: "Country",
            32: "Power Constraint",
            42: "ERP Information",
            45: "HT Capabilities",
            48: "RSN",
            50: "Extended Supported Rates",
            61: "HT Operation",
            107: "Interworking",
            127: "Extended Capabilities",
            191: "VHT Capabilities",
            192: "VHT Operation",
            221: "Vendor Specific",
        }

        if element_id is None:
            return "Unknown"

        return names.get(element_id, f"Unknown IE {element_id}")

    @staticmethod
    def _read_le_uint16(data: bytes, offset: int) -> tuple[int | None, int]:
        if offset + 2 > len(data):
            return None, offset

        return int.from_bytes(data[offset : offset + 2], "little"), offset + 2

    @staticmethod
    def _parse_suite(data: bytes, offset: int) -> tuple[dict | None, int]:
        """
        Parses a 4-byte cipher/AKM suite.

        Format:
        - 3 bytes OUI
        - 1 byte suite type
        """
        if offset + 4 > len(data):
            return None, offset

        oui = data[offset : offset + 3]
        suite_type = data[offset + 3]

        return (
            {
                "oui": oui.hex(":"),
                "suite_type": suite_type,
            },
            offset + 4,
        )

    @staticmethod
    def _suite_name(suite: dict | None, suite_map: dict[int, str]) -> str:
        if not suite:
            return "unknown"

        suite_type = suite.get("suite_type")
        return suite_map.get(suite_type, f"Unknown suite {suite_type}")

    @staticmethod
    def _parse_rsn_information(info: bytes) -> dict:
        """
        Parses RSN Information Element.

        RSN IE is used by WPA2 and WPA3 networks.
        It contains cipher suites and AKM suites such as PSK, SAE, OWE, etc.
        """
        result = {
            "present": True,
            "version": None,
            "group_cipher": None,
            "pairwise_ciphers": [],
            "akm_suites": [],
            "capabilities_raw": None,
            "security_labels": [],
            "parse_error": None,
        }

        try:
            offset = 0

            version, offset = WiFiPacketParser._read_le_uint16(info, offset)
            result["version"] = version

            group_suite, offset = WiFiPacketParser._parse_suite(info, offset)
            result["group_cipher"] = WiFiPacketParser._suite_name(
                group_suite,
                WiFiPacketParser.RSN_CIPHER_SUITES,
            )

            pairwise_count, offset = WiFiPacketParser._read_le_uint16(info, offset)
            if pairwise_count is None:
                return result

            for _ in range(pairwise_count):
                suite, offset = WiFiPacketParser._parse_suite(info, offset)
                result["pairwise_ciphers"].append(
                    WiFiPacketParser._suite_name(
                        suite,
                        WiFiPacketParser.RSN_CIPHER_SUITES,
                    )
                )

            akm_count, offset = WiFiPacketParser._read_le_uint16(info, offset)
            if akm_count is None:
                return result

            for _ in range(akm_count):
                suite, offset = WiFiPacketParser._parse_suite(info, offset)
                result["akm_suites"].append(
                    WiFiPacketParser._suite_name(
                        suite,
                        WiFiPacketParser.RSN_AKM_SUITES,
                    )
                )

            capabilities, offset = WiFiPacketParser._read_le_uint16(info, offset)
            result["capabilities_raw"] = capabilities

            akms = set(result["akm_suites"])

            if "SAE" in akms or "FT-SAE" in akms:
                result["security_labels"].append("WPA3-Personal")

            if "OWE" in akms:
                result["security_labels"].append("OWE")

            if "PSK" in akms or "FT-PSK" in akms or "PSK-SHA256" in akms:
                result["security_labels"].append("WPA2-Personal")

            if "802.1X" in akms or "802.1X-SHA256" in akms:
                result["security_labels"].append("WPA2-Enterprise")

            if not result["security_labels"]:
                result["security_labels"].append("RSN/WPA2-or-WPA3")

        except Exception as exc:
            result["parse_error"] = str(exc)

        return result

    @staticmethod
    def _parse_wpa_vendor_information(info: bytes) -> dict | None:
        """
        Parses WPA vendor-specific Information Element.

        WPA IE format starts with:
        00:50:f2:01
        """
        if len(info) < 6:
            return None

        if not info.startswith(WiFiPacketParser.WPA_VENDOR_OUI + b"\x01"):
            return None

        result = {
            "present": True,
            "version": None,
            "group_cipher": None,
            "pairwise_ciphers": [],
            "akm_suites": [],
            "security_labels": ["WPA"],
            "parse_error": None,
        }

        try:
            offset = 4

            version, offset = WiFiPacketParser._read_le_uint16(info, offset)
            result["version"] = version

            group_suite, offset = WiFiPacketParser._parse_suite(info, offset)
            result["group_cipher"] = WiFiPacketParser._suite_name(
                group_suite,
                WiFiPacketParser.RSN_CIPHER_SUITES,
            )

            pairwise_count, offset = WiFiPacketParser._read_le_uint16(info, offset)
            if pairwise_count is None:
                return result

            for _ in range(pairwise_count):
                suite, offset = WiFiPacketParser._parse_suite(info, offset)
                result["pairwise_ciphers"].append(
                    WiFiPacketParser._suite_name(
                        suite,
                        WiFiPacketParser.RSN_CIPHER_SUITES,
                    )
                )

            akm_count, offset = WiFiPacketParser._read_le_uint16(info, offset)
            if akm_count is None:
                return result

            for _ in range(akm_count):
                suite, offset = WiFiPacketParser._parse_suite(info, offset)
                result["akm_suites"].append(
                    WiFiPacketParser._suite_name(
                        suite,
                        WiFiPacketParser.RSN_AKM_SUITES,
                    )
                )

        except Exception as exc:
            result["parse_error"] = str(exc)

        return result

    @staticmethod
    def _has_wps(elements: list[dict]) -> bool:
        for element in elements:
            if element.get("id") != 221:
                continue

            info_hex = element.get("info_hex")
            if not info_hex:
                continue

            try:
                info = bytes.fromhex(info_hex)
            except Exception:
                continue

            if info.startswith(WiFiPacketParser.WPA_VENDOR_OUI + b"\x04"):
                return True

        return False

    @staticmethod
    def _extract_security_profile(packet) -> dict:
        """
        Extracts human-readable WiFi security information.

        This is what allows AirSentry to show WPA/WPA2/WPA3/AES/TKIP-like
        information in a cleaner way.
        """
        elements = WiFiPacketParser._extract_dot11_elements(packet)

        profile = {
            "is_open": None,
            "security": [],
            "group_cipher": None,
            "pairwise_ciphers": [],
            "akm_suites": [],
            "rsn": None,
            "wpa": None,
            "wps": WiFiPacketParser._has_wps(elements),
        }

        rsn_element = next(
            (element for element in elements if element.get("id") == 48),
            None,
        )

        if rsn_element and rsn_element.get("info_hex"):
            rsn_info = bytes.fromhex(rsn_element["info_hex"])
            rsn = WiFiPacketParser._parse_rsn_information(rsn_info)
            profile["rsn"] = rsn
            profile["security"].extend(rsn.get("security_labels", []))
            profile["group_cipher"] = rsn.get("group_cipher")
            profile["pairwise_ciphers"].extend(rsn.get("pairwise_ciphers", []))
            profile["akm_suites"].extend(rsn.get("akm_suites", []))

        for element in elements:
            if element.get("id") != 221 or not element.get("info_hex"):
                continue

            try:
                info = bytes.fromhex(element["info_hex"])
            except Exception:
                continue

            wpa = WiFiPacketParser._parse_wpa_vendor_information(info)
            if not wpa:
                continue

            profile["wpa"] = wpa
            profile["security"].extend(wpa.get("security_labels", []))
            profile["group_cipher"] = profile["group_cipher"] or wpa.get("group_cipher")
            profile["pairwise_ciphers"].extend(wpa.get("pairwise_ciphers", []))
            profile["akm_suites"].extend(wpa.get("akm_suites", []))

        profile["security"] = sorted(set(profile["security"]))
        profile["pairwise_ciphers"] = sorted(set(profile["pairwise_ciphers"]))
        profile["akm_suites"] = sorted(set(profile["akm_suites"]))

        if profile["security"]:
            profile["is_open"] = False
        else:
            # This is conservative. If no RSN/WPA IE exists in a Beacon,
            # it is likely open or legacy WEP. Later we can inspect capability
            # privacy bit to distinguish Open vs WEP.
            profile["is_open"] = True
            profile["security"] = ["Open or Legacy WEP"]

        return profile
