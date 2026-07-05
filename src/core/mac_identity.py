import json
from pathlib import Path
from typing import Any

DEFAULT_VENDOR_DB_PATH = Path("data/mac-vendors-export.json")

# Small fallback only. The real source should be data/mac-vendors-export.json.
FALLBACK_OUI_VENDORS = {
    "78:20:51": "TP-Link Systems / WiFi adapter",
    "88:e0:56": "Huawei Technologies / network device",
}


_vendor_cache: dict[str, str] | None = None


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None

    cleaned = mac.strip().lower().replace("-", ":").replace(".", "")

    if ":" in cleaned:
        parts = cleaned.split(":")
        if len(parts) >= 6:
            return ":".join(part.zfill(2) for part in parts[:6])

    if len(cleaned) >= 12:
        return ":".join(cleaned[index : index + 2] for index in range(0, 12, 2))

    return mac.strip().lower()


def mac_oui(mac: str | None) -> str | None:
    normalized = normalize_mac(mac)

    if not normalized:
        return None

    parts = normalized.split(":")

    if len(parts) < 3:
        return None

    return ":".join(parts[:3])


def is_locally_administered_mac(mac: str | None) -> bool:
    """
    Returns True when the MAC has the locally administered bit set.

    This often indicates randomized/private MAC addresses.
    """
    normalized = normalize_mac(mac)

    if not normalized:
        return False

    try:
        first_octet = int(normalized.split(":")[0], 16)
    except Exception:
        return False

    return bool(first_octet & 0b00000010)


def is_multicast_mac(mac: str | None) -> bool:
    normalized = normalize_mac(mac)

    if not normalized:
        return False

    try:
        first_octet = int(normalized.split(":")[0], 16)
    except Exception:
        return False

    return bool(first_octet & 0b00000001)


def guess_vendor(mac: str | None) -> str | None:
    normalized = normalize_mac(mac)

    if not normalized:
        return None

    if is_multicast_mac(normalized):
        return "multicast/broadcast address"

    if is_locally_administered_mac(normalized):
        return "private/randomized MAC"

    oui = mac_oui(normalized)

    if not oui:
        return None

    vendor_db = load_vendor_db()

    return vendor_db.get(oui) or FALLBACK_OUI_VENDORS.get(oui)


def load_vendor_db(path: Path = DEFAULT_VENDOR_DB_PATH) -> dict[str, str]:
    """
    Loads a local MAC/OUI vendor database.

    Expected file:
        data/mac-vendors-export.json

    The loader is intentionally tolerant because exported vendor DBs may use
    different JSON structures.
    """
    global _vendor_cache

    if _vendor_cache is not None:
        return _vendor_cache

    if not path.exists():
        _vendor_cache = {}
        return _vendor_cache

    try:
        with path.open("r", encoding="utf-8") as file:
            raw_data = json.load(file)
    except Exception:
        _vendor_cache = {}
        return _vendor_cache

    _vendor_cache = parse_vendor_db(raw_data)
    return _vendor_cache


def parse_vendor_db(raw_data: Any) -> dict[str, str]:
    """
    Normalizes common JSON OUI database formats into:

        {
            "88:e0:56": "Huawei Technologies Co., Ltd",
            ...
        }
    """
    vendors: dict[str, str] = {}

    if isinstance(raw_data, dict):
        # Format A:
        # {
        #   "88:E0:56": "Huawei Technologies Co., Ltd"
        # }
        if all(isinstance(value, str) for value in raw_data.values()):
            for prefix, vendor in raw_data.items():
                normalized_prefix = normalize_prefix(prefix)
                if normalized_prefix and vendor:
                    vendors[normalized_prefix] = vendor.strip()
            return vendors

        # Format B:
        # {
        #   "data": [...]
        # }
        for key in ("data", "vendors", "records", "items", "results"):
            value = raw_data.get(key)
            if isinstance(value, list):
                return parse_vendor_db(value)

    if isinstance(raw_data, list):
        for item in raw_data:
            if not isinstance(item, dict):
                continue

            prefix = first_existing_value(
                item,
                [
                    "macPrefix",
                    "mac_prefix",
                    "prefix",
                    "oui",
                    "assignment",
                    "mac",
                ],
            )

            vendor = first_existing_value(
                item,
                [
                    "vendorName",
                    "vendor_name",
                    "companyName",
                    "company_name",
                    "company",
                    "vendor",
                    "organization",
                    "name",
                ],
            )

            normalized_prefix = normalize_prefix(prefix)

            if normalized_prefix and vendor:
                vendors[normalized_prefix] = str(vendor).strip()

    return vendors


def normalize_prefix(prefix: Any) -> str | None:
    if not prefix:
        return None

    text = str(prefix).strip().lower()
    text = text.replace("-", ":").replace(".", "")

    if "/" in text:
        text = text.split("/", maxsplit=1)[0]

    if ":" in text:
        parts = text.split(":")
        if len(parts) >= 3:
            return ":".join(part.zfill(2) for part in parts[:3])

    compact = "".join(
        character for character in text if character in "0123456789abcdef"
    )

    if len(compact) >= 6:
        return ":".join(compact[index : index + 2] for index in range(0, 6, 2))

    return None


def first_existing_value(data: dict, keys: list[str]):
    for key in keys:
        value = data.get(key)

        if value:
            return value

    return None
