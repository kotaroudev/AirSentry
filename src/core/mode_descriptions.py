# 📖 Official Mode Descriptions for SUCCESS Messages & UI
MODE_DESCRIPTIONS = {
    "WIFI_MONITOR": {
        "desc": "Monitor Mode (Passive Air Sniffing)",
        "auditing": "Analyzes all nearby networks and all raw packets traveling through the air for any device near your position.",
    },
    "WIFI_PROMISCUOUS": {
        "desc": "Promiscuous Mode (LAN Channel Interception)",
        "auditing": "Analyzes the entire local network, capturing all packets traveling to any IP within the LAN. [REQUIREMENT: Network password needed].",
    },
    "WIFI_MANAGED": {
        "desc": "Managed Mode (Local Host Auditing)",
        "auditing": "Analyzes only packets traveling directly to your own host and broadcast packets (directed to the public).",
    },
    "BT_HCI": {
        "desc": "HCI Mode (Host Controller Interface)",
        "auditing": "Analyzes transmissions from your local controller only, capturing your own connection events and nearby device inquiry requests.",
    },
    "BT_BLE": {
        "desc": "BLE Mode (External Dedicated Hardware)",
        "auditing": "Passively analyzes the global electromagnetic air, capturing all advertising beacons from any nearby wearable or device without interacting with them.",
    },
}
