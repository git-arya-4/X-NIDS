# ==============================================================================
# intelligence/threat_intel.py — Threat Intelligence Enrichment
# ==============================================================================

"""
Enriches IP addresses with meta-data: ASN, ISP, country, internal/external.
Uses offline heuristics for fast, dependency-free lookups.
"""

import ipaddress

# ── RFC-1918 private ranges ──
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

# ── Offline geo / ASN / ISP heuristics by first-octet ranges ──
_ENRICHMENT_DB = {
    (1, 10):    {"country": "US", "asn": "AS7018",  "isp": "AT&T Services"},
    (8, 9):     {"country": "US", "asn": "AS15169", "isp": "Google LLC"},
    (13, 16):   {"country": "EU", "asn": "AS3356",  "isp": "Level 3 / Lumen"},
    (17, 18):   {"country": "US", "asn": "AS714",   "isp": "Apple Inc."},
    (20, 24):   {"country": "US", "asn": "AS701",   "isp": "Verizon"},
    (31, 38):   {"country": "EU", "asn": "AS1299",  "isp": "Arelion (Telia)"},
    (40, 48):   {"country": "US", "asn": "AS8075",  "isp": "Microsoft Corp"},
    (43, 44):   {"country": "JP", "asn": "AS2497",  "isp": "IIJ"},
    (49, 50):   {"country": "JP", "asn": "AS17676", "isp": "SoftBank"},
    (52, 55):   {"country": "US", "asn": "AS16509", "isp": "Amazon AWS"},
    (58, 62):   {"country": "CN", "asn": "AS4134",  "isp": "China Telecom"},
    (64, 72):   {"country": "US", "asn": "AS3356",  "isp": "Level 3 / Lumen"},
    (72, 77):   {"country": "US", "asn": "AS15169", "isp": "Google LLC"},
    (80, 86):   {"country": "EU", "asn": "AS3320",  "isp": "Deutsche Telekom"},
    (88, 92):   {"country": "EU", "asn": "AS6830",  "isp": "Liberty Global"},
    (101, 112): {"country": "CN", "asn": "AS4837",  "isp": "China Unicom"},
    (112, 120): {"country": "JP", "asn": "AS2516",  "isp": "KDDI Corp"},
    (125, 126): {"country": "KR", "asn": "AS4766",  "isp": "Korea Telecom"},
    (136, 142): {"country": "EU", "asn": "AS3257",  "isp": "GTT Communications"},
    (142, 145): {"country": "US", "asn": "AS701",   "isp": "Verizon"},
    (150, 156): {"country": "AU", "asn": "AS1221",  "isp": "Telstra"},
    (157, 162): {"country": "US", "asn": "AS209",   "isp": "CenturyLink"},
    (163, 170): {"country": "CN", "asn": "AS4134",  "isp": "China Telecom"},
    (172, 173): {"country": "US", "asn": "AS36351", "isp": "SoftLayer / IBM"},
    (176, 180): {"country": "EU", "asn": "AS12389", "isp": "Rostelecom"},
    (185, 189): {"country": "EU", "asn": "AS47541", "isp": "RIPE NCC Allocated"},
    (192, 200): {"country": "US", "asn": "AS3356",  "isp": "Level 3 / Lumen"},
    (200, 212): {"country": "SA", "asn": "AS28573", "isp": "LACNIC Allocated"},
    (212, 224): {"country": "EU", "asn": "AS1273",  "isp": "Vodafone"},
}


def _is_private(ip_str):
    """Check if an IP is in RFC-1918 or loopback space."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except Exception:
        return False


def enrich_ip(ip_str):
    """
    Enrich an IP with threat-intelligence metadata.

    Returns dict:
        country, asn, isp, network_type (Internal/External), is_private
    """
    if _is_private(ip_str):
        return {
            "country": "LAN",
            "asn": "N/A",
            "isp": "Private Network",
            "network_type": "Internal",
            "is_private": True,
        }

    try:
        first_octet = int(ip_str.split(".")[0])
    except Exception:
        return {
            "country": "Unknown",
            "asn": "N/A",
            "isp": "Unknown",
            "network_type": "External",
            "is_private": False,
        }

    for (lo, hi), info in _ENRICHMENT_DB.items():
        if lo <= first_octet < hi:
            return {
                "country": info["country"],
                "asn": info["asn"],
                "isp": info["isp"],
                "network_type": "External",
                "is_private": False,
            }

    return {
        "country": "Unknown",
        "asn": "N/A",
        "isp": "Unknown",
        "network_type": "External",
        "is_private": False,
    }
