# ==============================================================================
# intelligence/mitre_mapping.py — MITRE ATT&CK Technique Mapping
# ==============================================================================

"""
Maps detected attack classifications to MITRE ATT&CK techniques and tactics.
This provides analysts with standardised threat intelligence context for every alert.
"""

# Each entry: classification → { technique_id, technique_name, tactic, tactic_id, description, url }
MITRE_MAP = {
    "port_scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Scanning",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Adversary scans remote hosts to discover running services and open ports for lateral movement or exploitation.",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "packet_flood": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "description": "Adversary overwhelms the target with high-volume traffic to disrupt service availability.",
        "url": "https://attack.mitre.org/techniques/T1498/",
    },
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversary uses systematic password guessing to gain unauthorized access to accounts or services.",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "statistical_anomaly": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Unusual traffic patterns may indicate covert C2 communication using standard application protocols.",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    "dns_anomaly": {
        "technique_id": "T1071.004",
        "technique_name": "DNS",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Suspicious DNS queries may indicate DNS tunneling or DGA-based C2 communication.",
        "url": "https://attack.mitre.org/techniques/T1071/004/",
    },
    "beaconing": {
        "technique_id": "T1573",
        "technique_name": "Encrypted Channel",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Periodic connections at regular intervals indicate potential C2 beaconing behaviour.",
        "url": "https://attack.mitre.org/techniques/T1573/",
    },
    "c2_communication": {
        "technique_id": "T1095",
        "technique_name": "Non-Application Layer Protocol",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Repeated low-volume connections to external IPs may indicate command-and-control activity.",
        "url": "https://attack.mitre.org/techniques/T1095/",
    },
}


def get_mitre_mapping(classification):
    """Return MITRE ATT&CK mapping for a given alert classification."""
    return MITRE_MAP.get(classification, {
        "technique_id": "N/A",
        "technique_name": "Unknown Technique",
        "tactic": "Unknown",
        "tactic_id": "N/A",
        "description": "No MITRE mapping available for this classification.",
        "url": "",
    })
