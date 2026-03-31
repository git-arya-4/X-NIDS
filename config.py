# ==============================================================================
# config.py - Configuration Settings for X-NIDS
# ==============================================================================

# NETWORK CONFIGURATION
INTERFACE = "wlan0"

# SYSTEM SETTINGS
TIME_WINDOW = 5          # Sliding window duration (seconds)
BASELINE_DURATION = 60   # Baseline learning period (seconds)

# TRAFFIC FILTERING (BPF)
BPF_FILTER = "not broadcast and not multicast and not host 127.0.0.1"

# LOGGING
LOG_FILE = "logs/alerts.json"
PCAP_FILE = "capture/traffic.pcap"

# ── DETECTION TUNING ──

# Static fallback threshold (used only if baseline is unavailable)
PACKET_RATE_THRESHOLD = 100

# Adaptive threshold multiplier: threshold = mean + (SIGMA_MULT × stddev)
SIGMA_MULT = 2.0

# Burst tolerance: anomalies must persist for this many consecutive windows
# before an alert is actually generated (prevents single-burst false positives)
BURST_TOLERANCE = 3

# Port-scan threshold: a single IP contacting more than this many unique ports
# in one sliding window is flagged as a port scan candidate
PORT_SCAN_THRESHOLD = 15

# Risk-score alert threshold: alerts are only emitted if risk score exceeds this
RISK_ALERT_THRESHOLD = 50

# ── IP WHITELIST ──
# Traffic from these IPs will never trigger anomaly alerts.
# Supports individual IPs and CIDR ranges.
WHITELIST = [
    # Public DNS resolvers — never a threat
    "8.8.8.8",            # Google Primary DNS
    "8.8.4.4",            # Google Secondary DNS
    "1.1.1.1",            # Cloudflare Primary DNS
    "1.0.0.1",            # Cloudflare Secondary DNS
    "9.9.9.9",            # Quad9 DNS
    "149.112.112.112",    # Quad9 Secondary DNS
    # Private LAN ranges
    "10.0.0.0/8",         # Private LAN (Class A)
    "192.168.0.0/16",     # Private LAN (Class C)
    "172.16.0.0/12",      # Private LAN (Class B)
    "127.0.0.0/8",        # Localhost
]