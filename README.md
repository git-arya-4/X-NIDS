<div align="center">

# 🛡️ X-NIDS
### Next-Generation Network Intrusion Detection System

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-Web%20Dashboard-black?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com/)
[![Scapy](https://img.shields.io/badge/Scapy-Packet%20Capture-green?style=for-the-badge)](https://scapy.net/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-Isolation%20Forest-orange?style=for-the-badge&logo=scikit-learn)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey?style=for-the-badge&logo=linux)](https://www.linux.org/)

> A full-stack, AI-powered network security platform that captures raw packets, analyzes them through six parallel detection engines, and presents live threat intelligence on an interactive SOC dashboard.

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Project Structure](#-project-structure)
- [Detection Modules](#-detection-modules)
- [Threat Scoring Engine](#-threat-scoring-engine)
- [Alert Lifecycle](#-alert-lifecycle)
- [Incident Correlation](#-incident-correlation)
- [API Endpoints](#-api-endpoints)
- [Data Storage Schema](#-data-storage-schema)
- [Tech Stack](#-tech-stack)
- [Prerequisites](#-prerequisites)
- [Installation & Setup](#-installation--setup)
- [Configuration](#-configuration)
- [IP Blocking](#-ip-blocking)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [External Integrations](#-external-integrations)
- [PDF Report Generation](#-pdf-report-generation)
- [Security & Secrets](#-security--secrets)
- [Contributing](#-contributing)

---

## 🔍 Overview

**X-NIDS** is a next-generation Network Intrusion Detection System built entirely in Python. Unlike rule-based legacy tools, X-NIDS combines **machine learning**, **statistical analysis**, and **behavioral pattern recognition** to detect threats in real time — including novel attacks with no prior signature.

The system intercepts raw network packets using **Scapy** in promiscuous mode, extracts statistical features over sliding time windows, and routes them through **six independent detection engines**. Any confirmed threat is scored, correlated into an incident, enriched with geolocation and reputation data, and surfaced on a live **Flask dashboard** featuring interactive maps, charts, and a full IP blocking interface.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🧠 **AI-Based Anomaly Detection** | Isolation Forest ML model trained on live network baselines |
| 📊 **Statistical Spike Detection** | Adaptive Z-score thresholding with sliding window baselines |
| 🌐 **DGA Domain Detection** | Shannon entropy + consonant ratio scoring for malware-generated domains |
| 📡 **C2 Beaconing Detection** | Jitter/periodicity analysis to catch Command & Control callbacks |
| 🔎 **Port Scan Detection** | Unique destination port counting per source IP within a time window |
| 💥 **DoS / Packet Flood Detection** | Packets-per-second rate checks against adaptive baselines |
| 🗺️ **Live Geo-IP Attack Map** | Leaflet.js world map with pulsing red markers for attacker coordinates |
| 📈 **Real-Time Traffic Charts** | Chart.js dashboards updated every 1 second via polling |
| 🔗 **Incident Correlation** | Groups repeated alerts into named Campaigns to eliminate alert fatigue |
| 🚫 **One-Click IP Blocking** | Pushes `ufw` / `iptables` DROP rules directly from the dashboard |
| 📄 **PDF Report Generation** | SOC-style executive reports via ReportLab with incident summaries |
| 🌍 **Threat Intel Enrichment** | IP-API.com for geolocation, AbuseIPDB for reputation scoring |
| 🗡️ **MITRE ATT&CK Mapping** | Every alert type mapped to standardised ATT&CK technique IDs |

---

## 🏛️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          X-NIDS PIPELINE                            │
│                                                                     │
│  ┌───────────┐    ┌───────────────┐    ┌────────────────────────┐   │
│  │  Network  │───▶│ PacketSniffer │───▶│   Feature Extractor    │   │
│  │ Interface │    │   (Scapy)     │    │ (Statistics / State)   │   │
│  └───────────┘    └───────────────┘    └───────────┬────────────┘   │
│                                                    │                │
│                   ┌────────────────────────────────▼─────────────┐  │
│                   │              DETECTION ENGINES                │  │
│                   │  ┌──────────────┐   ┌──────────────────────┐ │  │
│                   │  │ Isolation    │   │  Statistical Anomaly  │ │  │
│                   │  │ Forest (ML)  │   │  (Adaptive Z-Score)   │ │  │
│                   │  └──────────────┘   └──────────────────────┘ │  │
│                   │  ┌──────────────┐   ┌──────────────────────┐ │  │
│                   │  │ DGA Detector │   │  Port Scan Detector   │ │  │
│                   │  └──────────────┘   └──────────────────────┘ │  │
│                   │  ┌──────────────┐   ┌──────────────────────┐ │  │
│                   │  │  Beaconing   │   │   Flood / DoS        │ │  │
│                   │  │  Detector    │   │   Detector           │ │  │
│                   │  └──────────────┘   └──────────────────────┘ │  │
│                   └───────────────────────────┬──────────────────┘  │
│                                               │                     │
│   ┌─────────────┐    ┌────────────────────────▼──────────────────┐  │
│   │   logs/     │◀───│   Alert Correlator + MITRE Mapper         │  │
│   │ alerts.json │    │   (Incident Grouping, Scoring, Tagging)   │  │
│   └─────────────┘    └────────────────────────┬──────────────────┘  │
│                                               │                     │
│                   ┌───────────────────────────▼──────────────────┐  │
│                   │           Flask Web Dashboard                 │  │
│                   │  Maps │ Charts │ Alerts │ Block │ PDF Report  │  │
│                   └──────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

Data flows in one direction: Raw packets → Feature extraction → Detection → Alerting → Dashboard. Each stage is fully decoupled; detection modules do not depend on each other.

---

## 📁 Project Structure

```
x-nids/
│
├── main.py                       # Entry point — health checks, thread initialisation
├── config.py                     # Global thresholds and configuration constants
├── requirements.txt              # Python dependency manifest
├── .env.example                  # Template for secrets (copy → .env)
├── .gitignore                    # Excludes .env and logs/ from version control
│
├── capture/
│   └── packet_sniffer.py         # Raw packet capture via Scapy (promiscuous mode)
│
├── features/
│   └── feature_extractor.py      # State management, statistics, detector coordination
│
├── detection/
│   └── anomaly_detector.py       # Isolation Forest ML model (scikit-learn)
│
├── intelligence/
│   ├── dns_analyzer.py           # DGA detection via Shannon entropy + consonant ratio
│   ├── beaconing_detector.py     # C2 beaconing via jitter/periodicity analysis
│   ├── alert_correlator.py       # Groups alerts into Incidents / Campaigns
│   ├── threat_intel.py           # IP enrichment — geolocation + reputation scoring
│   ├── mitre_mapping.py          # Maps attack types to MITRE ATT&CK technique IDs
│   └── attack_simulator.py       # Synthetic attack injection for testing
│
├── dashboard/
│   ├── app.py                    # Flask server — API routes
│   ├── templates/
│   │   └── index.html            # Main SOC dashboard UI
│   └── static/
│       ├── css/                  # Stylesheets
│       └── js/                   # Chart.js, Leaflet.js, network_map.js, dashboard.js
│
├── logs/
│   ├── alerts.json               # Persistent alert record (append-only) ✅
│   ├── metrics.json              # Rolling 60-second traffic window ❌ resets
│   ├── blocked_ips.json          # Persistent blocked IP registry ✅
│   ├── settings.json             # Thresholds, whitelists, UI config overrides ✅
│   └── geo_cache.json            # Geolocation API response cache ✅
│
└── baseline/
    └── baseline.json             # Learned normal traffic state ✅
```

> **Note:** `explainability/` and `datasets/` directories exist in the project root but are currently empty and reserved for future development.

---

## 🧠 Detection Modules

X-NIDS runs **six detection engines in parallel**. Each engine independently analyses a specific feature vector derived from a live sliding time window. A threat only needs to be caught by one engine to raise an alert.

### Module Summary

| # | Module | Algorithm | Trigger Condition | MITRE ID |
|---|---|---|---|---|
| 1 | **Isolation Forest** | Unsupervised ML (scikit-learn) | Feature vector isolated in fewer-than-average splits | — |
| 2 | **Statistical Anomaly** | Adaptive Z-Score | `current_pps > mean + (2.5 × std_dev)` | — |
| 3 | **DGA Detection** | Shannon Entropy + Consonant Ratio | Domain score > 0.6 | T1071 |
| 4 | **Port Scan Detection** | Unique Port Counter | Unique destination ports > 15 per window | T1046 |
| 5 | **C2 Beaconing** | Jitter / Periodicity Analysis | Jitter ratio < 0.35 + small payload size | T1071.004 |
| 6 | **Packet Flood / DoS** | Rate Threshold | Packets per second > 500 (or baseline limit) | T1498 |

---

### Module 1 — Isolation Forest (Machine Learning)

The ML engine learns what "normal" traffic looks like during a baseline period. It then flags any feature vector that is isolated in fewer random tree splits than average — meaning it is a statistical outlier.

**Input Feature Vector (5-second window):**

| Feature | Description |
|---|---|
| `packet_rate` | Packets captured per second |
| `unique_ports` | Count of distinct destination ports hit |
| `byte_volume` | Total bytes transferred |
| `ip_entropy` | Diversity of unique destination IP addresses contacted |

**Output:** `-1` = Anomaly detected &nbsp;|&nbsp; `1` = Normal behaviour

**Model Parameters:**

| Parameter | Value | Purpose |
|---|---|---|
| `n_estimators` | `100` | Number of isolation trees in the forest |
| `contamination` | `0.05` | Expected fraction of anomalous traffic (5%) |
| `random_state` | `42` | Deterministic seed — ensures reproducibility across restarts |

---

### Module 2 — Statistical Anomaly Detection

Uses an adaptive threshold calculated from a rolling traffic history:

```
threshold = mean(history) + (2.5 × std_dev(history))
```

If `current_value > threshold`, an anomaly alert is raised. The sensitivity multiplier (`2.5`) is configurable in `config.py`.

| Multiplier | Behaviour |
|---|---|
| `1.0` | High sensitivity — fires on small deviations |
| `2.5` | Balanced — default setting |
| `5.0` | Low sensitivity — only fires on extreme spikes |

---

### Module 3 — DGA Detection

Malware uses Domain Generation Algorithms to produce random-looking hostnames (e.g., `qzwx12rt90.xyz`) for covert C2 communication. X-NIDS scores each observed domain:

```
score = (entropy / 6.0) × 0.7 + (consonant_ratio × 0.3)
```

| Score Range | Classification |
|---|---|
| `0.0 – 0.4` | Legitimate — human-readable domain |
| `0.4 – 0.6` | Suspicious — elevated monitoring |
| `> 0.6` | **Flagged** — probable DGA / malware domain |

Shannon entropy measures character randomness; consonant ratio exploits the fact that human-written words use vowels, while randomly generated strings do not.

---

### Module 4 — Port Scan Detection

A per-IP set of destination ports is maintained within each time window. If the count exceeds **15 unique ports**, a Port Scan alert is raised.

```python
self.ip_ports[src_ip].add(dst_port)
if len(self.ip_ports[src_ip]) > 15:
    self.add_alert(src_ip, "Port Scan")
```

**Well-known port reference:**

| Port | Service |
|---|---|
| 22 | SSH |
| 80 | HTTP |
| 443 | HTTPS |
| 3306 | MySQL |
| 3389 | RDP |

---

### Module 5 — C2 Beaconing Detection

Malware on a compromised host "phones home" to its Command & Control server on a perfectly regular schedule. The jitter ratio measures how irregular the inter-packet gaps are:

```
jitter_ratio = std_dev(gaps) / mean(gaps)
```

| Jitter Ratio | Interpretation |
|---|---|
| Near `0.0` | Perfectly periodic — probable C2 beacon |
| `< 0.35` + small payload | **Flagged** as C2 beaconing |
| `> 0.35` | Random / human traffic pattern |

---

### Module 6 — Packet Flood / DoS Detection

```python
pps = packet_count / TIME_WINDOW
if pps > 500:
    self.add_alert(src_ip, "Packet Flood")
```

The threshold is also cross-checked against `baseline.json` to adapt to high-traffic environments (e.g., a data centre vs. a home network).

---

## 📊 Threat Scoring Engine

The circular Threat Gauge on the dashboard is calculated across all alerts from the **last 15 minutes**.

### Severity Weights

| Severity | Points | Typical Use Case |
|---|---|---|
| 🔴 **CRITICAL** | +40 | Active packet floods, exploitation attempts |
| 🟠 **HIGH** | +20 | Confirmed port scans, C2 beaconing |
| 🟡 **MEDIUM** | +10 | DGA anomalies, statistical spikes |
| **Maximum** | **100** | Score is capped — cannot exceed 100 |

### Decay Logic

Alerts lose weight over time to ensure the gauge reflects current activity, not stale history:

| Time Since Alert | Weight Applied |
|---|---|
| 0 – 5 minutes | 100% of points |
| 5 – 15 minutes | 50% of points |
| > 15 minutes | 0% — alert expired, no contribution |

---

## 📬 Alert Lifecycle

The complete journey of a detected threat, from raw packet to dashboard response:

```
 1. INTERCEPT   →  Scapy captures raw packet in promiscuous mode
 2. DISSECT     →  src_ip, dst_ip, protocol, size extracted
 3. AGGREGATE   →  Feature Extractor builds 5-second statistical window
 4. DETECT      →  6 engines analyse the feature vector in parallel
 5. SCORE       →  Threat points assigned based on severity
 6. MAP         →  mitre_mapping.py tags the alert with ATT&CK technique ID
 7. PERSIST     →  Alert object written to logs/alerts.json
 8. CORRELATE   →  Alert Correlator groups repeated alerts into an Incident
 9. ENRICH      →  Threat Intel adds country, ISP, and abuse reputation score
10. VISUALIZE   →  Dashboard polls /metrics every 1s and renders alert card
11. RESPOND     →  Analyst clicks Block → ufw/iptables DROP rule executed
```

**Alert JSON Schema:**

```json
{
  "id":          "A-168923412",
  "type":        "packet_flood",
  "attack_type": "Packet Flood",
  "severity":    "CRITICAL",
  "source_ip":   "185.5.5.5",
  "timestamp":   "2026-03-28 08:42:00",
  "risk_score":  95,
  "mitre_id":    "T1498"
}
```

---

## 🔗 Incident Correlation

Generating thousands of individual alerts for a single sustained attack causes **alert fatigue** — analysts ignore everything. The `alert_correlator.py` module solves this by grouping related alerts into **Incidents**.

| Scenario | Without Correlation | With Correlation |
|---|---|---|
| 5,000 alerts from one IP | 5,000 individual alert cards | 1 Incident: `INC-168923412` |
| Attack duration tracking | Not available | Start + End timestamp recorded |
| Analyst workload | Extremely high | Single incident to triage |

Each Incident tracks a unique ID, source IP, attack classification, start and end timestamps, and all constituent alert IDs grouped within it.

---

## 🌐 API Endpoints

All routes are served by the Flask server in `dashboard/app.py`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Renders the main SOC dashboard (`index.html`) |
| `GET` | `/metrics` | Returns live stats, alert history, and current threat level |
| `POST` | `/api/block` | Blocks an IP via `ufw` / `iptables` |
| `GET` | `/api/alerts` | Paginated alert history from `alerts.json` |
| `GET` | `/api/incidents` | Correlated incident groups from `alert_correlator` |
| `GET` | `/report` | Generates and streams a PDF threat report |

### `/metrics` — Response Schema

```json
{
  "summary": {
    "packet_rate": 42,
    "unique_ips": 15,
    "top_talkers": ["192.168.1.5", "10.0.0.8"]
  },
  "history": [
    { "timestamp": "08:42:01", "pps": 42 }
  ],
  "alerts": [
    { "id": "A-168923412", "severity": "CRITICAL", "attack_type": "Packet Flood" }
  ],
  "threat_level": 75
}
```

The frontend polls `/metrics` every **1,000 ms** to update charts, maps, and alert panels in real time.

---

## 🗄️ Data Storage Schema

X-NIDS uses lightweight JSON flat files for all persistence. No database installation is required.

### Storage Overview

| File | Written By | Persists | Purpose |
|---|---|---|---|
| `logs/alerts.json` | `FeatureExtractor.add_alert()` | ✅ Yes | Complete historical alert record |
| `logs/metrics.json` | Processing loop (every 1–5s) | ❌ No | Rolling 60-second traffic window |
| `logs/blocked_ips.json` | `dashboard/app.py` | ✅ Yes | Registry of firewall-blocked IPs |
| `logs/settings.json` | `dashboard/app.py` | ✅ Yes | Thresholds, whitelists, UI config overrides |
| `logs/geo_cache.json` | `threat_intel.py` | ✅ Yes | Geolocation API response cache |
| `baseline/baseline.json` | `feature_extractor.py` | ✅ Yes | Learned normal traffic baseline |

---

### `logs/alerts.json` — Field Reference

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Unique alert serial (e.g., `A-168923412`) |
| `type` | `string` | Internal type key (e.g., `packet_flood`) |
| `attack_type` | `string` | Human-readable attack name |
| `severity` | `string` | `CRITICAL` / `HIGH` / `MEDIUM` |
| `source_ip` | `string` | Originating IP address |
| `timestamp` | `string` | ISO 8601 datetime |
| `risk_score` | `integer` | Detection confidence score (0–100) |
| `mitre_id` | `string` | MITRE ATT&CK technique ID |

---

### `logs/settings.json` — Field Reference

| Field | Type | Description |
|---|---|---|
| `thresholds` | `object` | Per-detector runtime overrides (pps limit, port limit, etc.) |
| `whitelist_ips` | `array` | IP addresses excluded from all detection engines |
| `dashboard_config` | `object` | UI preferences (refresh rate, visible panels, etc.) |

---

## 🧰 Tech Stack

### Backend

| Library | Role |
|---|---|
| **Python 3.8+** | Core runtime |
| **Flask** | Web server and REST API framework |
| **Scapy** | Raw packet capture in promiscuous mode |
| **scikit-learn** | Isolation Forest unsupervised ML model |
| **NumPy** | Statistical calculations — mean, std dev, entropy |
| **ReportLab** | PDF report generation |
| **Requests** | HTTP client for external enrichment API calls |
| **ipaddress** | Internal vs. external IP classification |
| **python-dotenv** | `.env` secret loading |

### Frontend

| Library | Role |
|---|---|
| **Chart.js** | Real-time line charts and traffic bar graphs |
| **Leaflet.js** | Interactive geo-IP world attack map |
| **Canvas API** | Physics-based network topology node map (`network_map.js`) |
| **Vanilla JavaScript** | 1-second polling loop and UI update logic |

---

## ⚙️ Prerequisites

- **OS:** Linux (Ubuntu 20.04+ recommended)
- **Python:** 3.8 or higher
- **Privileges:** `sudo` / root access (required for raw socket capture)
- **Firewall Tools:** `ufw` or `iptables` installed (for the IP blocking feature)
- **Internet Access:** Optional — required only for IP-API.com and AbuseIPDB enrichment

---

## 🚀 Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/x-nids.git
cd x-nids
```

### 2. Create a Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Secrets

```bash
cp .env.example .env
nano .env
```

Paste your AbuseIPDB API key if you have one (see [Configuration](#-configuration)).

### 5. Run X-NIDS

```bash
sudo python main.py
```

> **Why `sudo`?** Linux restricts raw socket access to the root user. X-NIDS must intercept network traffic at the packet level, which requires elevated privileges.

### 6. Open the Dashboard

Navigate to `http://127.0.0.1:5000` in your browser.

---

## 🔧 Configuration

### `.env` File

```env
# External API Keys (optional — X-NIDS runs fully offline without these)
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

> **⚠️ Never commit your `.env` file.** It is excluded by `.gitignore` by default.

---

### `config.py` — Detection Thresholds

All detection thresholds are centralised in `config.py`. Runtime overrides can also be saved to `logs/settings.json` via the dashboard UI without requiring a restart.

| Constant | Default | Description |
|---|---|---|
| `PORT_SCAN_THRESHOLD` | `15` | Unique destination ports before scan alert fires |
| `FLOOD_THRESHOLD_PPS` | `500` | Packets/second before flood alert fires |
| `STAT_SENSITIVITY` | `2.5` | Z-score sensitivity multiplier |
| `DGA_SCORE_THRESHOLD` | `0.6` | Minimum entropy score to flag a domain |
| `BEACON_JITTER_MAX` | `0.35` | Maximum jitter ratio to classify as a C2 beacon |
| `ML_CONTAMINATION` | `0.05` | Expected fraction of anomalous traffic |
| `TIME_WINDOW` | `5` | Feature extraction window in seconds |
| `ALERT_DECAY_FULL` | `300` | Seconds before alert score weight is halved |
| `ALERT_DECAY_EXPIRE` | `900` | Seconds before alert score contribution expires |

---

## 🚫 IP Blocking

When an analyst clicks **Block** on the dashboard, X-NIDS executes a firewall DROP rule in the background. It tries `ufw` first and falls back to `iptables` automatically if unavailable.

**Priority order:**

```bash
# Attempt 1 — ufw (Uncomplicated Firewall)
ufw deny from <ip> to any

# Fallback — iptables (low-level kernel firewall)
iptables -A INPUT -s <ip> -j DROP
```

**Why DROP instead of REJECT?**

| Mode | Behaviour | Security Implication |
|---|---|---|
| `REJECT` | Sends an explicit denial response to the source | Confirms to the attacker that the host is alive and listening |
| `DROP` | Silently discards all packets with no response | Attacker receives no feedback — appears as a network timeout |

X-NIDS uses **DROP** exclusively. All blocked IPs are recorded in `logs/blocked_ips.json` and persist across restarts.

---

## 🗡️ MITRE ATT&CK Mapping

X-NIDS maps every alert type to the MITRE ATT&CK framework via `intelligence/mitre_mapping.py`. This enables direct integration with existing SOC workflows, SIEM platforms, and incident ticketing systems. Security professionals globally share a common vocabulary when referencing these technique IDs.

| Attack Type | MITRE ID | Tactic | Description |
|---|---|---|---|
| Packet Flood / DoS | `T1498` | Impact | Network Denial of Service |
| Brute Force | `T1110` | Credential Access | Repeated authentication attempts |
| DNS Exfiltration / DGA | `T1071` | Command and Control | Application Layer Protocol abuse |
| C2 Beaconing | `T1071.004` | Command and Control | DNS-based periodic callbacks |
| Port Scan | `T1046` | Discovery | Network Service Scanning |

---

## 🔗 External Integrations

Both integrations are **optional**. X-NIDS operates fully offline; enrichment fields will simply be empty if keys are not configured.

| Service | Data Returned | Caching |
|---|---|---|
| **IP-API.com** | City, Country, Latitude, Longitude | `logs/geo_cache.json` |
| **AbuseIPDB** | Abuse confidence score (0–100) | Per-request |

The geo cache prevents repeated lookups for the same IP address, reducing latency and respecting API rate limits.

---

## 📄 PDF Report Generation

The `/report` endpoint generates an on-demand SOC-style executive PDF using ReportLab:

1. **Cover Page** — Monitoring period metadata with key metrics: Total Incidents, Critical Alerts, Affected Hosts, Confidence Score
2. **Executive Summary** — Auto-generated narrative overview of the observation window
3. **Incident Table** — Per-incident breakdown with attacker IP, risk score, attack type, and status badge (red = actively ongoing)
4. **Correlated Timeline** — Chronological incident flow across the monitoring period

The completed PDF is streamed directly to the browser via `Content-Type: application/pdf`.

---

## 🔐 Security & Secrets

| Practice | Implementation |
|---|---|
| Secret management | All credentials stored in `.env`, never hardcoded |
| Version control safety | `.gitignore` excludes `.env`, `logs/`, and `baseline/` |
| Firewall mode | `DROP` (silent discard) — does not reveal system presence to attackers |
| Raw socket access | Requires `sudo`; system performs an admin privilege check on startup |
| Data privacy | No sensitive network data is transmitted to third-party services without explicit `.env` configuration |

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit your changes: `git commit -m "Add: your feature description"`
4. Push to the branch: `git push origin feature/your-feature-name`
5. Open a Pull Request

When adding or modifying a detection engine, please include corresponding synthetic test cases via `intelligence/attack_simulator.py`.

---

## ⚠️ Disclaimer

X-NIDS is intended for **authorised use only** on networks you own or have explicit written permission to monitor. Unauthorised interception of network traffic may violate local, national, or international law. The authors assume no liability for misuse of this software.

---

<div align="center">
Built with 🛡️ for network defenders everywhere.
</div>
