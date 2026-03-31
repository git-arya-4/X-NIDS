# ==============================================================================
# features/feature_extractor.py — Advanced IDS Engine
# Explainable alerts · Attack classification · Device profiling
# Threat enrichment · Attack timelines · Response simulation
# MITRE ATT&CK · DNS Analysis · C2 Beaconing · Alert Correlation
# ==============================================================================

import time
import json
import os
import ipaddress
import numpy as np
from collections import defaultdict
import config
from detection.anomaly_detector import AnomalyDetector
from intelligence.mitre_mapping import get_mitre_mapping
from intelligence.threat_intel import enrich_ip
from intelligence.dns_analyzer import DNSAnalyzer
from intelligence.beaconing_detector import BeaconingDetector
from intelligence.alert_correlator import AlertCorrelator


class NumpySafeEncoder(json.JSONEncoder):
    """Converts NumPy scalars/arrays to native Python types for json.dump."""
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)


LOGS_DIR = "/home/cybersec/pro/X-NIDS/logs"
METRICS_FILE = os.path.join(LOGS_DIR, "metrics.json")
ALERTS_FILE = os.path.join(LOGS_DIR, "alerts.json")
import ipaddress

def _is_whitelisted(ip_str):
    wl = getattr(config, "WHITELIST", [])
    if not wl:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        for entry in wl:
            try:
                if "/" in entry:
                    if ip in ipaddress.ip_network(entry, strict=False):
                        return True
                else:
                    if ip == ipaddress.ip_address(entry):
                        return True
            except Exception:
                pass
    except Exception:
        pass
    return False

# ── RFC-1918 private ranges ──
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# ── Simple geo lookup by first octet ranges (offline heuristic) ──
_GEO_HINTS = {
    range(1, 10):   "US",   range(13, 16):  "EU",  range(17, 18):  "US",
    range(20, 24):  "US",   range(31, 38):  "EU",  range(41, 42):  "ZA",
    range(43, 44):  "JP",   range(49, 50):  "JP",  range(58, 62):  "CN",
    range(72, 77):  "US",   range(80, 86):  "EU",  range(88, 92):  "EU",
    range(101, 112):"CN",   range(112, 120):"JP",  range(125, 126):"KR",
    range(136, 143):"EU",   range(142, 145):"US",  range(150, 156):"AU",
    range(157, 162):"US",   range(163, 170):"CN",  range(176, 180):"EU",
    range(185, 189):"EU",   range(192, 200):"US",  range(200, 212):"SA",
    range(212, 224):"EU",
}

def _geo_for(ip_str):
    """Best-effort offline country code from the first octet."""
    try:
        first = int(ip_str.split(".")[0])
        for rng, cc in _GEO_HINTS.items():
            if first in rng:
                return cc
    except Exception:
        pass
    return "Unknown"

def _is_private(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except Exception:
        return False

def _classify_ip(ip_str):
    """Returns (network_type, country)."""
    if _is_private(ip_str):
        return "Internal", "LAN"
    return "External", _geo_for(ip_str)


# ═══════════════════════════════════════════════════════════════════
#  Port service names (common well-known ports)
# ═══════════════════════════════════════════════════════════════════
_PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "Postgres", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MongoDB",
}

# ═══════════════════════════════════════════════════════════════════
#  Risk-based priority categories
# ═══════════════════════════════════════════════════════════════════
def _risk_category(score):
    """Map a numeric risk score to a priority category."""
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 30:
        return "Medium"
    else:
        return "Low"


class FeatureExtractor:
    def __init__(self):
        self.start_time = time.time()
        self.packet_count = 0

        # Per-window counters (reset every TIME_WINDOW)
        self.src_ips = defaultdict(int)
        self.dst_ips = defaultdict(int)
        self.ip_ports = defaultdict(set)
        self.ip_dst_port_hits = defaultdict(lambda: defaultdict(int))  # ip → {port: count}
        self.dest_ports = set()
        self.protocols = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.window_bytes = 0

        # Flow table: (src, dst, sport, dport, proto) → {start, packets, bytes}
        self.flows = {}

        # Persistent state
        self.history = []
        self.alerts = []
        self.ips_tracker = {}
        self.window_number = 0

        # ── Device behaviour profiles ──
        # ip → {"windows": n, "total_pkts": n, "avg_pps": f, "ports": set,
        #        "protos": {}, "first_seen": ts, "last_seen": ts}
        self.device_profiles = {}

        # ── Attack timelines ──
        # ip → [{event, timestamp, details}]
        self.attack_timelines = defaultdict(list)

        # ── Network asset discovery ──
        # ip → {first_seen, last_seen, total_bytes, activity_level, packet_count, is_new}
        self.network_assets = {}

        # Cumulative counters
        self.total_packets = 0
        self.total_bytes = 0
        self.all_unique_src_ips = set()

        # Burst tolerance
        self.consec_ml_anomaly = 0
        self.consec_pps_anomaly = 0
        self.consec_port_scan = defaultdict(int)
        self.consec_brute_force = defaultdict(int)

        # Alert cooldown: ip → last alert timestamp (epoch)
        self.last_alert_time = {}
        self.ALERT_COOLDOWN = 30  # seconds between alerts for same IP

        # ML model
        self.anomaly_detector = AnomalyDetector()

        # ── Intelligence modules ──
        self.dns_analyzer = DNSAnalyzer()
        self.beaconing_detector = BeaconingDetector()
        self.alert_correlator = AlertCorrelator(merge_window=300)

        # Track last threat score to suppress duplicate logs
        self._last_threat_score = -1

    # ==================================================================
    #  Packet ingestion
    # ==================================================================
    def _compute_threat_level(self):
        """Compute threat score from ACTIVE recent alerts only.
        
        Formula:
          - Only alerts from last 15 minutes are considered
          - Alerts < 5 min old: full weight
          - Alerts 5–15 min old: 50% weight
          - Alerts > 15 min old: ignored
          - CRITICAL × 40 pts, HIGH × 20 pts, MEDIUM × 10 pts
          - Score = min(sum, 100), 0 when no active alerts
        """
        now = time.time()
        
        crit = 0
        high = 0
        med = 0
        last_alert_epoch = 0

        for a in self.alerts:
            epoch = a.get("_epoch", 0)
            if epoch <= 0:
                continue
            age = now - epoch
            if age > 900:  # > 15 minutes — ignore completely
                continue
            
            sev = (a.get("severity") or "").lower()
            weight = 1.0 if age <= 300 else 0.5  # 50% after 5 min

            if sev == "critical":
                crit += weight
            elif sev == "high":
                high += weight
            elif sev == "medium":
                med += weight
            
            if epoch > last_alert_epoch:
                last_alert_epoch = epoch

        raw = (crit * 40) + (high * 20) + (med * 10)
        score = int(min(100, raw))

        # Label
        if score == 0:
            priority = "NONE"
            status = "Normal"
        elif score <= 30:
            priority = "LOW"
            status = "Normal"
        elif score <= 60:
            priority = "MEDIUM"
            status = "Suspicious"
        elif score <= 80:
            priority = "HIGH"
            status = "High Risk"
        else:
            priority = "CRITICAL"
            status = "Critical"

        # Time since last relevant alert
        if last_alert_epoch > 0:
            ago = int(now - last_alert_epoch)
        else:
            ago = -1

        if score != self._last_threat_score:
            print(f"  [THREAT] score changed: {self._last_threat_score} → {score}  "
                  f"(active={int(crit+high+med)} C={crit:.0f} H={high:.0f} M={med:.0f})")
            self._last_threat_score = score

        return {
            "score": score,
            "status": status,
            "priority": priority,
            "last_alert_ago": ago,
        }

    def process_packet(self, packet):
        # ── PIPELINE 1: ALWAYS RUN (TRACKING & DISPLAY) ──
        # Every packet is counted for metrics, protocol donuts, top IPs, and map.
        self.packet_count += 1
        self.total_packets += 1

        pkt_len = len(packet) if hasattr(packet, "__len__") else 0
        self.total_bytes += pkt_len
        self.window_bytes += pkt_len

        proto_str = "Other"
        if packet.haslayer("TCP"):
            proto_str = "TCP"
        elif packet.haslayer("UDP"):
            proto_str = "UDP"
        elif packet.haslayer("ICMP"):
            proto_str = "ICMP"
        self.protocols[proto_str] = self.protocols.get(proto_str, 0) + 1

        if packet.haslayer("IP"):
            src = packet["IP"].src
            dst = packet["IP"].dst
            self.src_ips[src] += 1
            self.dst_ips[dst] += 1
            self.all_unique_src_ips.add(src)

            # ── Network asset discovery ──
            self._update_network_asset(src, pkt_len)
            self._update_network_asset(dst, 0)

            # ── Port usage tracking ──
            sport = 0
            dport = 0
            if packet.haslayer("TCP") or packet.haslayer("UDP"):
                sport = getattr(packet, "sport", 0)
                dport = getattr(packet, "dport", 0)
                if dport:
                    self.dest_ports.add(dport)
                    self.ip_ports[src].add(dport)
                    self.ip_dst_port_hits[src][dport] += 1

            # ── Network Topology Map ──
            flow_key = (src, dst, sport, dport, proto_str)
            if flow_key not in self.flows:
                self.flows[flow_key] = {"start": time.time(), "packets": 0, "bytes": 0}
            self.flows[flow_key]["packets"] += 1
            self.flows[flow_key]["bytes"] += pkt_len

            # ── PIPELINE 2: ALERTING ONLY ──
            # Skip passing whitelisted traffic into specific detection engines
            if _is_whitelisted(src) or _is_whitelisted(dst):
                pass
            else:
                # ── DNS query extraction ──
                if packet.haslayer("DNS") and hasattr(packet["DNS"], "qd") and packet["DNS"].qd:
                    try:
                        qname = packet["DNS"].qd.qname
                        if isinstance(qname, bytes):
                            qname = qname.decode("utf-8", errors="ignore").rstrip(".")
                        elif isinstance(qname, str):
                            qname = qname.rstrip(".")
                        ts = time.strftime("%Y-%m-%d %H:%M:%S")
                        self.dns_analyzer.process_dns(src, dst, qname, ts)
                    except Exception:
                        pass

                # ── C2 beaconing tracking ──
                if not _is_private(dst):
                    self.beaconing_detector.record_connection(src, dst, pkt_len, is_external=True)

        if time.time() - self.start_time >= config.TIME_WINDOW:
            self.extract_features()
            self.reset_window()

    # ==================================================================
    #  Network Asset Discovery
    # ==================================================================
    def _update_network_asset(self, ip, byte_count):
        """Track a network device for asset discovery."""
        now = time.time()
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        if ip not in self.network_assets:
            self.network_assets[ip] = {
                "ip": ip,
                "first_seen": ts,
                "first_seen_epoch": now,
                "last_seen": ts,
                "last_seen_epoch": now,
                "total_bytes": 0,
                "packet_count": 0,
                "activity_level": "Low",
                "is_new": True,
            }
        asset = self.network_assets[ip]
        asset["last_seen"] = ts
        asset["last_seen_epoch"] = now
        asset["total_bytes"] += byte_count
        asset["packet_count"] += 1

        # Activity level
        if asset["packet_count"] > 1000:
            asset["activity_level"] = "High"
        elif asset["packet_count"] > 100:
            asset["activity_level"] = "Medium"
        else:
            asset["activity_level"] = "Low"

        # No longer new after 60 seconds
        if now - asset["first_seen_epoch"] > 60:
            asset["is_new"] = False

    def get_network_assets(self):
        """Return discovered network assets sorted by activity."""
        assets = []
        for ip, data in self.network_assets.items():
            net_type, country = _classify_ip(ip)
            assets.append({
                "ip": ip,
                "network_type": net_type,
                "country": country,
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "total_bytes": data["total_bytes"],
                "total_bytes_human": self._human_bytes(data["total_bytes"]),
                "packet_count": data["packet_count"],
                "activity_level": data["activity_level"],
                "is_new": data["is_new"],
            })
        assets.sort(key=lambda x: x["packet_count"], reverse=True)
        return assets[:100]

    # ==================================================================
    #  Feature computation & alert generation
    # ==================================================================
    def extract_features(self):
        duration = time.time() - self.start_time
        packet_rate = self.packet_count / duration if duration > 0 else 0
        unique_ports = len(self.dest_ports)
        timestamp = time.strftime("%H:%M:%S")
        full_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.window_number += 1

        filtered_ips = {ip: c for ip, c in self.src_ips.items() if not _is_whitelisted(ip)}
        top_ip = max(filtered_ips, key=filtered_ips.get) if filtered_ips else "None"

        # ── Protocol distribution ──
        total_proto = sum(self.protocols.values())
        proto_dist = {}
        if total_proto > 0:
            for k, v in self.protocols.items():
                proto_dist[k] = round((v / total_proto) * 100, 1)

        # ── ML evaluation ──
        ml_prediction = self.anomaly_detector.evaluate(packet_rate, unique_ports)
        ml_raw_score = self.anomaly_detector.score(packet_rate, unique_ports)
        anomaly_score = round(max(0.0, min(1.0, 0.5 - ml_raw_score)), 2)

        # ── Update device profiles ──
        self._update_device_profiles(timestamp)

        # ── DNS analysis ──
        dns_events = self.dns_analyzer.analyze_window(full_timestamp)

        # ── Beaconing analysis ──
        beacon_events = self.beaconing_detector.analyze(full_timestamp)

        # ==============================================================
        #  MULTI-FACTOR RISK SCORING (0–100)
        # ==============================================================
        risk = 0
        risk_factors = []

        pps_flag = self.anomaly_detector.is_pps_anomaly(packet_rate)
        if pps_flag:
            pps_thr = self.anomaly_detector.pps_threshold
            pps_mult = round(packet_rate / max(pps_thr, 0.01), 1)
            risk += 30
            risk_factors.append(f"Packet rate {packet_rate:.0f} pps exceeds adaptive threshold {pps_thr:.0f} pps ({pps_mult}x)")

        ports_flag = self.anomaly_detector.is_ports_anomaly(unique_ports)
        if ports_flag:
            risk += 20
            risk_factors.append(f"Unique ports ({unique_ports}) exceed adaptive threshold ({self.anomaly_detector.ports_threshold:.0f})")

        ml_flag = ml_prediction == -1
        if ml_flag:
            risk += 30
            risk_factors.append(f"ML Isolation Forest flagged anomalous (score={anomaly_score})")

        # Port scan detection
        scan_ips = []
        port_scan_thresh = getattr(config, "PORT_SCAN_THRESHOLD", 15)
        for ip, ports in self.ip_ports.items():
            if _is_whitelisted(ip):
                continue
            if len(ports) > port_scan_thresh:
                scan_ips.append(ip)
                if risk < 100:
                    risk += 20
                    risk_factors.append(f"IP {ip} contacted {len(ports)} unique ports (threshold: {port_scan_thresh})")
                break

        # Brute force detection: STRICT — requires high hit count, low port
        # diversity, and the PPS must exceed 4× the device's baseline.
        brute_ips = []
        for ip, port_hits in self.ip_dst_port_hits.items():
            if _is_whitelisted(ip):
                continue
            ip_port_count = len(self.ip_ports.get(ip, set()))
            if ip_port_count > 3:
                continue
            for port, hits in port_hits.items():
                if hits < 50:
                    continue
                profile = self.device_profiles.get(ip)
                ip_pps = self.src_ips.get(ip, 0) / max(duration, 0.01)
                if profile and profile["windows"] >= 3:
                    if ip_pps < profile["avg_pps"] * 4:
                        continue
                brute_ips.append((ip, port, hits))
                risk += 10
                svc = _PORT_NAMES.get(port, str(port))
                risk_factors.append(f"IP {ip} sent {hits} packets to port {port} ({svc}) — possible brute force")
                break

        # Flood from single source
        flood_ip = None
        for ip, count in filtered_ips.items():
            if count > self.packet_count * 0.8 and pps_flag:
                flood_ip = ip
                risk += 10
                risk_factors.append(f"IP {ip} generated {count}/{self.packet_count} packets ({count*100//max(self.packet_count,1)}% of window)")
                break

        # DNS anomaly risk contribution
        if dns_events:
            risk += min(10, len(dns_events) * 3)
            risk_factors.append(f"Suspicious DNS activity: {len(dns_events)} events detected")

        # Beaconing risk contribution
        if beacon_events:
            risk += min(15, len(beacon_events) * 5)
            risk_factors.append(f"C2 beaconing patterns detected: {len(beacon_events)} suspicious connections")

        risk = min(risk, 100)

        # Risk level label with priority categories
        risk_priority = _risk_category(risk)
        if risk >= 80:
            threat_status = "Critical"
        elif risk >= 50:
            threat_status = "High Risk"
        elif risk >= 20:
            threat_status = "Suspicious"
        else:
            threat_status = "Normal"

        # ==============================================================
        #  BURST TOLERANCE
        # ==============================================================
        burst_tol = getattr(config, "BURST_TOLERANCE", 3)

        if ml_flag:
            self.consec_ml_anomaly += 1
        else:
            self.consec_ml_anomaly = 0

        if pps_flag:
            self.consec_pps_anomaly += 1
        else:
            self.consec_pps_anomaly = 0

        active_scan_ips = set()
        for ip in scan_ips:
            self.consec_port_scan[ip] += 1
            if self.consec_port_scan[ip] >= burst_tol:
                active_scan_ips.add(ip)
        for ip in list(self.consec_port_scan.keys()):
            if ip not in scan_ips:
                del self.consec_port_scan[ip]

        active_brute_ips = []
        for ip, port, hits in brute_ips:
            self.consec_brute_force[ip] += 1
            if self.consec_brute_force[ip] >= burst_tol:
                active_brute_ips.append((ip, port, hits))
        for ip in list(self.consec_brute_force.keys()):
            if ip not in [b[0] for b in brute_ips]:
                del self.consec_brute_force[ip]

        # ==============================================================
        #  SMART EXPLAINABLE ALERT GENERATION
        # ==============================================================
        window_alerts = []
        risk_threshold = getattr(config, "RISK_ALERT_THRESHOLD", 50)

        # Traffic summary for this window
        traffic_summary = {
            "total_packets": self.packet_count,
            "packet_rate": round(packet_rate, 2),
            "unique_ports": unique_ports,
            "protocols": dict(proto_dist),
            "total_bytes": self.window_bytes,
            "total_bytes_human": self._human_bytes(self.window_bytes),
            "duration": round(duration, 1),
            "unique_src_ips": len(filtered_ips),
        }

        # ---- ML Anomaly Alert ----
        if self.consec_ml_anomaly >= burst_tol and risk >= risk_threshold:
            alert = self._build_alert(
                timestamp=full_timestamp,
                src_ip=top_ip,
                attack_type="Statistical Anomaly",
                severity="High" if risk >= 80 else "Medium",
                classification="statistical_anomaly",
                confidence=min(95, 60 + self.consec_ml_anomaly * 5),
                packet_rate=packet_rate,
                unique_ports=unique_ports,
                risk_score=risk,
                risk_factors=list(risk_factors),
                proto_dist=proto_dist,
                traffic_summary=traffic_summary,
                explanation=[
                    f"Isolation Forest ML model detected anomalous traffic pattern.",
                    f"Anomaly persisted for {self.consec_ml_anomaly} consecutive windows ({self.consec_ml_anomaly * config.TIME_WINDOW}s).",
                    f"Packet rate: {packet_rate:.0f} pps with {unique_ports} unique destination ports.",
                ],
                recommended_action="Investigate source IP traffic patterns. Consider rate limiting if sustained.",
                response_simulated="Rate limit applied (simulated): throttle traffic from source IP to 50 pps.",
                metrics={
                    "Z-score": round((packet_rate - (self.anomaly_detector.baseline_mean_pps or packet_rate)) / max(self.anomaly_detector.baseline_std_pps or 1, 0.01), 2),
                    "Threshold value": round(getattr(self.anomaly_detector, "pps_threshold", 0), 2),
                    "Current packet rate (pps)": round(packet_rate, 2),
                    "Baseline mean": round(self.anomaly_detector.baseline_mean_pps or 0, 2),
                    "Standard deviation": round(self.anomaly_detector.baseline_std_pps or 0, 2),
                }
            )
            self._enrich_alert(alert)
            window_alerts.append(alert)

        # ---- Packet Flood / DoS Alert ----
        if self.consec_pps_anomaly >= burst_tol:
            if not self._is_legitimate_bulk(top_ip):
                src = flood_ip or top_ip
                pps_thr = self.anomaly_detector.pps_threshold
                alert = self._build_alert(
                    timestamp=full_timestamp,
                    src_ip=src,
                    attack_type="Packet Flood / DoS",
                    severity="Critical" if risk >= 80 else "High",
                    classification="packet_flood",
                    confidence=min(98, 70 + self.consec_pps_anomaly * 5),
                    packet_rate=packet_rate,
                    unique_ports=unique_ports,
                    risk_score=risk,
                    risk_factors=list(risk_factors),
                    proto_dist=proto_dist,
                    traffic_summary=traffic_summary,
                    explanation=[
                        f"Packet rate {packet_rate:.0f} pps exceeds baseline threshold {pps_thr:.0f} pps by {packet_rate/max(pps_thr,0.01):.1f}x.",
                        f"Anomaly sustained for {self.consec_pps_anomaly} consecutive windows.",
                        f"{self.packet_count} packets observed in {duration:.1f}s window.",
                        f"Flow analysis ruled out legitimate bulk traffic (streaming/download).",
                    ],
                    recommended_action=f"Block or rate-limit IP {src}. Investigate for volumetric DoS attack.",
                    response_simulated=f"Firewall rule added (simulated): DROP all traffic from {src}.",
                    metrics={
                        "Current PPS": round(packet_rate, 2),
                        "Baseline PPS": round(self.anomaly_detector.baseline_mean_pps or 0, 2),
                        "Multiplication factor": f"{round(packet_rate / max(self.anomaly_detector.baseline_mean_pps or 1, 0.01), 1)}x baseline",
                    }
                )
                self._enrich_alert(alert)
                window_alerts.append(alert)

        # ---- Port Scan Alert ----
        for ip in active_scan_ips:
            n_ports = len(self.ip_ports.get(ip, set()))
            top_scanned = sorted(self.ip_ports.get(ip, set()))[:10]
            port_names = [f"{p} ({_PORT_NAMES.get(p, '?')})" for p in top_scanned]
            alert = self._build_alert(
                timestamp=full_timestamp,
                src_ip=ip,
                attack_type="Port Scan",
                severity="High",
                classification="port_scan",
                confidence=min(97, 65 + n_ports),
                packet_rate=packet_rate,
                unique_ports=n_ports,
                risk_score=risk,
                risk_factors=list(risk_factors),
                proto_dist=proto_dist,
                traffic_summary=traffic_summary,
                explanation=[
                    f"IP {ip} probed {n_ports} unique destination ports in a single window.",
                    f"Threshold for port scan detection: {port_scan_thresh} ports.",
                    f"Scanned ports include: {', '.join(port_names)}.",
                    f"Behaviour persisted for {self.consec_port_scan.get(ip, 0)} consecutive windows.",
                ],
                recommended_action=f"Block IP {ip} at the perimeter firewall. Flag for SOC review.",
                response_simulated=f"IP {ip} added to blocklist (simulated). Alert forwarded to SOC team.",
                metrics={
                    "Number of unique ports accessed": n_ports,
                    "Threshold": port_scan_thresh,
                    "Time window": f"{config.TIME_WINDOW}s",
                }
            )
            self._enrich_alert(alert)
            window_alerts.append(alert)

        # ---- Brute Force Alert ----
        for ip, port, hits in active_brute_ips:
            svc = _PORT_NAMES.get(port, str(port))
            alert = self._build_alert(
                timestamp=full_timestamp,
                src_ip=ip,
                attack_type="Brute Force Behaviour",
                severity="High",
                classification="brute_force",
                confidence=min(90, 55 + hits),
                packet_rate=packet_rate,
                unique_ports=len(self.ip_ports.get(ip, set())),
                risk_score=risk,
                risk_factors=list(risk_factors),
                proto_dist=proto_dist,
                traffic_summary=traffic_summary,
                explanation=[
                    f"IP {ip} sent {hits} packets to port {port} ({svc}) in one window.",
                    f"Low port diversity ({len(self.ip_ports.get(ip, set()))} ports) with high repetition indicates credential stuffing.",
                    f"Behaviour persisted for {self.consec_brute_force.get(ip, 0)} consecutive windows.",
                ],
                recommended_action=f"Temporarily block IP {ip}. Enable account lockout on {svc} service.",
                response_simulated=f"IP {ip} temporarily blocked for 15 min (simulated). {svc} rate-limited.",
                metrics={
                    "Number of attempts": hits,
                    "Target port/service": f"{port} ({svc})",
                    "Time duration": f"{config.TIME_WINDOW}s",
                }
            )
            self._enrich_alert(alert)
            window_alerts.append(alert)

        # ---- Save alerts with cooldown + deduplication ----
        now_epoch = time.time()

        # --- Suppression rule check ---
        def _is_suppressed(alert):
            try:
                import json as _json
                settings_paths = [
                    "/home/cybersec/pro/X-NIDS/logs/settings.json",
                    "/home/cybersec/pro/X-NIDS/dashboard/settings.json",
                ]
                sups = []
                for sp in settings_paths:
                    if os.path.exists(sp):
                        try:
                            with open(sp, "r") as f:
                                sups = _json.load(f).get("suppressions", [])
                            break
                        except Exception:
                            continue
                for rule in sups:
                    if rule.get("expires", 0) != 0 and rule["expires"] < now_epoch:
                        continue
                    rt = rule.get("type", "")
                    target = rule.get("target", "")
                    matched = False
                    if rt == "ip" and alert.get("source_ip") == target:
                        matched = True
                    elif rt == "alert_type" and alert.get("classification") == target:
                        matched = True
                    elif rt == "both" and alert.get("source_ip") == target.split("|")[0].strip():
                        matched = True
                    if matched:
                        rule["suppressed_count"] = rule.get("suppressed_count", 0) + 1
                        for sp in settings_paths:
                            if os.path.exists(sp):
                                try:
                                    with open(sp, "r") as f:
                                        sd = _json.load(f)
                                    sd["suppressions"] = sups
                                    with open(sp, "w") as f:
                                        _json.dump(sd, f, indent=2)
                                except Exception:
                                    pass
                                break
                        return True
            except Exception:
                pass
            return False

        if risk >= risk_threshold and window_alerts:
            seen_keys = set()
            deduped = []
            for a in window_alerts:
                if _is_suppressed(a):
                    continue
                key = (a["source_ip"], a["classification"])
                if key in seen_keys:
                    continue
                last_t = self.last_alert_time.get(a["source_ip"], 0)
                if now_epoch - last_t < self.ALERT_COOLDOWN:
                    continue
                seen_keys.add(key)
                deduped.append(a)

            for a in deduped:
                self.last_alert_time[a["source_ip"]] = now_epoch
                self._log_alert_terminal(a, risk)
                
                # Add to attack timeline
                self.attack_timelines[a["source_ip"]].append({
                    "event": a["attack_type"],
                    "timestamp": a["timestamp"],
                    "risk_score": risk,
                    "details": a["explanation"][0] if a["explanation"] else "",
                })
                # Feed to alert correlator
                self.alert_correlator.ingest(a)

            self.alerts.extend(deduped)

        # ── Trim history / alerts properly to maintain reference ──
        if len(self.alerts) > 200:
            del self.alerts[:-200]
        self._save_alerts()

        # ==============================================================
        #  IP TRACKER
        # ==============================================================
        for ip, count in self.src_ips.items():
            if ip not in self.ips_tracker:
                self.ips_tracker[ip] = {
                    "ip": ip,
                    "packet_count": 0,
                    "unique_ports": set(),
                    "last_seen": timestamp,
                }
            self.ips_tracker[ip]["packet_count"] += count
            self.ips_tracker[ip]["unique_ports"].update(self.ip_ports.get(ip, set()))
            self.ips_tracker[ip]["last_seen"] = timestamp

        top_ips_list = []
        alerted_ips = {a["source_ip"] for a in self.alerts}
        for ip, d in self.ips_tracker.items():
            s = (d["packet_count"] * 0.1) + (len(d["unique_ports"]) * 2)
            if ip in alerted_ips:
                s += 50
            net_type, country = _classify_ip(ip)
            top_ips_list.append({
                "ip": ip,
                "packet_count": d["packet_count"],
                "unique_ports": len(d["unique_ports"]),
                "risk_score": int(min(s, 100)),
                "last_seen": d["last_seen"],
                "network_type": net_type,
                "country": country,
            })
        top_ips_list.sort(key=lambda x: x["risk_score"], reverse=True)
        top_ips_list = top_ips_list[:20]

        # ── Bandwidth ──
        bw_str = self._human_bytes(self.total_bytes)

        # ── Top targeted ports ──
        port_counts = defaultdict(int)
        for ip, ports in self.ip_ports.items():
            for p in ports:
                port_counts[p] += 1
        top_ports_list = [
            {"port": p, "count": c, "service": _PORT_NAMES.get(p, "")}
            for p, c in sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

        # ── History entry ──
        is_anomaly = risk >= risk_threshold
        stat_entry = {
            "timestamp": timestamp,
            "packet_rate": round(packet_rate, 2),
            "unique_ports": unique_ports,
            "most_active_ip": top_ip,
            "packet_count": self.packet_count,
            "alert": window_alerts[0]["attack_type"] if window_alerts else "None",
            "anomaly_score": anomaly_score,
            "anomaly": is_anomaly,
            "risk_score": risk,
            "alerts_in_window": len(window_alerts),
        }
        self.history.append(stat_entry)
        if len(self.history) > 60:
            self.history.pop(0)

        # ── Attach timelines + MITRE to alerts going out ──
        alerts_out = list(reversed(self.alerts))
        for a in alerts_out:
            ip = a.get("source_ip", "")
            tl = self.attack_timelines.get(ip, [])
            a["timeline"] = tl[-10:] if tl else []
            # Attach MITRE mapping
            if "mitre" not in a:
                a["mitre"] = get_mitre_mapping(a.get("classification", ""))
            # Attach risk priority category
            if "risk_priority" not in a:
                a["risk_priority"] = _risk_category(a.get("risk_score", 0))

        # ── Sort alerts by risk score (highest first) ──
        alerts_out.sort(key=lambda a: a.get("risk_score", 0), reverse=True)

        # ── Build full metrics blob ──
        metrics = {
            "summary": {
                "total_packets": self.total_packets,
                "bandwidth": bw_str,
                "bandwidth_bytes": self.total_bytes,
                "unique_src_ips": len(self.all_unique_src_ips),
                "active_alerts": len(self.alerts),
                "network_assets": len(self.network_assets),
                "dns_queries": self.dns_analyzer.total_dns_queries,
            },
            "history": self.history,
            "current_window": {
                "timestamp": timestamp,
                "packet_rate": round(packet_rate, 2),
                "unique_ports": unique_ports,
                "packet_count": self.packet_count,
                "most_active_ip": top_ip,
                "protocol_distribution": proto_dist,
                "anomaly_score": anomaly_score,
                "risk_score": risk,
                "risk_priority": risk_priority,
            },
            "top_ips": top_ips_list,
            "top_ports": top_ports_list,
            "alerts": alerts_out,
            "threat_level": self._compute_threat_level(),
        }

        os.makedirs(LOGS_DIR, exist_ok=True)
        try:
            with open(METRICS_FILE, "w") as f:
                json.dump(metrics, f, cls=NumpySafeEncoder)
        except Exception as e:
            print(f"  [-] Metrics write error: {e}")

    # ==================================================================
    #  Alert builder
    # ==================================================================
    def _build_alert(self, *, timestamp, src_ip, attack_type, severity,
                     classification, confidence, packet_rate, unique_ports,
                     risk_score, risk_factors, proto_dist, traffic_summary,
                     explanation, recommended_action, response_simulated, metrics=None):
        mitre = get_mitre_mapping(classification)
        return {
            "_epoch": time.time(),
            "timestamp": timestamp,
            "source_ip": src_ip,
            "attack_type": attack_type,
            "severity": severity,
            "classification": classification,
            "confidence": confidence,
            "protocol": max(proto_dist, key=proto_dist.get) if proto_dist else "Unknown",
            "packet_rate": round(packet_rate, 2),
            "unique_ports": unique_ports,
            "risk_score": risk_score,
            "risk_priority": _risk_category(risk_score),
            "risk_factors": risk_factors,
            "protocol_distribution": dict(proto_dist),
            "traffic_summary": dict(traffic_summary),
            "explanation": list(explanation),
            "recommended_action": recommended_action,
            "response_simulated": response_simulated,
            "metrics": metrics or {},
            # MITRE ATT&CK mapping
            "mitre": mitre,
            # Enrichment fields (filled by _enrich_alert)
            "network_type": "",
            "country": "",
            "threat_intel": None,
            "device_profile": None,
            "timeline": [],
        }

    def _enrich_alert(self, alert):
        """Add threat intelligence & device profile to an alert."""
        ip = alert["source_ip"]

        # Full threat intel enrichment
        intel = enrich_ip(ip)
        alert["threat_intel"] = intel
        alert["network_type"] = intel["network_type"]
        alert["country"] = intel["country"]

        # Device behaviour deviation
        profile = self.device_profiles.get(ip)
        if profile and profile["windows"] >= 2:
            avg_pps = profile["avg_pps"]
            current_pps = alert["packet_rate"]
            deviation = round(current_pps / max(avg_pps, 0.01), 1)
            alert["device_profile"] = {
                "avg_pps": round(avg_pps, 2),
                "current_pps": round(current_pps, 2),
                "deviation_multiplier": deviation,
                "known_ports": len(profile["ports"]),
                "first_seen": profile["first_seen"],
                "windows_observed": profile["windows"],
            }
            if deviation > 2:
                alert["explanation"].append(
                    f"Traffic from this IP increased {deviation}x above its historical average ({avg_pps:.0f} pps)."
                )

        # Timeline
        tl = self.attack_timelines.get(ip, [])
        alert["timeline"] = tl[-10:] if tl else []

    # ==================================================================
    #  Device behaviour profiling
    # ==================================================================
    def _update_device_profiles(self, timestamp):
        """Update per-IP behavioural profiles from current window."""
        duration = time.time() - self.start_time
        for ip, count in self.src_ips.items():
            pps = count / max(duration, 0.01)
            if ip not in self.device_profiles:
                self.device_profiles[ip] = {
                    "windows": 0,
                    "total_pkts": 0,
                    "avg_pps": 0.0,
                    "ports": set(),
                    "protos": defaultdict(int),
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                }
            p = self.device_profiles[ip]
            p["windows"] += 1
            p["total_pkts"] += count
            # Exponential moving average for PPS
            alpha = 0.3
            p["avg_pps"] = alpha * pps + (1 - alpha) * p["avg_pps"]
            p["ports"].update(self.ip_ports.get(ip, set()))
            p["last_seen"] = timestamp

    # ==================================================================
    #  Terminal alert logger (structured, readable)
    # ==================================================================
    @staticmethod
    def format_alert(alert_data):
        """Format alert strictly using SOC-grade output style."""
        emoji_map = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
        sev = alert_data.get("severity", "Medium").upper()
        emoji = emoji_map.get(alert_data.get("severity", "Medium"), "🟡")
        
        lines = []
        lines.append(f"🚨 ALERT - {sev}")
        cls = alert_data.get("classification", "").upper()
        if not cls:
            cls = alert_data.get("attack_type", "UNKNOWN").upper().replace(" ", "_")
        lines.append(f"Type: {cls}")
        lines.append(f"Source: {alert_data.get('source_ip', 'Unknown')}")
        if alert_data.get("dest_ip"):
            lines.append(f"Destination IP: {alert_data['dest_ip']}")
        lines.append(f"Protocol: {alert_data.get('protocol', 'Unknown')}")
        lines.append(f"Timestamp: {alert_data.get('timestamp', '')}")
        lines.append(f"Risk Score: {alert_data.get('risk_score', 0)}")
        lines.append("")
        
        metrics = alert_data.get("metrics", {})
        if metrics:
            for k, v in metrics.items():
                lines.append(f"{k}: {v}")
            lines.append("")
            
        reasons = alert_data.get("explanation", [])
        if reasons:
            lines.append("Reason:")
            for r in reasons:
                lines.append(f"- {r}")
                
        return "\n".join(lines)

    @staticmethod
    def _log_alert_terminal(alert, risk):
        formatted = FeatureExtractor.format_alert(alert)
        print("\n" + "="*50)
        print(formatted)
        print("="*50 + "\n")

    # ==================================================================
    #  Incident Report Generator
    # ==================================================================
    def generate_report(self, alert_index=None, format_type="json"):
        """Generate a detailed incident report for an alert or all alerts."""
        if alert_index is not None and 0 <= alert_index < len(self.alerts):
            alerts_to_report = [self.alerts[alert_index]]
        else:
            alerts_to_report = list(self.alerts)

        reports = []
        for a in alerts_to_report:
            report = {
                "report_generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                "report_type": "Incident Report",
                "system": "X-NIDS — Intelligent Intrusion Detection System",
                "alert_details": {
                    "attack_type": a.get("attack_type", ""),
                    "classification": a.get("classification", ""),
                    "source_ip": a.get("source_ip", ""),
                    "timestamp": a.get("timestamp", ""),
                    "severity": a.get("severity", ""),
                    "confidence": a.get("confidence", 0),
                    "risk_score": a.get("risk_score", 0),
                    "risk_priority": _risk_category(a.get("risk_score", 0)),
                },
                "mitre_attack": a.get("mitre", {}),
                "threat_intelligence": a.get("threat_intel", {}),
                "packet_statistics": a.get("traffic_summary", {}),
                "detection_explanation": a.get("explanation", []),
                "risk_factors": a.get("risk_factors", []),
                "device_profile": a.get("device_profile"),
                "recommended_action": a.get("recommended_action", ""),
                "simulated_response": a.get("response_simulated", ""),
                "attack_timeline": a.get("timeline", []),
            }
            reports.append(report)

        return reports

    # ==================================================================
    #  Helpers
    # ==================================================================
    def _is_legitimate_bulk(self, ip):
        ports_hit = self.ip_ports.get(ip, set())
        pkts = self.src_ips.get(ip, 0)
        if len(ports_hit) <= 2 and pkts > 20:
            return True
        ip_flows = {k: v for k, v in self.flows.items() if k[0] == ip}
        if ip_flows:
            total_flow_bytes = sum(f["bytes"] for f in ip_flows.values())
            biggest = max(ip_flows.values(), key=lambda f: f["bytes"])
            if total_flow_bytes > 0 and biggest["bytes"] / total_flow_bytes > 0.8:
                return True
        return False

    def _save_alerts(self):
        try:
            with open(ALERTS_FILE, "w") as f:
                json.dump(self.alerts, f, cls=NumpySafeEncoder, indent=2)
        except Exception:
            pass

    @staticmethod
    def _human_bytes(b):
        if b > 1_073_741_824:
            return f"{b / 1_073_741_824:.2f} GB"
        if b > 1_048_576:
            return f"{b / 1_048_576:.2f} MB"
        if b > 1024:
            return f"{b / 1024:.2f} KB"
        return f"{b} B"

    # ==================================================================
    #  Window reset
    # ==================================================================
    def reset_window(self):
        self.start_time = time.time()
        self.packet_count = 0
        self.window_bytes = 0
        self.src_ips.clear()
        self.dst_ips.clear()
        self.ip_ports.clear()
        self.ip_dst_port_hits.clear()
        self.dest_ports.clear()
        self.protocols = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.flows.clear()
        # Reset per-window DNS data (persistent list keeps accumulating)
        self.dns_analyzer.reset_window()


# Global singleton
extractor = FeatureExtractor()