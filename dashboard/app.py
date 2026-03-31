import os
import json
import time
from flask import Flask, render_template, jsonify, request, Response

app = Flask(__name__, static_folder="static")

BASE_DIR = "/home/cybersec/pro/X-NIDS"
METRICS_FILE = os.path.join(BASE_DIR, "logs/metrics.json")
_SETTINGS_PRIMARY = os.path.join(BASE_DIR, "logs/settings.json")
_SETTINGS_FALLBACK = os.path.join(BASE_DIR, "dashboard/settings.json")
# Use the primary file if writable, otherwise fallback
SETTINGS_FILE = _SETTINGS_PRIMARY if os.access(os.path.dirname(_SETTINGS_PRIMARY), os.W_OK) else _SETTINGS_FALLBACK

EMPTY = {
    "summary": {
        "total_packets": 0,
        "bandwidth": "0 B",
        "bandwidth_bytes": 0,
        "unique_src_ips": 0,
        "active_alerts": 0,
        "network_assets": 0,
        "dns_queries": 0,
    },
    "history": [],
    "current_window": {},
    "top_ips": [],
    "top_ports": [],
    "alerts": [],
    "threat_level": {"score": 0, "status": "Initializing", "priority": "Low"},
}

# Default editable settings
DEFAULT_SETTINGS = {
    "pps_threshold": 500,
    "time_window": 5,
    "baseline_duration": 300,
    "polling_interval": 1,
    "max_data_points": 60,
    "burst_tolerance": 6,
    "port_scan_threshold": 15,
    "risk_alert_threshold": 70,
    "sigma_mult": 2.5,
    "browser_notifications": True,
    "whitelist": [
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
        "9.9.9.9", "149.112.112.112",
        "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "127.0.0.0/8",
    ],
}

def _load_settings():
    # Try both settings file locations
    for path in [SETTINGS_FILE, _SETTINGS_PRIMARY, _SETTINGS_FALLBACK]:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    saved = json.load(f)
                merged = {**DEFAULT_SETTINGS, **saved}
                return merged
            except Exception:
                continue
    return dict(DEFAULT_SETTINGS)

def _save_settings(data):
    try:
        os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
        with open(SETTINGS_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except PermissionError:
        os.makedirs(os.path.dirname(_SETTINGS_FALLBACK), exist_ok=True)
        with open(_SETTINGS_FALLBACK, "w") as f:
            json.dump(data, f, indent=2)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
@app.route("/metrics")
def stats():
    if not os.path.exists(METRICS_FILE):
        return jsonify(EMPTY)
    try:
        with open(METRICS_FILE, "r") as f:
            data = json.load(f)
        return jsonify(data)
    except Exception:
        return jsonify(EMPTY)

@app.route("/api/settings", methods=["GET"])
def get_settings():
    return jsonify(_load_settings())

@app.route("/api/settings", methods=["POST"])
def save_settings():
    try:
        incoming = request.get_json(force=True)
        current = _load_settings()

        # Validate and type-cast incoming values
        for key in DEFAULT_SETTINGS:
            if key in incoming:
                if key == "whitelist":
                    current[key] = list(incoming[key])
                else:
                    default_type = type(DEFAULT_SETTINGS[key])
                    try:
                        current[key] = default_type(incoming[key])
                    except (ValueError, TypeError):
                        pass

        _save_settings(current)

        # Hot-reload into config module (affects running engine)
        try:
            import config
            if "pps_threshold" in current:
                config.PACKET_RATE_THRESHOLD = int(current["pps_threshold"])
            if "time_window" in current:
                config.TIME_WINDOW = int(current["time_window"])
            if "baseline_duration" in current:
                config.BASELINE_DURATION = int(current["baseline_duration"])
            if "burst_tolerance" in current:
                config.BURST_TOLERANCE = int(current["burst_tolerance"])
            if "port_scan_threshold" in current:
                config.PORT_SCAN_THRESHOLD = int(current["port_scan_threshold"])
            if "risk_alert_threshold" in current:
                config.RISK_ALERT_THRESHOLD = int(current["risk_alert_threshold"])
            if "sigma_mult" in current:
                config.SIGMA_MULT = float(current["sigma_mult"])
            if "whitelist" in current:
                config.WHITELIST = current["whitelist"]
                try:
                    from features.feature_extractor import extractor as ext
                    from features.feature_extractor import _is_whitelisted
                    keys_to_resolve = []
                    for key, inc in ext.alert_correlator.incidents.items():
                        if _is_whitelisted(inc["source_ip"]):
                            keys_to_resolve.append(key)
                    for key in keys_to_resolve:
                        inc = ext.alert_correlator.incidents.pop(key)
                        inc["status"] = "RESOLVED"
                        inc["resolve_reason"] = "Source IP whitelisted"
                        ext.alert_correlator.incident_history.append(inc)
                except Exception:
                    pass
        except Exception:
            pass

        return jsonify({"status": "ok", "settings": current})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


# ═══════════════════════════════════════════════════════════════════
#  LIVE API: Alerts (reads directly from in-memory shared store)
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/alerts")
def api_alerts():
    """Return the live in-memory alert list — same reference the detection
    engine writes to, ensuring Alerts page matches Incidents page."""
    try:
        from features.feature_extractor import extractor as ext
        from intelligence.mitre_mapping import get_mitre_mapping
        alerts_out = list(reversed(ext.alerts))
        for a in alerts_out:
            ip = a.get("source_ip", "")
            tl = ext.attack_timelines.get(ip, [])
            a["timeline"] = tl[-10:] if tl else []
            if "mitre" not in a:
                a["mitre"] = get_mitre_mapping(a.get("classification", ""))
            if "risk_priority" not in a:
                from features.feature_extractor import _risk_category
                a["risk_priority"] = _risk_category(a.get("risk_score", 0))
        alerts_out.sort(key=lambda a: a.get("risk_score", 0), reverse=True)
        return jsonify({"alerts": alerts_out, "total": len(alerts_out)})
    except Exception as e:
        return jsonify({"alerts": [], "total": 0, "error": str(e)})


# ═══════════════════════════════════════════════════════════════════
#  LIVE API: Threat Score (recomputed fresh on every request)
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/threat-score")
def api_threat_score():
    """Recompute threat score from scratch on every request — no caching."""
    try:
        from features.feature_extractor import extractor as ext
        return jsonify(ext._compute_threat_level())
    except Exception as e:
        return jsonify({"score": 0, "status": "Normal", "priority": "NONE",
                        "last_alert_ago": -1, "error": str(e)})






@app.route("/api/ip/<address>")
def ip_investigation(address):
    """Per-IP deep investigation data."""
    try:
        from features.feature_extractor import extractor as ext
        from intelligence.threat_intel import enrich_ip
        profile = ext.device_profiles.get(address)
        timeline = ext.attack_timelines.get(address, [])
        ip_alerts = [a for a in ext.alerts if a.get("source_ip") == address]
        tracker = ext.ips_tracker.get(address, {})

        device_data = None
        if profile:
            device_data = {
                "avg_pps": round(profile.get("avg_pps", 0), 2),
                "total_pkts": profile.get("total_pkts", 0),
                "windows": profile.get("windows", 0),
                "known_ports": list(profile.get("ports", set()))[:30],
                "first_seen": profile.get("first_seen", ""),
                "last_seen": profile.get("last_seen", ""),
            }

        # Full threat intel enrichment
        intel = enrich_ip(address)

        # Protocol distribution for this IP
        proto_dist = {}
        if profile and "protos" in profile:
            total_proto_ip = sum(profile["protos"].values())
            if total_proto_ip > 0:
                for k, v in profile["protos"].items():
                    proto_dist[k] = round((v / total_proto_ip) * 100, 1)

        # Risk score history from alerts
        risk_history = []
        for a in ip_alerts:
            risk_history.append({
                "timestamp": a.get("timestamp", ""),
                "risk_score": a.get("risk_score", 0),
                "attack_type": a.get("attack_type", ""),
            })

        return jsonify({
            "ip": address,
            "network_type": intel["network_type"],
            "country": intel["country"],
            "asn": intel.get("asn", "N/A"),
            "isp": intel.get("isp", "Unknown"),
            "is_private": intel.get("is_private", False),
            "packet_count": tracker.get("packet_count", 0),
            "unique_ports": len(tracker.get("unique_ports", set())),
            "protocol_distribution": proto_dist,
            "device_profile": device_data,
            "timeline": timeline[-20:],
            "alerts": list(reversed(ip_alerts))[:20],
            "risk_history": risk_history[-20:],
            "last_seen": tracker.get("last_seen", ""),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/analytics")
def analytics():
    """Historical attack analytics."""
    alerts_file = os.path.join(BASE_DIR, "logs/alerts.json")
    alerts = []
    if os.path.exists(alerts_file):
        try:
            with open(alerts_file, "r") as f:
                alerts = json.load(f)
        except Exception:
            pass

    # Attack type distribution
    type_counts = {}
    ip_counts = {}
    port_counts = {}
    severity_counts = {}
    timeline_data = []
    for a in alerts:
        t = a.get("classification", a.get("attack_type", "unknown"))
        type_counts[t] = type_counts.get(t, 0) + 1
        ip = a.get("source_ip", "")
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        sev = a.get("severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        # Targeted ports from traffic summary
        for port_info in a.get("risk_factors", []):
            if "port" in port_info.lower():
                import re
                ports_found = re.findall(r'port (\d+)', port_info)
                for p in ports_found:
                    port_counts[p] = port_counts.get(p, 0) + 1
        # Timeline entry
        timeline_data.append({
            "timestamp": a.get("timestamp", ""),
            "type": t,
            "risk_score": a.get("risk_score", 0),
        })

    top_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_attackers = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return jsonify({
        "total_alerts": len(alerts),
        "attack_types": [{"type": t, "count": c} for t, c in top_types],
        "top_attackers": [{"ip": ip, "count": c} for ip, c in top_attackers],
        "top_ports": [{"port": p, "count": c} for p, c in top_ports],
        "severity_distribution": severity_counts,
        "attack_timeline": timeline_data[-100:],
    })


@app.route("/api/netmap")
def netmap():
    """Live network topology data for visualization."""
    try:
        from features.feature_extractor import extractor as ext, _classify_ip
        nodes = {}
        edges = []
        alerted_ips = {a["source_ip"] for a in ext.alerts}

        for ip, data in ext.ips_tracker.items():
            net_type, country = _classify_ip(ip)
            nodes[ip] = {
                "id": ip,
                "packets": data.get("packet_count", 0),
                "ports": len(data.get("unique_ports", set())),
                "risk": min(100, int((data.get("packet_count", 0) * 0.1) + (len(data.get("unique_ports", set())) * 2) + (50 if ip in alerted_ips else 0))),
                "alerted": ip in alerted_ips,
                "type": net_type,
                "country": country,
            }

        # Build edges from flows
        seen_edges = set()
        for flow_key in ext.flows:
            src, dst = flow_key[0], flow_key[1]
            edge_key = (src, dst)
            if edge_key not in seen_edges:
                seen_edges.add(edge_key)
                flow = ext.flows[flow_key]
                edges.append({
                    "source": src,
                    "target": dst,
                    "packets": flow.get("packets", 0),
                    "bytes": flow.get("bytes", 0),
                })
                if dst not in nodes:
                    net_type, country = _classify_ip(dst)
                    nodes[dst] = {
                        "id": dst, "packets": 0, "ports": 0, "risk": 0,
                        "alerted": False, "type": net_type, "country": country,
                    }

        return jsonify({
            "nodes": list(nodes.values()),
            "edges": edges[:100],
        })
    except Exception as e:
        return jsonify({"nodes": [], "edges": [], "error": str(e)})


# ═══════════════════════════════════════════════════════════════════
#  NEW API: Network Asset Discovery
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/assets")
def network_assets():
    """Discovered network devices."""
    try:
        from features.feature_extractor import extractor as ext
        assets = ext.get_network_assets()
        return jsonify({
            "total_assets": len(assets),
            "assets": assets,
        })
    except Exception as e:
        return jsonify({"total_assets": 0, "assets": [], "error": str(e)})


# ═══════════════════════════════════════════════════════════════════
#  NEW API: DNS Analysis
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/dns")
def dns_analysis():
    """Suspicious DNS activity."""
    try:
        from features.feature_extractor import extractor as ext
        summary = ext.dns_analyzer.get_summary()
        return jsonify(summary)
    except Exception as e:
        return jsonify({"total_dns_queries": 0, "suspicious_domains": [], "error": str(e)})


# ═══════════════════════════════════════════════════════════════════
#  NEW API: Beaconing / C2 Detection
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/beaconing")
def beaconing():
    """C2 beaconing detection results."""
    try:
        from features.feature_extractor import extractor as ext
        summary = ext.beaconing_detector.get_summary()
        return jsonify(summary)
    except Exception as e:
        return jsonify({"flagged_beacons": [], "error": str(e)})


# ═══════════════════════════════════════════════════════════════════
#  NEW API: Alert Correlation / Incidents
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/incidents")
def incidents():
    """Correlated alert incidents."""
    try:
        from features.feature_extractor import extractor as ext
        active = ext.alert_correlator.get_active_incidents()
        all_inc = ext.alert_correlator.get_all_incidents()
        return jsonify({
            "active_incidents": active,
            "all_incidents": all_inc,
            "total_active": len(active),
        })
    except Exception as e:
        return jsonify({"active_incidents": [], "all_incidents": [], "error": str(e)})


# ═══════════════════════════════════════════════════════════════════
#  NEW API: Incident Report Generator
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/report", methods=["GET"])
def generate_report():
    """Generate incident report (JSON or text)."""
    try:
        from features.feature_extractor import extractor as ext
        alert_idx = request.args.get("alert_index", None)
        if alert_idx is not None:
            alert_idx = int(alert_idx)

        reports = ext.generate_report(alert_index=alert_idx, format_type="json")

        fmt = request.args.get("format", "json")
        if fmt == "text":
            # Generate text report
            lines = []
            lines.append("=" * 70)
            lines.append("  X-NIDS INCIDENT REPORT")
            lines.append(f"  Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append("=" * 70)
            for r in reports:
                ad = r.get("alert_details", {})
                lines.append(f"\n{'─' * 60}")
                lines.append(f"  Attack Type     : {ad.get('attack_type', '')}")
                lines.append(f"  Classification  : {ad.get('classification', '')}")
                lines.append(f"  Source IP       : {ad.get('source_ip', '')}")
                lines.append(f"  Timestamp       : {ad.get('timestamp', '')}")
                lines.append(f"  Severity        : {ad.get('severity', '')}")
                lines.append(f"  Confidence      : {ad.get('confidence', 0)}%")
                lines.append(f"  Risk Score      : {ad.get('risk_score', 0)}/100 ({ad.get('risk_priority', '')})")

                mitre = r.get("mitre_attack", {})
                if mitre.get("technique_id"):
                    lines.append(f"\n  MITRE ATT&CK:")
                    lines.append(f"    Technique : {mitre['technique_id']} — {mitre.get('technique_name', '')}")
                    lines.append(f"    Tactic    : {mitre.get('tactic', '')} ({mitre.get('tactic_id', '')})")

                intel = r.get("threat_intelligence", {})
                if intel:
                    lines.append(f"\n  Threat Intelligence:")
                    lines.append(f"    Country   : {intel.get('country', '?')}")
                    lines.append(f"    ASN       : {intel.get('asn', '?')}")
                    lines.append(f"    ISP       : {intel.get('isp', '?')}")

                ps = r.get("packet_statistics", {})
                if ps:
                    lines.append(f"\n  Packet Statistics:")
                    lines.append(f"    Packets   : {ps.get('total_packets', 0)}")
                    lines.append(f"    Rate      : {ps.get('packet_rate', 0)} pps")
                    lines.append(f"    Bytes     : {ps.get('total_bytes_human', '0 B')}")
                    lines.append(f"    Ports     : {ps.get('unique_ports', 0)}")

                exp = r.get("detection_explanation", [])
                if exp:
                    lines.append(f"\n  Detection Logic:")
                    for e in exp:
                        lines.append(f"    • {e}")

                rf = r.get("risk_factors", [])
                if rf:
                    lines.append(f"\n  Risk Factors:")
                    for f in rf:
                        lines.append(f"    • {f}")

                if r.get("recommended_action"):
                    lines.append(f"\n  Recommended Action: {r['recommended_action']}")

                lines.append(f"\n{'─' * 60}")

            lines.append("\n" + "=" * 70)
            lines.append("  END OF REPORT")
            lines.append("=" * 70)

            text = "\n".join(lines)
            return Response(text, mimetype="text/plain",
                          headers={"Content-Disposition": "attachment; filename=incident_report.txt"})

        return jsonify({"reports": reports, "count": len(reports)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════
#  NEW API: Attack Simulation
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/simulate", methods=["POST"])
def start_simulation():
    """Start attack simulation."""
    try:
        from intelligence.attack_simulator import simulator
        data = request.get_json(force=True)
        sim_type = data.get("type", "port_scan")
        duration = min(int(data.get("duration", 30)), 120)  # cap at 2 min
        result = simulator.start_simulation(sim_type=sim_type, duration=duration)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/simulate/stop", methods=["POST"])
def stop_simulation():
    """Stop attack simulation."""
    try:
        from intelligence.attack_simulator import simulator
        result = simulator.stop_simulation()
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/simulate/status")
def simulation_status():
    """Get simulation status."""
    try:
        from intelligence.attack_simulator import simulator
        return jsonify(simulator.get_status())
    except Exception as e:
        return jsonify({"running": False, "error": str(e)})

# ═══════════════════════════════════════════════════════════════════
#  FEATURE: Geo Threat Map  (optimised: batch API + persistent cache)
# ═══════════════════════════════════════════════════════════════════
import ipaddress as _ipaddress
import threading

_geo_cache = {}                       # {ip_str: {lat, lon, country, city, cached_at}}
_geo_cache_lock = threading.Lock()
_GEO_TTL = 86400                      # 24 hours — geo of an IP never changes
_GEO_CACHE_FILE = os.path.join(BASE_DIR, "logs/geo_cache.json")

# ── Load persistent cache on import ──
def _load_geo_cache():
    global _geo_cache
    try:
        if os.path.exists(_GEO_CACHE_FILE):
            with open(_GEO_CACHE_FILE, "r") as f:
                raw = json.load(f)
            now = time.time()
            # Only keep entries that haven't expired
            _geo_cache = {ip: entry for ip, entry in raw.items()
                          if now - entry.get("cached_at", 0) < _GEO_TTL}
    except Exception:
        _geo_cache = {}

def _save_geo_cache():
    try:
        with _geo_cache_lock:
            snapshot = dict(_geo_cache)
        os.makedirs(os.path.dirname(_GEO_CACHE_FILE), exist_ok=True)
        with open(_GEO_CACHE_FILE, "w") as f:
            json.dump(snapshot, f)
    except Exception:
        pass

# Load cache at startup
_load_geo_cache()

# Periodic cache flush (every 5 min)
def _geo_cache_flusher():
    while True:
        time.sleep(300)
        _save_geo_cache()

_geo_flush_thread = threading.Thread(target=_geo_cache_flusher, daemon=True)
_geo_flush_thread.start()

def _is_private_ip(ip_str):
    try:
        return _ipaddress.ip_address(ip_str).is_private
    except Exception:
        return True

def _geo_cache_get(ip_str):
    """Return cached entry or None."""
    with _geo_cache_lock:
        entry = _geo_cache.get(ip_str)
        if entry and (time.time() - entry.get("cached_at", 0) < _GEO_TTL):
            return entry
    return None

def _geo_batch_resolve(ip_list):
    """Resolve a list of IPs via ip-api.com batch endpoint (max 100).
    Returns dict {ip: {lat, lon, country, city, cached_at}} for successes."""
    if not ip_list:
        return {}
    import requests as _requests
    results = {}
    # ip-api batch accepts up to 100 per call
    for i in range(0, len(ip_list), 100):
        batch = ip_list[i:i + 100]
        payload = [{"query": ip, "fields": "status,country,city,lat,lon,query"}
                   for ip in batch]
        try:
            resp = _requests.post("http://ip-api.com/batch",
                                  json=payload, timeout=10)
            if resp.status_code == 200:
                now = time.time()
                for item in resp.json():
                    if item.get("status") == "success":
                        ip = item["query"]
                        entry = {
                            "lat": item.get("lat", 0),
                            "lon": item.get("lon", 0),
                            "country": item.get("country", ""),
                            "city": item.get("city", ""),
                            "cached_at": now,
                        }
                        results[ip] = entry
                        with _geo_cache_lock:
                            _geo_cache[ip] = entry
        except Exception:
            pass
    # Persist after a batch resolve
    _save_geo_cache()
    return results

def _build_marker(ip, geo, data, alerted_ips):
    """Build a single marker dict from geo data + tracker data."""
    pkt = data.get("packet_count", 0)
    ports = len(data.get("unique_ports", set()))
    r = int(min(100, (pkt * 0.1) + (ports * 2) + (50 if ip in alerted_ips else 0)))
    return {
        "ip": ip,
        "lat": geo["lat"],
        "lon": geo["lon"],
        "country": geo["country"],
        "city": geo["city"],
        "risk": r,
        "packets": pkt,
        "alerted": ip in alerted_ips,
        "first_seen": data.get("last_seen", ""),
    }

@app.route("/api/geo/threats")
def geo_threats():
    """Return geolocated threat data — cached markers immediately,
    plus a list of pending IPs that still need resolution."""
    try:
        from features.feature_extractor import extractor as ext
        cached_markers = []
        pending_ips = []          # IPs not yet in cache
        pending_ip_data = {}      # IP → tracker data for pending IPs
        alerted_ips = {a["source_ip"] for a in ext.alerts}

        for ip, data in list(ext.ips_tracker.items())[:100]:
            if _is_private_ip(ip):
                continue
            geo = _geo_cache_get(ip)
            if geo:
                if geo["lat"] == 0 and geo["lon"] == 0:
                    continue
                cached_markers.append(_build_marker(ip, geo, data, alerted_ips))
            else:
                pending_ips.append(ip)
                pending_ip_data[ip] = {
                    "packet_count": data.get("packet_count", 0),
                    "unique_ports": len(data.get("unique_ports", set())),
                    "alerted": ip in alerted_ips,
                    "last_seen": data.get("last_seen", ""),
                }

        countries = len({m["country"] for m in cached_markers})
        high_risk = sum(1 for m in cached_markers if m["risk"] > 60)

        return jsonify({
            "markers": cached_markers,
            "countries": countries,
            "high_risk": high_risk,
            "pending_ips": pending_ips,
            "pending_ip_data": pending_ip_data,
            "total_ips": len(cached_markers) + len(pending_ips),
        })
    except Exception as e:
        return jsonify({"markers": [], "countries": 0, "high_risk": 0,
                        "pending_ips": [], "error": str(e)})


@app.route("/api/geo/resolve", methods=["POST"])
def geo_resolve():
    """Batch-resolve a list of IPs and return markers.
    Request body: {"ips": [...], "ip_data": {ip: {packet_count, unique_ports, alerted, last_seen}}}.
    """
    try:
        body = request.get_json(force=True)
        ips = body.get("ips", [])
        ip_data = body.get("ip_data", {})

        resolved = _geo_batch_resolve(ips)

        markers = []
        for ip, geo in resolved.items():
            if geo["lat"] == 0 and geo["lon"] == 0:
                continue
            data_for_ip = ip_data.get(ip, {})
            pkt = data_for_ip.get("packet_count", 0)
            ports = data_for_ip.get("unique_ports", 0)
            alerted = data_for_ip.get("alerted", False)
            r = int(min(100, (pkt * 0.1) + (ports * 2) + (50 if alerted else 0)))
            markers.append({
                "ip": ip,
                "lat": geo["lat"],
                "lon": geo["lon"],
                "country": geo["country"],
                "city": geo["city"],
                "risk": r,
                "packets": pkt,
                "alerted": alerted,
                "first_seen": data_for_ip.get("last_seen", ""),
            })

        countries = len({m["country"] for m in markers})
        high_risk = sum(1 for m in markers if m["risk"] > 60)
        return jsonify({"markers": markers, "countries": countries, "high_risk": high_risk})
    except Exception as e:
        return jsonify({"markers": [], "error": str(e)})


# ═══════════════════════════════════════════════════════════════════
#  FEATURE: MITRE ATT&CK Mapping
# ═══════════════════════════════════════════════════════════════════
_MITRE_MAP = {
    "packet_flood": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique_id": "T1498", "technique_name": "Network Denial of Service",
        "description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources.",
        "action": "Implement rate limiting and traffic filtering. Deploy DDoS mitigation appliances.",
    },
    "statistical_anomaly": {
        "tactic": "Reconnaissance", "tactic_id": "TA0043",
        "technique_id": "T1046", "technique_name": "Network Service Scanning",
        "description": "Adversaries may scan for services running on remote hosts to gather information for targeting.",
        "action": "Monitor for unusual scanning patterns. Block source IPs engaging in service enumeration.",
    },
    "port_scan": {
        "tactic": "Reconnaissance", "tactic_id": "TA0043",
        "technique_id": "T1046", "technique_name": "Network Service Scanning",
        "description": "Adversaries may scan for services running on remote hosts by probing multiple ports systematically.",
        "action": "Deploy port-scan detection at the perimeter. Rate-limit connection attempts from single IPs.",
    },
    "brute_force": {
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "technique_id": "T1110", "technique_name": "Brute Force",
        "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown.",
        "action": "Enforce account lockout policies. Implement multi-factor authentication.",
    },
    "c2_beaconing": {
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "technique_id": "T1071", "technique_name": "Application Layer Protocol",
        "description": "Adversaries may communicate using OSI application layer protocols to avoid detection by blending with normal traffic.",
        "action": "Analyze periodic communication patterns. Block or sinkhole suspicious C2 domains.",
    },
    "dns_tunneling": {
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "technique_id": "T1572", "technique_name": "Protocol Tunneling",
        "description": "Adversaries may tunnel network communications to avoid detection by encapsulating data within DNS queries.",
        "action": "Monitor DNS query lengths and entropy. Block unusually long or high-entropy DNS queries.",
    },
    "dga_detected": {
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "technique_id": "T1568", "technique_name": "Dynamic Resolution",
        "description": "Adversaries may dynamically establish connections using Domain Generation Algorithms to evade common detection.",
        "action": "Deploy DGA detection models. Sinkhole suspected DGA domains at the DNS resolver.",
    },
}

# Full tactic grid for display
_TACTIC_ORDER = [
    {"id": "TA0043", "name": "Reconnaissance"},
    {"id": "TA0001", "name": "Initial Access"},
    {"id": "TA0002", "name": "Execution"},
    {"id": "TA0011", "name": "Command and Control"},
    {"id": "TA0010", "name": "Exfiltration"},
    {"id": "TA0040", "name": "Impact"},
]

@app.route("/api/attack/mapping")
def attack_mapping():
    """Return MITRE ATT&CK mapping based on detected alerts."""
    try:
        from features.feature_extractor import extractor as ext
        cls_counts = {}
        cls_alerts = {}
        for i, a in enumerate(ext.alerts):
            cls = a.get("classification", "unknown")
            cls_counts[cls] = cls_counts.get(cls, 0) + 1
            if cls not in cls_alerts:
                cls_alerts[cls] = []
            cls_alerts[cls].append({"index": i, "timestamp": a.get("timestamp", ""), "source_ip": a.get("source_ip", "")})

        techniques = []
        seen_tech = set()
        for cls, info in _MITRE_MAP.items():
            count = cls_counts.get(cls, 0)
            tid = info["technique_id"]
            if tid in seen_tech:
                existing = next((t for t in techniques if t["technique_id"] == tid), None)
                if existing:
                    existing["alert_count"] += count
                    existing["classifications"].append(cls)
                    existing["alerts"].extend(cls_alerts.get(cls, [])[:10])
                continue
            seen_tech.add(tid)
            techniques.append({
                "tactic": info["tactic"],
                "tactic_id": info["tactic_id"],
                "technique_id": tid,
                "technique_name": info["technique_name"],
                "description": info["description"],
                "action": info["action"],
                "alert_count": count,
                "classifications": [cls],
                "alerts": cls_alerts.get(cls, [])[:10],
            })

        return jsonify({
            "tactics": _TACTIC_ORDER,
            "techniques": techniques,
            "total_mapped_alerts": sum(t["alert_count"] for t in techniques),
        })
    except Exception as e:
        return jsonify({"tactics": _TACTIC_ORDER, "techniques": [], "error": str(e)})


# ═══════════════════════════════════════════════════════════════════
#  FEATURE: IP Reputation Lookup
# ═══════════════════════════════════════════════════════════════════
_rep_cache = {}
_rep_cache_lock = threading.Lock()
_REP_TTL = 3600  # 1 hour

@app.route("/api/reputation/<address>")
def ip_reputation(address):
    """Check IP reputation via AbuseIPDB."""
    try:
        if _is_private_ip(address):
            return jsonify({"status": "private", "message": "Private IP — reputation check skipped."})

        from dotenv import load_dotenv
        load_dotenv()
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            return jsonify({"status": "unconfigured", "message": "Add ABUSEIPDB_API_KEY to .env"})

        now = time.time()
        with _rep_cache_lock:
            if address in _rep_cache:
                entry, ts = _rep_cache[address]
                if now - ts < _REP_TTL:
                    return jsonify(entry)

        import requests
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": address, "maxAgeInDays": 90},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            result = {
                "status": "ok",
                "ip": address,
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt", None),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "usage_type": data.get("usageType", ""),
                "country": data.get("countryCode", ""),
                "is_tor": data.get("isTor", False),
                "label": "MALICIOUS" if data.get("abuseConfidenceScore", 0) > 50
                         else "SUSPICIOUS" if data.get("abuseConfidenceScore", 0) > 10
                         else "CLEAN",
            }
            with _rep_cache_lock:
                _rep_cache[address] = (result, now)
            return jsonify(result)
        else:
            return jsonify({"status": "error", "message": f"API returned {resp.status_code}"}), 502
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════
#  FEATURE: Alert Suppression Rules
# ═══════════════════════════════════════════════════════════════════
def _load_suppressions():
    settings = _load_settings()
    sups = settings.get("suppressions", [])
    now = time.time()
    active = [s for s in sups if s.get("expires", 0) == 0 or s["expires"] > now]
    return active

def _save_suppressions(sups):
    settings = _load_settings()
    settings["suppressions"] = sups
    _save_settings(settings)

@app.route("/api/suppress", methods=["GET"])
def get_suppressions():
    """Return active suppression rules."""
    try:
        active = _load_suppressions()
        return jsonify({"rules": active})
    except Exception as e:
        return jsonify({"rules": [], "error": str(e)})

@app.route("/api/suppress", methods=["POST"])
def add_suppression():
    """Add a new suppression rule."""
    try:
        data = request.get_json(force=True)
        sup_type = data.get("type", "ip")  # ip, alert_type, both
        target = data.get("target", "")
        duration = int(data.get("duration_minutes", 0))

        if not target:
            return jsonify({"status": "error", "message": "Target required"}), 400

        now = time.time()
        rule = {
            "id": f"SUP-{int(now)}",
            "type": sup_type,
            "target": target,
            "created": now,
            "created_str": time.strftime("%Y-%m-%d %H:%M:%S"),
            "expires": now + (duration * 60) if duration > 0 else 0,
            "duration_minutes": duration,
            "suppressed_count": 0,
        }

        active = _load_suppressions()
        active.append(rule)
        _save_suppressions(active)
        return jsonify({"status": "ok", "rule": rule})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/api/suppress/<rule_id>", methods=["DELETE"])
def delete_suppression(rule_id):
    """Delete a suppression rule."""
    try:
        active = _load_suppressions()
        active = [s for s in active if s["id"] != rule_id]
        _save_suppressions(active)
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


# ═══════════════════════════════════════════════════════════════════
#  FEATURE: Automated IP Blocking
# ═══════════════════════════════════════════════════════════════════
import subprocess as _subprocess
import socket as _socket

_BLOCKED_FILE = os.path.join(BASE_DIR, "logs/blocked_ips.json")
_blocked_lock = threading.Lock()

# Safety: IPs that must NEVER be blocked
_NEVER_BLOCK = {"127.0.0.1", "0.0.0.0", "::1", "localhost"}

def _get_own_ips():
    """Return set of IPs belonging to the host machine."""
    own = set()
    try:
        hostname = _socket.gethostname()
        for info in _socket.getaddrinfo(hostname, None):
            own.add(info[4][0])
    except Exception:
        pass
    own.add("127.0.0.1")
    own.add("::1")
    return own

def _load_blocked():
    with _blocked_lock:
        try:
            if os.path.exists(_BLOCKED_FILE):
                with open(_BLOCKED_FILE, "r") as f:
                    return json.load(f).get("blocked", [])
        except Exception:
            pass
    return []

def _save_blocked(blocked_list):
    with _blocked_lock:
        try:
            os.makedirs(os.path.dirname(_BLOCKED_FILE), exist_ok=True)
            with open(_BLOCKED_FILE, "w") as f:
                json.dump({"blocked": blocked_list}, f, indent=2)
        except Exception:
            pass

def _validate_ip(ip_str):
    """Return True if ip_str is a valid IPv4/IPv6 address."""
    try:
        _ipaddress.ip_address(ip_str)
        return True
    except (ValueError, TypeError):
        return False

def _os_block(ip_str):
    """Attempt OS-level block. Returns (success, method, warning)."""
    # Priority 1: ufw
    try:
        r = _subprocess.run(["which", "ufw"], capture_output=True, timeout=5)
        if r.returncode == 0:
            try:
                _subprocess.run(["ufw", "deny", "from", ip_str, "to", "any"],
                                capture_output=True, timeout=10)
                return True, "ufw", None
            except Exception as e:
                return False, "ufw", str(e)
    except Exception:
        pass

    # Priority 2: iptables
    try:
        r = _subprocess.run(["which", "iptables"], capture_output=True, timeout=5)
        if r.returncode == 0:
            try:
                _subprocess.run(["iptables", "-A", "INPUT", "-s", ip_str, "-j", "DROP"],
                                capture_output=True, timeout=10)
                return True, "iptables", None
            except Exception as e:
                return False, "iptables", str(e)
    except Exception:
        pass

    # Priority 3: Software-only
    return False, "software", "OS firewall unavailable — software block only"

def _os_unblock(ip_str):
    """Remove OS-level block."""
    try:
        _subprocess.run(["ufw", "delete", "deny", "from", ip_str, "to", "any"],
                        capture_output=True, timeout=10)
    except Exception:
        pass
    try:
        _subprocess.run(["iptables", "-D", "INPUT", "-s", ip_str, "-j", "DROP"],
                        capture_output=True, timeout=10)
    except Exception:
        pass

@app.route("/api/block", methods=["GET"])
def get_blocked():
    """Return all blocked IPs."""
    try:
        blocked = _load_blocked()
        return jsonify({"blocked": blocked})
    except Exception as e:
        return jsonify({"blocked": [], "error": str(e)})

@app.route("/api/block", methods=["POST"])
def block_ip():
    """Block an IP address."""
    try:
        data = request.get_json(force=True)
        ip = data.get("ip", "").strip()
        reason = data.get("reason", "Manual block")

        if not ip:
            return jsonify({"status": "error", "message": "IP address required"}), 400

        if not _validate_ip(ip):
            return jsonify({"status": "error", "message": "Invalid IP format"}), 400

        # Safety checks
        if ip in _NEVER_BLOCK:
            return jsonify({"status": "error", "message": "Cannot block localhost or reserved addresses"}), 400

        own_ips = _get_own_ips()
        if ip in own_ips:
            return jsonify({"status": "error", "message": "Cannot block this machine's own IP"}), 400

        # Check whitelist
        settings = _load_settings()
        whitelist = settings.get("whitelist", [])
        for wl_entry in whitelist:
            try:
                if "/" in wl_entry:
                    import ipaddress
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(wl_entry, strict=False):
                        return jsonify({"status": "error",
                                        "message": f"IP {ip} is in the whitelist ({wl_entry})"}), 400
                elif ip == wl_entry:
                    return jsonify({"status": "error",
                                    "message": f"IP {ip} is whitelisted"}), 400
            except Exception:
                pass

        # Check if already blocked
        blocked = _load_blocked()
        for entry in blocked:
            if entry["ip"] == ip:
                return jsonify({"status": "error", "message": "IP already blocked"}), 400

        # Attempt OS-level block
        os_success, method, warning = _os_block(ip)

        entry = {
            "ip": ip,
            "blocked_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "reason": reason,
            "packets_dropped": 0,
            "method": method,
            "os_blocked": os_success,
        }
        blocked.append(entry)
        _save_blocked(blocked)

        result = {"status": "ok", "entry": entry}
        if warning:
            result["warning"] = warning
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/block/<address>", methods=["DELETE"])
def unblock_ip(address):
    """Unblock an IP address."""
    try:
        blocked = _load_blocked()
        found = False
        new_blocked = []
        for entry in blocked:
            if entry["ip"] == address:
                found = True
                _os_unblock(address)
            else:
                new_blocked.append(entry)

        if not found:
            return jsonify({"status": "error", "message": "IP not in blocked list"}), 404

        _save_blocked(new_blocked)
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════
#  FEATURE: PDF Incident Report Generator
# ═══════════════════════════════════════════════════════════════════
@app.route("/api/report/pdf")
def generate_pdf_report():
    """Generate and stream a professional PDF incident report using manual canvas."""
    try:
        import io, time
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import Paragraph
        from reportlab.lib.styles import ParagraphStyle
        from features.feature_extractor import extractor as ext

        # ── Color System ──
        COLOR_BG = HexColor('#0A0F1A')
        COLOR_PRIMARY = HexColor('#00FF88')
        COLOR_ACCENT = HexColor('#BF5FFF')
        COLOR_WHITE = HexColor('#E6F1FF')
        COLOR_MUTED = HexColor('#4A7FA5')
        COLOR_CRITICAL = HexColor('#FF2D55')
        COLOR_HIGH = HexColor('#FF6B00')
        COLOR_MEDIUM = HexColor('#FFD600')
        COLOR_LOW = HexColor('#00FF88')
        COLOR_DIVIDER = HexColor('#1A2A3A')

        PAGE_WIDTH, PAGE_HEIGHT = A4

        # ── Data Fetching ──
        incident_id = request.args.get("incident_id", None)
        single_mode = incident_id is not None

        all_incidents = ext.alert_correlator.get_all_incidents()
        active_incidents = ext.alert_correlator.get_active_incidents()
        alerts = ext.alerts

        target_incidents = all_incidents
        if single_mode:
            target_incidents = [i for i in all_incidents if i.get("incident_id") == incident_id]
            if not target_incidents:
                target_incidents = all_incidents[:1] if all_incidents else []

        assets = []
        try:
            assets = ext.get_network_assets()
        except:
            pass

        mitre_techniques = []
        try:
            from dashboard.app import _MITRE_MAP
            cls_counts = {}
            for inc in all_incidents:
                cls = inc.get("attack_type", "unknown").lower().replace(" ", "_")
                cls_counts[cls] = cls_counts.get(cls, 0) + 1
            for cls, info in _MITRE_MAP.items():
                match_count = sum(v for k, v in cls_counts.items() if info["technique_name"].lower() in k or k in info["technique_name"].lower())
                if match_count > 0:
                    mitre_techniques.append({
                        "tactic": info["tactic"],
                        "technique_id": info["technique_id"],
                        "technique_name": info["technique_name"],
                        "count": match_count,
                    })
        except:
            pass

        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        report_period = "N/A"
        if target_incidents:
            first = " ".join(target_incidents[0].get("first_seen", "").split()[:2])
            report_period = f"{first} -> {now_str}"

        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        
        page_num = 1
        total_pages = 5 if not single_mode else 3

        def draw_page_bg():
            c.setFillColor(COLOR_BG)
            c.rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, fill=1, stroke=0)

        def draw_page_footer():
            c.setFillColor(HexColor('#0F1E38'))
            c.rect(0, 0, PAGE_WIDTH, 40, fill=1, stroke=0)
            
            c.setStrokeColor(COLOR_ACCENT)
            c.setLineWidth(1)
            c.line(0, 40, PAGE_WIDTH, 40)
            
            c.setFont("Courier-Bold", 10)
            c.setFillColor(COLOR_PRIMARY)
            c.drawString(40, 15, "X-NIDS")
            
            c.setFont("Courier", 10)
            c.setFillColor(COLOR_MUTED)
            text_center = f"Incident Report | {now_str}"
            sw = c.stringWidth(text_center, "Courier", 10)
            c.drawString((PAGE_WIDTH - sw) / 2.0, 15, text_center)
            
            c.setFont("Courier", 10)
            c.setFillColor(COLOR_ACCENT)
            text_right = f"Page {page_num}"
            sw = c.stringWidth(text_right, "Courier", 10)
            c.drawString(PAGE_WIDTH - 40 - sw, 15, text_right)

        def do_page_break(y):
            nonlocal page_num
            draw_page_footer()
            c.showPage()
            page_num += 1
            draw_page_bg()
            return PAGE_HEIGHT - 60

        def draw_text(x, y, text, font, size, color):
            c.setFont(font, size)
            c.setFillColor(color)
            if y < 80:
                y = do_page_break(y)
            c.drawString(x, y, text)
            return y

        def draw_para(x, y, text_str, color=COLOR_WHITE, width=400, size=10, leading=14):
            style = ParagraphStyle('custom', fontName='Courier', fontSize=size,
                                   textColor=color, leading=leading, wordWrap='LTR')
            p = Paragraph(text_str, style)
            w, h = p.wrap(width, PAGE_HEIGHT)
            if y - h < 80:
                y = do_page_break(y)
            p.drawOn(c, x, y - h)
            return y - h - 10

        def draw_section_header(y, text):
            if y < 100: y = do_page_break(y)
            c.setFillColor(HexColor('#0F1E38'))
            c.rect(40, y-10, PAGE_WIDTH - 80, 24, fill=1, stroke=0)
            c.setFillColor(COLOR_ACCENT)
            c.rect(40, y-10, 4, 24, fill=1, stroke=0)
            y = draw_text(55, y, text.upper(), "Courier-Bold", 14, COLOR_PRIMARY)
            return y - 30

        # --- Page 1: Cover ---
        draw_page_bg()
        y = PAGE_HEIGHT - 100
        
        # Header Area
        y = draw_text(40, y, "X-NIDS", "Courier-Bold", 46, COLOR_PRIMARY)
        y -= 40
        y = draw_text(40, y, "CYBERSECURITY INCIDENT REPORT", "Courier-Bold", 24, COLOR_WHITE)
        y -= 25
        y = draw_text(40, y, "Automated Threat Detection & Analysis Summary", "Courier", 14, COLOR_MUTED)
        y -= 25
        
        c.setStrokeColor(COLOR_PRIMARY)
        c.setLineWidth(2)
        c.line(40, y, PAGE_WIDTH - 40, y)
        c.setStrokeColor(HexColor('#1A2A3A'))
        c.setLineWidth(1)
        c.line(40, y - 4, PAGE_WIDTH - 40, y - 4)
        y -= 45

        # Period and Metadata
        c.setFont("Courier-Bold", 12)
        c.setFillColor(COLOR_WHITE)
        c.drawString(40, y, "Report Period:")
        c.setFont("Courier", 12)
        c.setFillColor(COLOR_ACCENT)
        c.drawString(160, y, report_period)
        y -= 25
        
        c.setFont("Courier-Bold", 12)
        c.setFillColor(COLOR_WHITE)
        c.drawString(40, y, "Generated On:")
        c.setFont("Courier", 12)
        c.setFillColor(COLOR_MUTED)
        c.drawString(160, y, now_str)
        y -= 50

        # Metrics Section
        critical_count = len([i for i in all_incidents if i.get('max_risk', 0) >= 70])
        metrics_labels = ["Total Incidents", "Critical Alerts", "Affected Hosts", "Confidence Score (%)"]
        metrics_vals = [
            str(len(all_incidents)),
            str(critical_count),
            str(len(set(i.get('source_ip', '') for i in all_incidents))),
            f"{max((i.get('max_risk', 0) for i in all_incidents), default=0)}"
        ]
        
        box_w = 115
        box_h = 75
        box_gap = (PAGE_WIDTH - 80 - (box_w * 4)) / 3.0
        start_x = 40
        
        for i in range(4):
            bx = start_x + (box_w + box_gap) * i
            
            # Draw Box Background
            c.setFillColor(HexColor('#0F1E38'))
            c.setStrokeColor(HexColor('#1A2A3A'))
            c.setLineWidth(2)
            c.rect(bx, y - box_h, box_w, box_h, fill=1, stroke=1)
            
            # Accent Line Top
            c.setFillColor(COLOR_PRIMARY if i != 1 else COLOR_CRITICAL)
            c.rect(bx, y - box_h + box_h - 4, box_w, 4, fill=1, stroke=0)
            
            # Value
            c.setFont("Courier-Bold", 26)
            value_color = COLOR_CRITICAL if (i == 1 and critical_count > 0) else COLOR_WHITE
            c.setFillColor(value_color)
            c.drawCentredString(bx + box_w/2.0, y - 35, metrics_vals[i])
            
            # Label
            c.setFont("Courier", 10)
            c.setFillColor(COLOR_MUTED)
            c.drawCentredString(bx + box_w/2.0, y - 55, metrics_labels[i])
            
        y -= (box_h + 50)

        # Executive Summary moved to Page 1
        y = draw_section_header(y, "Executive Summary")
        
        high_risk_incidents = [i for i in all_incidents if i.get('max_risk', 0) > 70]
        exec_text = (
            f"During the current monitoring period, X-NIDS active threat hunting engines detected a total of {len(target_incidents)} security incidents across the network. "
            f"Of these events, {len(active_incidents)} incidents are currently tagged as active and ongoing. "
        )
        if high_risk_incidents:
            exec_text += f"A critical breach threshold was reached, as {len(high_risk_incidents)} high-risk incidents require " \
                         f"immediate operator intervention. Indicators of compromise (IoCs) suggest a potential severity that warrants urgent investigation."
        else:
            exec_text += "No critical incidents were detected exceeding the high-risk threshold. Routine monitoring and maintenance are advised."
            
        y = draw_para(40, y, exec_text, width=PAGE_WIDTH - 80, size=11, leading=16)
        y -= 40
        
        # End of Cover Page
        y = do_page_break(y)

        # --- Page 2+: Incident Blocks ---
        if not single_mode:
            y = do_page_break(y)
        y = draw_section_header(y, "Incident Details")
        
        for inc in target_incidents:
            if y < 150: y = do_page_break(y)
            inc_id = inc.get("incident_id", "N/A")
            active = inc.get("active", False)
            risk = inc.get("max_risk", 0)
            type_str = inc.get("attack_type", "Unknown")
            src_ip = inc.get("source_ip", "Unknown")
            duration = inc.get("duration_sec", 0)
            
            c.setStrokeColor(COLOR_ACCENT)
            c.setLineWidth(1)
            c.setFillColor(HexColor('#0F1E38'))
            h = 80
            c.rect(40, y - h, PAGE_WIDTH - 80, h, fill=1, stroke=1)
            
            # ID
            c.setFont("Courier-Bold", 13)
            c.setFillColor(COLOR_ACCENT)
            c.drawString(50, y - 20, inc_id)
            
            status_text = "ACTIVE" if active else "RESOLVED"
            bg_col = COLOR_CRITICAL if active else HexColor('#1A3A2A')
            txt_col = COLOR_WHITE if active else COLOR_PRIMARY
            
            c.setFillColor(bg_col)
            c.rect(180, y - 22, 60, 12, fill=1, stroke=0)
            c.setFont("Courier-Bold", 9)
            c.setFillColor(txt_col)
            c.drawString(185, y - 19, status_text)
            
            y_inner = y - 40
            c.setFont("Courier", 9)
            c.setFillColor(COLOR_MUTED)
            c.drawString(50, y_inner, "TYPE:")
            c.setFillColor(COLOR_WHITE)
            c.setFont("Courier", 11)
            c.drawString(90, y_inner, type_str)
            
            c.setFont("Courier", 9)
            c.setFillColor(COLOR_MUTED)
            c.drawString(300, y_inner, "IP:")
            c.setFillColor(COLOR_PRIMARY)
            c.setFont("Courier", 11)
            c.drawString(330, y_inner, src_ip)
            
            y_inner -= 15
            c.setFont("Courier", 9)
            c.setFillColor(COLOR_MUTED)
            c.drawString(50, y_inner, "DURATION:")
            c.setFillColor(COLOR_WHITE)
            c.setFont("Courier", 11)
            c.drawString(110, y_inner, f"{duration}s")
            
            c.setFont("Courier", 9)
            c.setFillColor(COLOR_MUTED)
            c.drawString(300, y_inner, "MAX RISK:")
            c.setFillColor(COLOR_CRITICAL if risk > 70 else COLOR_MEDIUM)
            c.setFont("Courier-Bold", 11)
            c.drawString(365, y_inner, str(risk))
            
            y -= (h + 15)

        # --- Optional Sections for Full Report ---
        if not single_mode:
            y = do_page_break(y)
            y = draw_section_header(y, "Network Assets At Risk")
            if assets:
                y_inner = y - 10
                c.setFillColor(HexColor('#0F1E38'))
                c.rect(40, y_inner-12, PAGE_WIDTH-80, 18, fill=1, stroke=0)
                c.setFont("Courier-Bold", 10)
                c.setFillColor(COLOR_PRIMARY)
                c.drawString(45, y_inner, "IP ADDRESS")
                c.drawString(140, y_inner, "TYPE")
                c.drawString(240, y_inner, "PACKETS")
                c.drawString(320, y_inner, "LAST SEEN")
                y = y_inner - 20
                for idx, a in enumerate(assets[:20]):
                    if y < 100: y = do_page_break(y)
                    bg = HexColor('#0D1A2E') if idx % 2 else HexColor('#0A1628')
                    c.setFillColor(bg)
                    c.rect(40, y-8, PAGE_WIDTH-80, 16, fill=1, stroke=0)
                    
                    c.setFont("Courier", 10)
                    c.setFillColor(COLOR_WHITE)
                    c.drawString(45, y-2, a.get("ip", ""))
                    c.drawString(140, y-2, a.get("network_type", "")[:12])
                    c.drawString(240, y-2, str(a.get("packet_count", 0)))
                    c.drawString(320, y-2, str(a.get("last_seen", ""))[-8:])
                    y -= 16
            else:
                y = draw_text(40, y, "No assets discovered.", "Courier", 10, COLOR_WHITE)

            y = do_page_break(y)
            y = draw_section_header(y, "MITRE ATT&CK Summary")
            if mitre_techniques:
                y_inner = y - 10
                c.setFillColor(HexColor('#0F1E38'))
                c.rect(40, y_inner-12, PAGE_WIDTH-80, 18, fill=1, stroke=0)
                c.setFont("Courier-Bold", 10)
                c.setFillColor(COLOR_PRIMARY)
                c.drawString(45, y_inner, "TECHNIQUE ID")
                c.drawString(140, y_inner, "TACTIC")
                c.drawString(340, y_inner, "DETECTED")
                y = y_inner - 20
                for idx, t in enumerate(mitre_techniques):
                    if y < 100: y = do_page_break(y)
                    bg = HexColor('#0D1A2E') if idx % 2 else HexColor('#0A1628')
                    c.setFillColor(bg)
                    c.rect(40, y-8, PAGE_WIDTH-80, 16, fill=1, stroke=0)
                    
                    c.setFont("Courier-Bold", 10)
                    c.setFillColor(COLOR_ACCENT)
                    c.drawString(45, y-2, t.get("technique_id", ""))
                    c.setFillColor(COLOR_PRIMARY)
                    c.drawString(140, y-2, t.get("tactic", "")[:20])
                    c.setFillColor(COLOR_WHITE)
                    c.drawString(340, y-2, str(t.get("count", 0)))
                    y -= 16
            else:
                y = draw_text(40, y, "No MITRE techniques mapped.", "Courier", 10, COLOR_WHITE)

            y = do_page_break(y)
            y = draw_section_header(y, "Recommendations")
            recs = [
                "Review firewall configurations and apply block rules to active attacker IPs.",
                "Ensure robust authentication policies are active across all endpoints.",
                "Verify no critical service ports remain publicly exposed."
            ]
            for r in recs:
                if y < 100: y = do_page_break(y)
                c.setFont("Courier-Bold", 12)
                c.setFillColor(COLOR_PRIMARY)
                c.drawString(40, y, "▸")
                y = draw_para(55, y + 10, r, width=PAGE_WIDTH - 100)
                y -= 10

        draw_page_footer()
        c.save()
        buf.seek(0)
        
        filename = f"XNIDS_{incident_id}.pdf" if single_mode and incident_id else f"XNIDS_Incident_Report.pdf"

        return Response(
            buf.getvalue(),
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": "application/pdf"
            }
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


def run_dashboard():
    """Called from main.py in a daemon thread."""
    print("[*] Dashboard live → http://127.0.0.1:5000")
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(host="127.0.0.1", port=5000, use_reloader=False, threaded=True)


if __name__ == "__main__":
    run_dashboard()
