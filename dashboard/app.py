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
    "pps_threshold": 100,
    "time_window": 5,
    "baseline_duration": 60,
    "polling_interval": 1,
    "max_data_points": 60,
    "burst_tolerance": 3,
    "port_scan_threshold": 15,
    "risk_alert_threshold": 50,
    "sigma_mult": 2.0,
    "browser_notifications": True,
    "email_alerts": False,
    "telegram_alerts": False,
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
        except Exception:
            pass

        return jsonify({"status": "ok", "settings": current})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


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


def run_dashboard():
    """Called from main.py in a daemon thread."""
    print("[*] Dashboard live → http://127.0.0.1:5000")
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(host="127.0.0.1", port=5000, use_reloader=False, threaded=True)


if __name__ == "__main__":
    run_dashboard()
