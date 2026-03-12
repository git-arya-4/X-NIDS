# ==============================================================================
# intelligence/attack_simulator.py — Attack Simulation Mode
# ==============================================================================

"""
Generates synthetic attack traffic for testing/demonstration without real attacks.
Simulations: port scan, packet flood, brute force attempts.
Injects simulated data directly into the feature extractor metrics.
"""

import time
import random
import json
import os
import threading

LOGS_DIR = "/home/cybersec/pro/X-NIDS/logs"
METRICS_FILE = os.path.join(LOGS_DIR, "metrics.json")
ALERTS_FILE = os.path.join(LOGS_DIR, "alerts.json")


class AttackSimulator:
    """Generates synthetic attack data for demo/testing."""

    def __init__(self):
        self.running = False
        self.sim_thread = None
        self.sim_type = None
        self.sim_log = []

    def start_simulation(self, sim_type="port_scan", duration=30):
        """Start a simulation in a background thread."""
        if self.running:
            return {"status": "error", "message": "Simulation already running"}

        self.sim_type = sim_type
        self.running = True
        self.sim_thread = threading.Thread(
            target=self._run_simulation,
            args=(sim_type, duration),
            daemon=True,
        )
        self.sim_thread.start()
        self.sim_log.append({
            "type": sim_type,
            "started": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration": duration,
            "status": "running",
        })
        return {"status": "started", "type": sim_type, "duration": duration}

    def stop_simulation(self):
        """Stop the running simulation."""
        self.running = False
        return {"status": "stopped"}

    def get_status(self):
        """Get current simulation status."""
        return {
            "running": self.running,
            "type": self.sim_type,
            "log": self.sim_log[-10:],
        }

    def _run_simulation(self, sim_type, duration):
        """Run the simulation loop."""
        start = time.time()
        sim_funcs = {
            "port_scan": self._sim_port_scan,
            "packet_flood": self._sim_packet_flood,
            "brute_force": self._sim_brute_force,
        }
        func = sim_funcs.get(sim_type, self._sim_port_scan)

        while self.running and (time.time() - start) < duration:
            func()
            time.sleep(1)

        self.running = False
        if self.sim_log:
            self.sim_log[-1]["status"] = "completed"

    def _inject_alert(self, alert):
        """Inject a simulated alert into the alerts file."""
        try:
            alerts = []
            if os.path.exists(ALERTS_FILE):
                with open(ALERTS_FILE, "r") as f:
                    alerts = json.load(f)
            alerts.append(alert)
            if len(alerts) > 200:
                alerts = alerts[-200:]
            os.makedirs(LOGS_DIR, exist_ok=True)
            with open(ALERTS_FILE, "w") as f:
                json.dump(alerts, f, indent=2)
        except Exception:
            pass

    def _sim_port_scan(self):
        """Simulate a port scan attack."""
        attacker_ip = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        ports_scanned = random.randint(20, 80)
        risk = random.randint(55, 90)

        alert = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": attacker_ip,
            "attack_type": "Port Scan",
            "severity": "High",
            "classification": "port_scan",
            "confidence": random.randint(70, 95),
            "protocol": "TCP",
            "packet_rate": round(random.uniform(50, 200), 2),
            "unique_ports": ports_scanned,
            "risk_score": risk,
            "risk_factors": [
                f"IP {attacker_ip} contacted {ports_scanned} unique ports",
                f"Scan targeted service ports: 22, 80, 443, 3306, 8080",
            ],
            "protocol_distribution": {"TCP": 85.0, "UDP": 10.0, "ICMP": 5.0},
            "traffic_summary": {
                "total_packets": random.randint(200, 1000),
                "packet_rate": round(random.uniform(50, 200), 2),
                "unique_ports": ports_scanned,
                "total_bytes_human": f"{random.randint(10, 100)} KB",
                "duration": 5.0,
                "unique_src_ips": 1,
            },
            "explanation": [
                f"[SIMULATED] IP {attacker_ip} probed {ports_scanned} unique ports.",
                "Sequential port probing pattern detected.",
                "Behaviour consistent with reconnaissance activity.",
            ],
            "recommended_action": f"Block IP {attacker_ip} at the perimeter firewall.",
            "response_simulated": f"IP {attacker_ip} added to blocklist (simulated).",
            "network_type": "Internal",
            "country": "LAN",
            "device_profile": None,
            "timeline": [],
            "simulated": True,
        }
        self._inject_alert(alert)

    def _sim_packet_flood(self):
        """Simulate a packet flood / DoS attack."""
        attacker_ip = f"203.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        pps = random.randint(500, 5000)
        risk = random.randint(75, 100)

        alert = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": attacker_ip,
            "attack_type": "Packet Flood / DoS",
            "severity": "Critical" if risk >= 80 else "High",
            "classification": "packet_flood",
            "confidence": random.randint(80, 98),
            "protocol": "TCP",
            "packet_rate": float(pps),
            "unique_ports": random.randint(1, 5),
            "risk_score": risk,
            "risk_factors": [
                f"Packet rate {pps} pps exceeds threshold by {pps//100}x",
                f"IP {attacker_ip} generated 95% of window traffic",
            ],
            "protocol_distribution": {"TCP": 95.0, "UDP": 3.0, "ICMP": 2.0},
            "traffic_summary": {
                "total_packets": pps * 5,
                "packet_rate": float(pps),
                "unique_ports": 2,
                "total_bytes_human": f"{(pps * 5 * 64) // 1024} KB",
                "duration": 5.0,
                "unique_src_ips": 1,
            },
            "explanation": [
                f"[SIMULATED] Packet rate {pps} pps far exceeds baseline.",
                f"Volumetric flood from {attacker_ip} detected.",
                "Pattern consistent with DoS/DDoS attack.",
            ],
            "recommended_action": f"Block or rate-limit IP {attacker_ip}.",
            "response_simulated": f"Firewall rule added: DROP all traffic from {attacker_ip}.",
            "network_type": "External",
            "country": "CN",
            "device_profile": None,
            "timeline": [],
            "simulated": True,
        }
        self._inject_alert(alert)

    def _sim_brute_force(self):
        """Simulate a brute force attack."""
        attacker_ip = f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        target_port = random.choice([22, 3389, 21, 3306])
        services = {22: "SSH", 3389: "RDP", 21: "FTP", 3306: "MySQL"}
        attempts = random.randint(50, 200)
        risk = random.randint(60, 90)

        alert = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": attacker_ip,
            "attack_type": "Brute Force Behaviour",
            "severity": "High",
            "classification": "brute_force",
            "confidence": random.randint(65, 92),
            "protocol": "TCP",
            "packet_rate": round(random.uniform(30, 100), 2),
            "unique_ports": 1,
            "risk_score": risk,
            "risk_factors": [
                f"IP {attacker_ip} sent {attempts} packets to port {target_port} ({services[target_port]})",
                "Low port diversity with high repetition indicates credential stuffing",
            ],
            "protocol_distribution": {"TCP": 98.0, "UDP": 1.0, "ICMP": 1.0},
            "traffic_summary": {
                "total_packets": attempts,
                "packet_rate": round(attempts / 5.0, 2),
                "unique_ports": 1,
                "total_bytes_human": f"{(attempts * 128) // 1024} KB",
                "duration": 5.0,
                "unique_src_ips": 1,
            },
            "explanation": [
                f"[SIMULATED] IP {attacker_ip} sent {attempts} packets to port {target_port} ({services[target_port]}).",
                "Authentication attempt pattern detected.",
                "Low port diversity with high repetition indicates credential brute force.",
            ],
            "recommended_action": f"Block IP {attacker_ip}. Enable account lockout on {services[target_port]}.",
            "response_simulated": f"IP {attacker_ip} temporarily blocked for 15 min (simulated).",
            "network_type": "External",
            "country": "EU",
            "device_profile": None,
            "timeline": [],
            "simulated": True,
        }
        self._inject_alert(alert)


# Global singleton
simulator = AttackSimulator()
