import json
import os
import numpy as np
import config
from sklearn.ensemble import IsolationForest

BASELINE_FILE = "/home/cybersec/pro/X-NIDS/baseline/baseline.json"


class AnomalyDetector:
    """
    Dual-layer anomaly detector:
      1. Adaptive statistical thresholds derived from the baseline.
      2. Isolation Forest ML model for multi-feature outlier scoring.
    """

    def __init__(self, baseline_file=BASELINE_FILE):
        # ML model
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.is_trained = False

        # Adaptive thresholds (populated from baseline)
        self.pps_threshold = config.PACKET_RATE_THRESHOLD  # fallback
        self.ports_threshold = 30                           # fallback
        self.conns_threshold = 200                          # fallback

        self.baseline_mean_pps = None
        self.baseline_std_pps = None

        self._load_baseline(baseline_file)

    # ------------------------------------------------------------------
    #  Load baseline and train ML model
    # ------------------------------------------------------------------
    def _load_baseline(self, baseline_file):
        if not os.path.exists(baseline_file):
            print("[-] ML warning: Baseline not found. Run --train first.")
            return

        try:
            with open(baseline_file, "r") as f:
                data = json.load(f)

            # ── Adaptive thresholds ──
            mean_pps = data.get("avg_packets_per_sec", 10)
            std_pps = data.get("std_packets_per_sec", 5)
            mean_ports = data.get("avg_unique_ports_per_window", 5)
            std_ports = data.get("std_unique_ports_per_window", 3)
            mean_conns = data.get("avg_connections_per_ip", 20)
            std_conns = data.get("std_connections_per_ip", 10)

            sigma = getattr(config, "SIGMA_MULT", 2.0)

            self.pps_threshold = mean_pps + sigma * max(std_pps, 1)
            self.ports_threshold = mean_ports + sigma * max(std_ports, 1)
            self.conns_threshold = mean_conns + sigma * max(std_conns, 1)

            self.baseline_mean_pps = mean_pps
            self.baseline_std_pps = std_pps

            print(f"[+] Adaptive thresholds loaded:")
            print(f"    PPS threshold   : {self.pps_threshold:.2f}")
            print(f"    Ports threshold : {self.ports_threshold:.2f}")
            print(f"    Conns threshold : {self.conns_threshold:.2f}")

            # ── ML model training ──
            history_packets = data.get("history_packet_counts", [])
            history_ports = data.get("history_unique_ports", [])

            if len(history_packets) < 5:
                np.random.seed(42)
                packets = np.random.normal(
                    loc=mean_pps * config.TIME_WINDOW,
                    scale=max(5, std_pps * config.TIME_WINDOW),
                    size=100,
                )
                ports = np.random.normal(
                    loc=mean_ports, scale=max(1, std_ports), size=100
                )
                history_packets = np.clip(packets, 0, None).tolist()
                history_ports = np.clip(ports, 0, None).tolist()

            pps_arr = [p / config.TIME_WINDOW for p in history_packets]
            X_train = np.column_stack((pps_arr, history_ports))
            self.model.fit(X_train)
            self.is_trained = True
            print("[+] ML Anomaly Detection model trained.")

        except Exception as e:
            print(f"[-] Error loading baseline: {e}")

    # ------------------------------------------------------------------
    #  Evaluate a single window
    # ------------------------------------------------------------------
    def evaluate(self, packet_rate, unique_ports):
        """
        Returns:
             1  → normal
            -1  → anomalous (according to ML model)
        """
        if not self.is_trained:
            return 1
        X = np.array([[packet_rate, unique_ports]])
        return int(self.model.predict(X)[0])

    def score(self, packet_rate, unique_ports):
        """
        Returns the raw anomaly score from the model (lower = more anomalous).
        Useful for the risk-scoring pipeline.
        """
        if not self.is_trained:
            return 0.0
        X = np.array([[packet_rate, unique_ports]])
        return float(self.model.decision_function(X)[0])

    def is_pps_anomaly(self, packet_rate):
        """Adaptive PPS check against baseline-derived threshold."""
        return packet_rate > self.pps_threshold

    def is_ports_anomaly(self, unique_ports):
        """Adaptive port count check."""
        return unique_ports > self.ports_threshold
