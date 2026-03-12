# ==============================================================================
# intelligence/beaconing_detector.py — C2 Beaconing Detection
# ==============================================================================

"""
Detects periodic communication patterns typical of malware C2 beaconing:
  - Repeated small connections to the same external IP
  - Regular time intervals between connections
  - Low data volume but frequent contact
"""

import time
import numpy as np
from collections import defaultdict


# ── Tuning ──
MIN_CONNECTIONS = 5         # Minimum connections to an IP before analysis
MAX_JITTER_RATIO = 0.35     # Coefficient of variation (σ/μ) threshold for regularity
MAX_AVG_BYTES = 2000        # Average bytes per connection — high-volume = likely legitimate
BEACON_SCORE_THRESHOLD = 60 # Score 0–100, above this → flagged


class BeaconingDetector:
    """
    Tracks connections to external IPs and scores them for beaconing behaviour.
    """

    def __init__(self):
        # dst_ip → [{timestamp, bytes, src_ip}]
        self.connection_log = defaultdict(list)
        self.flagged_beacons = []   # persistent list of flagged beacon events
        self.total_checked = 0

    def record_connection(self, src_ip, dst_ip, byte_count, is_external=True):
        """Record an outbound connection event."""
        if not is_external:
            return
        self.connection_log[dst_ip].append({
            "timestamp": time.time(),
            "bytes": byte_count,
            "src_ip": src_ip,
        })
        # Keep last 200 entries per IP
        if len(self.connection_log[dst_ip]) > 200:
            self.connection_log[dst_ip] = self.connection_log[dst_ip][-200:]

    def analyze(self, timestamp_str):
        """
        Analyse connection logs for beaconing.
        Returns list of beacon events detected this window.
        """
        new_beacons = []
        self.total_checked = 0

        for dst_ip, conns in self.connection_log.items():
            if len(conns) < MIN_CONNECTIONS:
                continue

            self.total_checked += 1

            # Calculate inter-arrival times
            timestamps = [c["timestamp"] for c in conns]
            timestamps.sort()
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

            if not intervals:
                continue

            avg_interval = np.mean(intervals)
            std_interval = np.std(intervals)

            # Coefficient of variation — low = regular = suspicious
            if avg_interval > 0:
                jitter_ratio = std_interval / avg_interval
            else:
                jitter_ratio = 1.0

            # Average bytes per connection
            avg_bytes = np.mean([c["bytes"] for c in conns])

            # Build beacon score (0–100)
            score = 0

            # Regular intervals (low jitter)
            if jitter_ratio < MAX_JITTER_RATIO:
                score += 40
            elif jitter_ratio < 0.5:
                score += 25

            # Low data volume
            if avg_bytes < MAX_AVG_BYTES:
                score += 20
            elif avg_bytes < 5000:
                score += 10

            # High connection count
            if len(conns) >= 20:
                score += 20
            elif len(conns) >= 10:
                score += 15
            elif len(conns) >= MIN_CONNECTIONS:
                score += 10

            # Bonus for very regular intervals
            if jitter_ratio < 0.15 and len(conns) >= 8:
                score += 20

            score = min(score, 100)

            if score >= BEACON_SCORE_THRESHOLD:
                src_ips = list(set(c["src_ip"] for c in conns))
                beacon = {
                    "dst_ip": dst_ip,
                    "src_ips": src_ips[:5],
                    "connections": len(conns),
                    "avg_interval": round(avg_interval, 2),
                    "jitter_ratio": round(jitter_ratio, 3),
                    "avg_bytes": round(avg_bytes, 0),
                    "beacon_score": score,
                    "timestamp": timestamp_str,
                    "description": self._describe(dst_ip, len(conns), avg_interval, jitter_ratio, avg_bytes),
                }
                new_beacons.append(beacon)

        self.flagged_beacons.extend(new_beacons)
        if len(self.flagged_beacons) > 100:
            self.flagged_beacons = self.flagged_beacons[-100:]

        return new_beacons

    @staticmethod
    def _describe(ip, count, interval, jitter, avg_bytes):
        """Human-readable description of the beacon."""
        parts = [f"{count} connections to {ip}"]
        if interval < 60:
            parts.append(f"every ~{interval:.0f}s")
        else:
            parts.append(f"every ~{interval/60:.1f}min")
        parts.append(f"jitter {jitter:.1%}")
        parts.append(f"avg {avg_bytes:.0f} bytes/conn")
        return " · ".join(parts)

    def get_summary(self):
        """Return summary for the API endpoint."""
        return {
            "total_tracked_ips": len(self.connection_log),
            "total_checked": self.total_checked,
            "flagged_beacons": list(reversed(self.flagged_beacons[-30:])),
            "total_flagged": len(self.flagged_beacons),
        }
