# ==============================================================================
# intelligence/alert_correlator.py — Alert Correlation Engine
# ==============================================================================

"""
Groups repeated alerts from the same source IP into correlated incidents,
reducing alert fatigue by summarising attack campaigns.
"""

import time
from collections import defaultdict


class AlertCorrelator:
    """
    Correlates alerts by (source_ip, classification) into campaigns.
    """

    def __init__(self, merge_window=300):
        """
        Args:
            merge_window: seconds within which alerts are correlated (default 5 min).
        """
        self.merge_window = merge_window
        # (src_ip, classification) → incident dict
        self.incidents = {}
        self.incident_history = []  # completed incidents

    def ingest(self, alert):
        """
        Process a new alert and correlate it with existing incidents.
        Returns the incident dict if updated/created.
        """
        ip = alert.get("source_ip", "")
        cls = alert.get("classification", alert.get("attack_type", "unknown"))
        key = (ip, cls)
        now = time.time()

        if key in self.incidents:
            inc = self.incidents[key]
            inc["count"] += 1
            inc["last_seen"] = alert.get("timestamp", "")
            inc["last_epoch"] = now
            inc["duration_sec"] = round(now - inc["start_epoch"], 1)
            inc["max_risk"] = max(inc["max_risk"], alert.get("risk_score", 0))
            inc["alerts"].append(alert)
            if len(inc["alerts"]) > 50:
                inc["alerts"] = inc["alerts"][-50:]
            return inc
        else:
            # Check if there's an old incident (beyond merge window) — archive it
            if key in self.incidents:
                old = self.incidents.pop(key)
                self.incident_history.append(old)

            inc = {
                "incident_id": f"INC-{int(now)}",
                "source_ip": ip,
                "classification": cls,
                "attack_type": alert.get("attack_type", cls),
                "count": 1,
                "first_seen": alert.get("timestamp", ""),
                "last_seen": alert.get("timestamp", ""),
                "start_epoch": now,
                "last_epoch": now,
                "duration_sec": 0,
                "max_risk": alert.get("risk_score", 0),
                "severity": alert.get("severity", "Medium"),
                "alerts": [alert],
            }
            self.incidents[key] = inc
            return inc

    def cleanup(self):
        """Archive incidents that have been inactive beyond the merge window."""
        now = time.time()
        expired = []
        for key, inc in self.incidents.items():
            if now - inc["last_epoch"] > self.merge_window:
                expired.append(key)
        for key in expired:
            self.incident_history.append(self.incidents.pop(key))
        if len(self.incident_history) > 200:
            self.incident_history = self.incident_history[-200:]

    def get_active_incidents(self):
        """Return active correlated incidents sorted by risk."""
        self.cleanup()
        incidents = list(self.incidents.values())
        incidents.sort(key=lambda x: x["max_risk"], reverse=True)
        # Build campaign summaries
        result = []
        for inc in incidents:
            summary = {
                "incident_id": inc["incident_id"],
                "source_ip": inc["source_ip"],
                "attack_type": inc["attack_type"],
                "classification": inc["classification"],
                "severity": inc["severity"],
                "count": inc["count"],
                "first_seen": inc["first_seen"],
                "last_seen": inc["last_seen"],
                "duration_sec": inc["duration_sec"],
                "max_risk": inc["max_risk"],
                "description": self._describe(inc),
            }
            result.append(summary)
        return result

    @staticmethod
    def _describe(inc):
        """Generate a human-readable campaign description."""
        attack = inc["attack_type"]
        ip = inc["source_ip"]
        count = inc["count"]
        dur = inc["duration_sec"]

        if dur > 60:
            dur_str = f"{dur/60:.1f} minutes"
        else:
            dur_str = f"{dur:.0f} seconds"

        return f"{attack} Campaign Detected — Source: {ip}, Attempts: {count}, Duration: {dur_str}"

    def get_all_incidents(self):
        """Return both active + historical incidents."""
        self.cleanup()
        all_inc = list(self.incidents.values()) + self.incident_history
        all_inc.sort(key=lambda x: x["last_epoch"], reverse=True)
        result = []
        for inc in all_inc[:50]:
            result.append({
                "incident_id": inc["incident_id"],
                "source_ip": inc["source_ip"],
                "attack_type": inc["attack_type"],
                "classification": inc["classification"],
                "severity": inc["severity"],
                "count": inc["count"],
                "first_seen": inc["first_seen"],
                "last_seen": inc["last_seen"],
                "duration_sec": inc["duration_sec"],
                "max_risk": inc["max_risk"],
                "description": self._describe(inc),
                "active": inc["incident_id"] in {v["incident_id"] for v in self.incidents.values()},
                "status": inc.get("status"),
                "resolve_reason": inc.get("resolve_reason"),
            })
        return result
