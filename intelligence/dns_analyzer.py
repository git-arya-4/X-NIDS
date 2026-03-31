# ==============================================================================
# intelligence/dns_analyzer.py — Suspicious DNS Detection
# ==============================================================================

"""
Analyses DNS queries in real-time to flag:
  1. Excessive DNS queries from a single source
  2. Unusual TLDs (.xyz, .top, .tk, .buzz, etc.)
  3. Algorithmically generated domains (DGA detection via entropy + consonant ratio)
"""

import math
import time
from collections import defaultdict


# Suspicious TLDs commonly used by malware / phishing
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "icu",
    "work", "info", "site", "online", "wang", "stream", "download",
    "bid", "racing", "review", "date", "loan", "trade", "win",
    "party", "science", "cricket", "accountant", "faith", "zip",
    "mov", "py", "rs", "su", "cc", "ws", "pw", "cn", "ru",
}

# ---------------------------------------------------------------------------
# Known-legitimate domain whitelists (two levels)
# ---------------------------------------------------------------------------

# Level 1 — Exact subdomain match: skip these domains entirely
KNOWN_SAFE_DOMAINS = {
    # Intercom
    "nexus-websocket-a.intercom.io",
    "nexus-websocket-b.intercom.io",
    "nexus-websocket.intercom.io",
    "api.intercom.io",
    "api-iam.intercom.io",
    # Spotify
    "gae2-spclient.spotify.com",
    "spclient.wg.spotify.com",
    "apresolve.spotify.com",
    "api.spotify.com",
    # Notion
    "msgstore-001.www.notion.so",
    "msgstore-002.www.notion.so",
    "www.notion.so",
    "api.notion.so",
    # Google
    "8.8.8.8",
    "dns.google",
    "googleapis.com",
    # Cloudflare
    "1.1.1.1",
    "cloudflare.com",
    "cloudflareinsights.com",
    # Microsoft / Windows Update
    "windowsupdate.com",
    "update.microsoft.com",
    "dl.delivery.mp.microsoft.com",
    # Apple
    "apple.com",
    "icloud.com",
    "captive.apple.com",
    # Common CDNs
    "fastly.net",
    "akamaiedge.net",
    "akamaized.net",
    "cloudfront.net",
}

# Level 2 — Root domain suffix match: skip any subdomain of these roots
KNOWN_SAFE_ROOTS = [
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "amazon.com",
    "amazonaws.com",
    "spotify.com",
    "intercom.io",
    "notion.so",
    "github.com",
    "githubusercontent.com",
    "microsoft.com",
    "windows.com",
    "apple.com",
    "icloud.com",
    "cloudflare.com",
    "fastly.net",
    "akamai.net",
    "akamaiedge.net",
    "cloudfront.net",
    "slack.com",
    "discord.com",
    "zoom.us",
    "dropbox.com",
    "reddit.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "netflix.com",
    "twitch.tv",
    "ubuntu.com",
    "debian.org",
    "npmjs.com",
    "pypi.org",
]

# Threshold tuning
DGA_ENTROPY_THRESHOLD = 3.5       # Shannon entropy above this → suspicious
DGA_CONSONANT_RATIO = 0.65        # Consonant ratio above this → suspicious
EXCESSIVE_QUERY_THRESHOLD = 100   # Queries per window from single src → suspicious
VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


def _shannon_entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _consonant_ratio(domain):
    """Fraction of alphabetic characters that are consonants."""
    alpha = [c for c in domain.lower() if c.isalpha()]
    if not alpha:
        return 0.0
    return sum(1 for c in alpha if c in CONSONANTS) / len(alpha)


def is_whitelisted(domain):
    """Return True if *domain* is known-legitimate (skip all detection)."""
    # Level 1: exact match
    if domain in KNOWN_SAFE_DOMAINS:
        return True
    # Level 2: root domain match
    for root in KNOWN_SAFE_ROOTS:
        if domain == root or domain.endswith('.' + root):
            return True
    return False


def _looks_like_dga(domain):
    """
    Heuristic DGA detection:
      - high entropy (random-looking)
      - high consonant ratio (unpronounceable)
      - numeric mixed in with letters
    """
    # Strip TLD for analysis
    parts = domain.split(".")
    label = parts[0] if parts else domain

    if len(label) < 6:
        return False, 0.0

    entropy = _shannon_entropy(label)
    cons_ratio = _consonant_ratio(label)
    has_digits = any(c.isdigit() for c in label)
    has_alpha = any(c.isalpha() for c in label)

    score = 0.0
    if entropy >= DGA_ENTROPY_THRESHOLD:
        score += 0.4
    if cons_ratio >= DGA_CONSONANT_RATIO:
        score += 0.3
    if has_digits and has_alpha and len(label) > 10:
        score += 0.2
    if len(label) > 15:
        score += 0.1

    return score >= 0.5, round(score, 2)


class DNSAnalyzer:
    """Tracks DNS queries per window and flags suspicious domains."""

    def __init__(self):
        # src_ip → [domain, ...]
        self.queries_per_ip = defaultdict(list)
        # domain → count
        self.domain_counts = defaultdict(int)
        # Persistent suspicious list
        self.suspicious_domains = []         # [{domain, src_ip, reason, timestamp, dga_score, tld}]
        self.total_dns_queries = 0

    def process_dns(self, src_ip, dst_ip, query_name, timestamp_str):
        """Called from the feature extractor when a DNS query is detected."""
        if not query_name:
            return

        self.total_dns_queries += 1
        self.queries_per_ip[src_ip].append(query_name)
        self.domain_counts[query_name] += 1

    def analyze_window(self, timestamp_str):
        """
        Analyse accumulated DNS data for the current window.
        Returns list of new suspicious domain events.
        """
        new_suspicious = []

        # 1. Excessive queries from single source
        #    Only count queries to non-whitelisted domains.
        for ip, domains in self.queries_per_ip.items():
            non_safe_count = sum(1 for d in domains if not is_whitelisted(d))
            if non_safe_count >= EXCESSIVE_QUERY_THRESHOLD:
                entry = {
                    "domain": f"{non_safe_count} queries",
                    "src_ip": ip,
                    "reason": f"Excessive DNS: {non_safe_count} non-whitelisted queries in one window",
                    "timestamp": timestamp_str,
                    "dga_score": 0.0,
                    "tld": "—",
                    "category": "excessive",
                }
                new_suspicious.append(entry)

        # 2. Check each queried domain
        seen_domains = set()
        for ip, domains in self.queries_per_ip.items():
            for domain in domains:
                if domain in seen_domains:
                    continue
                seen_domains.add(domain)

                # ── Whitelist check (runs FIRST — before any scoring) ──
                if is_whitelisted(domain):
                    continue

                parts = domain.rsplit(".", 1)
                tld = parts[-1].lower() if len(parts) > 1 else ""

                # Suspicious TLD check
                if tld in SUSPICIOUS_TLDS:
                    entry = {
                        "domain": domain,
                        "src_ip": ip,
                        "reason": f"Suspicious TLD: .{tld}",
                        "timestamp": timestamp_str,
                        "dga_score": 0.0,
                        "tld": tld,
                        "category": "suspicious_tld",
                    }
                    new_suspicious.append(entry)

                # DGA detection
                is_dga, dga_score = _looks_like_dga(domain)
                if is_dga:
                    entry = {
                        "domain": domain,
                        "src_ip": ip,
                        "reason": f"Possible DGA domain (score: {dga_score})",
                        "timestamp": timestamp_str,
                        "dga_score": dga_score,
                        "tld": tld,
                        "category": "dga",
                    }
                    new_suspicious.append(entry)

        # Append to persistent list
        self.suspicious_domains.extend(new_suspicious)
        if len(self.suspicious_domains) > 200:
            self.suspicious_domains = self.suspicious_domains[-200:]

        return new_suspicious

    def reset_window(self):
        """Reset per-window counters (persistent list is kept)."""
        self.queries_per_ip.clear()
        self.domain_counts.clear()

    def get_summary(self):
        """Return summary data for the API."""
        return {
            "total_dns_queries": self.total_dns_queries,
            "suspicious_domains": list(reversed(self.suspicious_domains[-50:])),
            "total_suspicious": len(self.suspicious_domains),
        }
