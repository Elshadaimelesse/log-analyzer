"""
core/detector.py
----------------
Detection engine for common web attack patterns:
  - Brute-force login attempts
  - Directory/port scanning (excessive 404s)
  - SQL injection probes
  - Suspicious endpoint access
  - High request frequency (DDoS-like behavior)
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from core.parser import LogEntry


# ── Thresholds ────────────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5       # same IP, same auth endpoint, N+ requests
SCAN_404_THRESHOLD = 4          # N+ 404 responses from single IP
HIGH_FREQ_THRESHOLD = 20        # N+ total requests from single IP
SQL_PATTERNS = [                # fragments that suggest SQL injection
    "' or '", "' or 1=1", "union select", "drop table",
    "insert into", "sleep(", "benchmark(", "xp_cmdshell",
    "/*", "--", ";--", "' and '",
]
SUSPICIOUS_PATHS = [
    "/admin", "/wp-admin", "/phpmyadmin", "/login",
    "/sql", "/.env", "/config", "/backup",
    "/shell", "/cmd", "/etc/passwd", "/proc/",
]


@dataclass
class ThreatSummary:
    total_entries: int = 0
    unique_ips: int = 0

    # per-IP request counts
    ip_request_counts: Counter = field(default_factory=Counter)

    # per-IP 404 counts
    ip_404_counts: Counter = field(default_factory=Counter)

    # per-IP auth-endpoint hits (brute force)
    ip_auth_counts: Counter = field(default_factory=Counter)

    # status code distribution
    status_counts: Counter = field(default_factory=Counter)

    # flagged threats — list of dicts for easy reporting
    brute_force_ips: list[dict] = field(default_factory=list)
    scanning_ips: list[dict] = field(default_factory=list)
    sqli_attempts: list[dict] = field(default_factory=list)
    suspicious_path_hits: list[dict] = field(default_factory=list)
    high_freq_ips: list[dict] = field(default_factory=list)

    # overall risk
    risk_level: str = "LOW"


def _normalize_path(path: str) -> str:
    return path.lower().split("?")[0].rstrip("/")


def analyze(entries: list[LogEntry]) -> ThreatSummary:
    """Run all detectors over the parsed log entries and return a ThreatSummary."""
    summary = ThreatSummary()
    summary.total_entries = len(entries)

    # ── Aggregate ──────────────────────────────────────────────────────────────
    for entry in entries:
        summary.ip_request_counts[entry.ip] += 1
        summary.status_counts[str(entry.status)] += 1

        if entry.status == 404:
            summary.ip_404_counts[entry.ip] += 1

        path_lower = entry.path.lower()
        if "/login" in path_lower or "/auth" in path_lower or "/signin" in path_lower:
            if entry.status in (401, 403):
                summary.ip_auth_counts[entry.ip] += 1

    summary.unique_ips = len(summary.ip_request_counts)

    # ── Brute-force detection ──────────────────────────────────────────────────
    for ip, count in summary.ip_auth_counts.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            summary.brute_force_ips.append({"ip": ip, "attempts": count})

    # ── Scanning detection (excessive 404s) ────────────────────────────────────
    for ip, count in summary.ip_404_counts.items():
        if count >= SCAN_404_THRESHOLD:
            summary.scanning_ips.append({"ip": ip, "not_found_requests": count})

    # ── High-frequency (DDoS-like) detection ───────────────────────────────────
    for ip, count in summary.ip_request_counts.items():
        if count >= HIGH_FREQ_THRESHOLD:
            summary.high_freq_ips.append({"ip": ip, "requests": count})

    # ── SQLi detection ────────────────────────────────────────────────────────
    seen_sqli: set[str] = set()
    for entry in entries:
        full_request = (entry.path + " " + entry.raw).lower()
        for pattern in SQL_PATTERNS:
            if pattern in full_request and entry.ip not in seen_sqli:
                seen_sqli.add(entry.ip)
                summary.sqli_attempts.append({
                    "ip": entry.ip,
                    "path": entry.path,
                    "pattern": pattern,
                })
                break

    # ── Suspicious path access ─────────────────────────────────────────────────
    seen_paths: defaultdict[str, set] = defaultdict(set)
    for entry in entries:
        norm = _normalize_path(entry.path)
        for sus_path in SUSPICIOUS_PATHS:
            if sus_path in norm and sus_path not in seen_paths[entry.ip]:
                seen_paths[entry.ip].add(sus_path)
                summary.suspicious_path_hits.append({
                    "ip": entry.ip,
                    "path": entry.path,
                    "matched": sus_path,
                    "status": entry.status,
                })

    # ── Risk level ────────────────────────────────────────────────────────────
    score = (
        len(summary.brute_force_ips) * 4
        + len(summary.sqli_attempts) * 5
        + len(summary.scanning_ips) * 3
        + len(summary.high_freq_ips) * 2
        + len(summary.suspicious_path_hits)
    )
    if score >= 15:
        summary.risk_level = "HIGH"
    elif score >= 6:
        summary.risk_level = "MEDIUM"
    else:
        summary.risk_level = "LOW"

    return summary


def top_attackers(summary: ThreatSummary, n: int = 5) -> list[tuple[str, int]]:
    """Return top N IPs by total request count."""
    return summary.ip_request_counts.most_common(n)
