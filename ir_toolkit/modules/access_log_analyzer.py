"""
modules/access_log_analyzer.py
-------------------------------
Parses Apache/Nginx Combined Log Format and runs the full
web-threat detection suite (brute-force, scanning, SQLi, etc.).

This module is a clean, standalone port of the original log-analyzer
core — self-contained so it can be imported by main.py or used alone.
"""

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

# ── Log parsing ───────────────────────────────────────────────────────────────

_ACCESS_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)

BRUTE_FORCE_THRESHOLD = 5
SCAN_404_THRESHOLD    = 4
HIGH_FREQ_THRESHOLD   = 20

SQL_PATTERNS = [
    "' or '", "union select", "drop table", "insert into",
    "sleep(", "benchmark(", "xp_cmdshell", "' and '", "/*", "--",
]
SUSPICIOUS_PATHS = [
    "/admin", "/wp-admin", "/phpmyadmin", "/login",
    "/.env", "/config", "/backup", "/shell", "/cmd",
    "/etc/passwd", "/proc/", "/sql",
]


@dataclass
class AccessEntry:
    ip: str
    timestamp: str
    method: str
    path: str
    status: int
    size: int
    raw: str = field(repr=False)


@dataclass
class AccessResult:
    source: str
    total: int = 0
    unique_ips: int = 0
    ip_counts: Counter       = field(default_factory=Counter)
    ip_200_counts: Counter   = field(default_factory=Counter)
    ip_404_counts: Counter   = field(default_factory=Counter)
    ip_auth_counts: Counter  = field(default_factory=Counter)
    status_counts: Counter   = field(default_factory=Counter)
    brute_force: list[dict]  = field(default_factory=list)
    scanners: list[dict]     = field(default_factory=list)
    sqli: list[dict]         = field(default_factory=list)
    sus_paths: list[dict]    = field(default_factory=list)
    high_freq: list[dict]    = field(default_factory=list)
    risk_level: str          = "LOW"


def parse(filepath: str) -> list[AccessEntry]:
    entries = []
    with open(filepath, "r", errors="ignore") as fh:
        for line in fh:
            m = _ACCESS_PATTERN.search(line.strip())
            if m:
                try:
                    size = int(m.group("size"))
                except ValueError:
                    size = 0
                entries.append(AccessEntry(
                    ip=m.group("ip"), timestamp=m.group("timestamp"),
                    method=m.group("method"), path=m.group("path"),
                    status=int(m.group("status")), size=size, raw=line.strip(),
                ))
    return entries


def analyze(filepath: str) -> AccessResult:
    entries = parse(filepath)
    r = AccessResult(source=filepath, total=len(entries))

    seen_sus: defaultdict[str, set] = defaultdict(set)
    seen_sqli: set[str] = set()

    for e in entries:
        r.ip_counts[e.ip] += 1
        r.status_counts[str(e.status)] += 1
        if e.status == 200:
            r.ip_200_counts[e.ip] += 1
        if e.status == 404:
            r.ip_404_counts[e.ip] += 1
        pl = e.path.lower()
        if any(x in pl for x in ("/login", "/auth", "/signin")) and e.status in (401, 403):
            r.ip_auth_counts[e.ip] += 1

        # SQLi
        full = (e.path + " " + e.raw).lower()
        if e.ip not in seen_sqli:
            for pat in SQL_PATTERNS:
                if pat in full:
                    seen_sqli.add(e.ip)
                    r.sqli.append({"ip": e.ip, "path": e.path, "pattern": pat})
                    break

        # Suspicious paths
        norm = pl.split("?")[0].rstrip("/")
        for sp in SUSPICIOUS_PATHS:
            if sp in norm and sp not in seen_sus[e.ip]:
                seen_sus[e.ip].add(sp)
                r.sus_paths.append({"ip": e.ip, "path": e.path, "matched": sp, "status": e.status})

    r.unique_ips = len(r.ip_counts)

    for ip, cnt in r.ip_auth_counts.items():
        if cnt >= BRUTE_FORCE_THRESHOLD:
            r.brute_force.append({"ip": ip, "attempts": cnt})
    for ip, cnt in r.ip_404_counts.items():
        if cnt >= SCAN_404_THRESHOLD:
            r.scanners.append({"ip": ip, "not_found": cnt})
    for ip, cnt in r.ip_counts.items():
        if cnt >= HIGH_FREQ_THRESHOLD:
            r.high_freq.append({"ip": ip, "requests": cnt})

    score = (len(r.brute_force)*4 + len(r.sqli)*5 +
             len(r.scanners)*3 + len(r.high_freq)*2 + len(r.sus_paths))
    r.risk_level = "HIGH" if score >= 15 else "MEDIUM" if score >= 6 else "LOW"
    return r
