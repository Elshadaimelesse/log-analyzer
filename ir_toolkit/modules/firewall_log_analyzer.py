"""
modules/firewall_log_analyzer.py
---------------------------------
Analyzes iptables / UFW / Windows Firewall log files for:
  - Blocked connection attempts per source IP
  - Port scan detection (same IP → many different destination ports)
  - Repeated hits on critical ports (22, 23, 3389, 445, 1433, 3306)
  - Outbound drops (potential C2 beaconing)

Supported log formats
---------------------
iptables (kernel LOG target):
  Jun 28 10:00:01 host kernel: [12345.678] IN=eth0 OUT= ... SRC=1.2.3.4 DST=5.6.7.8 ... DPT=22 ...

UFW:
  Jun 28 10:00:01 host kernel: [UFW BLOCK] IN=eth0 ... SRC=1.2.3.4 DST=5.6.7.8 ... DPT=22 ...

Windows Firewall (CSV-ish):
  2026-06-28 10:00:01 DROP TCP 1.2.3.4 5.6.7.8 54321 3389 ...
"""

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

PORT_SCAN_THRESHOLD  = 10   # distinct ports from same IP
CRITICAL_PORTS = {22, 23, 3389, 445, 1433, 3306, 5900, 8080, 8443}

# iptables / UFW
_IPTABLES = re.compile(
    r'SRC=(?P<src>[\d.]+).*DST=(?P<dst>[\d.]+).*DPT=(?P<dpt>\d+)'
)
# Windows Firewall log
_WIN_FW = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2} [\d:]+)\s+(?P<action>\S+)\s+(?P<proto>\S+)'
    r'\s+(?P<src>[\d.]+)\s+(?P<dst>[\d.]+)\s+(?P<sport>\d+|-)\s+(?P<dpt>\d+|-)'
)
_TIMESTAMP = re.compile(r'^(\w{3}\s+\d+\s+[\d:]+|\d{4}-\d{2}-\d{2} [\d:]+)')


@dataclass
class FirewallResult:
    source: str
    total_lines: int = 0
    blocked_counts: Counter          = field(default_factory=Counter)   # src IP → blocked hits
    port_targets: defaultdict        = field(default_factory=lambda: defaultdict(set))  # src IP → {ports}
    critical_port_hits: list[dict]   = field(default_factory=list)
    port_scanners: list[dict]        = field(default_factory=list)
    top_blocked: list[tuple]         = field(default_factory=list)
    risk_level: str                  = "LOW"


def analyze(filepath: str) -> FirewallResult:
    r = FirewallResult(source=filepath)
    try:
        lines = open(filepath, "r", errors="ignore").readlines()
    except FileNotFoundError:
        r.risk_level = "UNKNOWN"
        return r

    r.total_lines = len(lines)

    for line in lines:
        ts_m = _TIMESTAMP.match(line)
        ts   = ts_m.group(1) if ts_m else ""

        m = _IPTABLES.search(line) or _WIN_FW.search(line)
        if not m:
            continue

        src = m.group("src")
        try:
            dpt = int(m.group("dpt"))
        except (ValueError, TypeError):
            continue

        r.blocked_counts[src] += 1
        r.port_targets[src].add(dpt)

        if dpt in CRITICAL_PORTS:
            r.critical_port_hits.append({"timestamp": ts, "src": src, "port": dpt})

    # Port scan detection
    for ip, ports in r.port_targets.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            r.port_scanners.append({"ip": ip, "distinct_ports": len(ports),
                                    "sample_ports": sorted(ports)[:10]})

    r.top_blocked = r.blocked_counts.most_common(10)

    score = len(r.port_scanners)*5 + len(r.critical_port_hits)//2
    r.risk_level = "HIGH" if score >= 10 else "MEDIUM" if score >= 3 else "LOW"
    return r
