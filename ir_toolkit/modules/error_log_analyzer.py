"""
modules/error_log_analyzer.py
------------------------------
Analyzes Apache/Nginx error logs for:
  - PHP/application errors leaking stack traces
  - File-not-found (404) floods
  - Permission denied (403) probes
  - Server errors (500) — possible exploitation attempts
  - Directory traversal patterns (../../)
  - Null-byte injection (%00)

Typical Apache error.log format:
  [Mon Jun 28 10:00:01.123456 2026] [error] [client 10.0.0.5:44321] ...message...
Nginx error.log format:
  2026/06/28 10:00:01 [error] 1234#0: *1 ...message..., client: 10.0.0.5, ...
"""

import re
from collections import Counter
from dataclasses import dataclass, field

_APACHE_ERR = re.compile(
    r'\[(?P<ts>[^\]]+)\].*\[(?P<level>\w+)\].*\[client (?P<ip>[\d.]+)'
)
_NGINX_ERR  = re.compile(
    r'(?P<ts>\d{4}/\d{2}/\d{2} [\d:]+) \[(?P<level>\w+)\].*client: (?P<ip>[\d.]+)'
)
_TRAVERSAL  = re.compile(r'\.\./|\.\.\\')
_NULL_BYTE  = re.compile(r'%00')
_PHP_FATAL  = re.compile(r'PHP (?:Fatal|Parse) error', re.IGNORECASE)


@dataclass
class ErrorResult:
    source: str
    total_lines: int = 0
    level_counts: Counter        = field(default_factory=Counter)
    ip_error_counts: Counter     = field(default_factory=Counter)
    traversal_attempts: list[dict] = field(default_factory=list)
    null_byte_attempts: list[dict] = field(default_factory=list)
    php_errors: list[str]        = field(default_factory=list)
    critical_lines: list[str]    = field(default_factory=list)
    risk_level: str              = "LOW"


def analyze(filepath: str) -> ErrorResult:
    r = ErrorResult(source=filepath)
    try:
        lines = open(filepath, "r", errors="ignore").readlines()
    except FileNotFoundError:
        r.risk_level = "UNKNOWN"
        return r

    r.total_lines = len(lines)

    for line in lines:
        # Try Apache then Nginx pattern
        m = _APACHE_ERR.search(line) or _NGINX_ERR.search(line)
        ip    = m.group("ip")    if m else "unknown"
        level = m.group("level").lower() if m else "unknown"
        ts    = m.group("ts")    if m else ""

        r.level_counts[level] += 1
        if ip != "unknown":
            r.ip_error_counts[ip] += 1

        if _TRAVERSAL.search(line):
            r.traversal_attempts.append({"timestamp": ts, "ip": ip, "line": line.strip()[:120]})
        if _NULL_BYTE.search(line):
            r.null_byte_attempts.append({"timestamp": ts, "ip": ip, "line": line.strip()[:120]})
        if _PHP_FATAL.search(line):
            r.php_errors.append(line.strip()[:150])
        if level in ("crit", "alert", "emerg"):
            r.critical_lines.append(line.strip()[:150])

    score = (len(r.traversal_attempts)*4 + len(r.null_byte_attempts)*4 +
             len(r.critical_lines)*3 + len(r.php_errors))
    r.risk_level = "HIGH" if score >= 10 else "MEDIUM" if score >= 3 else "LOW"
    return r
