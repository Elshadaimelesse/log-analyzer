"""
core/parser.py
--------------
Responsible for reading and parsing raw Apache/Nginx Combined Log Format entries.
Each line is parsed into a structured LogEntry dataclass for downstream analysis.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# Combined Log Format regex
# Example:
#   192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
_LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'   # client IP
    r'\s+\S+\s+\S+\s+'                    # ident, auth user
    r'\[(?P<timestamp>[^\]]+)\]'           # timestamp
    r'\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"'  # request line
    r'\s+(?P<status>\d{3})'               # HTTP status
    r'\s+(?P<size>\S+)'                   # response size
)


@dataclass
class LogEntry:
    ip: str
    timestamp: str
    method: str
    path: str
    status: int
    size: int
    raw: str = field(repr=False)


def parse_log_file(filepath: str) -> list[LogEntry]:
    """Read a log file and return a list of parsed LogEntry objects.
    Malformed lines are silently skipped."""
    entries: list[LogEntry] = []

    try:
        with open(filepath, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                match = _LOG_PATTERN.search(line)
                if match:
                    try:
                        size = int(match.group("size"))
                    except ValueError:
                        size = 0
                    entries.append(LogEntry(
                        ip=match.group("ip"),
                        timestamp=match.group("timestamp"),
                        method=match.group("method"),
                        path=match.group("path"),
                        status=int(match.group("status")),
                        size=size,
                        raw=line,
                    ))
    except FileNotFoundError:
        raise FileNotFoundError(f"Log file not found: {filepath}")

    return entries
