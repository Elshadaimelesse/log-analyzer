"""
modules/timeline_builder.py
-----------------------------
Builds a unified, chronological attack timeline from all analyzed sources.

Each "event" is a TimelineEvent with:
  - timestamp (parsed datetime or raw string)
  - source    (which log file)
  - category  (SSH_FAIL, WEB_ATTACK, FIREWALL_BLOCK, etc.)
  - severity  (HIGH / MEDIUM / LOW / INFO)
  - actor     (IP or username)
  - detail    (human-readable description)

The timeline can be:
  - Printed to terminal (sorted, color-coded)
  - Exported to CSV for use in SIEM / spreadsheet tools
  - Exported to JSON for programmatic consumption
"""

import csv
import json
import datetime
import re
import os
from dataclasses import dataclass, asdict
from typing import Optional

# Attempt to parse timestamps in multiple formats
_TS_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",          # Apache access log
    "%b %d %H:%M:%S",                 # syslog (no year)
    "%Y-%m-%d %H:%M:%S",              # ISO / Windows FW
    "%Y/%m/%d %H:%M:%S",              # Nginx error
    "%a %b %d %H:%M:%S.%f %Y",        # Apache error
]

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


@dataclass
class TimelineEvent:
    timestamp_raw: str
    timestamp_dt: Optional[datetime.datetime]
    source: str
    category: str
    severity: str
    actor: str
    detail: str

    def sort_key(self):
        if self.timestamp_dt:
            return self.timestamp_dt
        return datetime.datetime.min


def _parse_ts(raw: str) -> Optional[datetime.datetime]:
    raw = raw.strip()
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.datetime.strptime(raw, fmt)
            if dt.year == 1900:           # syslog has no year — use current
                dt = dt.replace(year=datetime.datetime.now().year)
            return dt
        except ValueError:
            continue
    return None


# ── Event factory helpers ────────────────────────────────────────────────────

def events_from_access(access_result) -> list[TimelineEvent]:
    """Convert AccessResult findings into TimelineEvents."""
    events = []
    src = access_result.source

    for item in access_result.brute_force:
        events.append(TimelineEvent(
            timestamp_raw="", timestamp_dt=None,
            source=src, category="BRUTE_FORCE_WEB",
            severity="HIGH", actor=item["ip"],
            detail=f"Brute-force: {item['attempts']} failed auth attempts",
        ))
    for item in access_result.sqli:
        events.append(TimelineEvent(
            timestamp_raw="", timestamp_dt=None,
            source=src, category="SQL_INJECTION",
            severity="HIGH", actor=item["ip"],
            detail=f"SQLi probe → {item['path']}  [pattern: {item['pattern']}]",
        ))
    for item in access_result.scanners:
        events.append(TimelineEvent(
            timestamp_raw="", timestamp_dt=None,
            source=src, category="WEB_SCAN",
            severity="MEDIUM", actor=item["ip"],
            detail=f"Directory scan: {item['not_found']} 404 responses",
        ))
    for item in access_result.sus_paths:
        events.append(TimelineEvent(
            timestamp_raw="", timestamp_dt=None,
            source=src, category="SUSPICIOUS_PATH",
            severity="MEDIUM", actor=item["ip"],
            detail=f"Access to {item['path']}  (matched: {item['matched']}) → HTTP {item['status']}",
        ))
    return events


def events_from_auth(auth_result) -> list[TimelineEvent]:
    events = []
    src = auth_result.source

    for item in auth_result.brute_force_ips:
        events.append(TimelineEvent(
            timestamp_raw="", timestamp_dt=None,
            source=src, category="BRUTE_FORCE_SSH",
            severity="HIGH", actor=item["ip"],
            detail=f"SSH brute-force: {item['attempts']} failed attempts",
        ))
    for item in auth_result.success_logins:
        events.append(TimelineEvent(
            timestamp_raw=item["timestamp"], timestamp_dt=_parse_ts(item["timestamp"]),
            source=src, category="SSH_LOGIN_SUCCESS",
            severity="INFO", actor=item["ip"],
            detail=f"Successful SSH login as '{item['user']}'",
        ))
    for item in auth_result.sudo_events:
        events.append(TimelineEvent(
            timestamp_raw=item["timestamp"], timestamp_dt=_parse_ts(item["timestamp"]),
            source=src, category="PRIVILEGE_ESCALATION",
            severity="MEDIUM", actor=item["user"],
            detail=f"sudo: {item['command'][:80]}",
        ))
    for user in auth_result.new_users:
        events.append(TimelineEvent(
            timestamp_raw="", timestamp_dt=None,
            source=src, category="USER_CREATED",
            severity="MEDIUM", actor=user,
            detail=f"New user account created: {user}",
        ))
    return events


def events_from_firewall(fw_result) -> list[TimelineEvent]:
    events = []
    src = fw_result.source

    for item in fw_result.port_scanners:
        events.append(TimelineEvent(
            timestamp_raw="", timestamp_dt=None,
            source=src, category="PORT_SCAN",
            severity="HIGH", actor=item["ip"],
            detail=f"Port scan: {item['distinct_ports']} distinct ports probed",
        ))
    for item in fw_result.critical_port_hits[:20]:   # cap at 20
        events.append(TimelineEvent(
            timestamp_raw=item["timestamp"], timestamp_dt=_parse_ts(item["timestamp"]),
            source=src, category="CRITICAL_PORT_HIT",
            severity="MEDIUM", actor=item["src"],
            detail=f"Blocked connection to critical port {item['port']}",
        ))
    return events


def events_from_error(err_result) -> list[TimelineEvent]:
    events = []
    src = err_result.source

    for item in err_result.traversal_attempts:
        events.append(TimelineEvent(
            timestamp_raw=item["timestamp"], timestamp_dt=_parse_ts(item["timestamp"]),
            source=src, category="PATH_TRAVERSAL",
            severity="HIGH", actor=item["ip"],
            detail=item["line"][:100],
        ))
    for item in err_result.null_byte_attempts:
        events.append(TimelineEvent(
            timestamp_raw=item["timestamp"], timestamp_dt=_parse_ts(item["timestamp"]),
            source=src, category="NULL_BYTE_INJECTION",
            severity="HIGH", actor=item["ip"],
            detail=item["line"][:100],
        ))
    return events


# ── Timeline assembly ────────────────────────────────────────────────────────

def build(event_lists: list[list[TimelineEvent]]) -> list[TimelineEvent]:
    """Merge multiple event lists and sort chronologically."""
    all_events: list[TimelineEvent] = []
    for lst in event_lists:
        all_events.extend(lst)
    all_events.sort(key=lambda e: (e.sort_key(), SEVERITY_ORDER.get(e.severity, 9)))
    return all_events


# ── Export ───────────────────────────────────────────────────────────────────

def export_csv(events: list[TimelineEvent], filepath: str) -> None:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "timestamp_raw", "source", "category", "severity", "actor", "detail"
        ])
        writer.writeheader()
        for e in events:
            writer.writerow({
                "timestamp_raw": e.timestamp_raw,
                "source":        e.source,
                "category":      e.category,
                "severity":      e.severity,
                "actor":         e.actor,
                "detail":        e.detail,
            })


def export_json(events: list[TimelineEvent], filepath: str) -> None:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    data = []
    for e in events:
        d = asdict(e)
        d.pop("timestamp_dt", None)   # datetime not JSON-serialisable
        data.append(d)
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
