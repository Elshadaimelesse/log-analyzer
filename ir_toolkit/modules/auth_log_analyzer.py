"""
modules/auth_log_analyzer.py
-----------------------------
Analyzes Linux /var/log/auth.log (or auth.log samples) for:
  - Failed SSH login attempts
  - Successful SSH logins
  - Sudo privilege escalations
  - User account creation / deletion
  - Repeated failures → credential-stuffing / brute-force

Typical auth.log line formats:
  Jun 28 10:00:01 server sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2
  Jun 28 10:00:05 server sshd[1235]: Accepted password for alice from 192.168.1.10 port 51234 ssh2
  Jun 28 10:01:00 server sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
"""

import re
from collections import Counter
from dataclasses import dataclass, field

BRUTE_SSH_THRESHOLD = 5   # failed attempts before flagging an IP

_FAILED_SSH   = re.compile(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port')
_ACCEPTED_SSH = re.compile(r'Accepted (?:password|publickey) for (\S+) from (\S+) port')
_SUDO_USE     = re.compile(r'sudo:\s+(\S+)\s+:.*COMMAND=(.+)')
_NEW_USER     = re.compile(r'useradd.*name=(\S+)', re.IGNORECASE)
_DEL_USER     = re.compile(r'userdel.*name=(\S+)', re.IGNORECASE)
_TIMESTAMP    = re.compile(r'^(\w{3}\s+\d+\s+[\d:]+)')


@dataclass
class AuthResult:
    source: str
    total_lines: int = 0
    failed_logins: list[dict]   = field(default_factory=list)
    success_logins: list[dict]  = field(default_factory=list)
    sudo_events: list[dict]     = field(default_factory=list)
    new_users: list[str]        = field(default_factory=list)
    deleted_users: list[str]    = field(default_factory=list)
    brute_force_ips: list[dict] = field(default_factory=list)
    ip_fail_counts: Counter     = field(default_factory=Counter)
    risk_level: str             = "LOW"


def analyze(filepath: str) -> AuthResult:
    r = AuthResult(source=filepath)
    try:
        lines = open(filepath, "r", errors="ignore").readlines()
    except FileNotFoundError:
        r.risk_level = "UNKNOWN"
        return r

    r.total_lines = len(lines)

    for line in lines:
        ts_m = _TIMESTAMP.match(line)
        ts   = ts_m.group(1) if ts_m else ""

        m = _FAILED_SSH.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            r.failed_logins.append({"timestamp": ts, "user": user, "ip": ip})
            r.ip_fail_counts[ip] += 1
            continue

        m = _ACCEPTED_SSH.search(line)
        if m:
            r.success_logins.append({"timestamp": ts, "user": m.group(1), "ip": m.group(2)})
            continue

        m = _SUDO_USE.search(line)
        if m:
            r.sudo_events.append({"timestamp": ts, "user": m.group(1), "command": m.group(2).strip()})
            continue

        m = _NEW_USER.search(line)
        if m:
            r.new_users.append(m.group(1))
            continue

        m = _DEL_USER.search(line)
        if m:
            r.deleted_users.append(m.group(1))

    for ip, cnt in r.ip_fail_counts.items():
        if cnt >= BRUTE_SSH_THRESHOLD:
            r.brute_force_ips.append({"ip": ip, "attempts": cnt})

    score = len(r.brute_force_ips)*5 + len(r.sudo_events)*2 + len(r.new_users)*3
    r.risk_level = "HIGH" if score >= 10 else "MEDIUM" if score >= 3 else "LOW"
    return r
