"""
modules/report_generator.py
-----------------------------
Generates the final Incident Response Report in two formats:
  1. Colored terminal output  (SOC analyst style)
  2. Structured text file     (saved to reports/)

The report aggregates findings from all analyzers into one unified
incident narrative with:
  - Executive Summary
  - Risk Assessment
  - Per-module findings
  - IOC Summary
  - Attack Timeline snapshot
  - Recommendations
"""

import os
import datetime
from dataclasses import dataclass, field
from typing import Optional

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

# ── Color helpers ─────────────────────────────────────────────────────────────

def _c(text: str, color: str) -> str:
    if not HAS_COLOR:
        return text
    palette = {
        "red": Fore.RED, "green": Fore.GREEN, "yellow": Fore.YELLOW,
        "cyan": Fore.CYAN, "white": Fore.WHITE, "magenta": Fore.MAGENTA,
        "blue": Fore.BLUE,
    }
    return f"{palette.get(color, '')}{Style.BRIGHT}{text}{Style.RESET_ALL}"

def _risk_col(r: str) -> str:
    return {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "UNKNOWN": "white"}.get(r, "white")

def _div(ch="─", w=66):
    return ch * w


# ── Aggregated report structure ───────────────────────────────────────────────

@dataclass
class IncidentReport:
    case_id: str
    analyst: str
    generated_at: str
    overall_risk: str

    access_result:   object = None
    auth_result:     object = None
    error_result:    object = None
    firewall_result: object = None
    ioc_result:      object = None
    timeline:        list   = field(default_factory=list)
    ti_results:      dict   = field(default_factory=dict)   # {ip: IPIntel}


def _compute_overall_risk(*levels: str) -> str:
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNKNOWN": 3}
    valid = [l for l in levels if l in order]
    if not valid:
        return "LOW"
    return min(valid, key=lambda l: order[l])


def build_report(
    case_id: str = "IR-001",
    analyst: str = "SOC Analyst",
    access_result=None,
    auth_result=None,
    error_result=None,
    firewall_result=None,
    ioc_result=None,
    timeline=None,
    ti_results=None,
) -> IncidentReport:
    levels = [
        getattr(access_result,   "risk_level", "LOW"),
        getattr(auth_result,     "risk_level", "LOW"),
        getattr(error_result,    "risk_level", "LOW"),
        getattr(firewall_result, "risk_level", "LOW"),
    ]
    return IncidentReport(
        case_id=case_id,
        analyst=analyst,
        generated_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        overall_risk=_compute_overall_risk(*levels),
        access_result=access_result,
        auth_result=auth_result,
        error_result=error_result,
        firewall_result=firewall_result,
        ioc_result=ioc_result,
        timeline=timeline or [],
        ti_results=ti_results or {},
    )


# ── Terminal print ────────────────────────────────────────────────────────────

def print_report(rpt: IncidentReport) -> None:
    rc = _risk_col(rpt.overall_risk)

    print()
    print(_c("╔" + "═"*64 + "╗", "cyan"))
    print(_c("║     INCIDENT RESPONSE TOOLKIT — INVESTIGATION REPORT      ║", "cyan"))
    print(_c("╚" + "═"*64 + "╝", "cyan"))
    print(f"  Case ID   : {_c(rpt.case_id, 'white')}")
    print(f"  Analyst   : {_c(rpt.analyst, 'white')}")
    print(f"  Generated : {_c(rpt.generated_at, 'white')}")
    print(f"  Risk Level: {_c('[ ' + rpt.overall_risk + ' ]', rc)}")
    print()

    # ── Access log ────────────────────────────────────────────────────────────
    if rpt.access_result:
        r = rpt.access_result
        print(_c("  WEB ACCESS LOG ANALYSIS", "cyan"))
        print(_c(_div(), "white"))
        print(f"  Source        : {r.source}")
        print(f"  Total entries : {r.total}")
        print(f"  Unique IPs    : {r.unique_ips}")
        print(f"  Risk          : {_c(r.risk_level, _risk_col(r.risk_level))}")
        if r.brute_force:
            for item in r.brute_force:
                print(f"  {_c('⚠ BRUTE-FORCE', 'red')}  {item['ip']}  ({item['attempts']} attempts)")
        if r.scanners:
            for item in r.scanners:
                print(f"  {_c('⚠ SCANNER', 'yellow')}     {item['ip']}  ({item['not_found']} 404s)")
        if r.sqli:
            for item in r.sqli:
                print(f"  {_c('⚠ SQLi', 'red')}         {item['ip']}  → {item['path'][:60]}")
        if r.ip_200_counts:
            print(f"  {_c('✔ 200 ACCESS', 'green')}")
            for ip, cnt in r.ip_200_counts.most_common(5):
                print(f"    {ip.ljust(18)} → {cnt} successful requests")
        print()

    # ── Auth log ──────────────────────────────────────────────────────────────
    if rpt.auth_result:
        r = rpt.auth_result
        print(_c("  AUTH LOG ANALYSIS  (SSH / sudo)", "cyan"))
        print(_c(_div(), "white"))
        print(f"  Source           : {r.source}")
        print(f"  Failed logins    : {len(r.failed_logins)}")
        print(f"  Successful logins: {len(r.success_logins)}")
        print(f"  Sudo events      : {len(r.sudo_events)}")
        print(f"  New users        : {len(r.new_users)}")
        print(f"  Risk             : {_c(r.risk_level, _risk_col(r.risk_level))}")
        for item in r.brute_force_ips:
            print(f"  {_c('⚠ SSH BRUTE', 'red')}  {item['ip']}  ({item['attempts']} attempts)")
        for item in r.success_logins[:5]:
            print(f"  {_c('✔ SSH LOGIN', 'green')}   {item['ip']}  as {item['user']}")
        print()

    # ── Error log ─────────────────────────────────────────────────────────────
    if rpt.error_result:
        r = rpt.error_result
        print(_c("  ERROR LOG ANALYSIS", "cyan"))
        print(_c(_div(), "white"))
        print(f"  Source              : {r.source}")
        print(f"  Total lines         : {r.total_lines}")
        print(f"  Directory traversals: {len(r.traversal_attempts)}")
        print(f"  Null-byte injections: {len(r.null_byte_attempts)}")
        print(f"  PHP fatal errors    : {len(r.php_errors)}")
        print(f"  Critical events     : {len(r.critical_lines)}")
        print(f"  Risk                : {_c(r.risk_level, _risk_col(r.risk_level))}")
        print()

    # ── Firewall log ──────────────────────────────────────────────────────────
    if rpt.firewall_result:
        r = rpt.firewall_result
        print(_c("  FIREWALL LOG ANALYSIS", "cyan"))
        print(_c(_div(), "white"))
        print(f"  Source             : {r.source}")
        print(f"  Total lines        : {r.total_lines}")
        print(f"  Unique blocked IPs : {len(r.blocked_counts)}")
        print(f"  Port scanners      : {len(r.port_scanners)}")
        print(f"  Critical port hits : {len(r.critical_port_hits)}")
        print(f"  Risk               : {_c(r.risk_level, _risk_col(r.risk_level))}")
        for item in r.port_scanners:
            print(f"  {_c('⚠ PORT SCAN', 'red')}  {item['ip']}  ({item['distinct_ports']} ports)")
        if r.top_blocked:
            print(f"  Top blocked IP: {r.top_blocked[0][0]}  ({r.top_blocked[0][1]} hits)")
        print()

    # ── IOCs ──────────────────────────────────────────────────────────────────
    if rpt.ioc_result:
        ioc = rpt.ioc_result
        print(_c("  INDICATORS OF COMPROMISE (IOCs)", "cyan"))
        print(_c(_div(), "white"))
        print(f"  Source      : {ioc.source}")
        print(f"  Total IOCs  : {ioc.total}")
        if ioc.ips:
            print(f"  IPs         : {', '.join(ioc.ips[:8])}" + (" …" if len(ioc.ips) > 8 else ""))
        if ioc.domains:
            print(f"  Domains     : {', '.join(ioc.domains[:5])}")
        if ioc.urls:
            print(f"  URLs        : {len(ioc.urls)}")
        if ioc.md5s or ioc.sha1s or ioc.sha256s:
            print(f"  Hashes      : {len(ioc.md5s)} MD5 / {len(ioc.sha1s)} SHA1 / {len(ioc.sha256s)} SHA256")
        if ioc.cves:
            print(f"  CVEs        : {', '.join(ioc.cves)}")
        print()

    # ── TI enrichment ─────────────────────────────────────────────────────────
    if rpt.ti_results:
        print(_c("  THREAT INTELLIGENCE ENRICHMENT", "cyan"))
        print(_c(_div(), "white"))
        for ip, intel in list(rpt.ti_results.items())[:10]:
            tag_str = "  " + "  ".join([_c(t, "red") for t in intel.tags]) if intel.tags else ""
            geo     = f"{intel.city}, {intel.country}" if intel.city else intel.country
            print(f"  {_c(ip.ljust(18), 'white')}  {geo.ljust(24)}  {intel.isp[:28]}{tag_str}")
        print()

    # ── Timeline snapshot ─────────────────────────────────────────────────────
    if rpt.timeline:
        print(_c("  ATTACK TIMELINE  (most recent 15 events)", "cyan"))
        print(_c(_div(), "white"))
        SEV_COL = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "INFO": "white"}
        for ev in rpt.timeline[-15:]:
            ts  = ev.timestamp_raw[:19] if ev.timestamp_raw else "??:??:??"
            col = SEV_COL.get(ev.severity, "white")
            print(
                f"  {_c(ts.ljust(20), 'white')}"
                f"  {_c(ev.severity.ljust(7), col)}"
                f"  {_c(ev.category.ljust(22), 'cyan')}"
                f"  {ev.actor.ljust(16)}"
                f"  {ev.detail[:45]}"
            )
        print()

    # ── Recommendations ───────────────────────────────────────────────────────
    recs = _generate_recommendations(rpt)
    if recs:
        print(_c("  RECOMMENDATIONS", "cyan"))
        print(_c(_div(), "white"))
        for i, rec in enumerate(recs, 1):
            print(f"  {_c(str(i) + '.', 'yellow')} {rec}")
        print()

    # ── Footer ────────────────────────────────────────────────────────────────
    print(_c(_div("═"), "cyan"))
    print(_c(f"  FINAL VERDICT: {rpt.overall_risk} RISK  |  Case: {rpt.case_id}", _risk_col(rpt.overall_risk)))
    print(_c(_div("═"), "cyan"))
    print()


def _generate_recommendations(rpt: IncidentReport) -> list[str]:
    recs = []
    r_a = rpt.access_result
    r_u = rpt.auth_result
    r_f = rpt.firewall_result

    if r_a and r_a.brute_force:
        recs.append("Implement account lockout after 5 failed login attempts.")
        recs.append("Enable CAPTCHA or MFA on all authentication endpoints.")
    if r_a and r_a.sqli:
        recs.append("Audit all database queries — use parameterized statements / ORM.")
        recs.append("Deploy a Web Application Firewall (WAF) with SQLi rules.")
    if r_a and r_a.scanners:
        recs.append("Block scanning IPs at the perimeter firewall / CDN layer.")
    if r_u and r_u.brute_force_ips:
        recs.append("Disable SSH password auth — enforce key-based authentication only.")
        recs.append("Deploy fail2ban or equivalent to auto-ban SSH brute-forcers.")
    if r_u and r_u.sudo_events:
        recs.append("Review sudo rules — apply principle of least privilege.")
    if r_u and r_u.new_users:
        recs.append("Investigate newly created accounts — verify they are authorized.")
    if r_f and r_f.port_scanners:
        recs.append("Block source IPs conducting port scans at the network boundary.")
    if rpt.ioc_result and rpt.ioc_result.ips:
        recs.append("Feed extracted IOC IPs into SIEM / threat-intelligence platform.")
    if not recs:
        recs.append("No critical actions required. Continue routine monitoring.")
    return recs


# ── Text file export ──────────────────────────────────────────────────────────

def save_text_report(rpt: IncidentReport, output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"{rpt.case_id}_{ts}.txt")

    lines = [
        "=" * 66,
        "    INCIDENT RESPONSE TOOLKIT — INVESTIGATION REPORT",
        "=" * 66,
        f"  Case ID   : {rpt.case_id}",
        f"  Analyst   : {rpt.analyst}",
        f"  Generated : {rpt.generated_at}",
        f"  Risk Level: {rpt.overall_risk}",
        "",
    ]

    def _section(title):
        lines.extend(["", f"  {title}", "-" * 66])

    if rpt.access_result:
        r = rpt.access_result
        _section("WEB ACCESS LOG")
        lines += [
            f"  Source: {r.source}",
            f"  Entries: {r.total}  |  Unique IPs: {r.unique_ips}  |  Risk: {r.risk_level}",
        ]
        for item in r.brute_force:
            lines.append(f"  [BRUTE-FORCE]  {item['ip']}  —  {item['attempts']} attempts")
        for item in r.sqli:
            lines.append(f"  [SQLI]         {item['ip']}  →  {item['path']}")
        for item in r.scanners:
            lines.append(f"  [SCANNER]      {item['ip']}  —  {item['not_found']} 404s")
        lines.append("")
        lines.append("  SUCCESSFUL 200 ACCESS")
        for ip, cnt in r.ip_200_counts.most_common():
            lines.append(f"    ✔  {ip.ljust(18)}  →  {cnt} successful requests")

    if rpt.auth_result:
        r = rpt.auth_result
        _section("AUTH LOG")
        lines += [
            f"  Source: {r.source}",
            f"  Failed: {len(r.failed_logins)}  |  Success: {len(r.success_logins)}  "
            f"|  Sudo: {len(r.sudo_events)}  |  Risk: {r.risk_level}",
        ]
        for item in r.brute_force_ips:
            lines.append(f"  [SSH BRUTE]  {item['ip']}  —  {item['attempts']} attempts")
        for item in r.new_users:
            lines.append(f"  [NEW USER]   {item}")

    if rpt.error_result:
        r = rpt.error_result
        _section("ERROR LOG")
        lines += [
            f"  Source: {r.source}  |  Risk: {r.risk_level}",
            f"  Traversals: {len(r.traversal_attempts)}  |  Null-bytes: {len(r.null_byte_attempts)}  "
            f"|  PHP errors: {len(r.php_errors)}",
        ]

    if rpt.firewall_result:
        r = rpt.firewall_result
        _section("FIREWALL LOG")
        lines += [
            f"  Source: {r.source}  |  Risk: {r.risk_level}",
            f"  Port scanners: {len(r.port_scanners)}  |  Critical port hits: {len(r.critical_port_hits)}",
        ]
        for item in r.port_scanners:
            lines.append(f"  [PORT SCAN]  {item['ip']}  —  {item['distinct_ports']} ports")

    if rpt.ioc_result:
        ioc = rpt.ioc_result
        _section("IOCs")
        lines.append(f"  Total: {ioc.total}")
        if ioc.ips:
            lines.append(f"  IPs    : {', '.join(ioc.ips)}")
        if ioc.domains:
            lines.append(f"  Domains: {', '.join(ioc.domains)}")
        if ioc.cves:
            lines.append(f"  CVEs   : {', '.join(ioc.cves)}")

    if rpt.timeline:
        _section("ATTACK TIMELINE")
        for ev in rpt.timeline:
            ts_s = ev.timestamp_raw[:19] if ev.timestamp_raw else "N/A"
            lines.append(f"  [{ev.severity.ljust(6)}] {ts_s.ljust(20)} {ev.category.ljust(22)} {ev.actor.ljust(16)} {ev.detail[:50]}")

    _section("RECOMMENDATIONS")
    for i, rec in enumerate(_generate_recommendations(rpt), 1):
        lines.append(f"  {i}. {rec}")

    lines += [
        "",
        "=" * 66,
        f"  FINAL VERDICT: {rpt.overall_risk} RISK",
        "=" * 66,
    ]

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return filepath
