"""
Incident Response Toolkit — main.py
=====================================
Unified CLI for running the full IR investigation pipeline.

Usage
-----
    python main.py                          # run with default evidence files
    python main.py --access  path/to/access.log
    python main.py --auth    path/to/auth.log
    python main.py --error   path/to/error.log
    python main.py --fw      path/to/firewall.log
    python main.py --ioc     path/to/ioc_file.txt
    python main.py --case    IR-2026-001 --analyst "Jane Doe"
    python main.py --no-ti                  # skip threat-intel lookups
    python main.py --no-timeline            # skip timeline export

All arguments are optional — modules are skipped if their log path
is not provided and the default evidence file does not exist.
"""

import argparse
import os
import sys
import datetime

# ── Color helpers (inline, no import dependency) ─────────────────────────────
try:
    from colorama import Fore, Style, init as _ci
    _ci(autoreset=True)
    def info(m):  print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {m}")
    def ok(m):    print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} {m}")
    def warn(m):  print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {m}")
    def err(m):   print(f"{Fore.RED}[✗]{Style.RESET_ALL} {m}")
    def hdr(m):   print(f"\n{Fore.CYAN}{Style.BRIGHT}{'─'*64}\n  {m}\n{'─'*64}{Style.RESET_ALL}")
except ImportError:
    def info(m):  print(f"[*] {m}")
    def ok(m):    print(f"[+] {m}")
    def warn(m):  print(f"[!] {m}")
    def err(m):   print(f"[-] {m}")
    def hdr(m):   print(f"\n{'─'*64}\n  {m}\n{'─'*64}")

# ── Default evidence paths ─────────────────────────────────────────────────────
_EVIDENCE = os.path.join(os.path.dirname(__file__), "evidence")
_REPORTS  = os.path.join(os.path.dirname(__file__), "reports")

DEFAULTS = {
    "access":   os.path.join(_EVIDENCE, "access.log"),
    "auth":     os.path.join(_EVIDENCE, "auth.log"),
    "error":    os.path.join(_EVIDENCE, "error.log"),
    "fw":       os.path.join(_EVIDENCE, "firewall.log"),
    "ioc":      os.path.join(_EVIDENCE, "ioc_sample.txt"),
}

# ── Module imports ─────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))  # workspace root

from ir_toolkit.modules import (
    access_log_analyzer,
    auth_log_analyzer,
    error_log_analyzer,
    firewall_log_analyzer,
    ioc_extractor,
    timeline_builder,
    threat_intelligence,
    report_generator,
)


def _resolve(cli_val: str | None, key: str) -> str | None:
    """Return CLI path if given, else default if it exists, else None."""
    if cli_val:
        return cli_val
    default = DEFAULTS.get(key, "")
    return default if os.path.exists(default) else None


def run(args: argparse.Namespace) -> None:
    case_id  = args.case
    analyst  = args.analyst
    use_ti   = not args.no_ti
    use_tl   = not args.no_timeline

    hdr(f"INCIDENT RESPONSE TOOLKIT  |  Case: {case_id}")
    print(f"  Analyst   : {analyst}")
    print(f"  Started   : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # ── 1. Access log ──────────────────────────────────────────────────────────
    access_result = None
    path = _resolve(args.access, "access")
    if path:
        info(f"Analyzing access log   : {path}")
        access_result = access_log_analyzer.analyze(path)
        ok(f"Access log done  — risk: {access_result.risk_level}")
    else:
        warn("No access log found — skipping web analysis.")

    # Use the original project's log as fallback access log
    fallback = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "access.log")
    if access_result is None and os.path.exists(fallback):
        info(f"Using fallback access log: {fallback}")
        access_result = access_log_analyzer.analyze(fallback)
        ok(f"Access log done  — risk: {access_result.risk_level}")

    # ── 2. Auth log ────────────────────────────────────────────────────────────
    auth_result = None
    path = _resolve(args.auth, "auth")
    if path:
        info(f"Analyzing auth log     : {path}")
        auth_result = auth_log_analyzer.analyze(path)
        ok(f"Auth log done    — risk: {auth_result.risk_level}")
    else:
        warn("No auth log found — skipping SSH/sudo analysis.")

    # ── 3. Error log ───────────────────────────────────────────────────────────
    error_result = None
    path = _resolve(args.error, "error")
    if path:
        info(f"Analyzing error log    : {path}")
        error_result = error_log_analyzer.analyze(path)
        ok(f"Error log done   — risk: {error_result.risk_level}")
    else:
        warn("No error log found — skipping error analysis.")

    # ── 4. Firewall log ────────────────────────────────────────────────────────
    fw_result = None
    path = _resolve(args.fw, "fw")
    if path:
        info(f"Analyzing firewall log : {path}")
        fw_result = firewall_log_analyzer.analyze(path)
        ok(f"Firewall log done — risk: {fw_result.risk_level}")
    else:
        warn("No firewall log found — skipping firewall analysis.")

    # ── 5. IOC extraction ──────────────────────────────────────────────────────
    ioc_result = None
    path = _resolve(args.ioc, "ioc")
    if path:
        info(f"Extracting IOCs from   : {path}")
        ioc_result = ioc_extractor.extract(path)
        ok(f"IOC extraction done — {ioc_result.total} indicators found")
    else:
        warn("No IOC file found — skipping IOC extraction.")

    # ── 6. Threat intelligence ─────────────────────────────────────────────────
    ti_results: dict = {}
    if use_ti:
        # Collect all unique external IPs across all results
        all_ips: set[str] = set()
        for res in [access_result, auth_result, fw_result]:
            if res is None:
                continue
            counts = getattr(res, "ip_counts", None) or getattr(res, "ip_request_counts", None) or {}
            all_ips.update(counts.keys())
        if ioc_result:
            all_ips.update(ioc_result.ips)

        if all_ips:
            info(f"Threat intelligence lookup for {len(all_ips)} IPs (GeoIP, offline lists)…")
            ti_results = threat_intelligence.enrich_ips(
                list(all_ips),
                abuseipdb_key=os.environ.get("ABUSEIPDB_KEY", ""),
                geoip=True,
            )
            flagged = sum(1 for v in ti_results.values() if v.known_bad)
            ok(f"TI done — {flagged} known-bad IPs identified")
        else:
            warn("No IPs collected for TI lookup.")

    # ── 7. Timeline ────────────────────────────────────────────────────────────
    timeline = []
    if use_tl:
        info("Building attack timeline…")
        event_lists = []
        if access_result:
            event_lists.append(timeline_builder.events_from_access(access_result))
        if auth_result:
            event_lists.append(timeline_builder.events_from_auth(auth_result))
        if error_result:
            event_lists.append(timeline_builder.events_from_error(error_result))
        if fw_result:
            event_lists.append(timeline_builder.events_from_firewall(fw_result))

        timeline = timeline_builder.build(event_lists)
        ok(f"Timeline built — {len(timeline)} events")

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path  = os.path.join(_REPORTS, f"{case_id}_{ts}_timeline.csv")
        json_path = os.path.join(_REPORTS, f"{case_id}_{ts}_timeline.json")
        timeline_builder.export_csv(timeline, csv_path)
        timeline_builder.export_json(timeline, json_path)
        ok(f"Timeline CSV  → {csv_path}")
        ok(f"Timeline JSON → {json_path}")

    # ── 8. Build & print report ────────────────────────────────────────────────
    report = report_generator.build_report(
        case_id=case_id,
        analyst=analyst,
        access_result=access_result,
        auth_result=auth_result,
        error_result=error_result,
        firewall_result=fw_result,
        ioc_result=ioc_result,
        timeline=timeline,
        ti_results=ti_results,
    )

    report_generator.print_report(report)

    saved = report_generator.save_text_report(report, output_dir=_REPORTS)
    ok(f"Report saved → {saved}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Incident Response Toolkit — SOC Investigation CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ir_toolkit/main.py
  python ir_toolkit/main.py --case IR-2026-042 --analyst "Alice Smith"
  python ir_toolkit/main.py --access /var/log/nginx/access.log --auth /var/log/auth.log
  python ir_toolkit/main.py --no-ti
        """,
    )
    parser.add_argument("--case",        default="IR-001",       help="Case/incident ID")
    parser.add_argument("--analyst",     default="SOC Analyst",  help="Analyst name")
    parser.add_argument("--access",      default=None,           help="Path to web access log")
    parser.add_argument("--auth",        default=None,           help="Path to auth.log")
    parser.add_argument("--error",       default=None,           help="Path to error.log")
    parser.add_argument("--fw",          default=None,           help="Path to firewall log")
    parser.add_argument("--ioc",         default=None,           help="Path to IOC evidence file")
    parser.add_argument("--no-ti",       action="store_true",    help="Skip threat-intel lookups")
    parser.add_argument("--no-timeline", action="store_true",    help="Skip timeline export")
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
