"""
main.py
-------
Entry point for the SOC Log Analyzer CLI.

Usage:
    python main.py                          # analyze logs/access.log
    python main.py --log path/to/file.log   # custom log file
    python main.py --watch                  # real-time tail mode
    python main.py --no-chart               # skip chart generation
"""

import argparse
import time
import os
import sys

from core.parser import parse_log_file
from core.detector import analyze
from core.reporter import print_report, save_text_report, save_chart

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    def info(msg):  print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")
    def ok(msg):    print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} {msg}")
    def warn(msg):  print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
    def err(msg):   print(f"{Fore.RED}[✗]{Style.RESET_ALL} {msg}")
except ImportError:
    def info(msg):  print(f"[*] {msg}")
    def ok(msg):    print(f"[+] {msg}")
    def warn(msg):  print(f"[!] {msg}")
    def err(msg):   print(f"[-] {msg}")


DEFAULT_LOG = os.path.join("logs", "access.log")
OUTPUT_DIR  = "output"


def run_analysis(log_path: str, chart: bool = True) -> None:
    """Parse → Detect → Report in one shot."""
    info(f"Loading log file: {log_path}")
    entries = parse_log_file(log_path)

    if not entries:
        warn("No parseable log entries found. Check the log format.")
        return

    ok(f"Parsed {len(entries)} log entries")
    info("Running threat detection engine…")
    summary = analyze(entries)

    print_report(summary, log_path)

    report_path = save_text_report(summary, log_path, OUTPUT_DIR)
    ok(f"Text report saved → {report_path}")

    if chart:
        chart_path = save_chart(summary, OUTPUT_DIR)
        if chart_path:
            ok(f"Chart saved       → {chart_path}")
        else:
            warn("matplotlib not installed — skipping chart (pip install matplotlib)")


def watch_mode(log_path: str, interval: int = 5) -> None:
    """
    Real-time log monitoring: re-analyze the file every `interval` seconds
    and print a compact diff of new threats.
    Press Ctrl+C to stop.
    """
    warn(f"Watch mode active — polling {log_path} every {interval}s  (Ctrl+C to stop)")
    prev_size = 0

    try:
        while True:
            current_size = os.path.getsize(log_path) if os.path.exists(log_path) else 0
            if current_size != prev_size:
                os.system("cls" if os.name == "nt" else "clear")
                run_analysis(log_path, chart=False)
                prev_size = current_size
            time.sleep(interval)
    except KeyboardInterrupt:
        info("Watch mode stopped.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOC Log Analyzer — Cybersecurity Threat Intelligence Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py
  python main.py --log /var/log/nginx/access.log
  python main.py --watch --interval 10
  python main.py --no-chart
        """,
    )
    parser.add_argument("--log",      default=DEFAULT_LOG, help="Path to log file")
    parser.add_argument("--watch",    action="store_true",  help="Enable real-time watch mode")
    parser.add_argument("--interval", type=int, default=5,  help="Watch poll interval in seconds")
    parser.add_argument("--no-chart", action="store_true",  help="Disable chart generation")
    args = parser.parse_args()

    if not os.path.exists(args.log):
        err(f"Log file not found: {args.log}")
        sys.exit(1)

    if args.watch:
        watch_mode(args.log, args.interval)
    else:
        run_analysis(args.log, chart=not args.no_chart)


if __name__ == "__main__":
    main()
