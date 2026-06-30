"""
core/reporter.py
----------------
Handles all output:
  - Colored terminal output (SOC-analyst style)
  - Plain-text report file saved under output/
  - Optional matplotlib chart saved as PNG
"""

import os
import datetime
from core.detector import ThreatSummary, top_attackers

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False


# ── Color helpers ─────────────────────────────────────────────────────────────

def _c(text: str, color: str) -> str:
    """Wrap text in a colorama color if available, otherwise return plain."""
    if not HAS_COLOR:
        return text
    colors = {
        "red":    Fore.RED,
        "green":  Fore.GREEN,
        "yellow": Fore.YELLOW,
        "cyan":   Fore.CYAN,
        "white":  Fore.WHITE,
        "magenta": Fore.MAGENTA,
    }
    return f"{colors.get(color, '')}{Style.BRIGHT}{text}{Style.RESET_ALL}"


def _risk_color(level: str) -> str:
    mapping = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
    return mapping.get(level, "white")


# ── Terminal output ───────────────────────────────────────────────────────────

def _divider(char: str = "─", width: int = 62) -> str:
    return char * width


def print_report(summary: ThreatSummary, log_path: str) -> None:
    """Print a formatted SOC-style report to the terminal."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk = summary.risk_level
    risk_col = _risk_color(risk)

    print()
    print(_c("╔══════════════════════════════════════════════════════════════╗", "cyan"))
    print(_c("║         SOC LOG ANALYZER — THREAT INTELLIGENCE REPORT       ║", "cyan"))
    print(_c("╚══════════════════════════════════════════════════════════════╝", "cyan"))
    print(_c(f"  Analyzed : {log_path}", "white"))
    print(_c(f"  Generated: {now}", "white"))
    print()

    # ── Overview ──────────────────────────────────────────────────────────────
    print(_c("  OVERVIEW", "cyan"))
    print(_c(_divider(), "white"))
    print(f"  Total log entries   : {_c(str(summary.total_entries), 'white')}")
    print(f"  Unique IP addresses : {_c(str(summary.unique_ips), 'white')}")
    print(f"  Risk Level          : {_c(f'[ {risk} ]', risk_col)}")
    print()

    # ── Status codes ─────────────────────────────────────────────────────────
    print(_c("  HTTP STATUS CODES", "cyan"))
    print(_c(_divider(), "white"))
    for code, count in sorted(summary.status_counts.items()):
        if code.startswith("2"):
            col = "green"
        elif code.startswith("4"):
            col = "yellow"
        elif code.startswith("5"):
            col = "red"
        else:
            col = "white"
        bar = "█" * min(count, 30)
        print(f"  {_c(code, col)}  {bar}  {count}")
    print()

    # ── Top IPs ───────────────────────────────────────────────────────────────
    print(_c("  TOP REQUESTING IPs", "cyan"))
    print(_c(_divider(), "white"))
    for ip, count in top_attackers(summary, 8):
        label = ""
        if any(d["ip"] == ip for d in summary.brute_force_ips):
            label += _c(" [BRUTE-FORCE]", "red")
        if any(d["ip"] == ip for d in summary.scanning_ips):
            label += _c(" [SCANNER]", "yellow")
        if any(d["ip"] == ip for d in summary.sqli_attempts):
            label += _c(" [SQLI]", "red")
        print(f"  {_c(ip.ljust(18), 'white')}  {str(count).rjust(4)} requests{label}")
    print()

    # ── Successful 200 access list ────────────────────────────────────────────
    print(_c("  SUCCESSFUL 200 ACCESS LIST", "green"))
    print(_c(_divider(), "white"))
    if summary.ip_200_counts:
        for ip, count in summary.ip_200_counts.most_common():
            label = f"{count} successful request{'s' if count > 1 else ''}"
            print(f"  {_c('✔', 'green')} {_c(ip.ljust(18), 'white')}  → {_c(label, 'green')}")
    else:
        print(_c("  No successful (200) requests found.", "yellow"))
    print()

    # ── Brute force ───────────────────────────────────────────────────────────
    if summary.brute_force_ips:
        print(_c("  ⚠  BRUTE-FORCE ATTACKS DETECTED", "red"))
        print(_c(_divider(), "white"))
        for item in summary.brute_force_ips:
            print(f"  {_c('►', 'red')} IP {_c(item['ip'], 'white')} — {item['attempts']} failed auth attempts")
        print()

    # ── Scanning ─────────────────────────────────────────────────────────────
    if summary.scanning_ips:
        print(_c("  ⚠  SCANNING / ENUMERATION DETECTED", "yellow"))
        print(_c(_divider(), "white"))
        for item in summary.scanning_ips:
            print(f"  {_c('►', 'yellow')} IP {_c(item['ip'], 'white')} — {item['not_found_requests']} 404 responses")
        print()

    # ── SQLi ──────────────────────────────────────────────────────────────────
    if summary.sqli_attempts:
        print(_c("  ⚠  SQL INJECTION PROBES DETECTED", "red"))
        print(_c(_divider(), "white"))
        for item in summary.sqli_attempts:
            path_short = item["path"][:55] + "…" if len(item["path"]) > 55 else item["path"]
            print(f"  {_c('►', 'red')} IP {_c(item['ip'], 'white')} → {_c(path_short, 'yellow')}")
            print(f"      pattern: {_c(item['pattern'], 'magenta')}")
        print()

    # ── Suspicious paths ──────────────────────────────────────────────────────
    if summary.suspicious_path_hits:
        print(_c("  ⚠  SUSPICIOUS ENDPOINT ACCESS", "yellow"))
        print(_c(_divider(), "white"))
        for item in summary.suspicious_path_hits[:15]:  # cap display at 15
            status_col = "green" if item["status"] == 200 else "yellow"
            print(
                f"  {_c('►', 'yellow')} {_c(item['ip'].ljust(18), 'white')}"
                f"  [{_c(str(item['status']), status_col)}]  {item['path']}"
            )
        if len(summary.suspicious_path_hits) > 15:
            print(f"  ... and {len(summary.suspicious_path_hits) - 15} more")
        print()

    # ── Footer ────────────────────────────────────────────────────────────────
    print(_c(_divider("═"), "cyan"))
    print(_c(f"  FINAL VERDICT: {risk} RISK", risk_col))
    print(_c(_divider("═"), "cyan"))
    print()


# ── Text file report ─────────────────────────────────────────────────────────

def save_text_report(summary: ThreatSummary, log_path: str, output_dir: str = "output") -> str:
    """Save a plain-text report and return the path."""
    os.makedirs(output_dir, exist_ok=True)
    now = datetime.datetime.now()
    filename = os.path.join(output_dir, f"report_{now.strftime('%Y%m%d_%H%M%S')}.txt")

    lines = [
        "=" * 64,
        "   SOC LOG ANALYZER — THREAT INTELLIGENCE REPORT",
        "=" * 64,
        f"  Analyzed : {log_path}",
        f"  Generated: {now.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "  OVERVIEW",
        "-" * 64,
        f"  Total log entries   : {summary.total_entries}",
        f"  Unique IP addresses : {summary.unique_ips}",
        f"  Risk Level          : {summary.risk_level}",
        "",
        "  HTTP STATUS CODES",
        "-" * 64,
    ]
    for code, count in sorted(summary.status_counts.items()):
        lines.append(f"  {code}  :  {count}")

    lines += ["", "  TOP REQUESTING IPs", "-" * 64]
    for ip, count in top_attackers(summary, 10):
        lines.append(f"  {ip.ljust(18)}  {count} requests")

    if summary.brute_force_ips:
        lines += ["", "  BRUTE-FORCE ATTACKS", "-" * 64]
        for item in summary.brute_force_ips:
            lines.append(f"  {item['ip']}  —  {item['attempts']} failed auth attempts")

    if summary.scanning_ips:
        lines += ["", "  SCANNING / ENUMERATION", "-" * 64]
        for item in summary.scanning_ips:
            lines.append(f"  {item['ip']}  —  {item['not_found_requests']} 404 responses")

    if summary.sqli_attempts:
        lines += ["", "  SQL INJECTION PROBES", "-" * 64]
        for item in summary.sqli_attempts:
            lines.append(f"  {item['ip']}  →  {item['path']}")
            lines.append(f"      pattern: {item['pattern']}")

    lines += ["", "  SUCCESSFUL 200 ACCESS LIST", "-" * 64]
    if summary.ip_200_counts:
        for ip, count in summary.ip_200_counts.most_common():
            label = f"{count} successful request{'s' if count > 1 else ''}"
            lines.append(f"  ✔  {ip.ljust(18)}  →  {label}")
    else:
        lines.append("  No successful (200) requests found.")

    if summary.suspicious_path_hits:
        lines += ["", "  SUSPICIOUS ENDPOINT ACCESS", "-" * 64]
        for item in summary.suspicious_path_hits:
            lines.append(f"  [{item['status']}]  {item['ip'].ljust(18)}  {item['path']}")

    lines += [
        "",
        "=" * 64,
        f"  FINAL VERDICT: {summary.risk_level} RISK",
        "=" * 64,
    ]

    with open(filename, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return filename


# ── Matplotlib chart ──────────────────────────────────────────────────────────

def save_chart(summary: ThreatSummary, output_dir: str = "output") -> str | None:
    """
    Generate a bar chart of top IPs by request count.
    Returns the saved path, or None if matplotlib is unavailable.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")   # non-interactive backend
        import matplotlib.pyplot as plt
    except ImportError:
        return None

    os.makedirs(output_dir, exist_ok=True)
    now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    chart_path = os.path.join(output_dir, f"top_ips_{now}.png")

    attackers = top_attackers(summary, 10)
    if not attackers:
        return None

    ips = [a[0] for a in attackers]
    counts = [a[1] for a in attackers]

    # Assign colors: red for flagged IPs, steelblue otherwise
    flagged = {
        d["ip"] for lst in (
            summary.brute_force_ips,
            summary.scanning_ips,
            summary.sqli_attempts,
        )
        for d in lst
    }
    colors = ["#e74c3c" if ip in flagged else "#2980b9" for ip in ips]

    # Reverse so highest count appears at the top of a horizontal bar chart
    ips_r    = ips[::-1]
    counts_r = counts[::-1]
    colors_r = colors[::-1]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.barh(ips_r, counts_r, color=colors_r, edgecolor="white", linewidth=0.5)
    ax.set_xlabel("Request Count", fontsize=11)
    ax.set_title("Top IPs by Request Volume  (red = flagged threat)", fontsize=13, fontweight="bold")
    ax.set_facecolor("#1a1a2e")
    fig.patch.set_facecolor("#16213e")
    ax.tick_params(colors="white")
    ax.xaxis.label.set_color("white")
    ax.title.set_color("white")
    for spine in ax.spines.values():
        spine.set_edgecolor("#333355")
    # bar_label requires the BarContainer object — never slice it
    ax.bar_label(bars, padding=4, color="white", fontsize=9)

    plt.tight_layout()
    plt.savefig(chart_path, dpi=150, bbox_inches="tight")
    plt.close()

    return chart_path
