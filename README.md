# 🛡️ SOC Log Analyzer — Cybersecurity Threat Intelligence Tool

A professional, portfolio-ready Security Operations Center (SOC) tool that analyzes
Apache/Nginx access logs and generates actionable threat intelligence reports.

---

## Features

| Feature | Description |
|---|---|
| **Log Parsing** | Parses Combined Log Format (Apache / Nginx) |
| **Brute-Force Detection** | Flags IPs with repeated failed auth attempts |
| **Scanner Detection** | Identifies IPs generating excessive 404 responses |
| **SQLi Detection** | Detects SQL injection pattern fragments in requests |
| **Suspicious Endpoints** | Flags access to `/admin`, `/wp-admin`, `/.env`, etc. |
| **Risk Scoring** | Assigns overall risk: LOW / MEDIUM / HIGH |
| **Colored Terminal Report** | SOC-style output with ANSI colors |
| **Text Report Export** | Saves detailed report to `output/` |
| **Chart Generation** | Bar chart of top IPs saved as PNG (matplotlib) |
| **Real-Time Watch Mode** | Polls log file and refreshes analysis on change |
| **Streamlit Dashboard** | Interactive web dashboard with charts and tables |

---

## Project Structure

```
log-analyzer/
├── core/
│   ├── __init__.py
│   ├── parser.py        # Log parsing → LogEntry dataclass
│   ├── detector.py      # Threat detection engine → ThreatSummary
│   └── reporter.py      # Terminal output, text report, chart
├── logs/
│   └── access.log       # Input log file
├── output/              # Generated reports & charts (auto-created)
├── main.py              # CLI entry point
├── dashboard.py         # Streamlit web dashboard
├── requirements.txt
└── README.md
```

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run CLI analysis
python main.py

# 3. Analyze a custom log file
python main.py --log /var/log/nginx/access.log

# 4. Real-time watch mode (re-analyzes when file changes)
python main.py --watch

# 5. Skip chart generation
python main.py --no-chart

# 6. Launch web dashboard
streamlit run dashboard.py
```

---

## CLI Flags

```
--log PATH        Path to log file (default: logs/access.log)
--watch           Enable real-time monitoring mode
--interval N      Watch poll interval in seconds (default: 5)
--no-chart        Disable PNG chart generation
```

---

## Detection Thresholds

Thresholds are defined in `core/detector.py` and can be tuned:

```python
BRUTE_FORCE_THRESHOLD = 5    # failed auth attempts per IP
SCAN_404_THRESHOLD    = 4    # 404 responses per IP
HIGH_FREQ_THRESHOLD   = 20   # total requests per IP
```

---

## Output

Every run produces:
- Colored terminal report
- `output/report_YYYYMMDD_HHMMSS.txt` — plain-text report
- `output/top_ips_YYYYMMDD_HHMMSS.png` — bar chart (if matplotlib installed)

---

## Tech Stack

- **Python 3.11+**
- colorama — terminal colors
- matplotlib — chart generation
- streamlit — web dashboard

---

*Built as a cybersecurity portfolio project demonstrating SOC analyst tooling.*
