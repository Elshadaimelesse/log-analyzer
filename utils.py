# utils.py — legacy helpers (kept for reference)
# The upgraded project uses core/ modules instead.
# See core/parser.py and core/detector.py.

import re
from collections import Counter


def extract_ips(logs):
    return [m[0] for line in logs for m in [re.findall(r'\d+\.\d+\.\d+\.\d+', line)] if m]


def extract_status_codes(logs):
    return [m[0] for line in logs for m in [re.findall(r'"\s(\d{3})\s', line)] if m]


def detect_suspicious(logs):
    keywords = ["404", "500", "login", "admin", "sql", "error", "cmd", "bash"]
    return [line for line in logs if any(k in line.lower() for k in keywords)]
