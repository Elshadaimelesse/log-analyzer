import re
from collections import Counter

def extract_ips(logs):
    ips = []
    for line in logs:
        match = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
        if match:
            ips.append(match[0])
    return ips


def extract_status_codes(logs):
    codes = []
    for line in logs:
        match = re.findall(r'"\s(\d{3})\s', line)
        if match:
            codes.append(match[0])
    return codes


def detect_suspicious(logs):
    keywords = ["404", "500", "login", "admin", "sql", "error", "cmd", "bash"]
    alerts = []

    for line in logs:
        for word in keywords:
            if word in line.lower():
                alerts.append(line)
                break

    return alerts