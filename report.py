from utils import extract_ips, extract_status_codes, detect_suspicious
from collections import Counter

def generate_report(logs):
    ips = extract_ips(logs)
    alerts = detect_suspicious(logs)
    status_codes = extract_status_codes(logs)

    ip_count = Counter(ips)

    report = f"""
========== SECURITY REPORT ==========

Total Logs: {len(logs)}
Unique IPs: {len(set(ips))}
Suspicious Events: {len(alerts)}

Top Attacker IP:
{ip_count.most_common(1)}

Status Codes:
{Counter(status_codes)}

=====================================
"""
    return report