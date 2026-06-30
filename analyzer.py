from utils import extract_ips, extract_status_codes, detect_suspicious
from collections import Counter

file_path = "logs/access.log"

with open(file_path, "r", errors="ignore") as f:
    logs = f.readlines()

print("\n===== LOG ANALYZER STARTED =====\n")

ips = extract_ips(logs)
status_codes = extract_status_codes(logs)
alerts = detect_suspicious(logs)

ip_count = Counter(ips)
status_count = Counter(status_codes)

print("Total log lines:", len(logs))
print("Unique IPs:", len(set(ips)))
print("Suspicious events:", len(alerts))

print("\n--- TOP 5 IPs ---")
for ip, count in ip_count.most_common(5):
    print(ip, "->", count)

print("\n--- STATUS CODES ---")
for code, count in status_count.items():
    print(code, "->", count)

print("\n===== ANALYSIS DONE =====\n")