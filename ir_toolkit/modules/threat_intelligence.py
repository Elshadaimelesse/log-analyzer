"""
modules/threat_intelligence.py
--------------------------------
Offline threat intelligence enrichment.

Provides:
  1. Known-bad IP / domain lists (bundled, no API key required)
  2. AbuseIPDB lookup (optional — requires free API key)
  3. VirusTotal hash lookup (optional — requires free API key)
  4. GeoIP country lookup via ip-api.com (free, no key)

All network calls time out gracefully — the tool works fully offline
if no API keys are configured or if the network is unreachable.

Usage:
    from modules.threat_intelligence import enrich_ip, enrich_hash

    result = enrich_ip("45.33.32.156")
    print(result)
"""

import os
import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional

# ── Bundled known-bad lists (minimal, illustrative) ───────────────────────────
# In a real deployment these would be loaded from threat-feed files.

KNOWN_BAD_IPS: set[str] = {
    "45.33.32.156",    # Shodan scanner
    "80.82.77.33",     # Shodan
    "198.20.69.74",    # Shodan
    "209.126.110.87",  # known scanner
    "1.2.3.4",         # placeholder attacker (from sample log)
}

KNOWN_BAD_DOMAINS: set[str] = {
    "evil.onion",
    "malware-c2.ru",
    "phishing-site.xyz",
}

KNOWN_BAD_HASHES: set[str] = {
    "d41d8cd98f00b204e9800998ecf8427e",  # empty file MD5 (illustrative)
}

# ── GeoIP (free, no key) ─────────────────────────────────────────────────────

_GEOIP_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as,query"
_TIMEOUT   = 4   # seconds


@dataclass
class IPIntel:
    ip: str
    known_bad: bool              = False
    country: str                 = "Unknown"
    country_code: str            = ""
    city: str                    = ""
    isp: str                     = ""
    org: str                     = ""
    asn: str                     = ""
    abuseipdb_score: Optional[int] = None
    tags: list[str]              = field(default_factory=list)

    def __str__(self) -> str:
        flag = "🚨 KNOWN BAD" if self.known_bad else "ℹ"
        geo  = f"{self.city}, {self.country}" if self.city else self.country
        return (f"{flag}  {self.ip}  |  {geo}  |  {self.isp or self.org}  "
                f"|  {self.asn}  |  Score: {self.abuseipdb_score}")


@dataclass
class HashIntel:
    hash_value: str
    known_bad: bool  = False
    vt_detections: Optional[int]  = None
    vt_total: Optional[int]       = None
    tags: list[str]               = field(default_factory=list)


# ── Public API lookup helpers ─────────────────────────────────────────────────

def _http_get(url: str, headers: dict | None = None) -> dict | None:
    """Tiny HTTP GET wrapper — returns parsed JSON or None on any error."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _geoip(ip: str) -> dict:
    data = _http_get(_GEOIP_URL.format(ip=ip))
    if data and data.get("status") == "success":
        return data
    return {}


def _abuseipdb(ip: str, api_key: str) -> Optional[int]:
    """Return abuse confidence score (0–100) or None."""
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    data = _http_get(url, headers={"Key": api_key, "Accept": "application/json"})
    if data and "data" in data:
        return data["data"].get("abuseConfidenceScore")
    return None


def _virustotal_hash(h: str, api_key: str) -> tuple[Optional[int], Optional[int]]:
    """Return (detections, total) or (None, None)."""
    url  = f"https://www.virustotal.com/api/v3/files/{h}"
    data = _http_get(url, headers={"x-apikey": api_key})
    if data and "data" in data:
        stats = data["data"]["attributes"].get("last_analysis_stats", {})
        return stats.get("malicious", 0), sum(stats.values())
    return None, None


# ── Public interface ──────────────────────────────────────────────────────────

def enrich_ip(
    ip: str,
    abuseipdb_key: str = "",
    geoip: bool = True,
) -> IPIntel:
    """Return enriched IPIntel for a single IP address."""
    intel = IPIntel(ip=ip)
    intel.known_bad = ip in KNOWN_BAD_IPS

    if geoip:
        geo = _geoip(ip)
        intel.country      = geo.get("country", "Unknown")
        intel.country_code = geo.get("countryCode", "")
        intel.city         = geo.get("city", "")
        intel.isp          = geo.get("isp", "")
        intel.org          = geo.get("org", "")
        intel.asn          = geo.get("as", "")

    if abuseipdb_key:
        intel.abuseipdb_score = _abuseipdb(ip, abuseipdb_key)
        if intel.abuseipdb_score and intel.abuseipdb_score >= 50:
            intel.known_bad = True
            intel.tags.append(f"AbuseIPDB:{intel.abuseipdb_score}")

    if intel.known_bad and "KNOWN_BAD_LIST" not in intel.tags:
        intel.tags.insert(0, "KNOWN_BAD_LIST")

    return intel


def enrich_ips(
    ips: list[str],
    abuseipdb_key: str = "",
    geoip: bool = True,
) -> dict[str, IPIntel]:
    """Enrich a list of IPs. Returns {ip: IPIntel}."""
    return {ip: enrich_ip(ip, abuseipdb_key=abuseipdb_key, geoip=geoip) for ip in ips}


def enrich_hash(h: str, virustotal_key: str = "") -> HashIntel:
    """Return enriched HashIntel for an MD5/SHA1/SHA256 hash."""
    intel = HashIntel(hash_value=h)
    intel.known_bad = h.lower() in {x.lower() for x in KNOWN_BAD_HASHES}

    if virustotal_key:
        det, total = _virustotal_hash(h, virustotal_key)
        intel.vt_detections = det
        intel.vt_total      = total
        if det and det > 0:
            intel.known_bad = True
            intel.tags.append(f"VT:{det}/{total}")

    return intel


def load_feed_from_file(filepath: str) -> set[str]:
    """
    Load a plain-text threat feed (one IOC per line, # = comment).
    Returns a set of normalized strings.
    """
    iocs: set[str] = set()
    try:
        with open(filepath, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    iocs.add(line.lower())
    except FileNotFoundError:
        pass
    return iocs
