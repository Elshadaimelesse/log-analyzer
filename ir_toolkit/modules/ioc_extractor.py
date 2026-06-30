"""
modules/ioc_extractor.py
-------------------------
Extracts Indicators of Compromise (IOCs) from any text-based evidence file:
  - IPv4 addresses
  - Domain names
  - URLs (http / https / ftp)
  - MD5 / SHA1 / SHA256 hashes
  - Email addresses
  - CVE identifiers
  - Windows registry key paths
  - File paths (Unix & Windows)

Returns a structured IOCResult that can be fed into threat_intelligence.py
for reputation lookups or included directly in the final report.
"""

import re
from dataclasses import dataclass, field

# ── Regex patterns ────────────────────────────────────────────────────────────

_RE_IPV4   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|gov|edu|mil|int|co|uk|de|ru|cn|info|biz|xyz|onion)\b',
    re.IGNORECASE,
)
_RE_URL    = re.compile(r'https?://[^\s\'"<>]+|ftp://[^\s\'"<>]+', re.IGNORECASE)
_RE_MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')
_RE_SHA1   = re.compile(r'\b[a-fA-F0-9]{40}\b')
_RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_RE_EMAIL  = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')
_RE_CVE    = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
_RE_REGKEY = re.compile(
    r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKEY_\w+)'
    r'(?:\\[\w\s\-\.]+)+',
    re.IGNORECASE,
)
_RE_UNIXPATH  = re.compile(r'(?<!\w)/(?:[a-zA-Z0-9_\-\.]+/)+[a-zA-Z0-9_\-\.]*')
_RE_WINPATH   = re.compile(r'[A-Za-z]:\\(?:[^\\\s/:*?"<>|\r\n]+\\)*[^\\\s/:*?"<>|\r\n]*')

# Private / loopback ranges to filter from IPs
_PRIVATE = re.compile(
    r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.)'
)


@dataclass
class IOCResult:
    source: str
    ips: list[str]       = field(default_factory=list)
    domains: list[str]   = field(default_factory=list)
    urls: list[str]      = field(default_factory=list)
    md5s: list[str]      = field(default_factory=list)
    sha1s: list[str]     = field(default_factory=list)
    sha256s: list[str]   = field(default_factory=list)
    emails: list[str]    = field(default_factory=list)
    cves: list[str]      = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    file_paths: list[str]    = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum([
            len(self.ips), len(self.domains), len(self.urls),
            len(self.md5s), len(self.sha1s), len(self.sha256s),
            len(self.emails), len(self.cves),
            len(self.registry_keys), len(self.file_paths),
        ])


def extract(filepath: str, include_private_ips: bool = False) -> IOCResult:
    """Extract all IOCs from a file. Private IPs are filtered by default."""
    result = IOCResult(source=filepath)
    try:
        text = open(filepath, "r", errors="ignore").read()
    except FileNotFoundError:
        return result

    # Deduplicate while preserving order
    def dedup(lst):
        seen = set()
        return [x for x in lst if not (x in seen or seen.add(x))]

    raw_ips = _RE_IPV4.findall(text)
    result.ips = dedup([
        ip for ip in raw_ips
        if include_private_ips or not _PRIVATE.match(ip)
    ])

    result.domains = dedup(_RE_DOMAIN.findall(text))
    result.urls    = dedup(_RE_URL.findall(text))

    # Hashes — longest first to avoid substring collisions
    result.sha256s = dedup(_RE_SHA256.findall(text))
    result.sha1s   = dedup([h for h in _RE_SHA1.findall(text) if h not in result.sha256s])
    result.md5s    = dedup([h for h in _RE_MD5.findall(text)
                            if h not in result.sha256s and h not in result.sha1s])

    result.emails       = dedup(_RE_EMAIL.findall(text))
    result.cves         = dedup([c.upper() for c in _RE_CVE.findall(text)])
    result.registry_keys = dedup(_RE_REGKEY.findall(text))
    result.file_paths   = dedup(_RE_UNIXPATH.findall(text) + _RE_WINPATH.findall(text))

    return result
