"""
Parser for Apache/Nginx "combined" access log lines, e.g.:

    203.0.113.9 - - [31/Aug/2026:10:15:00 +0000] "GET /admin.php?id=1 UNION SELECT 1,2,3-- HTTP/1.1" 200 512 "-" "curl/8.4.0"

Beyond parsing, this module flags a couple of classic web-attack indicators
(SQL injection / path traversal patterns) into `extra["suspicious_patterns"]`
so detection rules can key off them without re-implementing string matching
in every rule.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from siem.models import Event

_LOG_RE = re.compile(
    r'^(?P<ip>[\d.]+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>.+?)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)

_SUSPICIOUS_PATTERNS = [
    ("sqli", re.compile(r"(union\s+select|or\s+1=1|--|;--|'\s*or\s*')", re.IGNORECASE)),
    ("path_traversal", re.compile(r"\.\./|%2e%2e%2f", re.IGNORECASE)),
    ("xss", re.compile(r"<script|onerror=|javascript:", re.IGNORECASE)),
]


def _parse_timestamp(ts: str) -> str:
    try:
        dt = datetime.strptime(ts.split()[0], "%d/%b/%Y:%H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).isoformat(timespec="seconds")
    except ValueError:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse(line: str) -> Optional[Event]:
    line = line.rstrip("\n")
    m = _LOG_RE.match(line)
    if not m:
        return None

    path = m.group("path")
    status = int(m.group("status"))
    matched_patterns = [name for name, pattern in _SUSPICIOUS_PATTERNS if pattern.search(path)]

    return Event.new(
        timestamp=_parse_timestamp(m.group("ts")),
        source="web_access",
        event_type="web_request",
        outcome="success" if status < 400 else "failure",
        src_ip=m.group("ip"),
        message=f"{m.group('method')} {path} -> {status}",
        raw=line,
        extra={
            "method": m.group("method"),
            "path": path,
            "http_status": status,
            "suspicious_patterns": matched_patterns,
        },
    )
