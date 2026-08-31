"""
Parser for generic newline-delimited JSON events.

Cloud services, EDR agents, and custom applications usually ship structured
JSON logs rather than free-text lines. This parser maps a loosely-defined
JSON schema onto the normalized `Event`. We use it here to represent
"network connection" telemetry (e.g. NetFlow/firewall-style records) for the
port-scan detection rule, since that data doesn't naturally come from
plain-text sshd/web logs.

Expected shape (extra keys are preserved verbatim in `Event.extra`):
    {
      "timestamp": "2026-08-31T10:15:00+00:00",
      "source": "firewall",
      "event_type": "network",
      "outcome": "success",
      "src_ip": "203.0.113.5",
      "dst_ip": "10.0.0.7",
      "dst_port": 22,
      "user": null,
      "message": "connection allowed",
      ...any other fields...
    }
"""

from __future__ import annotations

import json
from typing import Optional

from siem.models import Event, utcnow_iso

_KNOWN_FIELDS = {"timestamp", "source", "event_type", "outcome", "src_ip", "dst_ip", "dst_port", "user", "message"}


def parse(line: str) -> Optional[Event]:
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    extra = {k: v for k, v in data.items() if k not in _KNOWN_FIELDS}

    return Event.new(
        timestamp=data.get("timestamp", utcnow_iso()),
        source=data.get("source", "json"),
        event_type=data.get("event_type", "unknown"),
        outcome=data.get("outcome", "unknown"),
        src_ip=data.get("src_ip"),
        dst_ip=data.get("dst_ip"),
        dst_port=data.get("dst_port"),
        user=data.get("user"),
        message=data.get("message", ""),
        raw=line,
        extra=extra,
    )
