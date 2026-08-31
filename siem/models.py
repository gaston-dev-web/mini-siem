"""
Normalized data models shared across the whole pipeline.

Real SIEMs (Splunk's CIM, Elastic Common Schema, Sentinel's ASIM) all solve the
same problem: logs arrive in wildly different shapes (syslog, JSON, CSV, binary
Windows Event Log records...) but detection rules need to reason about them
uniformly. That's why the very first thing a SIEM does with a raw log line is
*normalize* it into a common schema. `Event` is that schema here.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Event:
    """A normalized log event (loosely inspired by Elastic Common Schema)."""

    id: str
    timestamp: str            # ISO-8601 UTC
    source: str                # e.g. "sshd", "nginx", "custom-json"
    event_type: str            # e.g. "authentication", "web_request", "network"
    outcome: str = "unknown"   # "success" | "failure" | "unknown"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    user: Optional[str] = None
    message: str = ""
    raw: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def new(**kwargs: Any) -> "Event":
        kwargs.setdefault("id", str(uuid.uuid4()))
        kwargs.setdefault("timestamp", utcnow_iso())
        return Event(**kwargs)

    def get(self, field_name: str, default: Any = None) -> Any:
        """Look up a field on the event, falling back to `extra`.

        This lets rules reference either a first-class column (src_ip, user, ...)
        or an arbitrary key a parser stashed in `extra` (e.g. http_status).
        """
        if hasattr(self, field_name):
            return getattr(self, field_name)
        return self.extra.get(field_name, default)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Alert:
    """An alert produced when a detection rule fires."""

    id: str
    rule_id: str
    rule_name: str
    severity: str
    timestamp: str
    description: str
    group_key: Optional[str] = None
    matched_event_ids: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def new(**kwargs: Any) -> "Alert":
        kwargs.setdefault("id", str(uuid.uuid4()))
        kwargs.setdefault("timestamp", utcnow_iso())
        return Alert(**kwargs)

    def to_dict(self) -> dict:
        return asdict(self)
