"""
Parser for OpenSSH daemon (sshd) auth log lines, e.g. from /var/log/auth.log.

This is one of the most common "SOC 101" log sources: SSH brute force and
credential stuffing show up here first. Real syslog lines look like:

    Aug 31 10:15:02 web01 sshd[1234]: Failed password for invalid user admin \
        from 203.0.113.5 port 51515 ssh2
    Aug 31 10:16:40 web01 sshd[1234]: Accepted password for gaston from \
        192.168.1.10 port 51522 ssh2

We deliberately keep this to regex + stdlib: a real ingestion pipeline for a
line-oriented text format almost always looks like this before anyone reaches
for a heavier parsing library.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from siem.models import Event

_SYSLOG_PREFIX = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(\[\d+\])?:\s+(?P<msg>.*)$"
)

_FAILED = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
_ACCEPTED = re.compile(
    r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
_INVALID_USER = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")


def _syslog_timestamp(mon: str, day: str, time_str: str) -> str:
    year = datetime.now(timezone.utc).year
    try:
        dt = datetime.strptime(f"{year} {mon} {int(day):02d} {time_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        dt = datetime.now(timezone.utc)
    return dt.replace(tzinfo=timezone.utc).isoformat(timespec="seconds")


def parse(line: str) -> Optional[Event]:
    """Parse a single sshd syslog line into a normalized Event, or None."""
    line = line.rstrip("\n")
    m = _SYSLOG_PREFIX.match(line)
    if not m:
        return None

    msg = m.group("msg")
    timestamp = _syslog_timestamp(m.group("mon"), m.group("day"), m.group("time"))

    fm = _FAILED.search(msg)
    if fm:
        return Event.new(
            timestamp=timestamp,
            source="sshd",
            event_type="authentication",
            outcome="failure",
            src_ip=fm.group("ip"),
            user=fm.group("user"),
            message=msg,
            raw=line,
            extra={"host": m.group("host"), "port": int(fm.group("port"))},
        )

    am = _ACCEPTED.search(msg)
    if am:
        return Event.new(
            timestamp=timestamp,
            source="sshd",
            event_type="authentication",
            outcome="success",
            src_ip=am.group("ip"),
            user=am.group("user"),
            message=msg,
            raw=line,
            extra={"host": m.group("host"), "port": int(am.group("port"))},
        )

    im = _INVALID_USER.search(msg)
    if im:
        return Event.new(
            timestamp=timestamp,
            source="sshd",
            event_type="authentication",
            outcome="failure",
            src_ip=im.group("ip"),
            user=im.group("user"),
            message=msg,
            raw=line,
            extra={"host": m.group("host"), "reason": "invalid_user"},
        )

    # Unrecognized sshd message (key rotation, session opened, etc.) - still
    # normalize it as a low-signal event rather than dropping it silently.
    return Event.new(
        timestamp=timestamp,
        source="sshd",
        event_type="daemon",
        outcome="unknown",
        message=msg,
        raw=line,
        extra={"host": m.group("host")},
    )
