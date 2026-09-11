"""
Parser for OpenSSH daemon (sshd) auth log lines, e.g. from /var/log/auth.log.

This is one of the most common "SOC 101" log sources: SSH brute force and
credential stuffing show up here first.

IMPORTANT — one connection produces many lines.
---------------------------------------------
Real sshd logs are not one-line-per-event. A single failed login attempt can
emit seven lines, all sharing the same sshd PID:

    sshd[24200]: reverse mapping checking getaddrinfo for ns.example.com
                 [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!
    sshd[24200]: Invalid user webmaster from 173.234.31.186
    sshd[24200]: input_userauth_request: invalid user webmaster [preauth]
    sshd[24200]: pam_unix(sshd:auth): check pass; user unknown
    sshd[24200]: pam_unix(sshd:auth): authentication failure; ... rhost=173.234.31.186
    sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926
    sshd[24200]: Connection closed by 173.234.31.186 [preauth]

If every one of those became an `authentication/failure` event, a threshold
rule counting 5 failures would fire after fewer than two real attempts. So the
parser classifies lines into distinct `event_type` values and marks exactly
ONE line per connection as the authoritative authentication event:

    authentication  the credential attempt itself (Failed */Accepted *)
    warning         security warnings sshd raises on its own
    scan            connections that never attempted to authenticate
    session         clean session end
    context         recognised, but a duplicate of the authentication event
    daemon          NOT RECOGNISED - the residual, useful as a coverage metric

Counting rules should look at `authentication`. `context` is stored for
investigation but never counted. A rising `daemon` count means real logs have
line shapes this parser still doesn't understand.

The sshd PID is captured into `extra["pid"]`. Nothing uses it yet, but it is
the key that groups all lines of one connection, and therefore the basis for
proper per-connection deduplication later.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from siem.models import Event

_SYSLOG_PREFIX = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

# --- authoritative authentication lines -----------------------------------
# "Failed password for invalid user admin from 1.2.3.4 port 5 ssh2"
# "Failed none for invalid user admin from 1.2.3.4 port 5 ssh2"   <- scanner probe
_FAILED = re.compile(
    r"Failed (?P<method>\S+) for (?P<invalid>invalid user\s+)?(?P<user>\S+)\s+"
    r"from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
_ACCEPTED = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
# NOTE: "No more user authentication methods" was originally classified as an
# authentication failure. Measured against real data, all 45 connections that
# emit it ALSO emit a "Failed ..." line — it is a duplicate, so it is context.

# --- security warnings sshd raises itself ---------------------------------
_BREAK_IN = re.compile(
    r"reverse mapping checking getaddrinfo for (?P<rdns>\S+) \[(?P<ip>[\d.]+)\] failed"
)

# --- scanning / never-authenticated ---------------------------------------
_NO_IDENT = re.compile(r"Did not receive identification string from (?P<ip>[\d.]+)")
_CLOSED_PREAUTH = re.compile(r"Connection closed by (?P<ip>[\d.]+) \[preauth\]")
_DISCONNECT_PREAUTH = re.compile(r"Received disconnect from (?P<ip>[\d.]+).*\[preauth\]")

# --- clean session end ----------------------------------------------------
_DISCONNECT_USER = re.compile(
    r"Received disconnect from (?P<ip>[\d.]+): \d+: disconnected by user"
)

# --- recognised duplicates of the authentication event --------------------
_CONTEXT = [
    re.compile(r"^Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"),
    re.compile(r"^input_userauth_request:"),
    re.compile(r"^pam_unix\(sshd:auth\):"),
    re.compile(r"^PAM \d+ more authentication failure"),
    re.compile(r"^PAM service\(sshd\) ignoring max retries"),
    re.compile(r"^Disconnecting: Too many authentication failures"),
    re.compile(r"No more user authentication methods"),
]
_RHOST = re.compile(r"rhost=(?P<rhost>\S+)")


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
    base = {
        "timestamp": _syslog_timestamp(m.group("mon"), m.group("day"), m.group("time")),
        "source": "sshd",
        "message": msg,
        "raw": line,
    }
    extra = {"host": m.group("host")}
    if m.group("pid"):
        extra["pid"] = m.group("pid")

    # 1. AUTHENTICATION — the authoritative credential attempt.
    fm = _FAILED.search(msg)
    if fm:
        return Event.new(
            **base, event_type="authentication", outcome="failure",
            src_ip=fm.group("ip"), user=fm.group("user"),
            extra={**extra, "port": int(fm.group("port")),
                   "auth_method": fm.group("method"),
                   "invalid_user": bool(fm.group("invalid"))},
        )

    am = _ACCEPTED.search(msg)
    if am:
        return Event.new(
            **base, event_type="authentication", outcome="success",
            src_ip=am.group("ip"), user=am.group("user"),
            extra={**extra, "port": int(am.group("port")),
                   "auth_method": am.group("method")},
        )

    # 2. WARNING — sshd flagging something itself.
    bm = _BREAK_IN.search(msg)
    if bm:
        return Event.new(
            **base, event_type="warning", outcome="unknown",
            src_ip=bm.group("ip"),
            extra={**extra, "reason": "reverse_dns_mismatch", "rdns": bm.group("rdns")},
        )

    # 3. SESSION — clean end. Checked before the scan patterns because a
    #    user-initiated disconnect is also a "Received disconnect" line.
    dm = _DISCONNECT_USER.search(msg)
    if dm:
        return Event.new(
            **base, event_type="session", outcome="success",
            src_ip=dm.group("ip"), extra={**extra, "reason": "disconnected_by_user"},
        )

    # 4. SCAN — spoke to the port but never completed an auth attempt.
    for pattern, reason in (
        (_NO_IDENT, "no_identification_string"),
        (_CLOSED_PREAUTH, "closed_preauth"),
        (_DISCONNECT_PREAUTH, "disconnect_preauth"),
    ):
        sm = pattern.search(msg)
        if sm:
            return Event.new(
                **base, event_type="scan", outcome="unknown",
                src_ip=sm.group("ip"), extra={**extra, "reason": reason},
            )

    # 5. CONTEXT — recognised, but a duplicate of the authentication event.
    #    Stored for investigation, deliberately not counted by threshold rules.
    for pattern in _CONTEXT:
        cm = pattern.search(msg)
        if cm:
            groups = cm.groupdict()
            ip = groups.get("ip")
            if not ip:
                rm = _RHOST.search(msg)          # pam_unix carries rhost=
                if rm and re.fullmatch(r"[\d.]+", rm.group("rhost")):
                    ip = rm.group("rhost")
            return Event.new(
                **base, event_type="context", outcome="unknown",
                src_ip=ip, user=groups.get("user"), extra=extra,
            )

    # 6. DAEMON — not recognised. The size of this bucket is a coverage metric:
    #    if it grows, real logs contain shapes this parser doesn't know yet.
    return Event.new(**base, event_type="daemon", outcome="unknown", extra=extra)
