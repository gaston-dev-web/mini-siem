"""
Maps a source/log-format name to the parser function that understands it.

This is deliberately tiny, but it's the same idea as a real SIEM's "sourcetype"
(Splunk) or "log source" (Sentinel/Sigma) concept: ingestion decides *which*
parser to run based on where the data came from, not by sniffing content.
"""

from __future__ import annotations

from typing import Callable, Optional

from siem.models import Event
from siem.parsers import sshd, web_access, json_event

ParserFn = Callable[[str], Optional[Event]]

PARSERS: dict[str, ParserFn] = {
    "sshd": sshd.parse,
    "web_access": web_access.parse,
    "json": json_event.parse,
}


def get_parser(name: str) -> ParserFn:
    try:
        return PARSERS[name]
    except KeyError as exc:
        raise ValueError(
            f"Unknown log format '{name}'. Available: {', '.join(sorted(PARSERS))}"
        ) from exc
