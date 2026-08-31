"""
Wires ingestion -> parsing -> storage -> correlation -> alerting together.

This module is intentionally the only place that knows about *all* the other
pieces. Everything else (a parser, the rule engine, a notifier) can be
understood and tested in isolation; `Pipeline` is just the assembly line.
"""

from __future__ import annotations

import logging
from typing import Optional

from siem.alerting.notifier import Notifier
from siem.models import Event
from siem.parsers.registry import get_parser
from siem.rules.engine import RuleEngine
from siem.storage.db import EventStore

logger = logging.getLogger("siem.pipeline")


class Pipeline:
    def __init__(self, store: EventStore, engine: RuleEngine, notifier: Optional[Notifier] = None):
        self.store = store
        self.engine = engine
        self.notifier = notifier or Notifier()

    def handle_event(self, event: Event) -> None:
        """Feed one already-normalized Event through storage + detection."""
        self.store.insert_event(event)
        for alert in self.engine.process_event(event):
            self.store.insert_alert(alert)
            self.notifier.notify(alert)

    def handle_raw_line(self, raw_line: str, log_format: str) -> Optional[Event]:
        """Parse one raw log line with the given format and run it through
        the pipeline. Returns the normalized Event, or None if the line
        couldn't be parsed (e.g. a blank line or an unrecognized format)."""
        parser = get_parser(log_format)
        event = parser(raw_line)
        if event is None:
            return None
        self.handle_event(event)
        return event
