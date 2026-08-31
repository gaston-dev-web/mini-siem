"""
Alert delivery ("notification sinks" in SIEM terms).

Detecting something is only half the job -- a SIEM has to get the alert in
front of a human (or a downstream system) fast. Real products fan alerts out
to email, Slack/Teams, PagerDuty, SOAR playbooks, ticketing systems, etc. We
model that as a small `Notifier` that holds a list of sink callables, so
adding a new delivery channel never means touching the rule engine.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Callable, Optional

import requests

from siem.models import Alert

logger = logging.getLogger("siem.alerts")

SinkFn = Callable[[Alert], None]


def console_sink(alert: Alert) -> None:
    print(f"[ALERT] ({alert.severity.upper()}) {alert.rule_name} — {alert.description} "
          f"[group={alert.group_key}] {alert.context}")


def file_sink(path: str = "data/alerts.log") -> SinkFn:
    Path(path).parent.mkdir(parents=True, exist_ok=True)

    def _sink(alert: Alert) -> None:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(alert.to_dict()) + "\n")

    return _sink


def webhook_sink(url: str, timeout: float = 5.0) -> SinkFn:
    """Post the alert as JSON to a generic webhook (Slack/Discord-compatible
    endpoints will accept a `{"text": ...}` shaped payload; adapt as needed).
    """

    def _sink(alert: Alert) -> None:
        payload = {
            "text": f"[{alert.severity.upper()}] {alert.rule_name}: {alert.description} (group={alert.group_key})",
            "alert": alert.to_dict(),
        }
        try:
            requests.post(url, json=payload, timeout=timeout)
        except requests.RequestException as exc:
            logger.warning("webhook_sink: failed to deliver alert %s: %s", alert.id, exc)

    return _sink


class Notifier:
    def __init__(self, sinks: Optional[list[SinkFn]] = None):
        self.sinks = sinks or [console_sink]

    def notify(self, alert: Alert) -> None:
        for sink in self.sinks:
            sink(alert)
