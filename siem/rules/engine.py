"""
The correlation / detection rule engine.

This is the heart of a SIEM: the piece that turns a stream of individual,
mostly-boring events into an alert an analyst should look at. Every real SIEM
rule language (Splunk SPL correlation searches, Sentinel Analytics Rules /
KQL, Elastic detection rules, Sigma) is doing one of a small number of things:

  1. "match"       - a single event is inherently suspicious on its own
                      (e.g. a login attempt from a known-malicious IP).
  2. "threshold"    - too many matching events from the same actor in a time
                      window (e.g. 5+ failed SSH logins from one IP in 60s
                      -> brute force).
  3. "unique_count" - one actor touching too many *distinct* values of some
                      field in a window (e.g. one IP hitting 15 different
                      destination ports in 30s -> port scan).

We implement exactly those three, because understanding them deeply teaches
you most of what you need to read (and later write) real Sigma/KQL/SPL rules.

Rules are defined declaratively in YAML (see rules_examples/*.yaml) and loaded
by `load_rules`, which keeps rule *logic* (this file) separate from rule
*content* (the YAML) -- the same separation real SIEMs make.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from siem.models import Alert, Event

VALID_TYPES = {"match", "threshold", "unique_count"}


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str
    type: str
    match: dict[str, Any] = field(default_factory=dict)
    group_by: Optional[str] = None
    threshold: int = 1
    window_seconds: int = 60
    unique_field: Optional[str] = None
    cooldown_seconds: int = 60

    def __post_init__(self) -> None:
        if self.type not in VALID_TYPES:
            raise ValueError(f"Rule {self.id}: unknown type '{self.type}' (must be one of {VALID_TYPES})")
        if self.type == "unique_count" and not self.unique_field:
            raise ValueError(f"Rule {self.id}: type 'unique_count' requires 'unique_field'")


def load_rules(paths: list[str] | str) -> list[Rule]:
    """Load one or more YAML rule files (or a directory of them)."""
    if isinstance(paths, str):
        paths = [paths]

    files: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            files.extend(sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml")))
        else:
            files.append(path)

    rules: list[Rule] = []
    for f in files:
        with open(f, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        detection = doc.get("detection", {})
        rules.append(
            Rule(
                id=doc["id"],
                name=doc["name"],
                description=doc.get("description", ""),
                severity=doc.get("severity", "medium"),
                type=detection["type"],
                match=detection.get("match", {}),
                group_by=detection.get("group_by"),
                threshold=detection.get("threshold", 1),
                window_seconds=detection.get("window_seconds", 60),
                unique_field=detection.get("unique_field"),
                cooldown_seconds=doc.get("cooldown_seconds", 60),
            )
        )
    return rules


def _field_value(event: Event, field_name: str) -> Any:
    return event.get(field_name)


def matches_filter(event: Event, filt: dict[str, Any], lists: Optional[dict[str, set[str]]] = None) -> bool:
    """Check whether `event` satisfies a rule's `match` block.

    Supported filter keys:
      equals:   {field: value, ...}          exact match
      contains: {field: substring, ...}      case-insensitive substring match
      in:       {field: [v1, v2, ...]}       inline membership match
      in_list:  {field: list_name}           membership against a named list
                                              loaded from rules_examples/lists/
                                              (see siem/rules/lists.py) -- this
                                              is the "blacklist" building block,
                                              e.g. known-malicious source IPs.
    Any keys present must ALL match (logical AND) -- same semantics as a
    Sigma rule's single detection selection.
    """
    lists = lists or {}
    for f, expected in filt.get("equals", {}).items():
        if _field_value(event, f) != expected:
            return False
    for f, substr in filt.get("contains", {}).items():
        value = str(_field_value(event, f) or "")
        if substr.lower() not in value.lower():
            return False
    for f, allowed in filt.get("in", {}).items():
        if _field_value(event, f) not in allowed:
            return False
    for f, list_name in filt.get("in_list", {}).items():
        value = _field_value(event, f)
        if value not in lists.get(list_name, set()):
            return False
    return True


def _parse_ts(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class RuleEngine:
    """Evaluates every loaded rule against each incoming event.

    State needed for "threshold" and "unique_count" rules (a sliding window
    of recent (timestamp, value) pairs per group key) is kept in memory,
    keyed by (rule_id, group_key). That mirrors how real correlation engines
    keep a bounded in-memory window rather than re-scanning the whole index
    on every event.
    """

    def __init__(self, rules: list[Rule], lists: Optional[dict[str, set[str]]] = None):
        self.rules = rules
        self.lists = lists or {}
        # (rule_id, group_key) -> deque[(datetime, value)]
        self._windows: dict[tuple[str, str], deque] = defaultdict(deque)
        # (rule_id, group_key) -> datetime of last alert (for cooldown)
        self._last_alert: dict[tuple[str, str], datetime] = {}

    def process_event(self, event: Event) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            alert = self._evaluate(rule, event)
            if alert:
                alerts.append(alert)
        return alerts

    def _evaluate(self, rule: Rule, event: Event) -> Optional[Alert]:
        if not matches_filter(event, rule.match, self.lists):
            return None

        if rule.type == "match":
            return self._fire(rule, event, group_key=str(_field_value(event, rule.group_by) if rule.group_by else "global"))

        group_key = str(_field_value(event, rule.group_by)) if rule.group_by else "global"
        now = _parse_ts(event.timestamp)
        window_key = (rule.id, group_key)
        window = self._windows[window_key]

        if rule.type == "threshold":
            window.append(now)
            self._prune(window, now, rule.window_seconds)
            if len(window) >= rule.threshold:
                return self._fire(
                    rule, event, group_key,
                    context={"count": len(window), "window_seconds": rule.window_seconds},
                )
            return None

        if rule.type == "unique_count":
            value = _field_value(event, rule.unique_field)
            window.append((now, value))
            self._prune_pairs(window, now, rule.window_seconds)
            distinct = {v for _, v in window}
            if len(distinct) >= rule.threshold:
                return self._fire(
                    rule, event, group_key,
                    context={
                        "distinct_count": len(distinct),
                        "field": rule.unique_field,
                        "values": sorted(str(v) for v in distinct)[:20],
                        "window_seconds": rule.window_seconds,
                    },
                )
            return None

        return None  # pragma: no cover - guarded by Rule.__post_init__

    def _fire(self, rule: Rule, event: Event, group_key: str, context: Optional[dict] = None) -> Optional[Alert]:
        now = _parse_ts(event.timestamp)
        cooldown_key = (rule.id, group_key)
        last = self._last_alert.get(cooldown_key)
        if last and (now - last) < timedelta(seconds=rule.cooldown_seconds):
            return None  # suppress duplicate alerts while the same condition persists
        self._last_alert[cooldown_key] = now

        return Alert.new(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            timestamp=event.timestamp,
            description=rule.description,
            group_key=group_key,
            matched_event_ids=[event.id],
            context=context or {},
        )

    @staticmethod
    def _prune(window: deque, now: datetime, window_seconds: int) -> None:
        cutoff = now - timedelta(seconds=window_seconds)
        while window and window[0] < cutoff:
            window.popleft()

    @staticmethod
    def _prune_pairs(window: deque, now: datetime, window_seconds: int) -> None:
        cutoff = now - timedelta(seconds=window_seconds)
        while window and window[0][0] < cutoff:
            window.popleft()
