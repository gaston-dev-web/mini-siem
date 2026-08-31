"""
Storage layer: normalized events and alerts persisted to SQLite.

Real SIEMs use purpose-built time-series/search backends (Splunk's indexers,
Elasticsearch, Sentinel's Log Analytics/Kusto) because they ingest far more
volume than SQLite can handle. For a learning lab, SQLite gives us the same
core idea -- durable, queryable storage of normalized events plus the alerts
generated from them -- with zero external services to stand up.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Iterable, Optional

from siem.models import Alert, Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    user TEXT,
    message TEXT,
    raw TEXT,
    extra_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    description TEXT,
    group_key TEXT,
    matched_event_ids_json TEXT,
    context_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
"""


class EventStore:
    """Thin, thread-safe wrapper around a SQLite database.

    A single connection with `check_same_thread=False` plus a lock is enough
    for a learning tool that isn't chasing high write throughput; it keeps the
    code readable instead of introducing a connection pool.
    """

    def __init__(self, path: str = "data/siem.db"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    # ---- writes -----------------------------------------------------
    def insert_event(self, event: Event) -> None:
        with self._lock:
            self.conn.execute(
                """INSERT OR IGNORE INTO events
                   (id, timestamp, source, event_type, outcome, src_ip, dst_ip,
                    dst_port, user, message, raw, extra_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event.id, event.timestamp, event.source, event.event_type,
                    event.outcome, event.src_ip, event.dst_ip, event.dst_port,
                    event.user, event.message, event.raw, json.dumps(event.extra),
                ),
            )
            self.conn.commit()

    def insert_alert(self, alert: Alert) -> None:
        with self._lock:
            self.conn.execute(
                """INSERT OR IGNORE INTO alerts
                   (id, rule_id, rule_name, severity, timestamp, description,
                    group_key, matched_event_ids_json, context_json)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    alert.id, alert.rule_id, alert.rule_name, alert.severity,
                    alert.timestamp, alert.description, alert.group_key,
                    json.dumps(alert.matched_event_ids), json.dumps(alert.context),
                ),
            )
            self.conn.commit()

    # ---- reads ------------------------------------------------------
    def recent_events(self, limit: int = 100, source: Optional[str] = None) -> list[dict]:
        with self._lock:
            if source:
                rows = self.conn.execute(
                    "SELECT * FROM events WHERE source = ? ORDER BY timestamp DESC LIMIT ?",
                    (source, limit),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
        return [_row_to_event_dict(r) for r in rows]

    def recent_alerts(self, limit: int = 100, severity: Optional[str] = None) -> list[dict]:
        with self._lock:
            if severity:
                rows = self.conn.execute(
                    "SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC LIMIT ?",
                    (severity, limit),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
        return [_row_to_alert_dict(r) for r in rows]

    def stats(self) -> dict:
        with self._lock:
            total_events = self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            total_alerts = self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            by_severity = dict(
                self.conn.execute(
                    "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
                ).fetchall()
            )
            by_source = dict(
                self.conn.execute(
                    "SELECT source, COUNT(*) FROM events GROUP BY source"
                ).fetchall()
            )
            top_src_ips = self.conn.execute(
                """SELECT src_ip, COUNT(*) as c FROM events
                   WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY c DESC LIMIT 10"""
            ).fetchall()
        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "alerts_by_severity": by_severity,
            "events_by_source": by_source,
            "top_src_ips": [{"ip": r[0], "count": r[1]} for r in top_src_ips],
        }

    def close(self) -> None:
        self.conn.close()


def _row_to_event_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["extra"] = json.loads(d.pop("extra_json") or "{}")
    return d


def _row_to_alert_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["matched_event_ids"] = json.loads(d.pop("matched_event_ids_json") or "[]")
    d["context"] = json.loads(d.pop("context_json") or "{}")
    return d
