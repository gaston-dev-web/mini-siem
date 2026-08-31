import tempfile
from pathlib import Path

from siem.alerting.notifier import Notifier
from siem.pipeline import Pipeline
from siem.rules.engine import Rule, RuleEngine
from siem.storage.db import EventStore


def _make_pipeline(tmp_path: Path) -> Pipeline:
    store = EventStore(str(tmp_path / "test.db"))
    rule = Rule(
        id="ssh-brute-force-test", name="SSH Brute Force", description="", severity="high",
        type="threshold", match={"equals": {"source": "sshd", "outcome": "failure"}},
        group_by="src_ip", threshold=3, window_seconds=60,
    )
    engine = RuleEngine([rule])
    captured = []
    notifier = Notifier([captured.append])
    pipeline = Pipeline(store, engine, notifier)
    pipeline._captured = captured  # type: ignore[attr-defined]
    return pipeline


def test_end_to_end_raw_line_to_alert(tmp_path):
    pipeline = _make_pipeline(tmp_path)
    lines = [
        "Aug 31 10:00:00 web01 sshd[1]: Failed password for invalid user root from 203.0.113.5 port 41000 ssh2",
        "Aug 31 10:00:01 web01 sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 41001 ssh2",
        "Aug 31 10:00:02 web01 sshd[1]: Failed password for invalid user test from 203.0.113.5 port 41002 ssh2",
    ]
    for line in lines:
        pipeline.handle_raw_line(line, "sshd")

    stats = pipeline.store.stats()
    assert stats["total_events"] == 3
    assert stats["total_alerts"] == 1
    assert len(pipeline._captured) == 1  # type: ignore[attr-defined]


def test_unparseable_line_is_skipped_not_crashed(tmp_path):
    pipeline = _make_pipeline(tmp_path)
    result = pipeline.handle_raw_line("garbage line that matches nothing", "sshd")
    assert result is None
    assert pipeline.store.stats()["total_events"] == 0
