from datetime import datetime, timedelta, timezone

from siem.models import Event
from siem.rules.engine import Rule, RuleEngine


def _ts(offset_seconds: int, base: datetime) -> str:
    return (base + timedelta(seconds=offset_seconds)).isoformat()


def make_ssh_failure(ts: str, src_ip: str, user: str = "root") -> Event:
    return Event.new(
        timestamp=ts, source="sshd", event_type="authentication",
        outcome="failure", src_ip=src_ip, user=user, message="failed",
    )


def test_threshold_rule_fires_after_enough_events_in_window():
    base = datetime.now(timezone.utc)
    rule = Rule(
        id="r1", name="Brute force", description="", severity="high", type="threshold",
        match={"equals": {"source": "sshd", "outcome": "failure"}},
        group_by="src_ip", threshold=3, window_seconds=60,
    )
    engine = RuleEngine([rule])

    alerts = []
    for i in range(3):
        alerts += engine.process_event(make_ssh_failure(_ts(i, base), "203.0.113.5"))

    assert len(alerts) == 1
    assert alerts[0].rule_id == "r1"
    assert alerts[0].context["count"] == 3


def test_threshold_rule_does_not_fire_below_threshold():
    base = datetime.now(timezone.utc)
    rule = Rule(
        id="r1", name="Brute force", description="", severity="high", type="threshold",
        match={"equals": {"source": "sshd", "outcome": "failure"}},
        group_by="src_ip", threshold=5, window_seconds=60,
    )
    engine = RuleEngine([rule])

    alerts = []
    for i in range(4):
        alerts += engine.process_event(make_ssh_failure(_ts(i, base), "203.0.113.5"))

    assert alerts == []


def test_threshold_rule_window_expiry_resets_count():
    base = datetime.now(timezone.utc)
    rule = Rule(
        id="r1", name="Brute force", description="", severity="high", type="threshold",
        match={"equals": {"source": "sshd", "outcome": "failure"}},
        group_by="src_ip", threshold=3, window_seconds=10,
    )
    engine = RuleEngine([rule])

    alerts = []
    alerts += engine.process_event(make_ssh_failure(_ts(0, base), "203.0.113.5"))
    alerts += engine.process_event(make_ssh_failure(_ts(1, base), "203.0.113.5"))
    # This event arrives well outside the 10s window relative to the first two,
    # so the window should have expired the earlier events instead of accumulating.
    alerts += engine.process_event(make_ssh_failure(_ts(50, base), "203.0.113.5"))

    assert alerts == []


def test_threshold_rule_groups_independently_per_key():
    base = datetime.now(timezone.utc)
    rule = Rule(
        id="r1", name="Brute force", description="", severity="high", type="threshold",
        match={"equals": {"source": "sshd", "outcome": "failure"}},
        group_by="src_ip", threshold=2, window_seconds=60,
    )
    engine = RuleEngine([rule])

    alerts = []
    alerts += engine.process_event(make_ssh_failure(_ts(0, base), "203.0.113.5"))
    alerts += engine.process_event(make_ssh_failure(_ts(1, base), "198.51.100.1"))

    assert alerts == []  # one event per distinct src_ip, neither reaches threshold=2


def test_match_rule_fires_immediately():
    rule = Rule(
        id="r2", name="Blacklist hit", description="", severity="critical", type="match",
        match={"in_list": {"src_ip": "bad_ips"}},
    )
    engine = RuleEngine([rule], lists={"bad_ips": {"203.0.113.13"}})

    event = make_ssh_failure(datetime.now(timezone.utc).isoformat(), "203.0.113.13")
    alerts = engine.process_event(event)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "r2"


def test_match_rule_respects_cooldown():
    rule = Rule(
        id="r2", name="Blacklist hit", description="", severity="critical", type="match",
        match={"in_list": {"src_ip": "bad_ips"}}, group_by="src_ip", cooldown_seconds=300,
    )
    engine = RuleEngine([rule], lists={"bad_ips": {"203.0.113.13"}})
    base = datetime.now(timezone.utc)

    alerts = []
    alerts += engine.process_event(make_ssh_failure(_ts(0, base), "203.0.113.13"))
    alerts += engine.process_event(make_ssh_failure(_ts(5, base), "203.0.113.13"))  # within cooldown

    assert len(alerts) == 1


def test_unique_count_rule_detects_port_scan():
    base = datetime.now(timezone.utc)
    rule = Rule(
        id="r3", name="Port scan", description="", severity="medium", type="unique_count",
        match={"equals": {"source": "firewall", "event_type": "network"}},
        group_by="src_ip", unique_field="dst_port", threshold=5, window_seconds=30,
    )
    engine = RuleEngine([rule])

    alerts = []
    for i, port in enumerate([22, 80, 443, 8080, 3389]):
        event = Event.new(
            timestamp=_ts(i, base), source="firewall", event_type="network",
            src_ip="203.0.113.5", dst_port=port, outcome="success",
        )
        alerts += engine.process_event(event)

    assert len(alerts) == 1
    assert alerts[0].context["distinct_count"] == 5


def test_unique_count_rule_ignores_repeated_ports():
    base = datetime.now(timezone.utc)
    rule = Rule(
        id="r3", name="Port scan", description="", severity="medium", type="unique_count",
        match={"equals": {"source": "firewall"}},
        group_by="src_ip", unique_field="dst_port", threshold=3, window_seconds=30,
    )
    engine = RuleEngine([rule])

    alerts = []
    for i in range(5):
        event = Event.new(
            timestamp=_ts(i, base), source="firewall", event_type="network",
            src_ip="203.0.113.5", dst_port=22, outcome="success",  # same port every time
        )
        alerts += engine.process_event(event)

    assert alerts == []
