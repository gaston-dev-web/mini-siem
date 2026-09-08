"""
Regression tests for the rules that actually ship in rules_examples/.

The tests in test_rule_engine.py check the *engine* using hand-built Rule
objects. These check the *content* -- the YAML files themselves -- which is a
different failure mode entirely: a rule whose field names don't match what the
parsers produce loads without error and silently detects nothing. That is the
worst outcome in a SIEM, because a dead rule looks exactly like a quiet network.
"""

from datetime import datetime, timedelta, timezone

import pytest

from siem.models import Event
from siem.rules.engine import RuleEngine, load_rules
from siem.rules.lists import load_lists

RULES_DIR = "rules_examples"
LISTS_DIR = "rules_examples/lists"


def _engine_for(rule_id: str) -> RuleEngine:
    """Build an engine containing only the shipped rule under test."""
    rules = [r for r in load_rules(RULES_DIR) if r.id == rule_id]
    assert rules, f"shipped rule '{rule_id}' not found in {RULES_DIR}"
    return RuleEngine(rules, lists=load_lists(LISTS_DIR))


def _web_404(ts: str, src_ip: str, path: str = "/admin") -> Event:
    """An event shaped exactly as siem/parsers/web_access.py produces it."""
    return Event.new(
        timestamp=ts, source="web_access", event_type="web_request",
        outcome="failure", src_ip=src_ip, message=f"GET {path} -> 404",
        extra={"method": "GET", "path": path, "http_status": 404, "suspicious_patterns": []},
    )


def test_every_shipped_rule_loads():
    """A malformed YAML rule should fail here, not silently at runtime."""
    rules = load_rules(RULES_DIR)
    assert len(rules) >= 5
    assert len({r.id for r in rules}) == len(rules), "duplicate rule ids"


def test_web_dir_scan_fires_on_scanner_burst():
    engine = _engine_for("web-dir-scan")
    base = datetime.now(timezone.utc)

    alerts = []
    for i in range(25):
        ts = (base + timedelta(seconds=i)).isoformat()
        alerts += engine.process_event(_web_404(ts, "203.0.113.77", f"/path{i}"))

    assert len(alerts) == 1, "expected exactly one directory-scan alert"
    assert alerts[0].group_key == "203.0.113.77"


def test_web_dir_scan_ignores_a_user_hitting_dead_links():
    """Four 404s from a real visitor with stale bookmarks must stay silent."""
    engine = _engine_for("web-dir-scan")
    base = datetime.now(timezone.utc)

    alerts = []
    for i, path in enumerate(["/old-page", "/favicon.ico", "/logo.png", "/blog/2019"]):
        ts = (base + timedelta(seconds=i)).isoformat()
        alerts += engine.process_event(_web_404(ts, "192.168.1.55", path))

    assert alerts == []


def test_web_dir_scan_counts_each_source_ip_separately():
    """25 404s spread across 25 different IPs is not one scanner."""
    engine = _engine_for("web-dir-scan")
    base = datetime.now(timezone.utc)

    alerts = []
    for i in range(25):
        ts = (base + timedelta(seconds=i)).isoformat()
        alerts += engine.process_event(_web_404(ts, f"192.168.1.{i + 1}"))

    assert alerts == []


# ---------------------------------------------------------------------------
# ssh-lateral-movement (T1021.004)
# ---------------------------------------------------------------------------

def _ssh_auth(ts: str, src_ip: str, host: str, outcome: str, user: str = "gaston") -> Event:
    """Un evento con la forma exacta que produce siem/parsers/sshd.py."""
    return Event.new(
        timestamp=ts, source="sshd", event_type="authentication",
        outcome=outcome, src_ip=src_ip, user=user,
        message=f"{outcome} password for {user} from {src_ip}",
        extra={"host": host, "port": 51000},
    )


def test_ssh_lateral_movement_fires_on_multiple_hosts():
    engine = _engine_for("ssh-lateral-movement")
    base = datetime.now(timezone.utc)

    alerts = []
    for i, host in enumerate(["web01", "db01", "app01"]):
        ts = (base + timedelta(seconds=i * 20)).isoformat()
        alerts += engine.process_event(_ssh_auth(ts, "192.168.1.50", host, "success"))

    assert len(alerts) == 1, "se esperaba exactamente una alerta de movimiento lateral"
    assert alerts[0].group_key == "192.168.1.50"


def test_ssh_lateral_movement_ignores_failed_authentications():
    """Tres fallos contra tres hosts no son movimiento lateral. Prueba `outcome: success`."""
    engine = _engine_for("ssh-lateral-movement")
    base = datetime.now(timezone.utc)

    alerts = []
    for i, host in enumerate(["web01", "db01", "app01"]):
        ts = (base + timedelta(seconds=i * 20)).isoformat()
        alerts += engine.process_event(_ssh_auth(ts, "192.168.1.50", host, "failure"))

    assert alerts == []


def test_ssh_lateral_movement_ignores_repeated_logins_to_one_host():
    """Tres logins al mismo servidor es trabajo normal. Prueba `unique_field: host`."""
    engine = _engine_for("ssh-lateral-movement")
    base = datetime.now(timezone.utc)

    alerts = []
    for i in range(3):
        ts = (base + timedelta(seconds=i * 20)).isoformat()
        alerts += engine.process_event(_ssh_auth(ts, "192.168.1.50", "web01", "success"))

    assert alerts == []