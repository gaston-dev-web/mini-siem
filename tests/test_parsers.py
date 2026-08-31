from siem.parsers import sshd, web_access, json_event


def test_sshd_failed_password():
    line = "Aug 31 10:15:02 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2"
    event = sshd.parse(line)
    assert event is not None
    assert event.source == "sshd"
    assert event.outcome == "failure"
    assert event.src_ip == "203.0.113.5"
    assert event.user == "admin"
    assert event.event_type == "authentication"


def test_sshd_accepted_password():
    line = "Aug 31 10:16:40 web01 sshd[1234]: Accepted password for gaston from 192.168.1.10 port 51522 ssh2"
    event = sshd.parse(line)
    assert event is not None
    assert event.outcome == "success"
    assert event.user == "gaston"
    assert event.src_ip == "192.168.1.10"


def test_sshd_unparseable_line_returns_none():
    assert sshd.parse("this is not a syslog line at all") is None


def test_web_access_benign_request():
    line = '203.0.113.9 - - [31/Aug/2026:10:15:00 +0000] "GET /index.html HTTP/1.1" 200 512'
    event = web_access.parse(line)
    assert event is not None
    assert event.outcome == "success"
    assert event.extra["http_status"] == 200
    assert event.extra["suspicious_patterns"] == []


def test_web_access_flags_sqli_pattern():
    line = '203.0.113.9 - - [31/Aug/2026:10:15:00 +0000] "GET /p?id=1 UNION SELECT user,pass FROM users-- HTTP/1.1" 500 512'
    event = web_access.parse(line)
    assert event is not None
    assert "sqli" in event.extra["suspicious_patterns"]


def test_json_event_parses_known_and_extra_fields():
    line = '{"timestamp": "2026-08-31T10:00:00+00:00", "source": "firewall", "event_type": "network", "src_ip": "203.0.113.5", "dst_port": 22, "custom_field": "x"}'
    event = json_event.parse(line)
    assert event is not None
    assert event.source == "firewall"
    assert event.dst_port == 22
    assert event.extra == {"custom_field": "x"}


def test_json_event_invalid_json_returns_none():
    assert json_event.parse("{not valid json") is None
