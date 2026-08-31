# mini-siem

A small SIEM (Security Information and Event Management) system, built from
scratch in Python, to actually understand how one works internally rather
than just clicking around a vendor product. Everything a real SIEM does —
collecting logs, normalizing them, correlating events into alerts, and
surfacing those alerts to an analyst — is implemented here in plain,
readable code with no external services required.

This project is part of a self-directed cybersecurity training path (SOC
fundamentals, detection engineering) and doubles as a portfolio piece.

## Why build one instead of just deploying Wazuh/ELK/Splunk?

Because the goal here is understanding, not just operating. Every SIEM
concept you'll meet on the job — log sources, normalization/schema mapping,
correlation rules, detection windows, alert fatigue and cooldowns, SOC
dashboards — is implemented from first principles below, in code small
enough to read end to end in one sitting. Once these concepts click, picking
up Splunk SPL, Microsoft Sentinel KQL, or Elastic detection rules is mostly
a matter of learning new syntax for ideas you already understand.

## Architecture

```
   raw logs                 normalized             correlation           delivery
 ─────────────           ─────────────────      ─────────────────    ─────────────────
  sshd syslog     ─┐                                                  console
  nginx/apache     │      ┌───────────┐          ┌───────────────┐    log file
  access log       ├──▶   │  parsers  │  ──▶      │  rule engine  │ ─▶ webhook (Slack/
  JSON / netflow   │      │ (siem/    │  Event    │  (siem/rules/ │    Discord/etc.)
  events           │      │ parsers/) │           │  engine.py)   │
  REST /api/ingest ─┘      └───────────┘          └───────┬───────┘
                                 │                          │
                                 ▼                          ▼
                          ┌─────────────┐            ┌─────────────┐
                          │   SQLite    │  ◀────────▶ │   alerts    │
                          │  event      │             │   table     │
                          │  store      │             └─────────────┘
                          └─────────────┘
                                 ▲
                                 │  read by
                          ┌─────────────┐
                          │  FastAPI +  │   http://localhost:8000
                          │  dashboard  │   (events, alerts, stats)
                          └─────────────┘
```

Every stage maps onto a real-world SIEM concept:

| Stage | What it does | Real-world equivalent |
|---|---|---|
| **Ingestion** (`siem/ingest/`) | Pulls raw log lines in from files (tailing), syslog UDP, or a REST endpoint | Filebeat/Splunk forwarders, syslog collectors, HTTP event collectors |
| **Parsing / normalization** (`siem/parsers/`) | Converts source-specific raw text/JSON into one common `Event` schema | Splunk CIM, Elastic Common Schema (ECS), Sentinel ASIM |
| **Storage** (`siem/storage/`) | Persists normalized events + generated alerts, queryable by time/IP/severity | Splunk indexers, Elasticsearch, Sentinel Log Analytics |
| **Correlation / detection** (`siem/rules/`) | Evaluates declarative YAML rules against the event stream to find things worth an analyst's attention | Sigma rules, Splunk correlation searches, Sentinel Analytics Rules |
| **Alerting** (`siem/alerting/`) | Delivers a fired alert somewhere a human will see it | Email/Slack/PagerDuty/SOAR integrations |
| **Dashboard/API** (`siem/api/`, `siem/web/`) | Lets an analyst see live events, alerts, and stats | Splunk/Sentinel/Kibana dashboards |

## Detection rule engine

Rules are declarative YAML files (see `rules_examples/`), kept deliberately
close to how [Sigma](https://github.com/SigmaHQ/sigma) rules are structured,
so what you learn here transfers directly. Three detection types cover the
large majority of real-world correlation logic:

- **`match`** — a single event is inherently suspicious (e.g. a login
  attempt from an IP on a known-malicious list).
- **`threshold`** — too many matching events from the same actor within a
  time window (e.g. 5+ failed SSH logins from one IP in 60s → brute force).
- **`unique_count`** — one actor touching too many *distinct* values of a
  field within a window (e.g. one IP hitting 10+ different destination
  ports in 30s → port scan).

Example (`rules_examples/ssh_brute_force.yaml`):

```yaml
id: ssh-brute-force
name: SSH Brute Force
description: 5+ failed SSH authentication attempts from the same source IP within 60 seconds
severity: high
cooldown_seconds: 120
detection:
  type: threshold
  match:
    equals:
      source: sshd
      event_type: authentication
      outcome: failure
  group_by: src_ip
  threshold: 5
  window_seconds: 60
```

Included out of the box:

| Rule | Type | Detects |
|---|---|---|
| `ssh_brute_force.yaml` | threshold | Repeated failed SSH logins from one IP |
| `ssh_login_from_blacklisted_ip.yaml` | match + list | SSH auth attempt from a known-bad IP (`rules_examples/lists/known_malicious_ips.txt`) |
| `web_sqli_attempt.yaml` | match | HTTP request path containing a SQL-injection pattern |
| `port_scan.yaml` | unique_count | One IP touching many distinct destination ports quickly |

Writing your own rule is just adding a new YAML file to `rules_examples/` —
no code changes needed. That's the same separation of "detection logic" vs.
"detection content" every real SIEM/EDR product makes.

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

# Fastest way to see it work end-to-end (no files, no waiting):
python -m siem.cli demo

# Or generate sample log files and ingest them one at a time:
python -m siem.cli simulate
python -m siem.cli ingest-file sample_logs/auth.log sshd
python -m siem.cli ingest-file sample_logs/access.log web_access
python -m siem.cli ingest-file sample_logs/network_events.jsonl json

# Then browse the dashboard:
python -m siem.cli serve
# -> http://127.0.0.1:8000
```

`python -m siem.cli demo` generates a realistic mix of benign traffic plus
an SSH brute force, a login from a blacklisted IP, a SQL injection attempt,
and a port scan — and prints the alerts each one triggers, so you can see
the whole pipeline fire in a few seconds.

### Live ingestion

```bash
# Follow a real, growing log file (e.g. your own machine's auth log):
python -m siem.cli tail /var/log/auth.log sshd

# Listen for syslog forwarded over UDP (point a device/daemon at this host):
python -m siem.cli syslog --port 1514 --format sshd

# Push a structured event directly from any script/app:
curl -X POST http://127.0.0.1:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{"source":"my-app","event_type":"authentication","outcome":"failure","user":"gaston","src_ip":"203.0.113.9"}'
```

### Running the tests

```bash
pytest -v
```

## Project layout

```
siem/
  models.py            normalized Event/Alert schema
  pipeline.py           wires ingestion -> parsing -> storage -> rules -> alerting
  ingest/                file tailer, syslog UDP listener
  parsers/                sshd, web access log, generic JSON normalizers
  storage/                SQLite-backed event/alert store
  rules/                  YAML rule loader + correlation engine
  alerting/               console / file / webhook alert delivery
  api/                    FastAPI REST API
  web/                    dashboard front-end (plain HTML/JS)
  simulator/              synthetic benign + attack log generator
  cli.py                  command-line entry point (simulate/demo/tail/syslog/serve)
rules_examples/          YAML detection rules + threat-intel style lists
tests/                    pytest suite for parsers, rule engine, pipeline
```

## Roadmap / ideas for extending this

- Add more parsers (Windows Event Log JSON, cloud provider audit logs, EDR telemetry)
- Add a "sequence" rule type (event A followed by event B within a window — e.g. recon then exploitation)
- Add a simple case-management view (acknowledge/close alerts, add analyst notes)
- Swap SQLite for a proper time-series/search backend once volume outgrows it
- Map each rule to its corresponding [MITRE ATT&CK](https://attack.mitre.org/) technique ID
- Containerize with `docker-compose` for a one-command lab spin-up

## License

MIT — see [LICENSE](LICENSE).
