"""
Attack simulator: generates realistic-looking benign + malicious log data so
you can exercise every detection rule without needing a real network of
victims and attackers. This is the same idea as "atomic red team" or purple
-team exercises, scaled down to log-line generation.

Two ways to use it:
  1. Write sample log files to sample_logs/ that you then feed through the
     file-tailer ingestion (closest to how a real analyst would demo this).
  2. Call `iter_events()` to get normalized Events directly in-process,
     which `run_demo.py` uses for a fast, no-file end-to-end smoke test.
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from siem.models import Event

BENIGN_USERS = ["gaston", "deploy", "backup", "monitoring"]
BENIGN_IPS = ["192.168.1.10", "192.168.1.11", "10.0.0.5"]
ATTACKER_IPS = ["203.0.113.5", "198.51.100.66", "203.0.113.13"]
SCANNER_IP = "203.0.113.77"
SCANNER_WORDLIST = [
    "/admin", "/administrator", "/wp-admin", "/phpmyadmin", "/.env", "/.git/config",
    "/backup.zip", "/config.php", "/db.sql", "/server-status", "/api/v1/users",
    "/login.bak", "/test.php", "/uploads", "/private", "/cgi-bin/test.cgi",
    "/.aws/credentials", "/old", "/tmp", "/staging", "/debug", "/console",
    "/actuator/env", "/.ssh/id_rsa", "/shell.php",
]


def _fmt_syslog(ts: datetime) -> str:
    return ts.strftime("%b %e %H:%M:%S").replace("  ", " ")


def gen_ssh_lines(start: datetime) -> list[str]:
    lines: list[str] = []
    t = start

    # benign traffic
    for _ in range(6):
        user = random.choice(BENIGN_USERS)
        ip = random.choice(BENIGN_IPS)
        lines.append(f"{_fmt_syslog(t)} web01 sshd[1000]: Accepted password for {user} from {ip} port {random.randint(40000,60000)} ssh2")
        t += timedelta(seconds=random.randint(5, 30))

    # brute force burst from one attacker IP (triggers ssh-brute-force)
    attacker = ATTACKER_IPS[0]
    for _ in range(8):
        user = random.choice(["root", "admin", "test", "ubuntu"])
        lines.append(f"{_fmt_syslog(t)} web01 sshd[1000]: Failed password for invalid user {user} from {attacker} port {random.randint(40000,60000)} ssh2")
        t += timedelta(seconds=random.randint(1, 4))

    # single login attempt from a blacklisted IP (triggers ssh-login-from-blacklisted-ip)
    blacklisted = ATTACKER_IPS[1]
    lines.append(f"{_fmt_syslog(t)} web01 sshd[1000]: Failed password for invalid user root from {blacklisted} port 51000 ssh2")
    t += timedelta(seconds=2)

    return lines


def gen_web_lines(start: datetime) -> list[str]:
    lines: list[str] = []
    t = start

    for _ in range(6):
        ip = random.choice(BENIGN_IPS)
        ts = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(f'{ip} - - [{ts}] "GET /index.html HTTP/1.1" 200 1024')
        t += timedelta(seconds=random.randint(2, 10))

    attacker = ATTACKER_IPS[2]
    for payload in ["/product?id=1' OR '1'='1", "/product?id=1 UNION SELECT username,password FROM users--"]:
        ts = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(f'{attacker} - - [{ts}] "GET {payload} HTTP/1.1" 500 512')
        t += timedelta(seconds=1)

    # Directory scanner: a burst of 404s from one IP as it walks a wordlist
    # looking for hidden admin panels, backups and secrets.
    scanner = SCANNER_IP
    for path in SCANNER_WORDLIST:
        ts = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(f'{scanner} - - [{ts}] "GET {path} HTTP/1.1" 404 209')
        t += timedelta(seconds=1)

    return lines


def gen_network_events(start: datetime) -> list[dict]:
    events: list[dict] = []
    t = start

    scanner = ATTACKER_IPS[0]
    for port in random.sample(range(20, 9000), 14):
        events.append({
            "timestamp": t.isoformat(),
            "source": "firewall",
            "event_type": "network",
            "outcome": "success",
            "src_ip": scanner,
            "dst_ip": "10.0.0.7",
            "dst_port": port,
            "message": "connection attempt",
        })
        t += timedelta(seconds=random.uniform(0.2, 1.5))

    return events


def write_sample_logs(output_dir: str = "sample_logs", seed: int | None = 42) -> dict[str, str]:
    if seed is not None:
        random.seed(seed)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    start = datetime.now(timezone.utc)

    auth_path = out / "auth.log"
    access_path = out / "access.log"
    network_path = out / "network_events.jsonl"

    auth_path.write_text("\n".join(gen_ssh_lines(start)) + "\n", encoding="utf-8")
    access_path.write_text("\n".join(gen_web_lines(start)) + "\n", encoding="utf-8")
    network_path.write_text(
        "\n".join(json.dumps(e) for e in gen_network_events(start)) + "\n", encoding="utf-8"
    )
    return {"sshd": str(auth_path), "web_access": str(access_path), "json": str(network_path)}


def iter_raw_lines(seed: int | None = 42) -> list[tuple[str, str]]:
    """Return [(log_format, raw_line), ...] for an in-memory demo (no files)."""
    if seed is not None:
        random.seed(seed)
    start = datetime.now(timezone.utc)
    lines: list[tuple[str, str]] = []
    lines += [("sshd", l) for l in gen_ssh_lines(start)]
    lines += [("web_access", l) for l in gen_web_lines(start)]
    lines += [("json", json.dumps(e)) for e in gen_network_events(start)]
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic SIEM lab log data")
    parser.add_argument("--output-dir", default="sample_logs")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    paths = write_sample_logs(args.output_dir, seed=args.seed)
    for fmt, path in paths.items():
        print(f"wrote {fmt} sample log -> {path}")


if __name__ == "__main__":
    main()
