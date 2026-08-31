"""
Command-line entry point tying every piece together.

    python -m siem.cli simulate                 # write synthetic sample logs
    python -m siem.cli demo                      # in-memory end-to-end demo
    python -m siem.cli ingest-file auth.log sshd  # replay a file through the pipeline
    python -m siem.cli tail auth.log sshd         # follow a growing file live
    python -m siem.cli syslog --port 1514         # listen for syslog over UDP
    python -m siem.cli serve                      # start the dashboard/API
"""

from __future__ import annotations

import argparse
import logging

from siem.alerting.notifier import Notifier, console_sink, file_sink
from siem.ingest import file_tailer, syslog_udp
from siem.models import Event
from siem.parsers.registry import get_parser
from siem.pipeline import Pipeline
from siem.rules.engine import RuleEngine, load_rules
from siem.rules.lists import load_lists
from siem.simulator.generate_logs import iter_raw_lines, write_sample_logs
from siem.storage.db import EventStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def build_pipeline(db_path: str = "data/siem.db", rules_dir: str = "rules_examples",
                    lists_dir: str = "rules_examples/lists", alert_log: str = "data/alerts.log") -> Pipeline:
    store = EventStore(db_path)
    rules = load_rules(rules_dir)
    lists = load_lists(lists_dir)
    engine = RuleEngine(rules, lists=lists)
    notifier = Notifier([console_sink, file_sink(alert_log)])
    print(f"Loaded {len(rules)} detection rule(s) from {rules_dir}: {[r.id for r in rules]}")
    return Pipeline(store, engine, notifier)


def cmd_simulate(args: argparse.Namespace) -> None:
    paths = write_sample_logs(args.output_dir, seed=args.seed)
    for fmt, path in paths.items():
        print(f"wrote {fmt} sample log -> {path}")


def cmd_demo(args: argparse.Namespace) -> None:
    pipeline = build_pipeline(db_path=args.db)
    total_alerts = 0
    for log_format, raw_line in iter_raw_lines(seed=args.seed):
        event = pipeline.handle_raw_line(raw_line, log_format)
        if event is None:
            print(f"  (unparsed {log_format} line skipped): {raw_line[:80]}")
    stats = pipeline.store.stats()
    print("\n--- demo complete ---")
    print(f"events stored: {stats['total_events']}, alerts fired: {stats['total_alerts']}")
    print(f"alerts by severity: {stats['alerts_by_severity']}")


def cmd_ingest_file(args: argparse.Namespace) -> None:
    pipeline = build_pipeline(db_path=args.db)
    count = 0
    for line in file_tailer.read_existing_lines(args.path):
        if pipeline.handle_raw_line(line, args.format):
            count += 1
    print(f"ingested {count} event(s) from {args.path}")


def cmd_tail(args: argparse.Namespace) -> None:
    pipeline = build_pipeline(db_path=args.db)
    print(f"tailing {args.path} as '{args.format}' (Ctrl+C to stop)...")
    for line in file_tailer.tail(args.path, from_start=args.from_start):
        pipeline.handle_raw_line(line, args.format)


def cmd_syslog(args: argparse.Namespace) -> None:
    pipeline = build_pipeline(db_path=args.db)
    parser = get_parser(args.format)

    def on_line(text: str) -> None:
        event = parser(text)
        if event:
            pipeline.handle_event(event)

    print(f"listening for syslog UDP on {args.host}:{args.port} (Ctrl+C to stop)...")
    syslog_udp.listen(host=args.host, port=args.port, on_line=on_line)


def cmd_serve(args: argparse.Namespace) -> None:
    import uvicorn
    from siem.api.app import create_app

    pipeline = build_pipeline(db_path=args.db)
    app = create_app(pipeline)
    print(f"dashboard: http://{args.host}:{args.port}/")
    uvicorn.run(app, host=args.host, port=args.port)


def main() -> None:
    parser = argparse.ArgumentParser(prog="siem", description="mini-siem: a from-scratch SIEM lab")
    parser.add_argument("--db", default="data/siem.db", help="path to the SQLite database")
    sub = parser.add_subparsers(dest="command", required=True)

    p_sim = sub.add_parser("simulate", help="write synthetic sample log files")
    p_sim.add_argument("--output-dir", default="sample_logs")
    p_sim.add_argument("--seed", type=int, default=42)
    p_sim.set_defaults(func=cmd_simulate)

    p_demo = sub.add_parser("demo", help="run an in-memory end-to-end demo (no files needed)")
    p_demo.add_argument("--seed", type=int, default=42)
    p_demo.set_defaults(func=cmd_demo)

    p_ingest = sub.add_parser("ingest-file", help="parse and ingest every line of an existing file once")
    p_ingest.add_argument("path")
    p_ingest.add_argument("format", choices=["sshd", "web_access", "json"])
    p_ingest.set_defaults(func=cmd_ingest_file)

    p_tail = sub.add_parser("tail", help="follow a growing log file and ingest new lines live")
    p_tail.add_argument("path")
    p_tail.add_argument("format", choices=["sshd", "web_access", "json"])
    p_tail.add_argument("--from-start", action="store_true")
    p_tail.set_defaults(func=cmd_tail)

    p_syslog = sub.add_parser("syslog", help="listen for syslog messages over UDP")
    p_syslog.add_argument("--host", default="0.0.0.0")
    p_syslog.add_argument("--port", type=int, default=1514)
    p_syslog.add_argument("--format", default="sshd", choices=["sshd", "web_access", "json"])
    p_syslog.set_defaults(func=cmd_syslog)

    p_serve = sub.add_parser("serve", help="start the REST API + web dashboard")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
