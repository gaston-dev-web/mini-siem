"""
File-based ingestion: read a log file either once (batch/demo mode) or keep
following it as new lines are appended (`tail -f` style), which is how most
on-host log-forwarding agents (Filebeat, Splunk Universal Forwarder,
Wazuh agent) actually work under the hood.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Iterator


def read_existing_lines(path: str) -> Iterator[str]:
    """Yield every line already in the file, then stop. Useful for replaying
    a sample log file in a demo without waiting in real time."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                yield line


def tail(path: str, from_start: bool = False, poll_interval: float = 0.5) -> Iterator[str]:
    """Follow a growing file forever, yielding new lines as they arrive.

    Handles the file not existing yet (waits for it to be created) so an
    ingestion agent can be started before the log source starts writing.
    """
    p = Path(path)
    while not p.exists():
        time.sleep(poll_interval)

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        if not from_start:
            fh.seek(0, 2)  # seek to end
        while True:
            line = fh.readline()
            if line:
                if line.strip():
                    yield line
            else:
                time.sleep(poll_interval)
