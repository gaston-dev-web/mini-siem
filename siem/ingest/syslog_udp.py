"""
Minimal syslog-over-UDP listener.

Real network devices, firewalls, and *nix daemons can be pointed at a
central "syslog collector" with a one-line config change (e.g. rsyslog's
`*.* @@collector:514`). This is a from-scratch, dependency-free
implementation of exactly that collector, so you can point a real machine's
syslog forwarding at this lab and watch normalized events show up.

Note: binding to port 514 requires root on most systems; use a higher port
(e.g. 1514) for local testing and forward/NAT it if you want to receive from
real devices.
"""

from __future__ import annotations

import socket
from typing import Callable

LineHandler = Callable[[str], None]


def listen(host: str = "0.0.0.0", port: int = 1514, on_line: LineHandler = print, bufsize: int = 8192) -> None:
    """Block forever, invoking `on_line(text)` for every UDP datagram received."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    try:
        while True:
            data, _addr = sock.recvfrom(bufsize)
            text = data.decode("utf-8", errors="replace").strip()
            if text:
                on_line(text)
    finally:
        sock.close()
