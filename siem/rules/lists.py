"""
Loads named "lists" (e.g. known-malicious IPs) referenced by rules via
`match: {in: {src_ip: <list contents>}}` after substitution here, or used
directly as a blacklist filter. Kept separate from the engine so threat-intel
style data can be swapped/updated without touching rule logic.
"""

from __future__ import annotations

from pathlib import Path


def load_list(path: str) -> set[str]:
    """Load a plain-text list file (one value per line, '#' comments allowed)."""
    values: set[str] = set()
    p = Path(path)
    if not p.exists():
        return values
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            values.add(line)
    return values


def load_lists(directory: str) -> dict[str, set[str]]:
    """Load every *.txt file in `directory` into a dict keyed by file stem."""
    result: dict[str, set[str]] = {}
    d = Path(directory)
    if not d.exists():
        return result
    for f in d.glob("*.txt"):
        result[f.stem] = load_list(str(f))
    return result
