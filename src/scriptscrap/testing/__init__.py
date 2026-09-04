"""Test infrastructure: deterministic capture, normalisation, golden snapshots.

Importing this package does NOT pull in Playwright or Camoufox; `capture` does
that lazily inside the function that needs a browser, so `normalize` and
`snapshot` stay usable offline.
"""

from .normalize import normalize, normalize_text, sort_network_log
from .snapshot import build_snapshot, diff_lines, dump

__all__ = [
    "build_snapshot",
    "diff_lines",
    "dump",
    "normalize",
    "normalize_text",
    "sort_network_log",
]
