"""Normalisation for golden-master comparison.

The rule that makes a golden master worth having: **normalise what is genuinely
nondeterministic, and nothing else.** Every value normalised here is a value that
would otherwise change between two runs of identical behaviour. Anything that
reflects what the investigator actually *did* is left alone, because that is the
thing under test.

Deliberately NOT normalised -- these must produce a diff when they change:

* endpoint methods, paths, query keys, status codes
* request and response body structure
* form/field/dropdown structure and option values
* dependency edges
* OpenAPI structure
* generated client function names and header names
* counters, scope policy, capture policy, known blind spots
* event types, sources and their order
"""

from __future__ import annotations

import re
from typing import Any

# ISO-8601, with or without timezone and fractional seconds.
_ISO = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?")
# Session ids minted as sess-YYYYMMDD-HHMMSS.
_SESSION = re.compile(r"sess-\d{8}-\d{6}")
# Visual trace artifacts: step_003_142317.png -> the HHMMSS is a clock reading.
_STEP = re.compile(r"(step_\d{3}_)\d{6}")
# Loopback addresses on an OS-assigned port. The scheme is optional because a
# `Host:` header carries a bare `127.0.0.1:63203` with no scheme at all.
_LOOPBACK = re.compile(r"((?:https?://)?(?:127\.0\.0\.1|localhost)):\d+")
# Windows and POSIX absolute paths.
_WIN_PATH = re.compile(r"[A-Za-z]:\\\\?(?:[^\\\\/:*?\"<>|\r\n]+[\\\\/])*[^\\\\/:*?\"<>|\r\n]*")
_TMP_PATH = re.compile(r"/tmp/[^\s\"']+|/var/folders/[^\s\"']+")  # noqa: S108 - a pattern, not a path

PLACEHOLDER_TS = "<TS>"
PLACEHOLDER_SESSION = "<SESSION>"
PLACEHOLDER_PORT = "<PORT>"
PLACEHOLDER_PATH = "<PATH>"
PLACEHOLDER_PINNED = "<PINNED>"
PLACEHOLDER_MONO = "<MONO>"

# Keys whose values are environment facts, not behaviour. They are pinned in
# pyproject.toml and asserted by a dedicated test, so an upgrade produces one
# clear failure instead of a diff smeared across every golden file.
PINNED_ENV_KEYS = frozenset(
    {"python", "platform", "camoufox_lib", "playwright", "camoufox_browser_build"}
)

# Keys carrying a monotonic clock reading. Ordering is asserted separately.
MONOTONIC_KEYS = frozenset({"t_mono"})

# Transport metrics, not behaviour. `batches` counts how many IPC round trips
# the runtime probe used to deliver its events; the same events can arrive in a
# different number of batches depending on how the flush timer lands. The event
# COUNT next to it is behaviour and stays pinned.
#
# `events_emitted` and `events_ingested` are totals that INCLUDE timer-batched
# events, so they inherit that batching's load sensitivity: the same observed
# mutations arrive as 6 or 7 dom_mutation events. The per-type counts and
# `dom_mutations_observed` carry the behavioural signal instead.
TRANSPORT_KEYS = frozenset({"batches", "events_emitted", "events_ingested"})
PLACEHOLDER_TRANSPORT = "<TRANSPORT>"


def normalize_text(text: str) -> str:
    """Apply every string-level rule, most specific first."""
    text = _SESSION.sub(PLACEHOLDER_SESSION, text)
    text = _ISO.sub(PLACEHOLDER_TS, text)
    text = _STEP.sub(rf"\g<1>{PLACEHOLDER_TS}", text)
    text = _LOOPBACK.sub(rf"\g<1>:{PLACEHOLDER_PORT}", text)
    text = _TMP_PATH.sub(PLACEHOLDER_PATH, text)
    return _WIN_PATH.sub(PLACEHOLDER_PATH, text)


def normalize(value: Any, *, key: str | None = None) -> Any:
    """Recursively normalise a decoded-JSON structure.

    `key` is the mapping key the value arrived under, which is what lets pinned
    environment values and monotonic clocks be replaced by name rather than by
    trying to pattern-match them out of arbitrary text.
    """
    if key in PINNED_ENV_KEYS:
        return PLACEHOLDER_PINNED
    if key in MONOTONIC_KEYS:
        return PLACEHOLDER_MONO
    if key in TRANSPORT_KEYS:
        return PLACEHOLDER_TRANSPORT
    if isinstance(value, str):
        return normalize_text(value)
    if isinstance(value, dict):
        return {k: normalize(v, key=k) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def sort_network_log(entries: list[dict]) -> list[dict]:
    """Order network entries deterministically.

    Response completion order genuinely varies between runs for concurrent
    requests, so comparing raw arrival order would produce flaky failures that
    teach developers to re-bless the baseline without reading it. Sorting by
    (method, url, body) keeps every entry and every field under test while
    removing only the ordering.

    Ordering is not lost from the system: the event spine's `seq` is the
    authoritative order and is checked by its own tests.
    """
    import json as _json

    return sorted(
        entries,
        key=lambda e: (
            str(e.get("method", "")),
            str(e.get("url", "")),
            _json.dumps(e.get("body"), sort_keys=True, default=str),
        ),
    )
