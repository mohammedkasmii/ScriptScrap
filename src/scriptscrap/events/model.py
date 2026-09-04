"""The event envelope.

Every observation from every sensor becomes one Event. This is the append-only
raw-evidence layer described in the evolution blueprint.

Two rules the rest of the system depends on:

1. **`seq` is the only total order.** It is allocated in Python, single-threaded,
   at ingest. Wall clocks from different sources disagree; the sequence does not.
   Never sort events by timestamp across sources.

2. **Sensors emit facts, never conclusions.** There is deliberately no
   `causes`/`confidence` field yet. Causal correlation is a later milestone and
   belongs to a derived layer that cites these events by id -- not to the events
   themselves.

During M1 this runs in DUAL-WRITE mode: the existing investigator structures
remain the behavioural authority and the event log is written alongside them, so
the model can be proven against real runs before anything depends on it.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class EventType(StrEnum):
    """The minimal set that represents what the current investigator observes.

    Deliberately small. Types are added when a sensor actually emits them, not
    in anticipation of one that might.
    """

    # Session lifecycle
    SESSION_START = "session_start"
    SESSION_END = "session_end"

    # Page / navigation
    PAGE_OPENED = "page_opened"
    NAVIGATION = "navigation"
    FRAME_NAVIGATED = "frame_navigated"

    # Network
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    HTTP_FAILED = "http_failed"

    # DOM / artifacts
    DOM_SNAPSHOT = "dom_snapshot"
    SCREENSHOT = "screenshot"
    HTML_SNAPSHOT = "html_snapshot"

    # Runtime
    RUNTIME_HOOKS = "runtime_hooks"
    DOM_MUTATION = "dom_mutation"

    # Honesty about the limits of observation
    SENSOR_ERROR = "sensor_error"
    CAPTURE_GAP = "capture_gap"


class Source(StrEnum):
    """Which sensor produced the event."""

    ENGINE = "engine"           # the investigator itself, not the application
    PLAYWRIGHT = "playwright"   # Playwright/Juggler events
    RUNTIME = "runtime"         # in-page injected probe
    EXTENSION = "extension"     # reserved; no extension sensor exists yet


# Payload bytes above this are truncated rather than retained in full. Content
# addressed blob storage is a later step; until then the log must not be able to
# grow without bound because one response was 200 MB.
MAX_PAYLOAD_FIELD_BYTES = 64 * 1024


def _truncate(value: Any) -> Any:
    """Bound a single payload value, marking anything shortened."""
    if isinstance(value, str) and len(value.encode("utf-8", "ignore")) > MAX_PAYLOAD_FIELD_BYTES:
        kept = value.encode("utf-8", "ignore")[:MAX_PAYLOAD_FIELD_BYTES].decode("utf-8", "ignore")
        return {
            "__truncated__": True,
            "original_bytes": len(value.encode("utf-8", "ignore")),
            "kept": kept,
        }
    if isinstance(value, dict):
        return {k: _truncate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_truncate(v) for v in value]
    return value


@dataclass(slots=True)
class Event:
    """One observation.

    `t_wall` is a wall-clock ISO-8601 UTC string: human-readable, comparable
    across machines, and useless for ordering.
    `t_mono` is `time.perf_counter()`: monotonic, immune to clock adjustment,
    meaningful only within one process.
    Both are kept because neither alone is sufficient.
    """

    session_id: str
    event_id: str
    seq: int
    t_wall: str
    t_mono: float
    source: Source
    type: EventType
    payload: dict[str, Any] = field(default_factory=dict)
    page_id: str | None = None
    frame_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "event_id": self.event_id,
            "seq": self.seq,
            "t_wall": self.t_wall,
            "t_mono": self.t_mono,
            "source": str(self.source),
            "type": str(self.type),
            "page_id": self.page_id,
            "frame_id": self.frame_id,
            "payload": self.payload,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=False)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Event:
        """Rebuild from a log line. Raises on a malformed envelope."""
        missing = REQUIRED_FIELDS - raw.keys()
        if missing:
            raise ValueError(f"event is missing required field(s): {sorted(missing)}")
        try:
            source = Source(raw["source"])
        except ValueError as exc:
            raise ValueError(f"unknown source {raw['source']!r}") from exc
        try:
            etype = EventType(raw["type"])
        except ValueError as exc:
            raise ValueError(f"unknown event type {raw['type']!r}") from exc
        if not isinstance(raw["seq"], int):
            raise ValueError(f"seq must be an int, got {type(raw['seq']).__name__}")
        payload = raw.get("payload") or {}
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        return cls(
            session_id=raw["session_id"],
            event_id=raw["event_id"],
            seq=raw["seq"],
            t_wall=raw["t_wall"],
            t_mono=raw["t_mono"],
            source=source,
            type=etype,
            payload=payload,
            page_id=raw.get("page_id"),
            frame_id=raw.get("frame_id"),
        )


REQUIRED_FIELDS = frozenset(
    {"session_id", "event_id", "seq", "t_wall", "t_mono", "source", "type"}
)


def now_wall() -> str:
    return datetime.now(UTC).isoformat()


def now_mono() -> float:
    return time.perf_counter()


def make_payload(**values: Any) -> dict[str, Any]:
    """Build a payload with unbounded values truncated and Nones dropped."""
    return {key: _truncate(val) for key, val in values.items() if val is not None}
