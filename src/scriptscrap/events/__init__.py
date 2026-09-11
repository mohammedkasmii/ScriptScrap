"""Append-only event spine.

`events.jsonl` is the only record a session produces. It was dual-written
alongside nine legacy JSON outputs while the model was proven against real
runs; those were retired once `scriptscrap analyze` derived everything they
stated, with the event ids behind each conclusion attached.

Everything downstream -- analysis, the workspace, the generators -- reads this
log or something rebuildable from it.
"""

from .log import EventLog, new_id
from .model import (
    MAX_PAYLOAD_FIELD_BYTES,
    Event,
    EventType,
    Source,
    make_payload,
    now_mono,
    now_wall,
)
from .reader import EventLogReader, LogProblem

__all__ = [
    "MAX_PAYLOAD_FIELD_BYTES",
    "Event",
    "EventLog",
    "EventLogReader",
    "EventType",
    "LogProblem",
    "Source",
    "make_payload",
    "new_id",
    "now_mono",
    "now_wall",
]
