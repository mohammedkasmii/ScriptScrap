"""Append-only event spine.

M1 runs this in DUAL-WRITE mode: the existing investigator structures remain the
behavioural authority and events are emitted alongside them. Nothing reads the
event log to produce investigator output yet -- the model is being proven against
real runs first.
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
