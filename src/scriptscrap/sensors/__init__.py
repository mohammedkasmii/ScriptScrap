"""Observation sensors.

Each sensor turns one source of browser observation into spine events. Sensors
emit facts; they never correlate, score or conclude. Analysis reads the recorded
log instead, which is what keeps it testable without a browser.

Network capture still lives in the investigator itself, because it also feeds
the running tally the session manifest reports. These sensors cover what it
does not see.

`scope.py` holds the engagement boundary every sensor applies: out of scope
means metadata only, on every observation path. It lives there rather than in
one sensor because a boundary rule present in only one of them is a boundary
rule with a hole in it -- which is exactly how the lifecycle sensor came to be
emitting third-party frame URLs with their query strings intact.
"""

from ..storage import BlobStore
from .extension import ExtensionSensor
from .graphql import describe as describe_graphql
from .graphql import looks_like_graphql, operation_label
from .identity import PageRegistry
from .lifecycle import LifecycleSensor
from .runtime import RuntimeSensor
from .storage import StorageSensor
from .websocket import WebSocketSensor

__all__ = [
    "BlobStore",
    "ExtensionSensor",
    "LifecycleSensor",
    "PageRegistry",
    "RuntimeSensor",
    "StorageSensor",
    "WebSocketSensor",
    "describe_graphql",
    "looks_like_graphql",
    "operation_label",
]
