"""Observation sensors.

Each sensor turns one source of browser observation into spine events. Sensors
emit facts; they never correlate, score or conclude. Analysis reads the recorded
log instead, which is what keeps it testable without a browser.

The existing network capture still lives in the investigator itself, because it
also feeds the M1 exporters that remain the behavioural authority. These sensors
cover what was previously unobserved.
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
