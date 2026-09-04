"""Extension sensor: ingests forensic evidence into the event spine.

The extension observes; this translates. Response bodies arrive base64-encoded
over the loopback socket and go straight into the content-addressed blob store,
so the event log keeps a hash and a size rather than megabytes of body.

Firefox request ids and ScriptScrap page/frame ids are DIFFERENT NAMESPACES and
are never conflated. The extension's `request_id`, `tab_id` and `frame_id` are
recorded verbatim as Firefox's own identifiers; relating them to Playwright's
view is the reconciliation layer's job, offline, with evidence.

Batches arrive on the transport thread, so emission must be thread-safe --
EventLog is.
"""

from __future__ import annotations

import base64
from typing import Any

from ..events import EventType, Source
from ..storage.blobs import BlobRef, BlobSkipped, BlobStore

# Extension record type -> spine event type. A record whose type is missing here
# is reported as a capture gap rather than dropped.
EXTENSION_EVENT_TYPES: dict[str, EventType] = {
    "forensic_sensor_started": EventType.FORENSIC_SENSOR_STARTED,
    "extension_request": EventType.EXTENSION_REQUEST,
    "extension_request_headers": EventType.EXTENSION_REQUEST_HEADERS,
    "extension_response": EventType.EXTENSION_RESPONSE,
    "extension_request_failed": EventType.EXTENSION_REQUEST_FAILED,
    "extension_redirect": EventType.EXTENSION_REDIRECT,
    "extension_navigation": EventType.EXTENSION_NAVIGATION,
    "response_body_skipped": EventType.RESPONSE_BODY_SKIPPED,
    "cookie_changed": EventType.COOKIE_CHANGED,
    "cookie_deleted": EventType.COOKIE_DELETED,
    "sensor_error": EventType.SENSOR_ERROR,
}

# Handled specially: the payload carries bytes that must reach the blob store
# instead of the event log.
BODY_RECORD = "response_body_captured"
SCRIPT_RECORD = "script_source"

# Envelope fields. A payload key with one of these names would collide with
# emit_event()'s own parameters and the whole record would be lost -- which is
# exactly what happened to every cookie event until this guard existed. The
# payload comes from JavaScript we do not control at call time, so it is
# defended against structurally rather than by convention.
RESERVED_PAYLOAD_KEYS = frozenset({"source", "event_type", "page_id", "frame_id"})


class ExtensionSensor:
    """Turns extension batches into spine events plus blobs."""

    def __init__(self, engine: Any, blob_store: BlobStore) -> None:
        self.engine = engine
        self.blobs = blob_store
        self.records = 0
        self.bodies_captured = 0
        self.bodies_skipped = 0
        self.scripts_captured = 0
        self.unknown_types: set[str] = set()
        self.started = False
        self.capabilities: dict[str, Any] = {}

    # -- ingest ------------------------------------------------------------
    def on_batch(self, batch: list[dict[str, Any]]) -> None:
        """Transport callback. Must never raise into the transport thread."""
        for record in batch:
            try:
                self._ingest(record)
            except Exception as exc:
                self.engine.emit_sensor_error("extension_record_ingest", exc)

    def _ingest(self, record: dict[str, Any]) -> None:
        kind = record.get("type")
        payload = dict(record.get("payload") or {})
        # The extension's own clock and ordering are evidence; the spine's seq
        # remains the authoritative ingest order.
        payload["extension_ordinal"] = record.get("ordinal")
        payload["extension_time_ms"] = record.get("t_wall")
        self.records += 1

        # Extract oversized fields BEFORE the reserved-key guard renames
        # anything: a script record's own `source` key is its text, not the
        # spine's sensor field, and must not be caught by the rename.
        if kind == SCRIPT_RECORD:
            source_text = payload.pop("source", None)
            self._guard_reserved(payload)
            self._store_script(payload, source_text)
            return

        self._guard_reserved(payload)

        if kind == BODY_RECORD:
            self._store_body(payload)
            return
        if kind == "forensic_sensor_started":
            self.started = True
            self.capabilities = payload.get("capabilities") or {}

        if kind == "response_body_skipped":
            # The extension declined the body browser-side, before it reached us.
            self.bodies_skipped += 1

        event_type = EXTENSION_EVENT_TYPES.get(str(kind))
        if event_type is None:
            self.unknown_types.add(str(kind))
            self.engine.emit_capture_gap(
                "unknown_extension_event_type", extension_type=str(kind))
            return

        self.engine.emit_event(Source.EXTENSION, event_type, **payload)

    # -- bodies ------------------------------------------------------------
    def _decode(self, payload: dict[str, Any]) -> bytes | None:
        raw = payload.pop("body_base64", None)
        if not isinstance(raw, str):
            return None
        try:
            return base64.b64decode(raw)
        except (ValueError, TypeError) as exc:
            self.engine.emit_sensor_error(
                "extension_body_decode", exc, url=payload.get("url"))
            return None

    def _store_body(self, payload: dict[str, Any]) -> None:
        data = self._decode(payload)
        if data is None:
            self.engine.emit_capture_gap(
                "response_body_undecodable", url=payload.get("url"),
                note="extension delivered a body that could not be decoded")
            return

        stored = self.blobs.put(data, media_type=payload.get("media_type"))
        if isinstance(stored, BlobSkipped):
            self.bodies_skipped += 1
            self.engine.emit_event(
                Source.EXTENSION, EventType.RESPONSE_BODY_SKIPPED,
                **payload, body_capture=stored.to_dict())
            return

        self.bodies_captured += 1
        self.engine.emit_event(
            Source.EXTENSION, EventType.RESPONSE_BODY_CAPTURED,
            **payload, body=stored.to_dict())

    @staticmethod
    def _guard_reserved(payload: dict[str, Any]) -> None:
        """Rename payload keys that would collide with envelope parameters."""
        for reserved in RESERVED_PAYLOAD_KEYS & payload.keys():
            payload[f"payload_{reserved}"] = payload.pop(reserved)

    def _store_script(self, payload: dict[str, Any], source: Any) -> None:
        """Script source, stored as a blob with an inventory of what is in it."""
        if not isinstance(source, str):
            return
        stored = self.blobs.put(source.encode("utf-8", "replace"),
                                media_type=payload.get("media_type"))
        self.scripts_captured += 1

        body: dict[str, Any] | None
        if isinstance(stored, BlobRef):
            body = stored.to_dict()
        else:
            body = None
            payload["body_capture"] = stored.to_dict()

        # Lightweight inventory only. Deliberately not an AST pass: the goal is
        # to make source searchable offline, not to reverse-engineer it here.
        from ..analysis.scriptinfo import summarise_source

        self.engine.emit_event(
            Source.EXTENSION, EventType.SCRIPT_SOURCE,
            **payload, body=body, inventory=summarise_source(source),
        )

    # -- reporting ---------------------------------------------------------
    def stats(self) -> dict[str, Any]:
        return {
            "started": self.started,
            "capabilities": self.capabilities,
            "records": self.records,
            "bodies_captured": self.bodies_captured,
            "bodies_skipped": self.bodies_skipped,
            "scripts_captured": self.scripts_captured,
            "unknown_types": sorted(self.unknown_types),
            "blobs": self.blobs.stats(),
        }
