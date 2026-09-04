"""Runtime sensor: hosts the in-page probe and ingests its batches.

The probe observes what only page JavaScript can see -- which user action ran,
which script called `fetch`, the stack behind it, SSE messages, DOM mutations,
storage writes -- and streams it here in batches.

Batching matters: `expose_binding` is one IPC round trip per call, and a busy
page can produce hundreds of events a second. One call per event would slow the
application down, which would make the observer the reason it behaves
differently.

This sensor translates probe records into spine events. It does NOT correlate
them with network events; that is M3's job over the recorded log.
"""

from __future__ import annotations

import json
from typing import Any

from ..events import EventType, Source
from ..probe import BINDING_NAME, DRAIN_FUNCTION, build_init_script
from .identity import PageRegistry

# Probe record type -> spine event type. A record whose type is not here is
# recorded as a sensor error rather than silently dropped.
PROBE_EVENT_TYPES: dict[str, EventType] = {
    "user_click": EventType.USER_CLICK,
    "user_input": EventType.USER_INPUT,
    "user_change": EventType.USER_CHANGE,
    "user_submit": EventType.USER_SUBMIT,
    "user_key": EventType.USER_KEY,
    "runtime_fetch": EventType.RUNTIME_FETCH,
    "runtime_xhr": EventType.RUNTIME_XHR,
    "runtime_beacon": EventType.RUNTIME_BEACON,
    "runtime_form_submit": EventType.RUNTIME_FORM_SUBMIT,
    "runtime_history": EventType.RUNTIME_HISTORY,
    "sse_open": EventType.SSE_OPEN,
    "sse_message": EventType.SSE_MESSAGE,
    "sse_error": EventType.SSE_ERROR,
    "dom_mutation": EventType.DOM_MUTATION,
    "storage_change": EventType.STORAGE_CHANGE,
    "sensor_error": EventType.SENSOR_ERROR,
}

DEFAULT_PROBE_CONFIG = {
    "maxBuffer": 500,
    "flushIntervalMs": 400,
    "maxStringBytes": 8192,
    "maxStackFrames": 12,
    "maxMutationsPerBatch": 40,
    "capturePasswordValues": False,
}


class RuntimeSensor:
    """Installs the probe on a context and ingests its event batches."""

    def __init__(self, engine: Any, registry: PageRegistry, config: dict | None = None) -> None:
        self.engine = engine
        self.registry = registry
        self.config = {**DEFAULT_PROBE_CONFIG, **(config or {})}
        self.received = 0
        self.batches = 0
        self.unknown_types: set[str] = set()
        self._installed = False

    async def attach(self, context: Any) -> None:
        """Expose the binding and inject the probe for every page in the context."""
        if self._installed:
            return
        try:
            await context.expose_binding(BINDING_NAME, self._on_batch)
            await context.add_init_script(build_init_script(self.config))
            self._installed = True
        except Exception as exc:
            self.engine.emit_sensor_error("runtime_sensor_attach", exc)
            self.engine.emit_capture_gap(
                "runtime_probe_unavailable",
                note="no user actions, runtime stacks, SSE or storage writes will be observed",
            )

    def _on_batch(self, binding_source: dict, raw: str) -> bool:
        """Playwright binding callback. Must never raise into the page."""
        self.batches += 1
        frame = binding_source.get("frame")
        page = binding_source.get("page")
        frame_id = self.registry.frame_id(frame) if frame is not None else None
        page_id = self.registry.page_id(page) if page is not None else None

        try:
            records = json.loads(raw)
        except (TypeError, ValueError) as exc:
            self.engine.emit_sensor_error("runtime_batch_decode", exc, batch_bytes=len(raw or ""))
            return True

        for record in records:
            try:
                self._ingest(record, page_id, frame_id)
            except Exception as exc:  # a bad record must not lose the rest
                self.engine.emit_sensor_error("runtime_record_ingest", exc)
        return True

    def _ingest(self, record: dict, page_id: str | None, frame_id: str | None) -> None:
        kind = record.get("type")
        event_type = PROBE_EVENT_TYPES.get(kind)
        if event_type is None:
            self.unknown_types.add(str(kind))
            self.engine.emit_capture_gap(
                "unknown_probe_event_type",
                probe_type=str(kind),
                note="probe emitted a record this build does not map",
            )
            return

        payload = dict(record.get("payload") or {})
        # The probe's own clock and ordering are preserved as evidence; the
        # spine's `seq` remains the authoritative order.
        payload["probe_ordinal"] = record.get("ordinal")
        payload["probe_time_ms"] = record.get("t_page")
        payload["frame_url"] = record.get("frame_url")
        payload["is_top_frame"] = record.get("is_top")

        self.received += 1
        self.engine.emit_event(
            Source.RUNTIME, event_type, page_id=page_id, frame_id=frame_id, **payload
        )

    async def drain(self, page: Any) -> None:
        """Ask every frame to flush before the session ends."""
        for frame in getattr(page, "frames", []) or []:
            try:
                await frame.evaluate(
                    f"() => typeof window.{DRAIN_FUNCTION} === 'function' "
                    f"&& window.{DRAIN_FUNCTION}()"
                )
            except Exception as exc:
                self.engine.emit_sensor_error(
                    "runtime_drain", exc, frame_id=self.registry.frame_id(frame)
                )

    def stats(self) -> dict[str, Any]:
        return {
            "installed": self._installed,
            "batches": self.batches,
            "events_ingested": self.received,
            "unknown_types": sorted(self.unknown_types),
        }
