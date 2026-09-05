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
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ..events import EventType, Source
from ..probe import (
    BINDING_NAME,
    DRAIN_FUNCTION,
    PATCH_MARKER,
    build_init_script,
    build_main_world_script,
)
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

# --- engagement boundary on the runtime path ------------------------------
#
# Playwright's handlers enforce InvestigationScope; this path did not. The
# probe patches the globals of an IN-SCOPE page, but that page's own third-party
# scripts call `fetch` to wherever they like -- so a scope check on the FRAME
# passes while the request target is somebody else's analytics endpoint. A real
# capture recorded 504 out-of-scope runtime observations, 213 of them carrying
# full query strings.
#
# The same policy as the Playwright path applies here: out of scope means
# metadata only.

# Payload keys that hold a URL. Any of them is stripped of query and fragment
# when its own host is out of scope, wherever it appears.
URL_PAYLOAD_KEYS = ("url", "action", "from", "frame_url")

# Everything a reduced (out-of-scope) event may keep. An allowlist, because a
# denylist silently admits every payload key added later.
REDUCED_KEEP_KEYS = frozenset({
    "method", "status", "via", "op", "store", "async", "count", "overflow",
    "probe_ordinal", "probe_world", "probe_time_ms", "probe_time_origin",
    "is_top_frame",
})

# A URL inside a stack frame, e.g. `handler@https://host/app.js?v=3:12:5`.
_STACK_URL = re.compile(r"https?://[^\s)]+")


def _strip_query(url: str) -> str:
    """`https://h/p?a=secret#frag` -> `https://h/p`. Origin and path survive."""
    parsed = urlsplit(url)
    if not parsed.scheme and not parsed.netloc:
        return url.split("?", 1)[0].split("#", 1)[0]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _redact_stack_frame(scope: Any, frame: Any) -> Any:
    """Strip query values from any out-of-scope script URL inside a stack frame.

    A stack is the evidence for WHICH code made a call, and that is worth
    keeping. The parameters on a third-party script's URL are not.
    """
    if not isinstance(frame, str):
        return frame

    def replace(match: re.Match) -> str:
        # A frame is `...url:line:column`; the trailing position is not part of
        # the URL and must survive the strip.
        raw = match.group(0)
        position = ""
        while raw and raw[-1].isdigit():
            head, _, tail = raw.rpartition(":")
            if not head or not tail.isdigit():
                break
            position = ":" + tail + position
            raw = head
        return (raw if scope.contains(raw) else _strip_query(raw)) + position

    return _STACK_URL.sub(replace, frame)


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
        self.reduced_out_of_scope = 0
        self.main_world_installs = 0
        self.main_world_failures = 0
        self.main_world_verified: dict[str, bool] | None = None
        self._main_world_reported = False

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

    # -- main world ---------------------------------------------------------
    async def install_main_world(self, frame: Any) -> dict[str, bool] | None:
        """Install the patch half in the page's OWN JavaScript world.

        `add_init_script` lands in the isolated world, where patching `fetch`
        changes a global no application ever calls. Camoufox exposes the real
        world only through `evaluate("mw:" + script)`, which cannot run at
        document_start -- so this is called on every navigation, as early as
        the driver is allowed to run anything, and is idempotent.

        Returns the patch marker the page reports back, or None on failure.
        """
        try:
            marker = await frame.evaluate(
                "mw:" + build_main_world_script(self.config))
        except Exception as exc:
            self.main_world_failures += 1
            # Reported once: a page with many frames would otherwise bury the
            # rest of the log in the same failure.
            if not self._main_world_reported:
                self._main_world_reported = True
                self.engine.emit_sensor_error("runtime_main_world_install", exc)
                self.engine.emit_capture_gap(
                    "runtime_main_world_unavailable",
                    error=str(exc),
                    note=("the probe's patched instruments (fetch, XHR, sendBeacon, "
                          "form submit, pushState) could not be installed in the "
                          "page's own JS world. No runtime network observation, "
                          "call stacks or initiators will be recorded. Check that "
                          "the browser was launched with main_world_eval=True."),
                )
            return None

        if isinstance(marker, dict):
            self.main_world_installs += 1
            self.main_world_verified = marker
            missing = sorted(k for k, v in marker.items() if not v)
            if missing and not self._main_world_reported:
                self._main_world_reported = True
                self.engine.emit_capture_gap(
                    "runtime_patches_not_installed",
                    missing=missing,
                    note=("the main-world script ran but these instruments did not "
                          "bind; the APIs they wrap will not be observed"),
                )
        return marker if isinstance(marker, dict) else None

    async def verify_main_world(self, frame: Any) -> dict[str, Any]:
        """Read the patch marker back from the page. The runtime self-test.

        The first real capture reported `runtime_probe healthy` while every
        patched instrument was silent, because nothing ever asked the page
        whether the patches were actually there. This asks.
        """
        result: dict[str, Any] = {"checked": True}
        try:
            result["marker"] = await frame.evaluate(
                f"mw:window.{PATCH_MARKER} || null")
        except Exception as exc:
            result["marker"] = None
            result["error"] = f"{type(exc).__name__}: {exc}"
        marker = result.get("marker")
        result["ok"] = bool(marker) and all(marker.values())
        if not result["ok"]:
            self.engine.emit_capture_gap(
                "runtime_patch_verification_failed",
                marker=marker,
                error=result.get("error"),
                note=("the page's own JS world does not report ScriptScrap's "
                      "patches. Runtime network evidence from this session is "
                      "missing, not absent."),
            )
        return result

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
        # Which JS world observed it. The two roles count ordinals separately,
        # so `probe_ordinal` is only comparable within one world -- the same
        # rule that applies to `seq` across sensors.
        payload["probe_world"] = record.get("world") or "isolated"
        # The document instance. An ordinal restarts on navigation while a
        # frame id survives it, so neither the ordinal nor the in-page clock
        # means anything against an observation carrying a different origin.
        payload["probe_time_origin"] = record.get("t_origin")
        payload["probe_time_ms"] = record.get("t_page")
        payload["frame_url"] = record.get("frame_url")
        payload["is_top_frame"] = record.get("is_top")

        payload = self._apply_scope(payload)

        self.received += 1
        self.engine.emit_event(
            Source.RUNTIME, event_type, page_id=page_id, frame_id=frame_id, **payload
        )

    # -- engagement boundary ------------------------------------------------
    def _apply_scope(self, payload: dict) -> dict:
        """Reduce an observation whose subject lies outside the engagement.

        Two independent reductions, because they protect different things:

        1. Every URL-valued field -- including the stack -- loses its query and
           fragment when ITS OWN host is out of scope. A stack frame naming a
           third-party script can carry that script's URL parameters, so this
           applies even on an in-scope observation.
        2. When the observation's own subject is out of scope, the payload is
           rebuilt from an allowlist: method, status and the probe's own
           bookkeeping survive; bodies, header names, typed values, storage
           values and element detail do not.

        The event is kept rather than dropped. "A third-party call happened
        here" is the same forensic fact the Playwright path preserves, and
        losing it would make an out-of-scope page look silent.
        """
        scope = getattr(self.engine, "scope", None)
        if scope is None:
            return payload

        for key in URL_PAYLOAD_KEYS:
            value = payload.get(key)
            if isinstance(value, str) and value and not scope.contains(value):
                payload[key] = _strip_query(value)

        stack = payload.get("stack")
        if isinstance(stack, list):
            payload["stack"] = [_redact_stack_frame(scope, f) for f in stack]

        subject = (payload.get("url") or payload.get("action")
                   or payload.get("frame_url"))
        if not isinstance(subject, str) or not subject or scope.contains(subject):
            return payload

        reduced = {k: v for k, v in payload.items() if k in REDUCED_KEEP_KEYS}
        for key in URL_PAYLOAD_KEYS:
            value = payload.get(key)
            if isinstance(value, str) and value:
                # Every URL on a reduced event loses its query, including one
                # that is itself in scope. A record labelled metadata-only must
                # be metadata-only throughout, or a reader filtering on that
                # label gets a surprise: `runtime_history` to a third-party URL
                # was keeping the full in-scope `from` URL beside it. The
                # in-scope side of that navigation is recorded on the in-scope
                # path anyway, so nothing is actually lost here.
                reduced[key] = _strip_query(value)
        removed = sorted(k for k in payload if k not in reduced)
        reduced["scope"] = "out_of_scope"
        reduced["evidence_reduced"] = True
        reduced["evidence_removed"] = removed
        self.reduced_out_of_scope += 1
        return reduced

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
            # Observations kept as metadata because their subject was outside
            # the engagement. Disclosed, so a reader can see the boundary ran.
            "reduced_out_of_scope": self.reduced_out_of_scope,
            "main_world_installs": self.main_world_installs,
            "main_world_failures": self.main_world_failures,
            "main_world_verified": self.main_world_verified,
        }
