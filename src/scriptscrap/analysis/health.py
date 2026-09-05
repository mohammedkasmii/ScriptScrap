"""Capture health: did the application do nothing, or did we fail to see it?

This is the question the whole project turns on. A session that captured
nothing looks identical to a session where every sensor failed, unless the tool
says which happened.

Statuses are CATEGORIES, not percentages:

    healthy         the sensor ran and reported no failures
    degraded        the sensor ran but lost evidence it should have had
    unavailable     the sensor did not run at all
    not_applicable  the sensor is not part of this session's mode
    unknown         no evidence either way

A percentage is only produced where a real denominator exists -- bodies
captured out of bodies attempted, frames instrumented out of frames seen.
Inventing a number for "how much of the application did we observe" would be
worse than saying `degraded`, because it would look like it meant something.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from ..events import Event, EventType, Source
from .reconcile import Reconciler, summarise

HEALTHY = "healthy"
DEGRADED = "degraded"
UNAVAILABLE = "unavailable"
NOT_APPLICABLE = "not_applicable"
UNKNOWN = "unknown"

# Gaps that mean a whole class of evidence is missing, not one datum.
_STRUCTURAL_GAPS = {
    "runtime_probe_unavailable",
    "service_worker_visibility_unavailable",
    "context_page_events_unavailable",
    "websocket_events_unavailable",
    "extension_disconnected",
}


@dataclass(slots=True)
class SensorHealth:
    name: str
    status: str
    reasons: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    # A whole FAMILY of evidence this sensor should have produced and did not.
    # Distinct from `reasons`, which covers lossy-but-working sensors.
    blind_spots: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"sensor": self.name, "status": self.status,
                "reasons": self.reasons, "metrics": self.metrics,
                "blind_spots": self.blind_spots}


@dataclass(slots=True)
class CaptureHealth:
    overall: str
    sensors: list[SensorHealth]
    gaps: dict[str, int]
    errors: dict[str, int]
    reconciliation: dict[str, Any]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall": self.overall,
            "sensors": [s.to_dict() for s in self.sensors],
            "capture_gaps": self.gaps,
            "sensor_errors": self.errors,
            "reconciliation": self.reconciliation,
            "notes": self.notes,
        }


class HealthAnalyzer:
    """Derives a session's capture health from its own evidence."""

    def analyze(self, events: list[Event], *, forensic: bool | None = None) -> CaptureHealth:
        gaps: dict[str, int] = defaultdict(int)
        errors: dict[str, int] = defaultdict(int)
        by_type: dict[EventType, int] = defaultdict(int)
        by_source: dict[Source, int] = defaultdict(int)

        # A count Playwright can supply and the runtime probe cannot fake: how
        # much in-scope xhr/fetch traffic actually happened. It is the only
        # honest denominator for "did the probe's network hooks bind?".
        xhr_fetch_requests = 0

        for event in events:
            by_type[event.type] += 1
            by_source[event.source] += 1
            if event.type is EventType.CAPTURE_GAP:
                gaps[str(event.payload.get("reason", "unknown"))] += 1
            elif event.type is EventType.SENSOR_ERROR:
                errors[str(event.payload.get("where", "unknown"))] += 1
            elif (event.type is EventType.HTTP_REQUEST
                  and event.payload.get("resource_type") in ("xhr", "fetch")):
                xhr_fetch_requests += 1

        if forensic is None:
            forensic = by_type[EventType.FORENSIC_SENSOR_STARTED] > 0 or any(
                by_type[t] for t in (EventType.EXTENSION_REQUEST,
                                     EventType.EXTENSION_RESPONSE))

        sensors = [
            self._playwright(by_type, errors),
            self._runtime(by_type, by_source, gaps, errors, xhr_fetch_requests),
            self._dom(by_type, errors),
            self._websocket(by_type, gaps),
            self._storage(by_type, gaps, errors),
            self._extension(by_type, gaps, errors, forensic=forensic),
        ]

        matches = Reconciler().analyze(events)
        reconciliation = summarise(matches)

        notes = self._notes(gaps, by_type, reconciliation)
        return CaptureHealth(
            overall=self._overall(sensors),
            sensors=sensors,
            gaps=dict(sorted(gaps.items())),
            errors=dict(sorted(errors.items())),
            reconciliation=reconciliation,
            notes=notes,
        )

    # -- per sensor --------------------------------------------------------
    def _playwright(self, by_type, errors) -> SensorHealth:
        requests = by_type[EventType.HTTP_REQUEST]
        failures = sum(v for k, v in errors.items() if "handle_re" in k)
        if not requests:
            return SensorHealth("playwright_network", UNAVAILABLE,
                                ["no HTTP requests observed"])
        status = DEGRADED if failures else HEALTHY
        reasons = [f"{failures} handler failure(s)"] if failures else []
        return SensorHealth("playwright_network", status, reasons,
                            {"requests": requests,
                             "responses": by_type[EventType.HTTP_RESPONSE],
                             "failed": by_type[EventType.HTTP_FAILED]})

    def _runtime(self, by_type, by_source, gaps, errors,
                 xhr_fetch_requests: int = 0) -> SensorHealth:
        """Coverage, not presence.

        The probe binds two KINDS of instrument: listeners (click, input,
        MutationObserver, popstate) and monkey-patches (fetch, XHR, sendBeacon,
        pushState). A browser change that re-isolates the JS world kills every
        patch while leaving every listener working -- and the old check, which
        only asked whether ANY runtime event existed, called that healthy while
        the entire network view was missing. Ask instead whether each family
        produced evidence when something else says it should have.
        """
        runtime_events = by_source[Source.RUNTIME]
        if gaps.get("runtime_probe_unavailable"):
            return SensorHealth("runtime_probe", UNAVAILABLE,
                                ["probe failed to install; no user actions, "
                                 "stacks, SSE or storage writes were observed"])
        if not runtime_events:
            return SensorHealth("runtime_probe", UNAVAILABLE,
                                ["no runtime events reached the collector"])

        patched = sum(by_type[t] for t in (
            EventType.RUNTIME_FETCH, EventType.RUNTIME_XHR,
            EventType.RUNTIME_BEACON, EventType.RUNTIME_FORM_SUBMIT))
        listened = sum(by_type[t] for t in (
            EventType.USER_CLICK, EventType.USER_INPUT,
            EventType.USER_CHANGE, EventType.USER_SUBMIT))

        reasons: list[str] = []
        blind_spots: list[str] = []
        drain_failures = sum(v for k, v in errors.items() if "runtime" in k)
        if drain_failures:
            reasons.append(f"{drain_failures} runtime sensor error(s)")

        # The one check with a real correlate. Playwright counted the xhr/fetch
        # traffic independently, so "the application made 202 requests and the
        # probe saw none of them" is a measurement, not a heuristic. A weaker
        # rule (user actions but no DOM mutations) was tried and dropped: a
        # click that changes nothing is ordinary, so it fired on quiet sessions.
        if xhr_fetch_requests and not patched:
            blind_spots.append(
                f"patched instruments (fetch/XHR/sendBeacon/form submit) produced "
                f"NOTHING while Playwright observed {xhr_fetch_requests} in-scope "
                f"xhr/fetch request(s). The patches are not reaching the page -- "
                f"check JS world isolation and the browser build against the "
                f"recorded baseline. Call stacks and initiators are missing.")
        if gaps.get("runtime_main_world_unavailable"):
            blind_spots.append(
                "the probe could not be installed in the page's own JS world; "
                "no runtime network observation was possible")
        if gaps.get("runtime_patches_not_installed"):
            blind_spots.append(
                "some patched instruments did not bind in the page's JS world")

        # A blind spot IS a reason. Every non-healthy status must say why.
        reasons = blind_spots + reasons
        status = DEGRADED if reasons else HEALTHY
        return SensorHealth(
            "runtime_probe", status, reasons,
            {"events": runtime_events,
             "user_actions": listened,
             "listener_instrument_events": listened + by_type[EventType.DOM_MUTATION],
             "patched_instrument_events": patched,
             "playwright_xhr_fetch_requests": xhr_fetch_requests,
             "runtime_calls": sum(by_type[t] for t in (
                 EventType.RUNTIME_FETCH, EventType.RUNTIME_XHR))},
            blind_spots)

    def _dom(self, by_type, errors) -> SensorHealth:
        snapshots = by_type[EventType.DOM_SNAPSHOT]
        failures = sum(v for k, v in errors.items()
                       if "scan_all_frames" in k or "capture_visual_state" in k)
        if not snapshots:
            return SensorHealth("dom_sensor", UNAVAILABLE, ["no DOM snapshots taken"])
        return SensorHealth("dom_sensor", DEGRADED if failures else HEALTHY,
                            [f"{failures} snapshot failure(s)"] if failures else [],
                            {"snapshots": snapshots,
                             "screenshots": by_type[EventType.SCREENSHOT]})

    def _websocket(self, by_type, gaps) -> SensorHealth:
        opened = by_type[EventType.WS_OPEN]
        if gaps.get("websocket_events_unavailable"):
            return SensorHealth("websocket_sensor", UNAVAILABLE,
                                ["listener could not be attached"])
        if not opened:
            return SensorHealth("websocket_sensor", NOT_APPLICABLE,
                                ["no WebSocket was opened during this session"])
        reasons = []
        if gaps.get("websocket_payload_truncated"):
            reasons.append(f"{gaps['websocket_payload_truncated']} payload(s) truncated")
        # A known, permanent limitation, not a failure of this session.
        if gaps.get("websocket_handshake_headers_unavailable"):
            reasons.append("handshake headers are not exposed by Playwright")
        return SensorHealth("websocket_sensor", DEGRADED if reasons else HEALTHY, reasons,
                            {"sockets": opened,
                             "frames": by_type[EventType.WS_FRAME_SENT]
                             + by_type[EventType.WS_FRAME_RECEIVED]})

    def _storage(self, by_type, gaps, errors) -> SensorHealth:
        snapshots = by_type[EventType.STORAGE_SNAPSHOT]
        reasons = []
        for reason in ("indexed_db_not_captured", "cache_storage_not_captured"):
            if gaps.get(reason):
                reasons.append(reason.replace("_", " "))
        if gaps.get("service_worker_visibility_unavailable"):
            reasons.append("service-worker traffic is not observable on Firefox")
        if any("storage" in k or "cookie" in k for k in errors):
            reasons.append("storage snapshot failure")
        if not snapshots:
            return SensorHealth("storage_sensor", UNAVAILABLE, ["no storage snapshot taken"])
        return SensorHealth("storage_sensor", DEGRADED if reasons else HEALTHY, reasons,
                            {"snapshots": snapshots,
                             "writes": by_type[EventType.STORAGE_CHANGE],
                             "cookie_events": by_type[EventType.COOKIE_CHANGED]
                             + by_type[EventType.COOKIE_DELETED]})

    def _extension(self, by_type, gaps, errors, *, forensic: bool) -> SensorHealth:
        if not forensic:
            return SensorHealth("extension_network", NOT_APPLICABLE,
                                ["forensic mode was not enabled"])
        if not by_type[EventType.FORENSIC_SENSOR_STARTED]:
            return SensorHealth("extension_network", UNAVAILABLE,
                                ["extension never connected"])

        attempted = (by_type[EventType.RESPONSE_BODY_CAPTURED]
                     + by_type[EventType.RESPONSE_BODY_SKIPPED])
        reasons = []
        metrics: dict[str, Any] = {
            "requests": by_type[EventType.EXTENSION_REQUEST],
            "responses": by_type[EventType.EXTENSION_RESPONSE],
            "bodies_captured": by_type[EventType.RESPONSE_BODY_CAPTURED],
            "bodies_skipped": by_type[EventType.RESPONSE_BODY_SKIPPED],
            "scripts": by_type[EventType.SCRIPT_SOURCE],
        }
        if attempted:
            # A real denominator exists here, so a ratio means something.
            metrics["body_capture_rate"] = round(
                by_type[EventType.RESPONSE_BODY_CAPTURED] / attempted, 3)
        if by_type[EventType.RESPONSE_BODY_SKIPPED]:
            reasons.append(
                f"{by_type[EventType.RESPONSE_BODY_SKIPPED]} body/bodies exceeded the size limit")
        if gaps.get("extension_disconnected"):
            reasons.append("extension disconnected during the session")
        if any("extension" in k or "filter" in k for k in errors):
            reasons.append("extension sensor error(s)")
        return SensorHealth("extension_network", DEGRADED if reasons else HEALTHY,
                            reasons, metrics)

    # -- overall -----------------------------------------------------------
    @staticmethod
    def _overall(sensors: list[SensorHealth]) -> str:
        considered = [s for s in sensors if s.status != NOT_APPLICABLE]
        if not considered:
            return UNKNOWN
        statuses = {s.status for s in considered}

        # These are different claims and a session can be all of them at once,
        # so they are composed rather than ranked. Ranking hid the worst one:
        # a sensor that RAN and lost an evidence family is the deceptive case,
        # and it was being masked by a sensor that plainly never started.
        parts: list[str] = []
        if any(s.blind_spots for s in considered):
            parts.append("SENSOR BLIND SPOT")
        if UNAVAILABLE in statuses:
            parts.append("SENSOR UNAVAILABLE")
        if not parts and DEGRADED in statuses:
            parts.append("HIGH COVERAGE")
        if not parts:
            return "COMPLETE / ALL SENSORS HEALTHY"
        return "PARTIAL / " + " + ".join(parts)

    @staticmethod
    def _notes(gaps, by_type, reconciliation) -> list[str]:
        notes: list[str] = []
        for reason, count in sorted(gaps.items()):
            if reason in _STRUCTURAL_GAPS:
                notes.append(f"structural gap: {reason} ({count})")
        unmatched = reconciliation.get("unmatched_by_sensor", {})
        for sensor, count in sorted(unmatched.items()):
            if sensor == "extension":
                notes.append(
                    f"{count} request(s) seen only by the extension -- traffic the "
                    f"other sensors could not observe")
            else:
                notes.append(f"{count} activity/activities seen only by {sensor}")
        # Zero conflicts reads as agreement. With zero multi-sensor activities
        # it means the opposite: only one sensor ever spoke, so nothing was
        # cross-checked. This line is what the first real capture needed and
        # did not get.
        if reconciliation.get("activities") and not reconciliation.get("multi_sensor"):
            notes.append(
                f"WARNING: none of the {reconciliation['activities']} reconciled "
                f"activity/activities was seen by more than one sensor, so no "
                f"claim in this session was cross-checked")
        if reconciliation.get("conflicts"):
            notes.append(
                f"{reconciliation['conflicts']} sensor conflict(s); both claims preserved")
        if by_type[EventType.SOURCE_REWRITE]:
            notes.append(
                f"{by_type[EventType.SOURCE_REWRITE]} script(s) were REWRITTEN before "
                f"execution; this session is not pure observation")
        return notes
