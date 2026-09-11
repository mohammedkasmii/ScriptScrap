"""Automatic offline activity segmentation.

The real operating model is one long session: an employee is handed the browser
and works normally for hours across many unrelated business activities, then the
session is stopped once. Nobody names a workflow, starts or stops a task, or
annotates a step. So the separation into activities has to be INFERRED here,
offline, from the evidence the capture already holds.

Two rules shape everything below:

1. **This is an interpretation, not a rewrite.** The ordered event log stays the
   single source of truth; a segment is a `(start_seq, end_seq)` window over it
   plus what was observed inside, and every segment cites the raw events behind
   it. `analyze_events` keeps the full `workflow` and timeline intact beside the
   segments.

2. **A boundary is only ever drawn from evidence a reader can check.** The
   signals are deliberately conservative and each one is named on the segment it
   opens (`boundary_reason`) and the one it closes (`outcome`):

       idle_gap                a wall-clock pause longer than IDLE_GAP_MS between
                               two consecutive operator actions
       after_form_submission   the previous activity ended by submitting a form
       return_to_home          navigation back to the site root / a dashboard
       route_section_change    navigation whose top-level path section changed

   Idle time and route structure are the two things a passive recorder can see
   without being told what the employee was doing, which is exactly why they are
   the backbone here.

Confidence is a deterministic function of the boundary evidence, stored on the
segment, in the same spirit as the rest of the analysis layer: a reader who
disagrees with the weighting can recompute it.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..events import Event, EventType
from .models import Evidence
from .states import route_shape

# A pause longer than this between two consecutive operator actions is read as
# the boundary between two activities. Chosen well above a slow human's
# think-time (reading a table, deciding what to click) and well below the gap a
# genuine context switch produces. It is a heuristic, and the segment says so by
# carrying `idle_gap` as its neighbour's boundary reason.
IDLE_GAP_MS = 45_000.0

# Top-level path sections that read as "home": returning to one of these almost
# always means the previous task is finished and a new one is about to begin.
HOME_SECTIONS = frozenset({"", "home", "dashboard", "accueil", "index", "start"})

# Events the operator performs. Navigations are handled separately because they
# can be a boundary rather than an action within one.
_ACTION_TYPES = {
    EventType.USER_CLICK: "click",
    EventType.USER_INPUT: "fill",
    EventType.USER_CHANGE: "change",
    EventType.USER_SUBMIT: "submit",
    EventType.USER_KEY: "press",
    EventType.RUNTIME_FORM_SUBMIT: "submit",
}

_NAV_TYPES = (EventType.NAVIGATION_COMMITTED, EventType.RUNTIME_HISTORY)

_REQUEST_TYPES = (EventType.HTTP_REQUEST, EventType.RUNTIME_FETCH, EventType.RUNTIME_XHR)


@dataclass(slots=True)
class ActivitySegment:
    """One inferred business activity: a window over the timeline, and what
    was observed inside it.

    Deliberately NOT a container of events -- it holds the `seq` range and the
    derived summary, and points back at the log through `evidence.event_ids`.
    Duplicating the events here would make this a second source of truth for
    something the log already records.
    """

    index: int
    start_seq: int
    end_seq: int
    start_wall: str | None
    end_wall: str | None
    label: str
    boundary_reason: str            # why THIS activity began
    outcome: str                    # how it ended (its successor's boundary)
    action_count: int
    action_kinds: dict[str, int] = field(default_factory=dict)
    routes: list[str] = field(default_factory=list)
    forms: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    confidence: float = 0.5
    evidence: Evidence = field(default_factory=Evidence)

    @property
    def duration_ms(self) -> float | None:
        start = _wall_ms(self.start_wall)
        end = _wall_ms(self.end_wall)
        return round(end - start, 1) if start is not None and end is not None else None


def _wall_ms(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp() * 1000.0
    except (TypeError, ValueError):
        return None


def _first_section(url: str) -> str:
    """The top-level path section of a URL, e.g. `/orders/44718?x=1` -> `orders`.

    A hash route counts as a section too, because an SPA carries its structure
    there: `/#/invoices/9` -> `invoices`.
    """
    shape = route_shape(url)
    body = shape.split("#", 1)
    for part in body:
        for segment in part.strip("/").split("/"):
            if segment and segment != "{id}":
                return segment
    return ""


# How much each boundary reason lets us trust the split. A form submission or a
# return home is a strong, intentional end; an idle gap is softer.
_BOUNDARY_CONFIDENCE = {
    "session_start": 0.5,
    "after_form_submission": 0.85,
    "return_to_home": 0.8,
    "route_section_change": 0.7,
    "idle_gap": 0.6,
}

# boundary reason of the NEXT segment -> how THIS segment ended.
_OUTCOME_OF = {
    "after_form_submission": "form_submitted",
    "return_to_home": "returned_to_home",
    "route_section_change": "navigated_away",
    "idle_gap": "idle",
}


@dataclass(slots=True)
class _Marker:
    """One salient event on the segmentation timeline."""

    seq: int
    event_id: str
    wall: str | None
    ms: float | None
    kind: str                       # an action kind, or "navigate"
    is_submit: bool
    is_nav: bool
    route: str | None
    section: str | None
    form: str | None


class SegmentationAnalyzer:
    """Groups the observed actions into probable business activities."""

    def analyze(self, events: list[Event]) -> list[ActivitySegment]:
        ordered = sorted(events, key=lambda e: e.seq)
        markers = self._markers(ordered)
        if not markers:
            return []

        # 1. Fold the salient markers into segments, recording why each began.
        raw_segments = self._fold(markers)

        # 2. Attribute routes, endpoints and forms observed anywhere in each
        #    segment's seq window -- not only on the salient markers.
        self._attribute(raw_segments, ordered)

        # 3. Each segment's outcome is how it ended, which is why its SUCCESSOR
        #    began; the last one ends with the session.
        segments: list[ActivitySegment] = []
        for i, seg in enumerate(raw_segments):
            successor = raw_segments[i + 1] if i + 1 < len(raw_segments) else None
            outcome = _OUTCOME_OF.get(successor["reason"], "ongoing") if successor \
                else "session_end"
            segments.append(self._finish(i, seg, outcome))
        return segments

    # -- salient timeline --------------------------------------------------
    def _markers(self, events: list[Event]) -> list[_Marker]:
        markers: list[_Marker] = []
        for event in events:
            action_kind = _ACTION_TYPES.get(event.type)
            if action_kind is not None:
                element = event.payload.get("element") or {}
                form = None
                if event.type in (EventType.USER_SUBMIT, EventType.RUNTIME_FORM_SUBMIT):
                    form = element.get("id") or element.get("name") or event.payload.get("form")
                elif isinstance(element, dict):
                    form = element.get("form")
                markers.append(_Marker(
                    seq=event.seq, event_id=event.event_id, wall=event.t_wall,
                    ms=_wall_ms(event.t_wall), kind=action_kind,
                    is_submit=action_kind == "submit", is_nav=False,
                    route=None, section=None,
                    form=str(form) if form else None))
            elif event.type in _NAV_TYPES:
                url = event.payload.get("url")
                if not url:
                    continue
                markers.append(_Marker(
                    seq=event.seq, event_id=event.event_id, wall=event.t_wall,
                    ms=_wall_ms(event.t_wall), kind="navigate",
                    is_submit=False, is_nav=True,
                    route=route_shape(str(url)), section=_first_section(str(url)),
                    form=None))
        return markers

    # -- folding -----------------------------------------------------------
    def _fold(self, markers: list[_Marker]) -> list[dict[str, Any]]:
        segments: list[dict[str, Any]] = []
        current: dict[str, Any] | None = None
        previous: _Marker | None = None
        current_section: str | None = None

        for marker in markers:
            reason = self._boundary(marker, previous, current, current_section)
            if reason is not None:
                current = {"reason": reason, "markers": [], "start_section": None}
                segments.append(current)
            assert current is not None
            current["markers"].append(marker)
            if marker.is_nav:
                current_section = marker.section
                if current["start_section"] is None:
                    current["start_section"] = marker.section
            previous = marker
        return segments

    @staticmethod
    def _boundary(marker: _Marker, previous: _Marker | None,
                  current: dict[str, Any] | None, current_section: str | None) -> str | None:
        """Why a new activity begins at this marker, or None to continue one."""
        if current is None or previous is None:
            return "session_start"
        # A submit ends the activity it belongs to; the NEXT marker opens a new
        # one. Checked first: it is the most intentional boundary there is.
        if previous.is_submit:
            return "after_form_submission"
        if (marker.ms is not None and previous.ms is not None
                and marker.ms - previous.ms > IDLE_GAP_MS):
            return "idle_gap"
        if marker.is_nav and marker.section is not None:
            if marker.section in HOME_SECTIONS and current_section not in HOME_SECTIONS:
                return "return_to_home"
            if current_section is not None and marker.section != current_section:
                return "route_section_change"
        return None

    # -- attribution -------------------------------------------------------
    def _attribute(self, segments: list[dict[str, Any]], events: list[Event]) -> None:
        """Fill each segment with everything observed in its seq window."""
        if not segments:
            return
        # A segment owns [start_seq, next.start_seq) so events between the last
        # salient marker and the next boundary (responses, mutations) are
        # attributed to the activity that caused them.
        starts = [seg["markers"][0].seq for seg in segments]
        for idx, seg in enumerate(segments):
            lo = starts[idx]
            hi = starts[idx + 1] if idx + 1 < len(segments) else None
            routes: list[str] = []
            endpoints: list[str] = []
            forms: list[str] = []
            for event in events:
                if event.seq < lo or (hi is not None and event.seq >= hi):
                    continue
                if event.type in _NAV_TYPES:
                    url = event.payload.get("url")
                    if url:
                        shape = route_shape(str(url))
                        if shape not in routes:
                            routes.append(shape)
                elif event.type in _REQUEST_TYPES:
                    if event.payload.get("evidence_reduced"):
                        continue
                    path = event.payload.get("path") or event.payload.get("url")
                    if path and path not in endpoints:
                        endpoints.append(str(path))
            for marker in seg["markers"]:
                if marker.form and marker.form not in forms:
                    forms.append(marker.form)
            seg["routes"] = routes
            seg["endpoints"] = _template_endpoints(endpoints)
            seg["forms"] = forms

    # -- finishing ---------------------------------------------------------
    def _finish(self, index: int, seg: dict[str, Any], outcome: str) -> ActivitySegment:
        markers: list[_Marker] = seg["markers"]
        actions = [m for m in markers if not m.is_nav]
        action_kinds: dict[str, int] = defaultdict(int)
        for marker in actions:
            action_kinds[marker.kind] += 1

        evidence = Evidence()
        for marker in markers:
            evidence.cite(marker.event_id)
        evidence.add("boundary_reason", seg["reason"])
        evidence.add("action_count", len(actions))

        routes = seg.get("routes") or []
        confidence = round(min(
            0.99,
            _BOUNDARY_CONFIDENCE.get(seg["reason"], 0.5)
            + (0.1 if outcome != "ongoing" else 0.0)), 3)

        return ActivitySegment(
            index=index,
            start_seq=markers[0].seq,
            end_seq=markers[-1].seq,
            start_wall=markers[0].wall,
            end_wall=markers[-1].wall,
            label=_label(routes, action_kinds, outcome),
            boundary_reason=seg["reason"],
            outcome=outcome,
            action_count=len(actions),
            action_kinds=dict(sorted(action_kinds.items())),
            routes=routes,
            forms=seg.get("forms") or [],
            endpoints=seg.get("endpoints") or [],
            confidence=confidence,
            evidence=evidence,
        )


def _template_endpoints(paths: list[str]) -> list[str]:
    """Collapse sibling concrete paths to a route shape, order preserved."""
    out: list[str] = []
    for path in paths:
        shape = route_shape(path) if path.startswith("/") else path
        if shape not in out:
            out.append(shape)
    return out


def _label(routes: list[str], action_kinds: dict[str, int], outcome: str) -> str:
    """A short ASCII label: the dominant route and what happened there.

    ASCII only, because labels travel through consoles, reports and the
    workspace. It names the activity from structure, never from page content.
    """
    where = routes[0].strip("/") if routes else "activity"
    where = where.replace("/", " > ") or "root"
    total = sum(action_kinds.values())
    noun = "action" if total == 1 else "actions"
    return f"{where} - {total} {noun} ({outcome})"


__all__ = ["IDLE_GAP_MS", "ActivitySegment", "SegmentationAnalyzer"]
