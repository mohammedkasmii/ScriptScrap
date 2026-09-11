"""Automatic offline activity segmentation.

A real agency session is one long recording of many unrelated business
activities. Nobody named a workflow or pressed start/stop; the segmentation has
to be inferred, offline, from the evidence the capture already holds -- idle
gaps, form submissions, returns to a home route, section changes.

Synthetic events are used deliberately: a test can state exactly which boundary
evidence is present, which is the only way to prove a split happened for the
intended reason rather than by accident. The one rule that outranks all the
others: segmentation is an INTERPRETATION laid over the timeline, never a
rewrite of it -- the ordered event log is untouched and every segment cites the
raw events behind it.
"""

from __future__ import annotations

import itertools

from scriptscrap.analysis import analyze_events
from scriptscrap.analysis.segmentation import (
    IDLE_GAP_MS,
    ActivitySegment,
    SegmentationAnalyzer,
)
from scriptscrap.events import Event, EventType, Source

_seq = itertools.count(1)


def _reset() -> None:
    global _seq
    _seq = itertools.count(1)


def ev(event_type, payload, *, source=Source.RUNTIME, ms=0.0,
       frame="f1", page="p1"):
    """One event at wall-clock `ms` milliseconds after an epoch."""
    n = next(_seq)
    # A fixed epoch plus an offset in milliseconds, formatted as ISO-8601 UTC.
    from datetime import UTC, datetime
    wall = datetime.fromtimestamp(1_700_000_000 + ms / 1000.0, tz=UTC).isoformat()
    return Event(
        session_id="s", event_id=f"evt-{n:05d}", seq=n,
        t_wall=wall, t_mono=float(n), source=source, type=event_type,
        payload=payload, page_id=page, frame_id=frame,
    )


def click(ms, element_id="btn", **el):
    return ev(EventType.USER_CLICK, {
        "element": {"tag": "button", "id": element_id, **el}}, ms=ms)


def fill(ms, element_id="field", form="frm"):
    return ev(EventType.USER_INPUT, {
        "value": {"value": "x"},
        "element": {"tag": "input", "id": element_id, "type": "text", "form": form}}, ms=ms)


def submit(ms, form="frm"):
    return ev(EventType.USER_SUBMIT, {
        "element": {"tag": "form", "id": form}, "fields": []}, ms=ms)


def navigate(ms, url):
    return ev(EventType.NAVIGATION_COMMITTED, {"url": url}, source=Source.PLAYWRIGHT, ms=ms)


def request(ms, path, method="GET"):
    return ev(EventType.HTTP_REQUEST, {
        "method": method, "url": f"http://h{path}", "path": path,
        "resource_type": "fetch"}, source=Source.PLAYWRIGHT, ms=ms)


# --- the shape of the output ---------------------------------------------

def test_an_empty_session_has_no_segments():
    _reset()
    assert SegmentationAnalyzer().analyze([]) == []


def test_a_single_burst_of_actions_is_one_activity():
    _reset()
    events = [navigate(0, "http://h/orders"),
              fill(1000, "customer"), fill(1500, "amount"), click(2000, "save")]
    segments = SegmentationAnalyzer().analyze(events)
    assert len(segments) == 1
    seg = segments[0]
    assert isinstance(seg, ActivitySegment)
    assert seg.start_seq == events[0].seq
    assert seg.end_seq == events[-1].seq
    # UI actions only; the navigation is recorded in `routes`, not counted here.
    assert seg.action_count == 3
    assert "/orders" in seg.routes
    assert seg.evidence.event_ids, "a segment must cite the events behind it"


def test_an_idle_gap_splits_two_activities():
    _reset()
    events = [
        click(0, "a"), click(500, "b"),
        # A long pause: the employee finished one thing and started another.
        click(IDLE_GAP_MS + 5000, "c"), click(IDLE_GAP_MS + 5500, "d"),
    ]
    segments = SegmentationAnalyzer().analyze(events)
    assert len(segments) == 2
    assert segments[0].action_count == 2
    assert segments[1].action_count == 2
    assert segments[1].boundary_reason == "idle_gap"
    # The activity that ended because the operator went idle says so.
    assert segments[0].outcome == "idle"


def test_a_form_submission_closes_an_activity():
    _reset()
    events = [
        fill(0, "customer"), submit(1000),
        # The next action belongs to a new task.
        click(2000, "new-task"),
    ]
    segments = SegmentationAnalyzer().analyze(events)
    assert len(segments) == 2
    assert segments[0].outcome == "form_submitted"
    assert segments[1].boundary_reason == "after_form_submission"


def test_a_return_to_home_starts_a_new_activity():
    _reset()
    events = [
        navigate(0, "http://h/orders/44718"),
        click(1000, "edit"),
        navigate(2000, "http://h/"),   # back to the dashboard
        click(3000, "reports"),
    ]
    segments = SegmentationAnalyzer().analyze(events)
    assert len(segments) == 2
    assert segments[1].boundary_reason == "return_to_home"


def test_a_section_change_starts_a_new_activity():
    _reset()
    events = [
        navigate(0, "http://h/orders/1"),
        click(1000, "a"),
        navigate(2000, "http://h/invoices/9"),   # different top-level section
        click(3000, "b"),
    ]
    segments = SegmentationAnalyzer().analyze(events)
    assert len(segments) == 2
    assert segments[1].boundary_reason == "route_section_change"


def test_a_segment_records_its_routes_forms_and_endpoints():
    _reset()
    events = [
        navigate(0, "http://h/orders/44718"),
        request(500, "/api/orders/44718"),
        fill(1000, "customer", form="order-form"),
        request(1200, "/api/lookup"),
        submit(1500, form="order-form"),
    ]
    seg = SegmentationAnalyzer().analyze(events)[0]
    assert "/orders/{id}" in seg.routes
    assert "order-form" in seg.forms
    assert "/api/orders/{id}" in seg.endpoints or "/api/orders/44718" in seg.endpoints
    assert "/api/lookup" in seg.endpoints
    assert seg.action_kinds.get("fill", 0) >= 1
    assert seg.action_kinds.get("submit", 0) >= 1


def test_confidence_is_between_zero_and_one():
    _reset()
    events = [click(0, "a"), submit(1000), click(2000, "b")]
    for seg in SegmentationAnalyzer().analyze(events):
        assert 0.0 <= seg.confidence <= 1.0


def test_the_last_segment_outcome_is_session_end():
    _reset()
    events = [click(0, "a"), click(500, "b")]
    segments = SegmentationAnalyzer().analyze(events)
    assert segments[-1].outcome == "session_end"


def test_segmentation_does_not_rewrite_the_timeline():
    """The ordered log is evidence; segmentation is a view over it."""
    _reset()
    events = [click(0, "a"), submit(1000), click(2000, "b")]
    before = [(e.seq, e.event_id, str(e.type)) for e in events]
    SegmentationAnalyzer().analyze(events)
    after = [(e.seq, e.event_id, str(e.type)) for e in events]
    assert before == after


def test_segments_are_exposed_on_the_analysis_result():
    _reset()
    events = [navigate(0, "http://h/orders"), click(1000, "a"),
              submit(2000), click(3000, "b")]
    result = analyze_events(events, "s")
    assert result.segments, "analyze_events must expose inferred activity segments"
    assert all(isinstance(s, ActivitySegment) for s in result.segments)
    # Every segment's seq range lies within the observed sequence.
    seqs = [e.seq for e in events]
    for seg in result.segments:
        assert min(seqs) <= seg.start_seq <= seg.end_seq <= max(seqs)
