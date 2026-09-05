"""Dependency ordering: what may be claimed, and what may not.

The failure this fixes: an operator typed a search term and the request left
7ms later. Cross-sensor clock tolerance is 50ms, so the causal pair was
classified `unordered` and dropped -- while a coincidental duplicate request
2.5 seconds later scored an edge. The tool kept the accident and discarded the
relationship.

The correction is NOT "close in time means caused by". It is that an
unorderable pair is a statement about the CLOCK, not a denial of the
relationship, and may survive as an explicitly ambiguous hypothesis when
independent evidence supports it -- never reported as `precedes`.
"""

from __future__ import annotations

import itertools

from scriptscrap.analysis.correlation import (
    AMBIGUOUS_MAX_CONFIDENCE,
    PROBE_CLOCK_RESOLUTION_MS,
    CorrelationAnalyzer,
)
from scriptscrap.analysis.endpoints import EndpointAnalyzer
from scriptscrap.analysis.pipeline import _attribute_events
from scriptscrap.events import Event, EventType, Source

_seq = itertools.count(1)
WALL = "2026-01-01T00:00:00.{:03d}+00:00"


def ev(event_type, payload, *, source=Source.RUNTIME, ms=0, frame="f1", page="p1"):
    n = next(_seq)
    return Event(session_id="s", event_id=f"evt-{n:05d}", seq=n,
                 t_wall=WALL.format(ms % 1000), t_mono=float(n), source=source,
                 type=event_type, payload=payload, page_id=page, frame_id=frame)


def user_input(value, *, ms, t_page, origin=1000.0, field="search-input"):
    return ev(EventType.USER_INPUT, {
        "value": {"value": value}, "element": {"id": field},
        "probe_world": "isolated", "probe_ordinal": 1,
        "probe_time_origin": origin, "probe_time_ms": t_page,
    }, ms=ms)


def runtime_request(value, *, ms, t_page, origin=1000.0, param="search",
                    path="/examples"):
    return ev(EventType.RUNTIME_XHR, {
        "url": f"https://app.test{path}?{param}={value}", "method": "GET",
        "probe_world": "main", "probe_ordinal": 1,
        "probe_time_origin": origin, "probe_time_ms": t_page,
    }, ms=ms)


def analyze(events):
    endpoints = EndpointAnalyzer().analyze(events)
    return CorrelationAnalyzer().analyze(events, _attribute_events(events, endpoints))


def signals(edge):
    return edge.evidence.signals


# --- the case that was lost ----------------------------------------------

def test_fast_input_to_request_is_recovered():
    """5-10ms apart: the exact shape the 50ms tolerance discarded."""
    events = [user_input("Radi", ms=100, t_page=5000.0),
              runtime_request("Radi", ms=107, t_page=5007.0)]
    edges = analyze(events)

    assert len(edges) == 1, "the real relationship must not be dropped"
    edge = edges[0]
    assert edge.source_field == "#search-input"
    assert edge.target_field == "?search"
    assert edge.target_endpoint == "GET /examples", \
        "the probe's view of a request belongs to that request's endpoint"


def test_the_recovered_edge_states_its_ordering_basis_truthfully():
    events = [user_input("Radi", ms=100, t_page=5000.0),
              runtime_request("Radi", ms=107, t_page=5007.0)]
    edge = analyze(events)[0]
    s = signals(edge)

    assert s["ordering_relation"] == "precedes"
    assert s["ordering_method"] == "same_document_clock", s
    assert s["same_document_instance"] is True
    assert s["temporal_distance_ms"] == 7.0


def test_a_gap_inside_the_clock_resolution_is_ambiguous_not_precedes():
    """The in-page clock is quantised; a 1ms gap proves nothing."""
    events = [user_input("Radi", ms=100, t_page=5000.0),
              runtime_request("Radi", ms=101, t_page=5001.0)]
    edges = analyze(events)

    assert len(edges) == 1, "an unorderable pair is not a disproved one"
    s = signals(edges[0])
    assert s["ordering_relation"] == "ambiguous"
    assert s["ordering_method"] == "within_probe_clock_resolution"
    assert "NOT established" in s["ordering_caveat"]
    assert edges[0].confidence <= AMBIGUOUS_MAX_CONFIDENCE


def test_an_ambiguous_edge_never_outranks_a_proven_one():
    ambiguous = analyze([user_input("Radi", ms=100, t_page=5000.0),
                         runtime_request("Radi", ms=101, t_page=5001.0)])[0]
    proven = analyze([user_input("Dyna", ms=200, t_page=6000.0),
                      runtime_request("Dyna", ms=210, t_page=6010.0)])[0]
    assert ambiguous.confidence < proven.confidence


def test_the_clock_resolution_is_declared_not_assumed():
    assert PROBE_CLOCK_RESOLUTION_MS >= 1.0, \
        "Firefox quantises the in-page clock; claiming sub-ms order invents precision"


# --- false positives that must NOT be created ----------------------------

def test_a_request_before_the_input_is_not_a_dependency():
    """Contradicted ordering is a denial, and must stay one."""
    events = [runtime_request("Radi", ms=100, t_page=5000.0),
              user_input("Radi", ms=200, t_page=5100.0)]
    assert analyze(events) == []


def test_a_common_value_shared_by_unrelated_endpoints_is_not_a_dependency():
    """Distinctiveness is what an ambiguous pair rests on. Without it, nothing."""
    value = "Radi"
    events = [user_input(value, ms=100, t_page=5000.0)]
    for path in ("/a", "/b", "/c", "/d"):
        events.append(runtime_request(value, ms=101, t_page=5001.0, path=path))
    edges = analyze(events)
    assert edges == [], f"a value seen at many endpoints is not an identity: {edges}"


def test_unrelated_fields_near_the_same_time_are_not_a_dependency():
    """Proximity alone must never carry an ambiguous pair."""
    events = [user_input("Radi", ms=100, t_page=5000.0, field="postcode"),
              runtime_request("Radi", ms=101, t_page=5001.0, param="q")]
    assert analyze(events) == [], "field names disagree; proximity is not evidence"


def test_probe_ordinal_reset_across_documents_creates_no_edge():
    """`f1` survives navigation while the ordinal restarts at 1.

    Two observations from DIFFERENT documents both carrying ordinal 1 must not
    be ordered against each other by that ordinal, or by a clock measured from
    two different navigation starts.
    """
    events = [
        # Second document: the request happened FIRST in wall time.
        runtime_request("Radi", ms=100, t_page=5000.0, origin=2000.0),
        # First document: same ordinal, unrelated time base.
        user_input("Radi", ms=300, t_page=9999.0, origin=1000.0),
    ]
    edges = analyze(events)
    for edge in edges:
        s = signals(edge)
        assert s["ordering_method"] != "probe_ordinal", \
            "ordinals from different documents are not comparable"
        assert s["same_document_instance"] is False


def test_two_worlds_of_one_document_are_not_ordered_by_ingest_seq():
    """The probe's two worlds batch independently through one binding, so
    arrival order is not occurrence order even within one sensor."""
    events = [user_input("Radi", ms=100, t_page=5000.0),
              runtime_request("Radi", ms=101, t_page=5001.0)]
    edge = analyze(events)[0]
    assert signals(edge)["ordering_method"] != "same_source_seq"


# --- repetition is evidence of the relationship, not of the order ---------

def test_repeated_ambiguous_observations_do_not_accumulate_into_certainty():
    """Four unorderable pairs are still four unorderable pairs.

    Merging raises confidence by repeat, which is right for the relationship
    and wrong for the ordering. Without a ceiling here, the real Run #2
    dependency reported 0.99 -- higher than a properly ordered edge -- purely
    because the operator searched four times.
    """
    events = []
    for i, value in enumerate(("Radi", "Dyna", "Cons", "Drag")):
        events.append(user_input(value, ms=100 + i * 10, t_page=5000.0 + i * 10))
        events.append(runtime_request(value, ms=101 + i * 10, t_page=5001.0 + i * 10))

    edges = analyze(events)
    assert len(edges) == 1, "one relationship, observed four times"
    edge = edges[0]
    assert edge.repeat_count == 4
    assert signals(edge)["ordering_relation"] == "ambiguous"
    assert edge.confidence <= AMBIGUOUS_MAX_CONFIDENCE, (
        f"repetition lifted an unordered edge to {edge.confidence}")


def test_one_ordered_occurrence_establishes_the_order_for_the_relationship():
    """If any single instance WAS orderable, the relationship is ordered."""
    events = [
        user_input("Radi", ms=100, t_page=5000.0),
        runtime_request("Radi", ms=101, t_page=5001.0),      # ambiguous
        user_input("Dyna", ms=200, t_page=6000.0),
        runtime_request("Dyna", ms=210, t_page=6010.0),      # precedes: 10ms
    ]
    edge = analyze(events)[0]
    s = signals(edge)
    assert s["ordering_relation"] == "precedes"
    assert s["ordering_method"] == "same_document_clock"
    assert "ordering_caveat" not in s, "a resolved order must drop the caveat"
    assert edge.confidence > AMBIGUOUS_MAX_CONFIDENCE
