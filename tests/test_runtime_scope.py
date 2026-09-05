"""The engagement boundary on the runtime observation path.

Playwright's handlers enforced `InvestigationScope`; the runtime probe did not.
A real capture of a public demo site recorded 722 runtime network observations,
504 of them out of scope and 213 carrying full query strings -- because the
scope check ran against the FRAME, and an in-scope page's own third-party
scripts call `fetch` wherever they like.

These tests pin the policy, not the implementation: out of scope means metadata
only, on every observation path.
"""

from __future__ import annotations

import json

import pytest

from scriptscrap.sensors.runtime import RuntimeSensor, _redact_stack_frame, _strip_query

TARGET = "https://app.test"
THIRD_PARTY = "https://analytics.elsewhere.test"


class _Scope:
    """The same semantics as InvestigationScope, without importing the driver."""

    def __init__(self, *roots: str) -> None:
        self.roots = set(roots)

    def contains(self, url: str) -> bool:
        from urllib.parse import urlsplit
        host = (urlsplit(url).hostname or "").lower()
        return any(host == r or host.endswith("." + r) for r in self.roots)


class _Engine:
    def __init__(self) -> None:
        self.scope = _Scope("app.test")
        self.events: list[tuple] = []

    def emit_event(self, source, event_type, **payload):
        self.events.append((event_type, payload))

    def emit_sensor_error(self, *a, **k): pass
    def emit_capture_gap(self, *a, **k): pass


@pytest.fixture
def sensor():
    engine = _Engine()
    return RuntimeSensor(engine, registry=None), engine


def _record(kind, payload, *, frame_url=f"{TARGET}/page", world="main"):
    return {"type": kind, "ordinal": 1, "world": world, "t_origin": 1000.0,
            "t_page": 1234.0, "frame_url": frame_url, "is_top": True,
            "payload": payload}


def _last(engine):
    return engine.events[-1][1]


# --- in scope keeps everything -------------------------------------------

def test_in_scope_runtime_fetch_keeps_full_evidence(sensor):
    probe, engine = sensor
    probe._ingest(_record("runtime_fetch", {
        "url": f"{TARGET}/api/items?token=KEEPME",
        "method": "POST",
        "header_names": ["x-requested-with"],
        "body": {"kind": "string", "text": "payload-KEEPME"},
        "stack": [f"handler@{TARGET}/app.js?v=3:12:5"],
    }), "p1", "f1")

    payload = _last(engine)
    assert payload["url"].endswith("?token=KEEPME"), "in-scope query must survive"
    assert payload["body"]["text"] == "payload-KEEPME"
    assert payload["header_names"] == ["x-requested-with"]
    assert "?v=3" in payload["stack"][0], "in-scope script URL keeps its query"
    assert "scope" not in payload
    assert probe.reduced_out_of_scope == 0


# --- out of scope is reduced to metadata ----------------------------------

def test_out_of_scope_fetch_loses_query_values(sensor):
    probe, engine = sensor
    probe._ingest(_record("runtime_fetch", {
        "url": f"{THIRD_PARTY}/collect?tid=G-123&cid=SECRETCID",
        "method": "POST",
    }), "p1", "f1")

    payload = _last(engine)
    assert payload["url"] == f"{THIRD_PARTY}/collect"
    assert "SECRETCID" not in json.dumps(payload)
    assert "tid=" not in json.dumps(payload)
    assert payload["method"] == "POST", "method is metadata and is kept"
    assert probe.reduced_out_of_scope == 1


def test_out_of_scope_xhr_loses_its_body(sensor):
    probe, engine = sensor
    probe._ingest(_record("runtime_xhr", {
        "url": f"{THIRD_PARTY}/beacon",
        "method": "POST",
        "header_names": ["authorization"],
        "body": {"kind": "string", "text": "uid=SECRETUSER&session=SECRETTOKEN"},
    }), "p1", "f1")

    blob = json.dumps(_last(engine))
    assert "SECRETUSER" not in blob
    assert "SECRETTOKEN" not in blob
    assert "authorization" not in blob, "header names go with the body"
    assert "body" not in _last(engine)


def test_reduced_event_is_identifiable_as_out_of_scope_metadata(sensor):
    """A reader must be able to tell a reduced record from a complete one."""
    probe, engine = sensor
    probe._ingest(_record("runtime_fetch", {
        "url": f"{THIRD_PARTY}/ping?q=SECRET", "method": "GET",
        "body": {"kind": "string", "text": "x"}, "stack": ["a@b:1:1"],
    }), "p1", "f1")

    payload = _last(engine)
    assert payload["scope"] == "out_of_scope"
    assert payload["evidence_reduced"] is True
    assert "body" in payload["evidence_removed"]
    assert "stack" in payload["evidence_removed"]
    # The forensic fact survives: a third-party call happened, from this page.
    assert payload["url"] == f"{THIRD_PARTY}/ping"
    assert payload["frame_url"] == f"{TARGET}/page"


def test_third_party_iframe_observation_is_reduced(sensor):
    """Scope follows the frame when the observation has no URL of its own."""
    probe, engine = sensor
    probe._ingest(_record("dom_mutation",
                          {"count": 1, "mutations": [{"target": {"id": "ad-SECRET"}}]},
                          frame_url=f"{THIRD_PARTY}/ads?slot=SECRETSLOT",
                          world="isolated"), "p1", "f9")

    payload = _last(engine)
    assert payload["scope"] == "out_of_scope"
    assert "SECRETSLOT" not in json.dumps(payload)
    assert "ad-SECRET" not in json.dumps(payload)
    assert payload["frame_url"] == f"{THIRD_PARTY}/ads"
    assert payload["count"] == 1, "the countable fact survives"


# --- stacks ---------------------------------------------------------------

def test_stack_cannot_leak_third_party_query_values(sensor):
    """A stack names WHICH code called; a third-party script's parameters are
    not part of that, and an in-scope request can still have a third-party
    frame on its stack."""
    probe, engine = sensor
    probe._ingest(_record("runtime_fetch", {
        "url": f"{TARGET}/api/ok",
        "method": "GET",
        "stack": [
            f"vd@{THIRD_PARTY}/gtag.js?id=G-SECRETID:302:391",
            f"app@{TARGET}/main.js?build=7:10:2",
        ],
    }), "p1", "f1")

    stack = _last(engine)["stack"]
    assert "G-SECRETID" not in json.dumps(stack)
    assert stack[0] == f"vd@{THIRD_PARTY}/gtag.js:302:391", stack[0]
    assert "?build=7" in stack[1], "in-scope script keeps its query"


def test_stack_frame_keeps_its_line_and_column():
    scope = _Scope("app.test")
    frame = _redact_stack_frame(scope, "f@https://x.test/a.js?k=SECRET:12:34")
    assert frame == "f@https://x.test/a.js:12:34"


def test_strip_query_keeps_origin_and_path():
    assert _strip_query("https://h.test/a/b?x=1#f") == "https://h.test/a/b"


def test_a_reduced_event_is_reduced_throughout(sensor):
    """Found by an adversarial scan, not by writing the code.

    A `pushState` to a third-party URL was reduced, and then kept the full
    IN-SCOPE `from` URL beside it -- query and all. Each half was defensible
    and the combination was not: a reader filtering on `scope == out_of_scope`
    would assume everything in the record was metadata. The in-scope side of a
    navigation is recorded on the in-scope path anyway.
    """
    probe, engine = sensor
    probe._ingest(_record("runtime_history", {
        "via": "pushState",
        "url": f"{THIRD_PARTY}/h?x=SECRETX",
        "from": f"{TARGET}/page?y=SECRETY",
    }), "p1", "f1")

    payload = _last(engine)
    assert payload["scope"] == "out_of_scope"
    assert "SECRETX" not in json.dumps(payload)
    assert "SECRETY" not in json.dumps(payload), \
        "a reduced record must not carry a full query in any field"
    assert payload["from"] == f"{TARGET}/page", "origin and path still survive"


def test_a_fully_in_scope_navigation_keeps_its_queries(sensor):
    """The counterpart: reduction must not bleed into in-scope records."""
    probe, engine = sensor
    probe._ingest(_record("runtime_history", {
        "via": "pushState",
        "url": f"{TARGET}/h?x=KEEPX",
        "from": f"{TARGET}/page?y=KEEPY",
    }), "p1", "f1")

    payload = _last(engine)
    assert "scope" not in payload
    assert payload["url"].endswith("?x=KEEPX")
    assert payload["from"].endswith("?y=KEEPY")


def test_a_subdomain_of_the_target_is_in_scope(sensor):
    probe, engine = sensor
    probe._ingest(_record("runtime_fetch", {
        "url": "https://api.app.test/x?k=KEEPME", "method": "GET"}), "p1", "f1")
    assert _last(engine)["url"].endswith("?k=KEEPME")
    assert probe.reduced_out_of_scope == 0


# --- reconciliation and correlation must not adopt reduced traffic --------

def test_reduced_traffic_cannot_become_an_in_scope_dependency():
    """A reduced third-party observation carries no values, so it must not be
    paired with in-scope activity."""
    import itertools

    from scriptscrap.analysis.correlation import CorrelationAnalyzer
    from scriptscrap.events import Event, EventType, Source

    counter = itertools.count(1)

    def ev(event_type, payload, source=Source.RUNTIME):
        n = next(counter)
        return Event(session_id="s", event_id=f"evt-{n:05d}", seq=n,
                     t_wall="2026-01-01T00:00:00.000+00:00", t_mono=float(n),
                     source=source, type=event_type, payload=payload,
                     page_id="p1", frame_id="f1")

    events = [
        ev(EventType.USER_INPUT,
           {"value": {"value": "TOKEN-AA1234"}, "element": {"id": "field"},
            "probe_time_origin": 1.0, "probe_time_ms": 10.0, "probe_world": "isolated"}),
        # Reduced: no body, no query -- exactly what the sensor now emits.
        ev(EventType.RUNTIME_FETCH,
           {"url": f"{THIRD_PARTY}/collect", "method": "POST",
            "scope": "out_of_scope", "evidence_reduced": True,
            "evidence_removed": ["body", "stack"],
            "probe_time_origin": 1.0, "probe_time_ms": 20.0, "probe_world": "main"}),
    ]
    edges = CorrelationAnalyzer().analyze(events, {})
    assert edges == [], "third-party metadata must not become an application edge"
