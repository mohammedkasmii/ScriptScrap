"""The timeline and entity routes.

The timeline is the one view whose cost scales with the session rather than
with the knowledge derived from it, so what is pinned here is that it pages in
`seq` order, filters in SQL, and never reads a payload to render a collapsed
row. A nine-thousand-event session must not cost nine thousand seeks to scroll.

The entity routes are pinned on the same property as everything else: each row
carries the event ids behind it.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scriptscrap.analysis import DerivedStore, analyze_log
from scriptscrap.workspace import api
from scriptscrap.workspace.server import Workspace, WorkspaceConfig

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"

def _fixture_event_count() -> int:
    """How many events the golden fixture holds.

    Derived, not hard-coded: the fixture is regenerated whenever a sensor
    change is re-blessed, and a literal here made four unrelated tests fail on
    every re-bless. What these tests assert is a RELATIONSHIP to the log, not
    a number.
    """
    return sum(1 for line in SAMPLE.read_text(encoding="utf-8").splitlines()
               if line.strip())



@pytest.fixture(scope="module")
def workspace(tmp_path_factory):
    root = tmp_path_factory.mktemp("views") / "session"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")
    with DerivedStore(root / "session.sqlite") as store:
        store.write(analyze_log(root / "events.jsonl"))
    return Workspace(WorkspaceConfig(root=root))


def q(**kwargs) -> dict[str, list[str]]:
    return {k: [str(v)] for k, v in kwargs.items()}


# --- timeline -------------------------------------------------------------

def test_timeline_returns_envelopes_in_seq_order(workspace):
    """seq is the only total order; wall clocks across sensors disagree."""
    body = api.timeline(workspace, q(limit=50))
    seqs = [row["seq"] for row in body["rows"]]
    assert seqs == sorted(seqs)
    assert len(seqs) == 50


def test_timeline_rows_are_envelopes_not_payloads(workspace):
    """A collapsed row shows type, source and time. Fetching 200 payloads to
    draw 200 rows would be 200 seeks for text nobody has opened."""
    row = api.timeline(workspace, q(limit=1))["rows"][0]
    assert {"event_id", "seq", "type", "source", "t_wall"} <= set(row)
    assert "payload" not in row


def test_timeline_pages_through_the_whole_log_exactly_once(workspace):
    seen, cursor = [], None
    while True:
        body = api.timeline(workspace, q(limit=40, **({"after_seq": cursor} if cursor else {})))
        seen.extend(r["event_id"] for r in body["rows"])
        if body["next_seq"] is None:
            break
        cursor = body["next_seq"]
    assert len(seen) == len(set(seen)) == _fixture_event_count()


def test_timeline_filters_by_type(workspace):
    body = api.timeline(workspace, q(types="http_request", limit=100))
    assert body["rows"]
    assert {r["type"] for r in body["rows"]} == {"http_request"}
    assert body["total"] == 19


def test_timeline_filters_by_several_types(workspace):
    body = api.timeline(workspace, q(types="http_request,http_response", limit=100))
    assert {r["type"] for r in body["rows"]} == {"http_request", "http_response"}
    assert body["total"] == 38


def test_timeline_filters_by_source(workspace):
    body = api.timeline(workspace, q(sources="runtime", limit=200))
    assert {r["source"] for r in body["rows"]} == {"runtime"}
    assert body["total"] == 64


def test_timeline_intersects_type_and_source(workspace):
    body = api.timeline(workspace, q(types="http_request", sources="runtime", limit=200))
    for row in body["rows"]:
        assert row["type"] == "http_request"
        assert row["source"] == "runtime"


def test_timeline_offers_the_filter_facets(workspace):
    """The chips are built from what the session actually contains, so a
    filter can never be offered for something that is not there."""
    body = api.timeline(workspace, q(limit=1))
    assert body["facets"]["types"]["user_click"] == 22
    assert body["facets"]["sources"]["runtime"] == 64


def test_a_cursor_past_the_end_is_empty_not_an_error(workspace):
    body = api.timeline(workspace, q(after_seq=10**9, limit=10))
    assert body["rows"] == []
    assert body["next_seq"] is None


def test_an_unmatched_filter_is_empty_not_an_error(workspace):
    body = api.timeline(workspace, q(types="ws_frame_sent", limit=10))
    assert body["rows"] == []
    assert body["total"] == 0


def test_timeline_rejects_an_unbounded_limit(workspace):
    with pytest.raises(api.BadRequest):
        api.timeline(workspace, q(limit=100000))


def test_timeline_rejects_a_non_numeric_cursor(workspace):
    with pytest.raises(api.BadRequest):
        api.timeline(workspace, q(after_seq="banana"))


# --- entities -------------------------------------------------------------

@pytest.mark.parametrize("route,key", [
    ("states", "states"),
    ("ui_elements", "ui_elements"),
    ("schemas", "schemas"),
    ("dependencies", "dependencies"),
    ("technologies", "technologies"),
])
def test_entity_routes_return_rows(workspace, route, key):
    body = getattr(api, route)(workspace, {})
    assert key in body
    assert isinstance(body[key], list)


@pytest.mark.parametrize("route,key", [
    ("states", "states"),
    ("ui_elements", "ui_elements"),
    ("schemas", "schemas"),
])
def test_every_entity_row_cites_its_evidence(workspace, route, key):
    rows = getattr(api, route)(workspace, {})[key]
    assert rows, f"{route} produced no rows to check"
    for row in rows:
        assert row["evidence_ids"], f"{route} row {row} cites no evidence"


def test_entity_counts_match_the_analysis(workspace):
    result = analyze_log(workspace.sessions[0].log_path)
    assert len(api.states(workspace, {})["states"]) == len(result.states)
    assert len(api.ui_elements(workspace, {})["ui_elements"]) == len(result.ui_elements)
    assert len(api.schemas(workspace, {})["schemas"]) == len(result.schemas)
    assert len(api.technologies(workspace, {})["technologies"]) == len(result.technologies)


def test_states_carry_their_transitions(workspace):
    body = api.states(workspace, {})
    assert "transitions" in body
    for transition in body["transitions"]:
        assert {"from_state", "to_state", "trigger", "evidence_ids"} <= set(transition)


def test_ui_elements_expose_every_selector_with_its_stability(workspace):
    """The unstable ones are the point: they are what a generated script
    breaks on, so they must be visible rather than filtered out."""
    elements = api.ui_elements(workspace, {})["ui_elements"]
    assert elements
    with_locators = [e for e in elements if e["locators"]]
    assert with_locators, "no element exposed a locator candidate"
    for locator in with_locators[0]["locators"]:
        assert {"strategy", "value", "stability"} <= set(locator)


def test_the_dependency_graph_is_nodes_and_edges(workspace):
    body = api.dependencies(workspace, {})
    assert "nodes" in body
    assert "dependencies" in body
    for edge in body["dependencies"]:
        assert edge["source_endpoint"] in body["nodes"]
        assert edge["target_endpoint"] in body["nodes"]


def test_the_state_graph_edges_reference_known_states(workspace):
    """Transitions key on fingerprint, not label -- two states can share a
    label, so the fingerprint is the identity a graph must join on."""
    body = api.states(workspace, {})
    fingerprints = {s["fingerprint"] for s in body["states"]}
    for transition in body["transitions"]:
        assert transition["to_state"] in fingerprints
        assert (transition["from_state"] in fingerprints
                or transition["from_state"] == "(entry)")


def test_transitions_carry_a_readable_label_for_each_end(workspace):
    """A graph drawing the raw column would show hashes for node names."""
    body = api.states(workspace, {})
    label_of = {s["fingerprint"]: s["label"] for s in body["states"]}
    assert body["transitions"], "no transitions to check"
    for transition in body["transitions"]:
        assert transition["to_label"] == label_of[transition["to_state"]]
        assert transition["to_label"] != transition["to_state"]
