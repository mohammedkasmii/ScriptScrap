"""The workspace API, called as functions rather than over a socket.

Handlers are `(workspace, query) -> dict`, so the behaviour that matters is
testable without a server. The live-server path is covered in
`test_workspace_server.py`; what is pinned here is the contract each route
returns.

The recurring assertion is that every record carries `evidence_ids`. That is
the property the whole workspace exists for: a view that states a fact without
a path back to the events behind it is the thing the retired legacy JSON files
already did, and doing it again in a browser would be no improvement.
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

def _fixture_count(*, type: str | None = None, source: str | None = None) -> int:
    """How many fixture events match a type or a source.

    Derived, not hard-coded, for the same reason `_fixture_event_count` is: the
    fixture is regenerated whenever a sensor change is re-blessed, and a live
    browser run varies by a mutation or two. What these tests assert is that a
    filter agrees with the log, not that the log has a particular size.
    """
    import json as _json

    total = 0
    for line in SAMPLE.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = _json.loads(line)
        if type is not None and event["type"] != type:
            continue
        if source is not None and event["source"] != source:
            continue
        total += 1
    return total



@pytest.fixture(scope="module")
def workspace(tmp_path_factory):
    root = tmp_path_factory.mktemp("api") / "session"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")
    with DerivedStore(root / "session.sqlite") as store:
        store.write(analyze_log(root / "events.jsonl"))
    return Workspace(WorkspaceConfig(root=root))


def q(**kwargs) -> dict[str, list[str]]:
    return {k: [str(v)] for k, v in kwargs.items()}


# --- sessions -------------------------------------------------------------

def test_sessions_lists_the_open_session(workspace):
    body = api.sessions(workspace, {})
    assert len(body["sessions"]) == 1
    assert body["sessions"][0]["event_count"] == _fixture_event_count()


def test_sessions_reports_the_redaction_posture(workspace):
    """The header has to be able to say UNREDACTED without guessing."""
    assert body_redaction(workspace) == "unredacted"


def body_redaction(workspace) -> str:
    return api.sessions(workspace, {})["sessions"][0]["redaction"]


def test_a_sanitised_export_is_labelled_differently(tmp_path):
    from scriptscrap.workspace.session import open_session

    root = tmp_path / "sess" / "export" / "shared"
    root.mkdir(parents=True)
    shutil.copy(SAMPLE, root / "events.jsonl")
    with DerivedStore(root / "session.sqlite") as store:
        store.write(analyze_log(root / "events.jsonl"))
    assert open_session(root).redaction == "sanitised"


# --- overview -------------------------------------------------------------

def test_overview_counts_match_the_analysis(workspace):
    handle = workspace.sessions[0]
    result = analyze_log(handle.log_path)
    body = api.session_overview(workspace, {})
    assert body["counts"]["endpoints"] == len(result.endpoints)
    assert body["counts"]["schemas"] == len(result.schemas)
    assert body["counts"]["states"] == len(result.states)
    assert body["counts"]["ui_elements"] == len(result.ui_elements)
    assert body["counts"]["events"] == result.event_count


def test_overview_reports_event_type_counts(workspace):
    body = api.session_overview(workspace, {})
    assert body["events_by_type"]["user_click"] == _fixture_count(type="user_click")
    assert body["events_by_source"]["runtime"] == _fixture_count(source="runtime")


def test_overview_orders_findings_by_severity(workspace):
    severities = [f["severity"] for f in api.session_overview(workspace, {})["findings"]]
    rank = {"critical": 0, "warning": 1, "info": 2}
    assert severities == sorted(severities, key=lambda s: rank.get(s, 3))


def test_overview_reports_a_missing_manifest_rather_than_hiding_it(workspace):
    """The fixture session has no manifest. That must be visible, because a
    manifest is how a reader judges everything beside it."""
    assert api.session_overview(workspace, {})["manifest_present"] is False


# --- endpoints ------------------------------------------------------------

def test_endpoints_are_listed_with_evidence(workspace):
    body = api.endpoints(workspace, {})
    assert body["endpoints"]
    for endpoint in body["endpoints"]:
        assert endpoint["evidence_ids"], f"{endpoint['key']} cites no evidence"


def test_endpoint_detail_carries_params_schemas_and_dependencies(workspace):
    key = api.endpoints(workspace, {})["endpoints"][0]["key"]
    detail = api.endpoint_detail(workspace, q(endpoint_key=key))
    assert detail["key"] == key
    assert "params" in detail
    assert "schemas" in detail
    assert "dependencies" in detail


def test_endpoint_detail_schema_fields_keep_their_optionality(workspace):
    """Optionality is inference, and a reader has to see what it rests on."""
    for endpoint in api.endpoints(workspace, {})["endpoints"]:
        detail = api.endpoint_detail(workspace, q(endpoint_key=endpoint["key"]))
        for schema in detail["schemas"]:
            for field in schema["fields"]:
                assert "observed_optional" in field
                assert "sample_count" in field
            return


def test_unknown_endpoint_is_not_found(workspace):
    with pytest.raises(api.NotFound):
        api.endpoint_detail(workspace, q(endpoint_key="GET /nope"))


def test_endpoint_detail_requires_a_key(workspace):
    with pytest.raises(api.BadRequest):
        api.endpoint_detail(workspace, {})


# --- evidence drill-through ----------------------------------------------

def test_an_endpoints_evidence_id_resolves_to_a_real_event(workspace):
    """The whole point of the workspace, in one assertion."""
    endpoint = api.endpoints(workspace, {})["endpoints"][0]
    event_id = endpoint["evidence_ids"][0]
    body = api.event(workspace, q(event_id=event_id))
    assert body["event"]["event_id"] == event_id
    assert body["event"]["payload"]


def test_unknown_event_is_not_found(workspace):
    with pytest.raises(api.NotFound):
        api.event(workspace, q(event_id="no-such-event"))


def test_event_requires_an_id(workspace):
    with pytest.raises(api.BadRequest):
        api.event(workspace, {})


def test_events_returns_many_in_the_order_asked(workspace):
    ids = api.endpoints(workspace, {})["endpoints"][0]["evidence_ids"][:3]
    body = api.events(workspace, q(ids=",".join(reversed(ids))))
    assert [e["event_id"] for e in body["events"]] == list(reversed(ids))
    assert body["requested"] == len(ids)


def test_events_rejects_an_unbounded_request(workspace):
    with pytest.raises(api.BadRequest, match="500"):
        api.events(workspace, q(ids=",".join(str(i) for i in range(600))))


def test_a_stale_index_is_reported_not_silently_wrong(workspace):
    """Appending to the log invalidates every offset. The reader must be told,
    because the alternative is evidence belonging to a different event."""
    handle = workspace.sessions[0]
    endpoint = api.endpoints(workspace, {})["endpoints"][0]
    event_id = endpoint["evidence_ids"][0]
    with handle.log_path.open("ab") as fh:
        fh.write(b'{"padding": true}\n')
    try:
        with pytest.raises(api.BadRequest, match="analyze"):
            api.event(workspace, q(event_id=event_id))
    finally:
        # Restore, so module-scoped fixtures stay usable.
        data = handle.log_path.read_bytes()
        handle.log_path.write_bytes(data[:data.rindex(b'{"padding": true}\n')])


# --- session selection ----------------------------------------------------

def test_an_unknown_session_name_is_not_found(workspace):
    with pytest.raises(api.NotFound):
        api.endpoints(workspace, q(session="nope"))
