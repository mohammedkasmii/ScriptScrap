"""The workflow survives a round trip through the derived store."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scriptscrap.analysis import DerivedStore, analyze_log
from scriptscrap.analysis.store import STORE_SCHEMA_VERSION
from scriptscrap.workspace import Workspace, WorkspaceConfig, api

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"


@pytest.fixture
def analysed(tmp_path):
    root = tmp_path / "session"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")
    with DerivedStore(root / "session.sqlite") as store:
        store.write(analyze_log(root / "events.jsonl"))
    return root


def test_the_store_schema_version_was_bumped():
    assert STORE_SCHEMA_VERSION >= 2, (
        "adding workflow_steps and two transition columns is a SQL change")


def test_every_workflow_step_is_stored_in_order(analysed):
    result = analyze_log(analysed / "events.jsonl")
    assert result.workflow, "the sample log records no workflow"

    with DerivedStore(analysed / "session.sqlite") as store:
        run = store.latest_run()
        rows = list(store.conn.execute(
            "SELECT * FROM workflow_steps WHERE run_id=? ORDER BY ordinal",
            (run["id"],)))
    assert len(rows) == len(result.workflow)
    assert [r["ordinal"] for r in rows] == list(range(len(rows)))
    assert [r["kind"] for r in rows] == [s.kind for s in result.workflow]
    assert [r["seq"] for r in rows] == sorted(r["seq"] for r in rows)


def test_an_allowlisted_key_survives_the_round_trip(analysed):
    """`key` is a column, not a field the store drops on the floor.

    The plan's DDL omitted it. A step whose key the analyser deemed safe would
    round-trip as a bare `press` with no key, and a generator reading the store
    would emit something the analyser had already decided not to say.
    """
    result = analyze_log(analysed / "events.jsonl")
    with DerivedStore(analysed / "session.sqlite") as store:
        run = store.latest_run()
        rows = list(store.conn.execute(
            "SELECT * FROM workflow_steps WHERE run_id=? ORDER BY ordinal",
            (run["id"],)))
    assert [r["key"] for r in rows] == [s.key for s in result.workflow]


def test_the_api_serves_the_workflow_joined_to_its_elements(analysed):
    workspace = Workspace(WorkspaceConfig(root=analysed))
    try:
        body = api.workflow(workspace, {})
    finally:
        workspace.server.server_close()   # F7; becomes shutdown() at D4

    assert body["steps"], "no steps served"
    second = Workspace(WorkspaceConfig(root=analysed))
    try:
        element_keys = {e["key"] for e in api.ui_elements(second, {})["ui_elements"]}
    finally:
        second.server.server_close()      # F7; becomes shutdown() at D4
    unresolved = [s for s in body["steps"]
                  if s["element_key"] and s["element_key"] not in element_keys]
    assert unresolved == [], f"{len(unresolved)} step(s) do not join"


def test_the_states_route_resolves_a_transition_to_its_element(analysed):
    workspace = Workspace(WorkspaceConfig(root=analysed))
    try:
        body = api.states(workspace, {})
    finally:
        workspace.server.server_close()   # F7; becomes shutdown() at D4
    assert body["transitions"]
    assert all("trigger_element_key" in t for t in body["transitions"])
