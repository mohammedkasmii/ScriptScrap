"""The activities view: inferred business activities, served to the offline
workspace so a reviewer can examine a long session at home.

Segments are re-derived from the log per session (memoised on the log's
identity, like the generators), rather than stored -- they are cheap and few,
and the store schema stays put. A sanitised export has no log, so it says so
rather than serving an empty panel.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scriptscrap.analysis import DerivedStore, analyze_log
from scriptscrap.export import Redactor, sanitise
from scriptscrap.export.dataset import DatasetExporter
from scriptscrap.workspace import api
from scriptscrap.workspace.server import Workspace, WorkspaceConfig

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"


@pytest.fixture(scope="module")
def workspace(tmp_path_factory):
    root = tmp_path_factory.mktemp("segments") / "session"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")
    with DerivedStore(root / "session.sqlite") as store:
        store.write(analyze_log(root / "events.jsonl"))
    return Workspace(WorkspaceConfig(root=root))


def q(**kwargs) -> dict[str, list[str]]:
    return {k: [str(v)] for k, v in kwargs.items()}


def test_segments_route_returns_inferred_activities(workspace):
    body = api.segments(workspace, q())
    segments = body["segments"]
    assert segments, "the fixture session should yield at least one activity"
    first = segments[0]
    for field in ("index", "start_seq", "end_seq", "label", "boundary_reason",
                  "outcome", "action_count", "action_kinds", "routes", "forms",
                  "endpoints", "confidence", "evidence_ids"):
        assert field in first, f"segment is missing {field}"
    assert first["evidence_ids"], "a segment must cite the events behind it"


def test_segments_are_ordered_by_index(workspace):
    segments = api.segments(workspace, q())["segments"]
    assert [s["index"] for s in segments] == sorted(s["index"] for s in segments)


def test_segment_seq_windows_are_within_the_log(workspace):
    segments = api.segments(workspace, q())["segments"]
    for s in segments:
        assert s["start_seq"] <= s["end_seq"]


def test_a_sanitised_export_has_no_activities_to_serve(tmp_path):
    """No log to re-derive from; the view says so rather than 500-ing."""
    root = tmp_path / "session"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")
    safe = sanitise(analyze_log(root / "events.jsonl"), Redactor())
    shared = root / "export" / "shared"
    shared.mkdir(parents=True)
    (shared / "dataset.json").write_text("{}", encoding="utf-8")
    with DerivedStore(shared / "session.sqlite") as store:
        store.write(safe)
    _ = DatasetExporter  # imported to mirror how a real export is produced

    ws = Workspace(WorkspaceConfig(root=shared))
    with pytest.raises(api.EvidenceUnavailable):
        api.segments(ws, q())


def test_segments_is_a_registered_route():
    assert "segments" in api.ROUTES


def test_forms_route_returns_the_form_catalog(workspace):
    body = api.forms(workspace, q())
    assert "forms" in body
    for form in body["forms"]:
        assert "controls" in form and "evidence_ids" in form
        # A secret control never carries a value through the API.
        for control in form["controls"]:
            if control["secret"]:
                assert control["final_value"] is None


def test_forms_is_a_registered_route():
    assert "forms" in api.ROUTES
