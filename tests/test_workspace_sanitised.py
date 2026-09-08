"""SANITISED mode, end to end.

README:156 and the design doc both promise it: 'the page header states
UNREDACTED or SANITISED, because a session directory and its export/shared twin
are indistinguishable in a screenshot'. The exporter wrote only dataset.json and
report.md, and discovery required events.jsonl and session.sqlite, so the mode
could never be entered and the branch was dead code.
"""

from __future__ import annotations

import http.client
import json
import shutil
import threading
from pathlib import Path
from urllib.parse import quote

import pytest

from scriptscrap.cli import build_parser
from scriptscrap.workspace import SANITISED, UNREDACTED, Workspace, WorkspaceConfig

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"


@pytest.fixture
def exported(tmp_path):
    root = tmp_path / "capture"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")
    for command in (["analyze", str(root)], ["export", str(root)]):
        args = build_parser().parse_args(command)
        assert args.func(args) == 0
    return tmp_path


@pytest.fixture
def workspace(exported):
    ws = Workspace(WorkspaceConfig(root=exported))
    thread = threading.Thread(target=ws.serve_forever, daemon=True)
    thread.start()
    yield ws
    ws.shutdown()
    thread.join(timeout=5)


def _get(ws, path):
    """A session name can contain a space -- "capture (shared)" -- so anything
    interpolated into a URL is encoded. The shell does the same: `api.js` uses
    URLSearchParams, which encodes for it."""
    conn = http.client.HTTPConnection(*ws.address, timeout=5)
    try:
        conn.request("GET", path, headers={"Cookie": f"scriptscrap_token={ws.token}"})
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def test_the_sanitised_export_is_discovered(workspace):
    postures = {h.name: h.redaction for h in workspace.sessions}
    assert UNREDACTED in postures.values()
    assert SANITISED in postures.values(), postures


def test_the_sessions_route_reports_both_postures(workspace):
    status, body = _get(workspace, "/api/sessions")
    assert status == 200
    postures = {s["name"]: s["redaction"] for s in json.loads(body)["sessions"]}
    assert sorted(postures.values()) == ["sanitised", "unredacted"]


@pytest.mark.parametrize("route", [
    "session", "endpoints", "states", "ui_elements", "schemas",
    "dependencies", "technologies",
])
def test_every_derived_route_serves_the_sanitised_session(workspace, route):
    name = next(h.name for h in workspace.sessions if h.redaction == SANITISED)
    status, body = _get(workspace, f"/api/{route}?session={quote(name)}")
    assert status == 200, body


@pytest.mark.parametrize("route", ["event?event_id=evt-00000001",
                                   "events?ids=evt-00000001",
                                   "timeline?limit=5"])
def test_evidence_drill_through_says_why_it_is_unavailable(workspace, route):
    """Not a 500 and not a blank panel: an event id in a sanitised export
    points at a log the recipient does not have."""
    name = next(h.name for h in workspace.sessions if h.redaction == SANITISED)
    status, body = _get(workspace, f"/api/{route}&session={quote(name)}")
    assert status == 409, body
    assert b"sanitised export" in body


def test_the_unredacted_session_still_drills_through(workspace):
    name = next(h.name for h in workspace.sessions if h.redaction == UNREDACTED)
    status, body = _get(workspace, f"/api/event?event_id=evt-00000001&session={quote(name)}")
    assert status == 200, body
    assert json.loads(body)["event"]["payload"]


def test_the_overview_reports_which_posture_and_whether_evidence_exists(workspace):
    name = next(h.name for h in workspace.sessions if h.redaction == SANITISED)
    status, body = _get(workspace, f"/api/session?session={quote(name)}")
    assert status == 200
    payload = json.loads(body)
    assert payload["redaction"] == "sanitised"
    assert payload["has_evidence"] is False
    assert payload["counts"]["events"] == 0
