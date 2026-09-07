"""`scriptscrap generate` and the workspace's generate route."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scriptscrap.analysis import DerivedStore, analyze_log
from scriptscrap.cli import build_parser, cmd_generate
from scriptscrap.workspace import api
from scriptscrap.workspace.server import Workspace, WorkspaceConfig

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"


@pytest.fixture
def session(tmp_path):
    root = tmp_path / "session"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")
    with DerivedStore(root / "session.sqlite") as store:
        store.write(analyze_log(root / "events.jsonl"))
    return root


# --- the command ----------------------------------------------------------

def test_generate_is_a_command():
    args = build_parser().parse_args(["generate", "client", "some/session"])
    assert args.func is cmd_generate
    assert args.kind == "client"


def test_both_kinds_parse():
    for kind in ("client", "playwright"):
        assert build_parser().parse_args(["generate", kind, "s"]).kind == kind


def test_an_unknown_kind_is_rejected():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["generate", "cobol", "s"])


@pytest.mark.parametrize("kind,filename", [
    ("client", "generated_client.py"),
    ("playwright", "observed_workflow.py"),
])
def test_generate_writes_into_the_session(session, kind, filename, capsys):
    args = build_parser().parse_args(["generate", kind, str(session)])
    assert cmd_generate(args) == 0
    written = session / filename
    assert written.is_file()
    compile(written.read_text(encoding="utf-8"), filename, "exec")


def test_output_path_can_be_redirected(session, tmp_path):
    target = tmp_path / "elsewhere" / "client.py"
    target.parent.mkdir()
    args = build_parser().parse_args(
        ["generate", "client", str(session), "-o", str(target)])
    assert cmd_generate(args) == 0
    assert target.is_file()


def test_the_command_reports_the_auth_headers_it_could_not_supply(session, capsys):
    """The reader is told what to provide, having been given no values."""
    cmd_generate(build_parser().parse_args(["generate", "client", str(session)]))
    out = capsys.readouterr().out
    assert "cookie" in out.lower()
    assert "SCRIPTSCRAP_AUTH_HEADERS" in out


def test_the_command_says_the_output_describes_one_session(session, capsys):
    cmd_generate(build_parser().parse_args(["generate", "client", str(session)]))
    assert "ONE observed session" in capsys.readouterr().out


# --- the workspace route --------------------------------------------------

@pytest.fixture
def workspace(session):
    return Workspace(WorkspaceConfig(root=session))


@pytest.mark.parametrize("kind", ["client", "playwright"])
def test_the_route_returns_compilable_source(workspace, kind):
    body = api.generate(workspace, {"kind": [kind]})
    assert body["kind"] == kind
    compile(body["source"], body["filename"], "exec")


def test_the_route_defaults_to_the_client(workspace):
    assert api.generate(workspace, {})["kind"] == "client"


def test_an_unknown_generator_is_a_bad_request(workspace):
    with pytest.raises(api.BadRequest, match="cobol"):
        api.generate(workspace, {"kind": ["cobol"]})


def test_the_route_writes_nothing_to_disk(workspace, session):
    """The workspace is read-only. Generating must not drop a file into the
    operator's capture directory as a side effect."""
    before = {p.name for p in session.iterdir()}
    api.generate(workspace, {"kind": ["client"]})
    api.generate(workspace, {"kind": ["playwright"]})
    assert {p.name for p in session.iterdir()} == before


def test_the_route_reports_the_auth_headers(workspace):
    assert "cookie" in api.generate(workspace, {"kind": ["client"]})["auth_headers"]
