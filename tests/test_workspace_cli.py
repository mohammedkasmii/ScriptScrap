"""The `scriptscrap workspace` command."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scriptscrap.analysis import DerivedStore, analyze_log
from scriptscrap.cli import build_parser, cmd_workspace

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"


def test_workspace_is_a_command():
    args = build_parser().parse_args(["workspace", "some/session"])
    assert args.func is cmd_workspace
    assert args.session == "some/session"


def test_port_and_no_open_parse():
    args = build_parser().parse_args(
        ["workspace", "s", "--port", "8731", "--no-open"])
    assert args.port == 8731
    assert args.no_open is True


def test_defaults_are_an_ephemeral_port_and_an_opened_browser():
    args = build_parser().parse_args(["workspace", "s"])
    assert args.port == 0
    assert args.no_open is False


def test_an_unanalysed_session_exits_with_the_remedy(tmp_path, capsys):
    """A workspace over a session with no derived store would render empty
    views and look like an application with nothing in it."""
    root = tmp_path / "session"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")

    args = build_parser().parse_args(["workspace", str(root), "--no-open"])
    with pytest.raises(SystemExit) as excinfo:
        cmd_workspace(args)
    assert "analyze" in str(excinfo.value)


def test_a_directory_that_is_not_a_session_says_so(tmp_path):
    args = build_parser().parse_args(["workspace", str(tmp_path), "--no-open"])
    with pytest.raises(SystemExit) as excinfo:
        cmd_workspace(args)
    assert "no analysed session" in str(excinfo.value)


def test_a_parent_directory_finds_every_session(tmp_path):
    """One workspace over several captures of the same target."""
    from scriptscrap.workspace import discover_sessions

    for name in ("run1", "run2"):
        root = tmp_path / name
        root.mkdir()
        shutil.copy(SAMPLE, root / "events.jsonl")
        with DerivedStore(root / "session.sqlite") as store:
            store.write(analyze_log(root / "events.jsonl"))

    found = discover_sessions(tmp_path)
    assert {s.name for s in found} == {"run1", "run2"}


def test_an_unanalysed_session_does_not_hide_its_analysed_neighbours(tmp_path):
    from scriptscrap.workspace import discover_sessions

    good = tmp_path / "good"
    good.mkdir()
    shutil.copy(SAMPLE, good / "events.jsonl")
    with DerivedStore(good / "session.sqlite") as store:
        store.write(analyze_log(good / "events.jsonl"))

    bad = tmp_path / "bad"
    bad.mkdir()
    shutil.copy(SAMPLE, bad / "events.jsonl")   # no session.sqlite

    assert {s.name for s in discover_sessions(tmp_path)} == {"good"}
