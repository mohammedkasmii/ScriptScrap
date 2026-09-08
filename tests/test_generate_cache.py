"""The generate route does not re-analyse a log that has not changed.

`api.generate` calls analyze_log on every request. It is authenticated, so it
is not an amplifier -- but the view re-renders and the log is the whole log.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path

import pytest

from scriptscrap.analysis import DerivedStore, analyze_log
from scriptscrap.workspace import Workspace, WorkspaceConfig, api

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"


@pytest.fixture
def workspace(tmp_path):
    root = tmp_path / "session"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")
    with DerivedStore(root / "session.sqlite") as store:
        store.write(analyze_log(root / "events.jsonl"))
    ws = Workspace(WorkspaceConfig(root=root))
    yield ws
    ws.shutdown()


@pytest.fixture
def counted(monkeypatch):
    """Counts real analyses, whichever route triggers them."""
    from scriptscrap.analysis import pipeline

    calls: list = []
    original = pipeline.analyze_log

    def counting(path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(pipeline, "analyze_log", counting)
    api._analysis_for.cache_clear()
    return calls


def test_a_repeated_request_analyses_the_log_once(workspace, counted):
    for _ in range(5):
        api.generate(workspace, {"kind": ["client"]})
    assert len(counted) == 1, f"analysed {len(counted)} times"


def test_a_changed_log_is_analysed_again(workspace, counted):
    handle = workspace.sessions[0]
    api.generate(workspace, {"kind": ["client"]})
    time.sleep(0.01)
    with handle.log_path.open("a", encoding="utf-8") as fh:
        fh.write("\n")
    api.generate(workspace, {"kind": ["client"]})
    assert len(counted) == 2, "an appended log must be analysed again"


def test_both_generators_share_one_analysis(workspace, counted):
    api.generate(workspace, {"kind": ["client"]})
    api.generate(workspace, {"kind": ["playwright"]})
    assert len(counted) == 1


def test_the_route_still_writes_nothing_to_disk(workspace):
    handle = workspace.sessions[0]
    before = sorted(p.name for p in handle.root.iterdir())
    api.generate(workspace, {"kind": ["playwright"]})
    assert sorted(p.name for p in handle.root.iterdir()) == before
