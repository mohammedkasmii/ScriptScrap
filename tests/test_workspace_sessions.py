"""Session discovery, identity and redaction posture."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scriptscrap.analysis import DerivedStore, analyze_log
from scriptscrap.workspace import (
    SANITISED,
    UNREDACTED,
    SessionError,
    Workspace,
    WorkspaceConfig,
    discover_sessions,
)

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"


def _session(root: Path) -> Path:
    root.mkdir(parents=True)
    shutil.copy(SAMPLE, root / "events.jsonl")
    with DerivedStore(root / "session.sqlite") as store:
        store.write(analyze_log(root / "events.jsonl"))
    return root


def _fake_shared(root: Path) -> Path:
    """An export/shared that IS a session, as Task D7 will produce."""
    shared = root / "export" / "shared"
    return _session(shared)


def test_two_sessions_with_exports_produce_four_distinct_names(tmp_path):
    """Both export/shared handles were named 'shared', and session('shared')
    returned the first -- one session's data under another's name."""
    for name in ("runA", "runB"):
        _session(tmp_path / name)
        _fake_shared(tmp_path / name)

    handles = discover_sessions(tmp_path)
    names = [h.name for h in handles]
    assert len(names) == 4, names
    assert len(set(names)) == 4, f"duplicate session names: {names}"


def test_a_name_says_which_session_and_which_posture(tmp_path):
    _session(tmp_path / "runA")
    _fake_shared(tmp_path / "runA")
    by_name = {h.name: h for h in discover_sessions(tmp_path)}
    assert "runA" in by_name
    shared = next(h for h in by_name.values() if h.redaction == SANITISED)
    assert "runA" in shared.name, f"the name must identify the session: {shared.name}"
    assert by_name["runA"].redaction == UNREDACTED


def test_a_workspace_can_address_every_session_it_opened(tmp_path):
    for name in ("runA", "runB"):
        _session(tmp_path / name)
        _fake_shared(tmp_path / name)
    workspace = Workspace(WorkspaceConfig(root=tmp_path))
    try:
        for handle in workspace.sessions:
            assert workspace.session(handle.name).root == handle.root
    finally:
        workspace.shutdown()


def test_a_workspace_refuses_to_open_two_sessions_with_one_name(tmp_path,
                                                               monkeypatch):
    """The guard, not the naming scheme. If a future change reintroduces a
    collision, it must fail at launch rather than serve the wrong session."""
    _session(tmp_path / "runA")
    _session(tmp_path / "runB")

    from scriptscrap.workspace import session as session_module

    original = session_module.discover_sessions

    def collide(path):
        handles = original(path)
        return [h.__class__(**{**h.__dict__, "name": "same"}) for h in handles]

    monkeypatch.setattr("scriptscrap.workspace.server.discover_sessions", collide)
    with pytest.raises(SessionError) as excinfo:
        Workspace(WorkspaceConfig(root=tmp_path))
    assert "same" in str(excinfo.value)


def test_a_single_session_root_keeps_its_directory_name(tmp_path):
    root = _session(tmp_path / "solo")
    handles = discover_sessions(root)
    assert [h.name for h in handles] == ["solo"]


# --- an ambiguous request names its session (R2) --------------------------

def test_a_request_without_a_session_is_ambiguous_when_there_are_several(tmp_path):
    """`session(None)` returned `self.sessions[0]`. In a workspace holding an
    unredacted capture and a sanitised export, a route reached before the UI
    had chosen served whichever sorted first -- possibly the unredacted one,
    under a header that had not been painted yet."""
    from scriptscrap.workspace import api

    _session(tmp_path / "runA")
    _fake_shared(tmp_path / "runA")
    workspace = Workspace(WorkspaceConfig(root=tmp_path))
    try:
        with pytest.raises(api.BadRequest) as excinfo:
            workspace.session(None)
        assert "session=" in str(excinfo.value)
        for handle in workspace.sessions:
            assert handle.name in str(excinfo.value)
    finally:
        workspace.shutdown()


def test_a_single_session_workspace_needs_no_session_parameter(tmp_path):
    _session(tmp_path / "solo")
    workspace = Workspace(WorkspaceConfig(root=tmp_path / "solo"))
    try:
        assert workspace.session(None).name == "solo"
    finally:
        workspace.shutdown()


def test_the_sessions_route_never_needs_a_session(tmp_path):
    """The listing is how a client learns the names, so it cannot require one."""
    from scriptscrap.workspace import api

    _session(tmp_path / "runA")
    _session(tmp_path / "runB")
    workspace = Workspace(WorkspaceConfig(root=tmp_path))
    try:
        assert len(api.sessions(workspace, {})["sessions"]) == 2
    finally:
        workspace.shutdown()
