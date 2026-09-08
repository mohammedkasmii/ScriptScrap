"""Every route closes what it opens, explicitly.

`api.sessions` used `with handle.connect() as conn`, which commits or rolls
back and does NOT close -- unlike the twelve handlers around it. Measured: no
connection outlives a request under CPython, because refcounting closes it.
This pins the property rather than the implementation detail that currently
provides it.
"""

from __future__ import annotations

import gc
import shutil
import sqlite3
from pathlib import Path

import pytest

from scriptscrap.analysis import DerivedStore, analyze_log
from scriptscrap.workspace import Workspace, WorkspaceConfig, api

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"

ROUTES_NEEDING_NO_ARGUMENTS = [
    "sessions", "session", "endpoints", "states", "ui_elements",
    "schemas", "dependencies", "technologies", "workflow",
]


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


def _is_open(conn: sqlite3.Connection) -> bool:
    try:
        conn.execute("SELECT 1")
    except sqlite3.ProgrammingError:
        return False
    except sqlite3.Error:
        return True
    return True


def _open_connections() -> int:
    gc.collect()
    return sum(1 for obj in gc.get_objects()
               if isinstance(obj, sqlite3.Connection) and _is_open(obj))


@pytest.mark.parametrize("route", ROUTES_NEEDING_NO_ARGUMENTS)
def test_a_route_leaves_no_open_connection_behind(workspace, route):
    baseline = _open_connections()
    for _ in range(20):
        api.ROUTES[route](workspace, {})
    assert _open_connections() <= baseline, (
        f"{route} left an open connection behind")


def test_a_route_that_raises_still_closes_its_connection(workspace):
    """A handler that raises mid-query must not hold the file open."""
    baseline = _open_connections()
    for _ in range(20):
        with pytest.raises(api.BadRequest):
            api.endpoint_detail(workspace, {})
    assert _open_connections() <= baseline


def test_every_handler_uses_the_same_connection_idiom():
    """Twelve handlers used try/finally: conn.close(); one used `with`, which
    does not close. One idiom, so the odd one out cannot recur."""
    import inspect

    from scriptscrap.workspace import api as module

    source = inspect.getsource(module)
    assert "with handle.connect()" not in source, (
        "sqlite3.Connection.__exit__ commits, it does not close")
