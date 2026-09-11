"""A store written by an older ScriptScrap must not be a dead end.

`analyze` against any session captured before the events index existed died
with `sqlite3.OperationalError: table analysis_runs has no column named
log_size` -- an unhandled traceback, no message, and no mention of --rebuild.
All three real captures in this repository were affected.
"""

from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

import pytest

from scriptscrap.analysis import analyze_log
from scriptscrap.analysis.store import (
    STORE_SCHEMA_VERSION,
    DerivedStore,
    StoreSchemaError,
)
from scriptscrap.cli import build_parser

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"

# The exact shape of a pre-Phase-2 store: no log fingerprint, no events table.
LEGACY_SCHEMA = """
CREATE TABLE analysis_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       TEXT    NOT NULL,
    created_at       TEXT    NOT NULL,
    analysis_version INTEGER NOT NULL,
    event_count      INTEGER NOT NULL
);
CREATE TABLE endpoints (id INTEGER PRIMARY KEY, run_id INTEGER);
"""


def _legacy_session(tmp_path: Path) -> Path:
    root = tmp_path / "legacy"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")
    conn = sqlite3.connect(root / "session.sqlite")
    conn.executescript(LEGACY_SCHEMA)
    conn.execute("INSERT INTO analysis_runs (session_id, created_at, "
                 "analysis_version, event_count) VALUES ('old', 'then', 1, 5)")
    conn.commit()
    conn.close()
    return root


def _analyze(root: Path) -> int:
    args = build_parser().parse_args(["analyze", str(root)])
    return args.func(args)


def test_analyze_over_a_pre_phase_2_store_succeeds(tmp_path, capsys):
    root = _legacy_session(tmp_path)
    assert _analyze(root) == 0
    assert "rebuilt" in capsys.readouterr().out.lower()


def test_the_rebuilt_store_holds_the_new_tables(tmp_path):
    root = _legacy_session(tmp_path)
    _analyze(root)
    conn = sqlite3.connect(root / "session.sqlite")
    try:
        columns = {r[1] for r in conn.execute("PRAGMA table_info(analysis_runs)")}
        assert {"log_size", "log_sha256"} <= columns
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] > 0
        assert conn.execute("PRAGMA user_version").fetchone()[0] == STORE_SCHEMA_VERSION
    finally:
        conn.close()


def test_a_legacy_store_is_reported_not_silently_replaced(tmp_path):
    """`on_mismatch="raise"` exists so a caller can refuse."""
    root = _legacy_session(tmp_path)
    with pytest.raises(StoreSchemaError) as excinfo:
        DerivedStore(root / "session.sqlite", on_mismatch="raise")
    assert "rebuild" in str(excinfo.value)


def test_a_store_from_the_future_is_never_discarded(tmp_path):
    root = tmp_path / "future"
    root.mkdir()
    conn = sqlite3.connect(root / "session.sqlite")
    conn.execute(f"PRAGMA user_version = {STORE_SCHEMA_VERSION + 1}")
    conn.execute("CREATE TABLE precious (x)")
    conn.commit()
    conn.close()

    with pytest.raises(StoreSchemaError) as excinfo:
        DerivedStore(root / "session.sqlite")
    assert "newer" in str(excinfo.value).lower()

    conn = sqlite3.connect(root / "session.sqlite")
    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='precious'"
        ).fetchone()[0] == 1
    finally:
        conn.close()


def test_a_fresh_store_is_stamped(tmp_path):
    with DerivedStore(tmp_path / "session.sqlite") as store:
        assert store.rebuilt is False
    conn = sqlite3.connect(tmp_path / "session.sqlite")
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == STORE_SCHEMA_VERSION
    finally:
        conn.close()


def test_a_current_store_is_not_rebuilt(tmp_path):
    path = tmp_path / "session.sqlite"
    shutil.copy(SAMPLE, tmp_path / "events.jsonl")
    with DerivedStore(path) as store:
        store.write(analyze_log(tmp_path / "events.jsonl"))
    with DerivedStore(path) as store:
        assert store.rebuilt is False


# --- readers ignore a run from another analysis version -------------------

def test_a_reader_ignores_a_run_from_another_analysis_version(tmp_path):
    """A stored run the current code would not produce is not evidence."""
    from scriptscrap.analysis.events_index import EventStore, StaleIndexError
    from scriptscrap.analysis.models import ANALYSIS_VERSION

    root = tmp_path / "s"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")
    with DerivedStore(root / "session.sqlite") as store:
        store.write(analyze_log(root / "events.jsonl"))

    conn = sqlite3.connect(root / "session.sqlite")
    conn.execute("UPDATE analysis_runs SET analysis_version = ?",
                 (ANALYSIS_VERSION - 1,))
    conn.commit()
    conn.close()

    with pytest.raises(StaleIndexError) as excinfo:
        EventStore(root / "session.sqlite", root / "events.jsonl")
    assert "analyze" in str(excinfo.value)


def test_the_workspace_says_the_same_thing(tmp_path):
    from scriptscrap.analysis.models import ANALYSIS_VERSION
    from scriptscrap.workspace import Workspace, WorkspaceConfig, api

    root = tmp_path / "s2"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")
    with DerivedStore(root / "session.sqlite") as store:
        store.write(analyze_log(root / "events.jsonl"))
    conn = sqlite3.connect(root / "session.sqlite")
    conn.execute("UPDATE analysis_runs SET analysis_version = ?",
                 (ANALYSIS_VERSION - 1,))
    conn.commit()
    conn.close()

    workspace = Workspace(WorkspaceConfig(root=root))
    try:
        with pytest.raises(api.NotFound) as excinfo:
            api.session_overview(workspace, {})
        assert "analyze" in str(excinfo.value)
    finally:
        workspace.shutdown()


# --- retention: one run per session (F13) ---------------------------------

def test_analyzing_three_times_leaves_one_run(tmp_path):
    """Each run appended a full duplicate of the events index: ~2 MB a time."""
    root = tmp_path / "repeat"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")

    sizes = []
    for _ in range(3):
        assert _analyze(root) == 0
        sizes.append((root / "session.sqlite").stat().st_size)

    conn = sqlite3.connect(root / "session.sqlite")
    try:
        assert conn.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0] == 1
        run_id = conn.execute("SELECT id FROM analysis_runs").fetchone()[0]
        events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        orphans = conn.execute(
            "SELECT COUNT(*) FROM events WHERE run_id != ?", (run_id,)).fetchone()[0]
        assert orphans == 0
        for table in ("endpoints", "schemas", "dependencies", "ui_elements",
                      "states", "state_transitions", "technologies", "findings"):
            assert conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE run_id != ?",  # noqa: S608
                (run_id,)).fetchone()[0] == 0, f"{table} kept an orphan run"
        assert events > 0
    finally:
        conn.close()

    # F13 is about growth PER RUN, so the assertion is on the steady state.
    # Run 1 never vacuums -- there is nothing to prune yet -- so run 2 settles
    # the page layout and can differ from it by a page either way. On this
    # 135 KB fixture one page is 6%; on the real 9,255-event capture the same
    # sequence measures 1.88 / 1.83 / 1.84 / 1.86 MB against a pre-fix
    # 1.97 / 3.90 / 5.84.
    assert sizes[2] <= sizes[1] * 1.05, f"the store grew per run: {sizes}"
    assert sizes[2] < sizes[0] * 2, (
        f"the store is duplicating the events index: {sizes}")


def test_child_rows_of_a_replaced_run_are_deleted(tmp_path):
    """endpoint_params, schema_fields and selectors hang off ids, not run_id."""
    root = tmp_path / "children"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")
    for _ in range(2):
        _analyze(root)

    conn = sqlite3.connect(root / "session.sqlite")
    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM endpoint_params WHERE endpoint_id NOT IN "
            "(SELECT id FROM endpoints)").fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM schema_fields WHERE schema_id NOT IN "
            "(SELECT id FROM schemas)").fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM selectors WHERE element_id NOT IN "
            "(SELECT id FROM ui_elements)").fetchone()[0] == 0
    finally:
        conn.close()
