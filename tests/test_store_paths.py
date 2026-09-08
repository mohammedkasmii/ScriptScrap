"""A session directory is named by its operator, not by us.

`sqlite3.connect(f"file:{path}?mode=ro", uri=True)` pasted an unquoted path
into a URI, so a `#` in a directory name started a URI fragment and SQLite
silently opened a different file. `analyze` succeeded; the workspace then
reported `no such table: analysis_runs`, which points at the schema rather than
at the path.
"""

from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

import pytest

from scriptscrap.analysis import DerivedStore, analyze_log
from scriptscrap.analysis.dbpath import read_only_uri
from scriptscrap.analysis.events_index import EventStore
from scriptscrap.workspace.session import open_session

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"

# `?` and `*` are illegal in Windows filenames; the rest are legal everywhere.
AWKWARD_NAMES = ["plain", "has#hash", "has space", "has%pct", "has$dollar",
                 "has'quote", "has(paren)", "has+plus", "has&amp"]


def _analysed(root: Path) -> Path:
    root.mkdir(parents=True)
    shutil.copy(SAMPLE, root / "events.jsonl")
    with DerivedStore(root / "session.sqlite") as store:
        store.write(analyze_log(root / "events.jsonl"))
    return root


@pytest.mark.parametrize("name", AWKWARD_NAMES)
def test_a_session_directory_with_a_uri_significant_name_opens(tmp_path, name):
    root = _analysed(tmp_path / name)
    handle = open_session(root)
    conn = handle.connect()
    try:
        assert conn.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0] == 1
    finally:
        conn.close()


@pytest.mark.parametrize("name", AWKWARD_NAMES)
def test_evidence_lookup_works_under_a_uri_significant_name(tmp_path, name):
    root = _analysed(tmp_path / name)
    store = EventStore(root / "session.sqlite", root / "events.jsonl")
    try:
        found = store.get("evt-00000001")
        assert found is not None and found.event_id == "evt-00000001"
    finally:
        store.close()


def test_read_only_uri_refuses_to_write(tmp_path):
    root = _analysed(tmp_path / "ro")
    conn = sqlite3.connect(read_only_uri(root / "session.sqlite"), uri=True)
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("CREATE TABLE t (x)")
    finally:
        conn.close()


def test_read_only_uri_percent_encodes_a_fragment_character(tmp_path):
    uri = read_only_uri(tmp_path / "a#b" / "session.sqlite")
    assert "%23" in uri
    assert "#" not in uri.split("?", 1)[0]


def test_a_missing_database_says_so_rather_than_creating_one(tmp_path):
    """mode=ro must not invent an empty database that reports a schema error."""
    with pytest.raises(sqlite3.OperationalError) as excinfo:
        sqlite3.connect(read_only_uri(tmp_path / "nope.sqlite"), uri=True).execute(
            "SELECT 1 FROM analysis_runs")
    assert "unable to open" in str(excinfo.value).lower()
