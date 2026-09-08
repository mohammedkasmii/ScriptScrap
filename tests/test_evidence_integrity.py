"""An event id resolves to one event, or the citation means nothing.

`EventStore.get` uses fetchone(). `EventLogReader.validate` detects duplicate
ids but analyze_log never acted on the finding, so a log with two lines sharing
an id resolved every citation of it to whichever row came back first.
"""

from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

import pytest

from scriptscrap.analysis import DerivedStore, analyze_log
from scriptscrap.analysis.store import STORE_SCHEMA_VERSION

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"


def _log_with_a_duplicate_id(tmp_path: Path) -> Path:
    lines = SAMPLE.read_text(encoding="utf-8").splitlines()
    duplicated = [*lines, lines[0]]          # evt-00000001 twice
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(duplicated) + "\n", encoding="utf-8")
    return path


def test_the_index_refuses_a_duplicate_event_id(tmp_path):
    log = _log_with_a_duplicate_id(tmp_path)
    result = analyze_log(log)
    with pytest.raises(sqlite3.IntegrityError), \
            DerivedStore(tmp_path / "session.sqlite") as store:
        store.write(result)


def test_a_duplicate_id_is_a_critical_finding(tmp_path):
    """Refusing to store it is not enough: the reader must be told the log is
    the problem, not the tool."""
    result = analyze_log(_log_with_a_duplicate_id(tmp_path))
    duplicates = [f for f in result.findings if f.kind == "duplicate_event_id"]
    assert len(duplicates) == 1
    assert duplicates[0].severity == "critical"
    assert "evt-00000001" in duplicates[0].message


def test_a_clean_log_produces_no_such_finding(tmp_path):
    shutil.copy(SAMPLE, tmp_path / "events.jsonl")
    result = analyze_log(tmp_path / "events.jsonl")
    assert not [f for f in result.findings if f.kind == "duplicate_event_id"]


def test_a_clean_log_still_stores(tmp_path):
    shutil.copy(SAMPLE, tmp_path / "events.jsonl")
    with DerivedStore(tmp_path / "session.sqlite") as store:
        run_id = store.write(analyze_log(tmp_path / "events.jsonl"))
    assert run_id > 0


def test_the_store_schema_version_covers_this_index():
    """4, not the plan's 3: the SANITISED-mode commit already spent 3 on the
    nullable columns. The numbers are a chain with no gaps and no reuse."""
    assert STORE_SCHEMA_VERSION >= 4, (
        "making ix_events_id UNIQUE is a SQL change")


def test_the_analysis_version_covers_the_new_findings():
    """Two new finding kinds is a change to what analysis derives, which is
    exactly what ANALYSIS_VERSION means. Plan C left it at 3."""
    from scriptscrap.analysis.models import ANALYSIS_VERSION

    assert ANALYSIS_VERSION >= 4


def test_two_runs_of_the_same_log_do_not_collide(tmp_path):
    """The index is UNIQUE per (run_id, event_id), not per event_id."""
    shutil.copy(SAMPLE, tmp_path / "events.jsonl")
    path = tmp_path / "session.sqlite"
    with DerivedStore(path) as store:
        store.write(analyze_log(tmp_path / "events.jsonl"), keep=2)
    with DerivedStore(path) as store:
        store.write(analyze_log(tmp_path / "events.jsonl"), keep=2)
    conn = sqlite3.connect(path)
    try:
        assert conn.execute(
            "SELECT COUNT(DISTINCT run_id) FROM events").fetchone()[0] == 2
    finally:
        conn.close()


def test_the_cli_reports_the_finding_rather_than_a_traceback(tmp_path, capsys):
    """A duplicated id is the LOG's defect. An IntegrityError traceback names
    a SQLite index and reads like a tool failure."""
    from scriptscrap.cli import build_parser

    _log_with_a_duplicate_id(tmp_path)
    args = build_parser().parse_args(["analyze", str(tmp_path)])
    with pytest.raises(SystemExit) as excinfo:
        args.func(args)
    message = str(excinfo.value)
    assert "repeats an event id" in message
    assert "evt-00000001" in message
    assert "Traceback" not in message
