"""The events index inside the derived store.

`session.sqlite` gains one row per event holding the ENVELOPE and a byte offset
into `events.jsonl` -- never the payload. That split is the whole design:

  * ~100 bytes a row, so a 9,000-event session costs about 1 MB rather than 7
  * the store stays derived and deletable; copying payloads would make it a
    second source of truth, which its own docstring forbids
  * timeline filtering becomes an indexed query instead of a linear scan

The run also records the log's size and sha256, because an offset is only
valid for the exact bytes it was built from.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from scriptscrap.analysis import DerivedStore, analyze_log

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"


@pytest.fixture
def written(tmp_path):
    result = analyze_log(SAMPLE)
    db = tmp_path / "session.sqlite"
    with DerivedStore(db) as store:
        run_id = store.write(result)
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    yield result, conn, run_id
    conn.close()


def test_every_event_is_indexed(written):
    result, conn, run_id = written
    count = conn.execute(
        "SELECT COUNT(*) FROM events WHERE run_id=?", (run_id,)).fetchone()[0]
    assert count == result.event_count


def test_payload_is_not_copied_into_sqlite(written):
    """The store must not become a second source of truth."""
    _, conn, _ = written
    columns = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
    assert "payload" not in columns
    assert {"event_id", "seq", "type", "source", "byte_offset", "byte_length"} <= columns


def test_offsets_locate_the_real_line(written):
    _, conn, run_id = written
    raw = SAMPLE.read_bytes()
    rows = conn.execute(
        "SELECT event_id, byte_offset, byte_length FROM events WHERE run_id=?",
        (run_id,)).fetchall()
    assert rows
    for row in rows:
        line = raw[row["byte_offset"]:row["byte_offset"] + row["byte_length"]]
        assert json.loads(line)["event_id"] == row["event_id"]


def test_run_records_the_log_fingerprint(written):
    """An offset is only valid for the bytes it was built from."""
    _, conn, run_id = written
    row = conn.execute(
        "SELECT log_size, log_sha256 FROM analysis_runs WHERE id=?", (run_id,)).fetchone()
    assert row["log_size"] == SAMPLE.stat().st_size
    assert len(row["log_sha256"]) == 64


def test_envelope_fields_match_the_log(written):
    """Every indexed envelope field is the log's, not a re-derived one."""
    _, conn, run_id = written
    from_log = {
        json.loads(line)["event_id"]: json.loads(line)
        for line in SAMPLE.read_bytes().splitlines() if line.strip()
    }
    rows = conn.execute("SELECT * FROM events WHERE run_id=?", (run_id,)).fetchall()
    assert rows
    for row in rows:
        raw = from_log[row["event_id"]]
        assert row["seq"] == raw["seq"]
        assert row["type"] == raw["type"]
        assert row["source"] == raw["source"]
        assert row["t_wall"] == raw["t_wall"]
        assert row["t_mono"] == pytest.approx(raw["t_mono"])
        assert row["page_id"] == raw.get("page_id")
        assert row["frame_id"] == raw.get("frame_id")


def test_the_store_is_still_rebuildable(tmp_path):
    """Deleting the database and re-analysing must reproduce it."""
    result = analyze_log(SAMPLE)
    db = tmp_path / "s.sqlite"

    def rows():
        # Windows will not unlink a file with an open handle, so the read
        # connection has to be closed before the delete below.
        conn = sqlite3.connect(db)
        try:
            return conn.execute(
                "SELECT event_id, byte_offset, byte_length FROM events ORDER BY seq"
            ).fetchall()
        finally:
            conn.close()

    with DerivedStore(db) as store:
        store.write(result)
    first = rows()

    db.unlink()
    for suffix in ("-wal", "-shm"):
        Path(str(db) + suffix).unlink(missing_ok=True)

    with DerivedStore(db) as store:
        store.write(analyze_log(SAMPLE))

    assert rows() == first
