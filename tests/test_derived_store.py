"""The derived store must be rebuildable from raw events.

This is the property that keeps `events.jsonl` the single source of truth: if
`session.sqlite` held anything that could not be re-derived, it would quietly
have become a second one.
"""

from __future__ import annotations

from golden_support import SAMPLE_EVENT_LOG

from scriptscrap.analysis import DerivedStore, analyze_log


def test_round_trip_through_sqlite(tmp_path):
    result = analyze_log(SAMPLE_EVENT_LOG)
    db = tmp_path / "session.sqlite"
    with DerivedStore(db) as store:
        run_id = store.write(result)

    with DerivedStore(db) as store:
        run = store.latest_run()
        assert run is not None
        assert run["id"] == run_id
        assert run["event_count"] == result.event_count
        assert len(store.rows("endpoints", run_id)) == len(result.endpoints)
        assert len(store.rows("schemas", run_id)) == len(result.schemas)
        assert len(store.rows("dependencies", run_id)) == len(result.dependencies)
        assert len(store.rows("ui_elements", run_id)) == len(result.ui_elements)
        assert len(store.rows("states", run_id)) == len(result.states)
        assert len(store.rows("findings", run_id)) == len(result.findings)


def test_deleting_the_database_and_rebuilding_reproduces_it(tmp_path):
    db = tmp_path / "session.sqlite"

    def build() -> list[tuple]:
        with DerivedStore(db) as store:
            run_id = store.write(analyze_log(SAMPLE_EVENT_LOG))
            return [
                (r["endpoint_key"], r["method"], r["template"], r["observation_count"],
                 r["confidence"], r["evidence_ids"])
                for r in store.rows("endpoints", run_id)
            ]

    first = build()
    for suffix in ("", "-wal", "-shm"):
        candidate = db.with_name(db.name + suffix)
        if candidate.exists():
            candidate.unlink()
    second = build()

    assert first == second, "rebuilt store differs from the original"
    assert first, "no endpoints were derived at all"


def test_children_are_linked_to_their_parents(tmp_path):
    result = analyze_log(SAMPLE_EVENT_LOG)
    with DerivedStore(tmp_path / "s.sqlite") as store:
        run_id = store.write(result)
        for schema_row in store.rows("schemas", run_id):
            fields = store.children("schema_fields", "schema_id", schema_row["id"])
            expected = next(
                s for s in result.schemas
                if s.endpoint_key == schema_row["endpoint_key"]
                and s.direction == schema_row["direction"]
                and (s.status or None) == schema_row["status"]
            )
            assert len(fields) == len(expected.fields)


def test_derived_rows_carry_evidence(tmp_path):
    result = analyze_log(SAMPLE_EVENT_LOG)
    with DerivedStore(tmp_path / "s.sqlite") as store:
        run_id = store.write(result)
        for row in store.rows("dependencies", run_id):
            assert row["evidence_ids"] not in ("[]", "", None)
            assert row["confidence"] > 0
        for row in store.rows("endpoints", run_id):
            assert row["evidence_ids"] not in ("[]", "", None)


def test_unknown_table_is_refused(tmp_path):
    import pytest

    with DerivedStore(tmp_path / "s.sqlite") as store:
        with pytest.raises(ValueError, match="unknown table"):
            store.rows("sqlite_master", 1)
        with pytest.raises(ValueError, match="unknown child query"):
            store.children("sqlite_master", "id", 1)
