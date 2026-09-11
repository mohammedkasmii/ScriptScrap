"""`EventStore` -- the only module that knows byte offsets exist.

Everything else asks it for events by id, by filter, or by window. Swapping
the backing store later should change that one file and nothing else, so these
tests are written against the API and never against a byte position.

The staleness tests are the important ones. An offset is valid only for the
bytes it was built from, and events.jsonl is append-only: a session that kept
recording after `analyze` ran leaves an index that points into the right file
at the wrong places. Returning whatever now sits at that offset would be
evidence that silently belongs to a different event, which is worse than an
error.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scriptscrap.analysis import DerivedStore, analyze_log
from scriptscrap.analysis.events_index import EventStore, StaleIndexError

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"

def _fixture_event_count() -> int:
    """How many events the golden fixture holds.

    Derived, not hard-coded: the fixture is regenerated whenever a sensor
    change is re-blessed, and a literal here made four unrelated tests fail on
    every re-bless. What these tests assert is a RELATIONSHIP to the log, not
    a number.
    """
    return sum(1 for line in SAMPLE.read_text(encoding="utf-8").splitlines()
               if line.strip())

def _fixture_count(*, type: str | None = None, source: str | None = None) -> int:
    """How many fixture events match a type or a source.

    Derived, not hard-coded, for the same reason `_fixture_event_count` is: the
    fixture is regenerated whenever a sensor change is re-blessed, and a live
    browser run varies by a mutation or two. What these tests assert is that a
    filter agrees with the log, not that the log has a particular size.
    """
    import json as _json

    total = 0
    for line in SAMPLE.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = _json.loads(line)
        if type is not None and event["type"] != type:
            continue
        if source is not None and event["source"] != source:
            continue
        total += 1
    return total



@pytest.fixture
def session(tmp_path):
    """A session directory with a log and a freshly built index."""
    log = tmp_path / "events.jsonl"
    shutil.copy(SAMPLE, log)
    db = tmp_path / "session.sqlite"
    with DerivedStore(db) as store:
        store.write(analyze_log(log))
    return db, log


@pytest.fixture
def store(session):
    db, log = session
    s = EventStore(db, log)
    yield s
    s.close()


# --- point lookup ---------------------------------------------------------

def test_get_returns_the_event_with_its_payload(store):
    """The payload comes from the log, which is the point of the offset."""
    page = store.page(types=["http_request"], limit=1)
    event = store.get(page.events[0].event_id)
    assert event is not None
    assert event.payload


def test_get_unknown_id_returns_none(store):
    assert store.get("no-such-event") is None


def test_get_many_preserves_the_requested_order(store):
    ids = [e.event_id for e in store.page(limit=5).events]
    assert [e.event_id for e in store.get_many(list(reversed(ids)))] == list(reversed(ids))


def test_get_many_skips_unknown_ids_without_failing(store):
    ids = [e.event_id for e in store.page(limit=2).events]
    assert len(store.get_many([ids[0], "ghost", ids[1]])) == 2


# --- paging and filtering -------------------------------------------------

def test_page_walks_the_whole_log_exactly_once(store):
    seen, cursor = [], None
    while True:
        page = store.page(after_seq=cursor, limit=25)
        seen.extend(e.event_id for e in page.events)
        if page.next_seq is None:
            break
        cursor = page.next_seq
    assert len(seen) == len(set(seen)) == _fixture_event_count()


def test_page_filters_by_type(store):
    page = store.page(types=["http_request"], limit=100)
    assert page.events
    assert {str(e.type) for e in page.events} == {"http_request"}
    assert page.total == _fixture_count(type="http_request")


def test_page_filters_by_source(store):
    page = store.page(sources=["runtime"], limit=200)
    assert {str(e.source) for e in page.events} == {"runtime"}
    assert page.total == _fixture_count(source="runtime")


def test_page_intersects_type_and_source(store):
    page = store.page(types=["http_request"], sources=["runtime"], limit=200)
    assert all(str(e.type) == "http_request" and str(e.source) == "runtime"
               for e in page.events)


def test_page_filters_by_page_id(store):
    page = store.page(page_id="p1", limit=500)
    assert page.events
    assert {e.page_id for e in page.events} == {"p1"}


def test_page_returns_events_in_seq_order(store):
    """seq is the only total order; timestamps across sources disagree."""
    seqs = [e.seq for e in store.page(limit=500).events]
    assert seqs == sorted(seqs)


def test_a_cursor_past_the_end_returns_an_empty_page(store):
    page = store.page(after_seq=10**9, limit=10)
    assert page.events == []
    assert page.next_seq is None


def test_an_unmatched_filter_returns_an_empty_page(store):
    page = store.page(types=["ws_frame_sent"], limit=10)
    assert page.events == []
    assert page.total == 0


def test_counts_by_type_matches_the_log(store):
    counts = store.counts_by_type()
    assert counts["user_click"] == _fixture_count(type="user_click")
    assert counts["http_request"] == _fixture_count(type="http_request")
    assert sum(counts.values()) == _fixture_event_count()


def test_window_returns_an_inclusive_seq_range(store):
    events = store.window(5, 9)
    assert [e.seq for e in events] == [5, 6, 7, 8, 9]


# --- staleness ------------------------------------------------------------

def test_appending_to_the_log_makes_the_index_stale(session):
    db, log = session
    store = EventStore(db, log)
    try:
        with log.open("ab") as handle:
            handle.write(b'{"session_id":"s","event_id":"late","seq":9999,'
                         b'"t_wall":"2026-01-01T00:00:00+00:00","t_mono":1.0,'
                         b'"source":"engine","type":"session_end"}\n')
        with pytest.raises(StaleIndexError):
            store.get(store.page(limit=1).events[0].event_id)
    finally:
        store.close()


def test_re_analysing_clears_the_staleness(session):
    db, log = session
    with log.open("ab") as handle:
        handle.write(b'{"session_id":"s","event_id":"late","seq":9999,'
                     b'"t_wall":"2026-01-01T00:00:00+00:00","t_mono":1.0,'
                     b'"source":"engine","type":"session_end"}\n')
    with DerivedStore(db) as ds:
        ds.write(analyze_log(log))

    store = EventStore(db, log)
    try:
        assert store.get("late") is not None
    finally:
        store.close()


def test_the_stale_error_names_the_remedy(session):
    db, log = session
    store = EventStore(db, log)
    try:
        with log.open("ab") as handle:
            handle.write(b'{"padding": true}\n')
        with pytest.raises(StaleIndexError, match="analyze"):
            store.get("anything")
    finally:
        store.close()


def test_metadata_reads_do_not_require_the_log(session):
    """Counting and listing envelopes come from sqlite alone.

    Only a payload needs the log, which is what lets a timeline render 200
    collapsed rows without 200 seeks.
    """
    db, log = session
    store = EventStore(db, log)
    try:
        log.unlink()
        assert store.counts_by_type()["user_click"] == _fixture_count(type="user_click")
        assert store.counts_by_source()["runtime"] == _fixture_count(source="runtime")
        assert len(store.page_index(limit=3).rows) == 3
        assert store.seq_range() is not None
    finally:
        store.close()


def test_reading_a_payload_without_the_log_is_an_error_not_a_blank(session):
    db, log = session
    store = EventStore(db, log)
    try:
        event_id = store.page_index(limit=1).rows[0].event_id
        log.unlink()
        with pytest.raises(StaleIndexError, match="missing"):
            store.get(event_id)
    finally:
        store.close()


def test_page_index_agrees_with_page(session):
    """The two walks must not disagree about what matches a filter."""
    db, log = session
    store = EventStore(db, log)
    try:
        full = store.page(types=["http_request"], limit=100)
        envelopes = store.page_index(types=["http_request"], limit=100)
        assert [e.event_id for e in full.events] == [r.event_id for r in envelopes.rows]
        assert full.total == envelopes.total
        assert full.next_seq == envelopes.next_seq
    finally:
        store.close()


# --- run selection --------------------------------------------------------

def test_the_latest_run_is_used_by_default(session):
    """Re-analysing appends a run; the workspace reads the newest."""
    db, log = session
    with DerivedStore(db) as ds:
        second = ds.write(analyze_log(log))
    store = EventStore(db, log)
    try:
        assert store.run_id == second
    finally:
        store.close()
