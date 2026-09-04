"""Event spine unit tests. No browser, no network."""

from __future__ import annotations

import json

import pytest

from scriptscrap.events import (
    MAX_PAYLOAD_FIELD_BYTES,
    Event,
    EventLog,
    EventLogReader,
    EventType,
    Source,
)


def test_seq_is_allocated_monotonically(tmp_path):
    with EventLog(tmp_path / "events.jsonl", "sess-1") as log:
        events = [
            log.emit(Source.ENGINE, EventType.HTTP_REQUEST, url=f"/a/{i}") for i in range(10)
        ]
    assert [e.seq for e in events] == list(range(1, 11))
    assert len({e.event_id for e in events}) == 10


def test_events_reach_disk_immediately(tmp_path):
    """The crash-resilience property: no event may wait for close()."""
    path = tmp_path / "events.jsonl"
    log = EventLog(path, "sess-1")
    log.emit(Source.ENGINE, EventType.SESSION_START, target="https://example.test")
    log.emit(Source.PLAYWRIGHT, EventType.HTTP_REQUEST, url="/api/x")

    # Read while the log is still open and was never closed.
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["type"] == "session_start"
    log.close()


def test_roundtrip_through_reader(tmp_path):
    path = tmp_path / "events.jsonl"
    with EventLog(path, "sess-9") as log:
        log.emit(Source.ENGINE, EventType.SESSION_START, target="https://example.test")
        log.emit(Source.PLAYWRIGHT, EventType.HTTP_REQUEST, method="GET", url="/api/dossier")
        log.emit(Source.PLAYWRIGHT, EventType.HTTP_RESPONSE, status=200, url="/api/dossier")
        log.emit(Source.ENGINE, EventType.SESSION_END)

    reader = EventLogReader(path)
    assert len(reader) == 4
    assert reader.validate() == []
    assert [e.type for e in reader] == [
        EventType.SESSION_START,
        EventType.HTTP_REQUEST,
        EventType.HTTP_RESPONSE,
        EventType.SESSION_END,
    ]
    assert reader.of_type(EventType.HTTP_RESPONSE)[0].payload["status"] == 200


def test_reader_recovers_from_truncated_final_line(tmp_path):
    """A killed process leaves a partial line; everything before it must survive."""
    path = tmp_path / "events.jsonl"
    with EventLog(path, "sess-crash") as log:
        for i in range(5):
            log.emit(Source.PLAYWRIGHT, EventType.HTTP_REQUEST, url=f"/api/{i}")

    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"session_id": "sess-crash", "event_id": "evt-000000')  # cut mid-write

    reader = EventLogReader(path)
    assert len(reader) == 5
    kinds = {p.kind for p in reader.validate()}
    assert "truncated_final_line" in kinds


def test_reader_reports_bad_lines_without_losing_good_ones(tmp_path):
    path = tmp_path / "events.jsonl"
    with EventLog(path, "s") as log:
        log.emit(Source.ENGINE, EventType.SESSION_START)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("not json at all\n")
        handle.write('{"session_id": "s", "event_id": "e"}\n')  # missing required fields
    with EventLog(path, "s") as log:
        log.emit(Source.ENGINE, EventType.SESSION_END)

    reader = EventLogReader(path)
    assert len(reader) == 2
    kinds = {p.kind for p in reader.validate()}
    assert "invalid_json" in kinds
    assert "invalid_envelope" in kinds


def test_sequence_gap_is_detected(tmp_path):
    path = tmp_path / "events.jsonl"
    with EventLog(path, "s") as log:
        log.emit(Source.ENGINE, EventType.SESSION_START)
        log.emit(Source.ENGINE, EventType.SESSION_END)

    lines = path.read_text(encoding="utf-8").splitlines()
    doctored = json.loads(lines[1])
    doctored["seq"] = 7
    path.write_text(lines[0] + "\n" + json.dumps(doctored) + "\n", encoding="utf-8")

    reader = EventLogReader(path)
    assert reader.sequence_gaps() == [(2, 6)]
    assert any(p.kind == "sequence_gap" for p in reader.validate())


def test_large_payload_is_truncated_not_retained(tmp_path):
    path = tmp_path / "events.jsonl"
    huge = "x" * (MAX_PAYLOAD_FIELD_BYTES * 3)
    with EventLog(path, "s") as log:
        event = log.emit(Source.PLAYWRIGHT, EventType.HTTP_RESPONSE, body=huge)

    assert event is not None
    assert event.payload["body"]["__truncated__"] is True
    assert event.payload["body"]["original_bytes"] == len(huge)
    assert len(event.payload["body"]["kept"]) <= MAX_PAYLOAD_FIELD_BYTES
    assert path.stat().st_size < MAX_PAYLOAD_FIELD_BYTES * 2


def test_sensor_error_and_capture_gap_are_first_class(tmp_path):
    path = tmp_path / "events.jsonl"
    with EventLog(path, "s") as log:
        log.sensor_error(Source.PLAYWRIGHT, "handle_response", RuntimeError("body evicted"),
                         url="/api/x")
        log.capture_gap(Source.ENGINE, "out_of_scope", host="mail.example.test")

    reader = EventLogReader(path)
    err = reader.of_type(EventType.SENSOR_ERROR)[0]
    assert err.payload["error_type"] == "RuntimeError"
    assert err.payload["where"] == "handle_response"
    gap = reader.of_type(EventType.CAPTURE_GAP)[0]
    assert gap.payload["reason"] == "out_of_scope"
    # A gap must never carry the sensitive detail it exists to exclude.
    assert "body" not in gap.payload


def test_emit_after_close_returns_none(tmp_path):
    log = EventLog(tmp_path / "events.jsonl", "s")
    log.close()
    assert log.emit(Source.ENGINE, EventType.SESSION_END) is None


def test_unknown_event_type_is_rejected():
    with pytest.raises(ValueError, match="unknown event type"):
        Event.from_dict(
            {
                "session_id": "s", "event_id": "e", "seq": 1,
                "t_wall": "2026-01-01T00:00:00+00:00", "t_mono": 1.0,
                "source": "engine", "type": "not_a_real_type",
            }
        )


def test_missing_required_field_is_rejected():
    with pytest.raises(ValueError, match="missing required field"):
        Event.from_dict({"session_id": "s", "event_id": "e", "seq": 1})


def test_summary_shape(tmp_path):
    path = tmp_path / "events.jsonl"
    with EventLog(path, "s") as log:
        log.emit(Source.ENGINE, EventType.SESSION_START)
        log.emit(Source.PLAYWRIGHT, EventType.HTTP_REQUEST, url="/a")
        log.emit(Source.PLAYWRIGHT, EventType.HTTP_REQUEST, url="/b")

    summary = EventLogReader(path).summary()
    assert summary["events"] == 3
    assert summary["by_type"]["http_request"] == 2
    assert summary["by_source"]["playwright"] == 2
    assert summary["problems"] == []
