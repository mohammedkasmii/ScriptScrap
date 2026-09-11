"""Byte offsets into the event log.

Every derived table cites `evidence_ids`, but the events they name live only in
`events.jsonl`. Without an index, one evidence lookup costs a full re-parse of
the log -- 7.1 MB for an eight-minute session.

The index records where each event's line starts and how long it is, so a
lookup is a seek. The payload is never copied: `events.jsonl` stays the only
source of truth.

Offsets are opt-in so the existing read path is unchanged, and they are
produced by the SAME parser, so there remains exactly one definition of a valid
event line.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scriptscrap.events import EventLogReader

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"


@pytest.fixture
def sample_bytes() -> bytes:
    return SAMPLE.read_bytes()


def test_offsets_are_absent_unless_requested():
    assert EventLogReader(SAMPLE).offsets == {}


def test_every_event_has_an_offset():
    reader = EventLogReader(SAMPLE, with_offsets=True)
    assert reader.events
    assert len(reader.offsets) == len(reader.events)
    assert {e.event_id for e in reader.events} == set(reader.offsets)


def test_every_offset_round_trips_to_its_own_line(sample_bytes):
    """The whole point: offset -> the exact bytes of that event."""
    reader = EventLogReader(SAMPLE, with_offsets=True)
    for event in reader.events:
        offset, length = reader.offsets[event.event_id]
        raw = sample_bytes[offset:offset + length]
        assert json.loads(raw)["event_id"] == event.event_id


def test_offsets_survive_non_ascii_payloads(tmp_path):
    """Offsets are BYTE positions. Counting characters would drift on any
    multi-byte payload and silently return the wrong event."""
    log = tmp_path / "events.jsonl"
    base = {
        "session_id": "s", "seq": 0, "t_wall": "2026-01-01T00:00:00+00:00",
        "t_mono": 0.0, "source": "engine", "type": "session_start",
    }
    lines = []
    for i, text in enumerate(["ascii", "日本語のペイロード", "emoji 🎯🔬", "ok"]):
        lines.append(json.dumps({**base, "event_id": f"e{i}", "seq": i,
                                 "payload": {"note": text}}, ensure_ascii=False))
    log.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))

    reader = EventLogReader(log, with_offsets=True)
    raw = log.read_bytes()
    assert len(reader.offsets) == 4
    for event in reader.events:
        offset, length = reader.offsets[event.event_id]
        assert json.loads(raw[offset:offset + length])["event_id"] == event.event_id


def test_truncated_final_line_still_indexes_every_intact_event(tmp_path):
    """A killed process leaves a partial final line. Everything before it is
    still valid evidence and must still be addressable."""
    log = tmp_path / "events.jsonl"
    log.write_bytes(SAMPLE.read_bytes() + b'{"session_id":"x","event_id":"trunc"')

    reader = EventLogReader(log, with_offsets=True)
    assert "trunc" not in reader.offsets
    assert len(reader.offsets) == len(reader.events)
    assert any(p.kind == "truncated_final_line" for p in reader.problems)


def test_blank_lines_do_not_shift_offsets(tmp_path):
    log = tmp_path / "events.jsonl"
    body = SAMPLE.read_bytes()
    log.write_bytes(b"\n" + body[: body.index(b"\n") + 1] + b"\n\n" + body[body.index(b"\n") + 1:])

    reader = EventLogReader(log, with_offsets=True)
    raw = log.read_bytes()
    for event in reader.events:
        offset, length = reader.offsets[event.event_id]
        assert json.loads(raw[offset:offset + length])["event_id"] == event.event_id


def test_the_existing_read_contract_is_unchanged():
    """Requesting offsets must not change what the reader considers valid."""
    plain = EventLogReader(SAMPLE)
    indexed = EventLogReader(SAMPLE, with_offsets=True)
    assert [e.event_id for e in plain.events] == [e.event_id for e in indexed.events]
    assert [str(p) for p in plain.validate()] == [str(p) for p in indexed.validate()]
