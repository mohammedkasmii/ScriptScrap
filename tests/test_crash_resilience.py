"""A crash must not destroy the investigation history.

The pre-M0 investigator held its whole network log in memory and wrote it once
at exit, so an interruption lost everything. The event spine writes incrementally
precisely so that stops being true.

This test interrupts a real fixture investigation partway through, WITHOUT
calling export(), and proves the events emitted before the interruption are
still on disk and still readable.
"""

from __future__ import annotations

import pytest

from scriptscrap.events import EventLogReader, EventType

pytestmark = pytest.mark.browser


@pytest.fixture(scope="module")
def crashed_output(tmp_path_factory):
    """Run the scripted investigation and kill it mid-workflow."""
    from scriptscrap.testing.capture import SimulatedCrash, capture

    out = tmp_path_factory.mktemp("crashed") / "output"
    with pytest.raises(SimulatedCrash):
        capture(out, headless=True, stop_after_step=4)
    return out


def test_export_never_ran(crashed_output):
    """Establishes that this really was an interrupted session."""
    assert not (crashed_output / "session_manifest.json").exists()
    assert not (crashed_output / "network_traffic.json").exists()
    assert not (crashed_output / "generated_client.py").exists()


def test_event_log_survives_the_crash(crashed_output):
    log = crashed_output / "events.jsonl"
    assert log.exists(), "no event log survived the interruption"
    assert log.stat().st_size > 0


def test_surviving_events_are_readable_and_intact(crashed_output):
    reader = EventLogReader(crashed_output / "events.jsonl")
    assert len(reader) > 0

    # A truncated final line is tolerable and recoverable; nothing else is.
    fatal = [p for p in reader.validate() if p.kind != "truncated_final_line"]
    assert fatal == [], f"log damaged beyond the final line: {fatal}"

    assert reader.events[0].type is EventType.SESSION_START
    # The session never ended cleanly, so there must be no session_end.
    assert reader.of_type(EventType.SESSION_END) == []


def test_work_completed_before_the_crash_is_present(crashed_output):
    """Not just 'a file exists' -- the actual observations must be there."""
    reader = EventLogReader(crashed_output / "events.jsonl")
    paths = {
        e.payload.get("path")
        for e in reader.of_type(EventType.HTTP_REQUEST, EventType.HTTP_RESPONSE)
    }
    # Steps 1-4 load the page, fill the form, and fetch the dossier.
    assert "/" in paths
    assert "/api/dossier" in paths
    assert reader.of_type(EventType.DOM_SNAPSHOT), "DOM snapshot before the crash is missing"
    assert reader.of_type(EventType.SCREENSHOT), "screenshot before the crash is missing"
