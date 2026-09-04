"""Replay: an event log must be readable and checkable with no browser.

This is the architectural boundary M1 exists to establish:

    capture  ->  event log  ->  offline reader

These tests run against a COMMITTED event log recorded from a real fixture
investigation. They import nothing from Playwright or Camoufox, need no network,
and would pass on a machine with no browser installed at all. That is the
property that will make M3's analysis layer testable.
"""

from __future__ import annotations

import json

import pytest
from golden_support import SAMPLE_EVENT_LOG

from scriptscrap.events import EventLogReader, EventType, Source


@pytest.fixture(scope="module")
def reader() -> EventLogReader:
    assert SAMPLE_EVENT_LOG.exists(), (
        f"missing recorded log {SAMPLE_EVENT_LOG}; regenerate with "
        f"SCRIPTSCRAP_UPDATE_GOLDEN=1 uv run pytest -m browser"
    )
    return EventLogReader(SAMPLE_EVENT_LOG)


def test_recorded_log_loads_without_a_browser(reader):
    assert len(reader) > 0
    assert reader.validate() == []


def test_log_is_a_single_ordered_session(reader):
    assert len(reader.summary()["sessions"]) == 1
    seqs = [e.seq for e in reader]
    assert seqs == sorted(seqs)
    assert reader.sequence_gaps() == []


def test_session_is_bounded_by_start_and_end(reader):
    assert reader.events[0].type is EventType.SESSION_START
    assert reader.events[-1].type is EventType.SESSION_END


def test_network_events_are_reconstructable_offline(reader):
    """The point of replay: derive facts from the log alone."""
    requests = reader.of_type(EventType.HTTP_REQUEST)
    paths = {e.payload["path"] for e in requests}
    assert {"/api/dossier", "/api/valider", "/api/form", "/api/error"} <= paths

    responses = reader.of_type(EventType.HTTP_RESPONSE)
    by_path_status = {(e.payload["path"], e.payload["status"]) for e in responses}
    assert ("/api/error", 500) in by_path_status
    assert ("/api/dossier", 200) in by_path_status


def test_request_precedes_its_response_in_sequence(reader):
    """seq is the total order; causality work in later milestones depends on it."""
    first_request = next(
        e for e in reader if e.type is EventType.HTTP_REQUEST
        and e.payload.get("path") == "/api/valider"
    )
    first_response = next(
        e for e in reader if e.type is EventType.HTTP_RESPONSE
        and e.payload.get("path") == "/api/valider"
    )
    assert first_request.seq < first_response.seq


def test_credential_headers_are_named_but_never_valued(reader):
    """The log records WHICH headers authenticate, never their values."""
    for event in reader.of_type(EventType.HTTP_REQUEST):
        assert "headers" not in event.payload, "raw header values must not be in the spine"
        assert isinstance(event.payload.get("header_names", []), list)


def test_capture_gaps_are_recorded(reader):
    """Absence of observation must be distinguishable from absence of activity."""
    gaps = reader.of_type(EventType.CAPTURE_GAP)
    assert gaps, "expected at least one recorded capture gap"
    reasons = {g.payload["reason"] for g in gaps}
    assert "runtime_buffers_read_once_at_exit" in reasons


def test_sources_are_attributed(reader):
    sources = {e.source for e in reader}
    assert Source.ENGINE in sources
    assert Source.PLAYWRIGHT in sources


def test_every_event_roundtrips_through_json(reader):
    for event in reader:
        assert json.loads(event.to_json())["seq"] == event.seq


def test_committed_log_came_from_the_fixture_and_not_a_real_portal():
    """Guard on a file that is committed to git.

    The event spine is RAW evidence: it records full URLs, and a GET form
    submission puts passwords and CSRF tokens in the query string. That is
    correct for a local, gitignored session directory -- but this particular log
    is committed so the replay tests can run offline.

    If someone re-blesses the baseline while investigating a real portal, this
    fails loudly instead of committing their live session to the repository.
    """
    raw = SAMPLE_EVENT_LOG.read_text(encoding="utf-8")
    reader = EventLogReader(SAMPLE_EVENT_LOG)

    for event in reader:
        url = event.payload.get("url")
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            assert "127.0.0.1" in url or "localhost" in url, (
                f"committed event log references a non-loopback host: {url!r}. "
                "This log must come from the local fixture app only."
            )

    # Shapes that only ever appear in a real capture, never in the fixture.
    assert "BEGIN PRIVATE KEY" not in raw
    assert "Bearer " not in raw, "a real bearer token may have been committed"
    assert "eyJ" not in raw, "a JWT may have been committed"
