"""Out-of-scope traffic must be recorded on the spine, statuses included.

`out_of_scope_metadata.json` used to be the only place an out-of-scope
response's status was written down: the request side emitted a capture gap, but
the response side only updated an in-memory tally that went nowhere else.
Retiring that file without this would have silently lost how third-party calls
answered -- and a 401 from an identity provider is not the same observation as
a 200 from an ad network.

Driven directly rather than through the browser: the fixture app is entirely in
scope by construction, so a capture against it has no out-of-scope traffic to
observe, and a test that needs the open internet to prove a scope rule is a
test that will one day pass because a request failed.
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest

from scriptscrap.events import EventLogReader, EventType
from scriptscrap.testing.capture import load_investigator


class _Request:
    """The parts of a Playwright request the handlers actually read."""

    def __init__(self, url: str, method: str = "GET", resource_type: str = "xhr") -> None:
        self.url = url
        self.method = method
        self.resource_type = resource_type


class _Response:
    def __init__(self, request: _Request, status: int) -> None:
        self.request = request
        self.status = status


@pytest.fixture
def engine(tmp_path):
    inv = load_investigator(tmp_path / "output")
    scope = inv.InvestigationScope("https://app.test")
    harvester = inv.WebHarvester("https://app.test", scope, session_id="sess-test")
    yield harvester
    with contextlib.suppress(Exception):
        harvester.close_events()


def _gaps(engine, reason: str = "out_of_scope") -> list[dict]:
    """Read the gaps back off the log the engine actually wrote."""
    engine.close_events()
    reader = EventLogReader(engine.event_log.path)
    return [e.payload for e in reader.of_type(EventType.CAPTURE_GAP)
            if e.payload.get("reason") == reason]


def test_out_of_scope_response_records_its_status(engine):
    asyncio.run(engine.handle_response(
        _Response(_Request("https://ads.elsewhere.test/px?uid=SECRET"), 204)))
    gaps = _gaps(engine)
    assert gaps, "no out-of-scope gap recorded for the response"
    assert gaps[-1]["status"] == 204
    assert gaps[-1]["host"] == "ads.elsewhere.test"
    assert gaps[-1]["path"] == "/px"


def test_out_of_scope_response_withholds_the_query(engine):
    asyncio.run(engine.handle_response(
        _Response(_Request("https://ads.elsewhere.test/px?uid=SECRET&t=TOKEN"), 200)))
    gaps = _gaps(engine)
    assert "SECRET" not in str(gaps)
    assert "TOKEN" not in str(gaps)
    assert "query" in gaps[-1]["withheld"]


def test_in_scope_response_records_no_gap(engine):
    asyncio.run(engine.handle_response(
        _Response(_Request("https://app.test/api/items?q=keep"), 200)))
    assert _gaps(engine) == []


def test_request_and_response_are_both_recorded(engine):
    """Two observations of one exchange, so a third-party call that never
    answered stays distinguishable from one that answered 500."""
    request = _Request("https://ads.elsewhere.test/beacon")

    async def drive():
        await engine.handle_request(request)
        await engine.handle_response(_Response(request, 500))

    asyncio.run(drive())
    gaps = _gaps(engine)
    assert len(gaps) == 2
    assert [g.get("status") for g in gaps] == [None, 500]
