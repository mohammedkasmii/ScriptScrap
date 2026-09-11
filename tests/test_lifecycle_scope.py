"""The engagement boundary on the lifecycle observation path.

`LifecycleSensor` emitted `page.url`, `frame.url`, `popup.url` and
`download.url` straight from Playwright, with no scope check at all. An
in-scope page embeds a third-party iframe; an SSO flow redirects through an
identity provider with a token in the query. Both land in the event log in
full.

This is the same defect already fixed on the runtime path, where a real capture
recorded 213 out-of-scope observations carrying full query strings. These tests
pin the policy on this path: out of scope means the URL keeps its origin and
path and loses everything after them.

The event is never dropped. "A third-party iframe attached here" is a real
forensic fact and the reason the reduction is not a filter.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from scriptscrap.sensors.identity import PageRegistry
from scriptscrap.sensors.lifecycle import LifecycleSensor

TARGET = "https://app.test"
THIRD_PARTY = "https://ads.elsewhere.test"


class _Scope:
    def __init__(self, *roots: str) -> None:
        self.roots = set(roots)

    def contains(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        return any(host == r or host.endswith("." + r) for r in self.roots)


class _Engine:
    def __init__(self) -> None:
        self.scope = _Scope("app.test")
        self.events: list[tuple] = []

    def emit_event(self, source, event_type, **payload):
        self.events.append((event_type, payload))

    def emit_sensor_error(self, *a, **k): pass
    def emit_capture_gap(self, *a, **k): pass


class _Frame:
    def __init__(self, url: str, *, parent=None, name: str = "") -> None:
        self.url = url
        self.parent_frame = parent
        self.name = name


class _Page:
    def __init__(self, url: str) -> None:
        self.url = url
        self._handlers: dict = {}

    def on(self, event, handler):
        self._handlers[event] = handler


class _Download:
    def __init__(self, url: str) -> None:
        self.url = url
        self.suggested_filename = "f.txt"


@pytest.fixture
def sensor():
    engine = _Engine()
    return LifecycleSensor(engine, PageRegistry()), engine


def _last(engine):
    return engine.events[-1][1]


# --- in scope keeps everything -------------------------------------------

def test_in_scope_frame_url_is_untouched(sensor):
    probe, engine = sensor
    probe._on_frame_attached(_Frame(f"{TARGET}/x?q=KEEPME"), "page-1")
    payload = _last(engine)
    assert payload["url"] == f"{TARGET}/x?q=KEEPME"
    assert "evidence_reduced" not in payload


def test_in_scope_page_url_is_untouched(sensor):
    probe, engine = sensor
    probe.observe_page(_Page(f"{TARGET}/login?next=%2Fsecure"))
    payload = _last(engine)
    assert payload["url"] == f"{TARGET}/login?next=%2Fsecure"
    assert "evidence_reduced" not in payload


# --- out of scope loses the query ----------------------------------------

def test_out_of_scope_frame_url_loses_query(sensor):
    probe, engine = sensor
    probe._on_frame_attached(_Frame(f"{THIRD_PARTY}/i?token=SECRET"), "page-1")
    payload = _last(engine)
    assert payload["url"] == f"{THIRD_PARTY}/i"
    assert "SECRET" not in str(payload)
    assert payload["evidence_reduced"] is True
    assert payload["scope"] == "out_of_scope"


def test_out_of_scope_page_url_loses_query(sensor):
    probe, engine = sensor
    probe.observe_page(_Page(f"{THIRD_PARTY}/sso?id_token=SECRET"))
    payload = _last(engine)
    assert payload["url"] == f"{THIRD_PARTY}/sso"
    assert "SECRET" not in str(payload)


def test_out_of_scope_popup_url_loses_query(sensor):
    probe, engine = sensor
    probe._on_popup(_Page(f"{THIRD_PARTY}/auth?code=SECRET"), "page-1")
    # observe_page fires first (page_opened), then popup_opened. Both carry
    # the popup's URL, so reducing one and not the other would still leak.
    assert len(engine.events) == 2
    for _, payload in engine.events:
        assert "SECRET" not in str(payload)


def test_out_of_scope_download_url_loses_query(sensor):
    probe, engine = sensor
    probe._on_download(_Download(f"{THIRD_PARTY}/f.txt?sig=SECRET"), "page-1")
    payload = _last(engine)
    assert payload["url"] == f"{THIRD_PARTY}/f.txt"
    assert "SECRET" not in str(payload)


def test_out_of_scope_navigation_reduces_both_emitted_events(sensor):
    """framenavigated on a main frame emits FRAME_NAVIGATED and
    NAVIGATION_COMMITTED. Reducing one and not the other would leak."""
    probe, engine = sensor
    probe._on_frame_navigated(_Frame(f"{THIRD_PARTY}/land?t=SECRET"), "page-1")
    assert len(engine.events) == 2
    for _, payload in engine.events:
        assert "SECRET" not in str(payload)
        assert payload["evidence_reduced"] is True


# --- the reduction must not depend on a scope being configured ------------

def test_without_a_scope_nothing_is_reduced(sensor):
    """An engine with no scope is the fixture/test path, not a leak."""
    probe, engine = sensor
    engine.scope = None
    probe._on_frame_attached(_Frame(f"{THIRD_PARTY}/i?token=KEEPME"), "page-1")
    assert _last(engine)["url"] == f"{THIRD_PARTY}/i?token=KEEPME"


# --- non-URL payloads are unaffected --------------------------------------

def test_console_messages_are_not_touched(sensor):
    """Console text carries no URL key, so the reduction must not mark it."""
    probe, engine = sensor

    class _Msg:
        type = "log"
        text = "hello"
        location = None

    probe._on_console(_Msg(), "page-1")
    assert "evidence_reduced" not in _last(engine)
