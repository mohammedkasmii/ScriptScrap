"""The shared URL scope reduction.

`_strip_query` and `_redact_stack_frame` were private to the runtime probe.
Every sensor that emits a URL needs them -- the lifecycle sensor emitted frame
and page URLs verbatim, so an out-of-scope iframe or an SSO redirect landed in
the log with its query string intact.

These tests pin the helpers themselves. The policy they serve is pinned per
sensor in `test_runtime_scope.py` and `test_lifecycle_scope.py`.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from scriptscrap.sensors.scope import (
    REDUCED_KEEP_KEYS,
    URL_PAYLOAD_KEYS,
    redact_stack_frame,
    strip_query,
)


class _Scope:
    """The same semantics as InvestigationScope, without importing the driver."""

    def __init__(self, *roots: str) -> None:
        self.roots = set(roots)

    def contains(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        return any(host == r or host.endswith("." + r) for r in self.roots)


# --- strip_query ----------------------------------------------------------

def test_strip_query_keeps_origin_and_path():
    assert strip_query("https://h/p?a=secret#f") == "https://h/p"


def test_strip_query_keeps_a_url_that_has_no_query():
    assert strip_query("https://h/p") == "https://h/p"


def test_strip_query_handles_a_bare_path():
    """No scheme and no netloc: the split-based rebuild would lose the path."""
    assert strip_query("/p?a=1#f") == "/p"


def test_strip_query_keeps_the_port():
    assert strip_query("https://h:8443/p?a=1") == "https://h:8443/p"


def test_strip_query_drops_a_fragment_without_a_query():
    assert strip_query("https://h/p#tok") == "https://h/p"


# --- redact_stack_frame ---------------------------------------------------

def test_redact_stack_frame_strips_out_of_scope_query_and_keeps_position():
    scope = _Scope("app.test")
    frame = "handler@https://cdn.other.test/a.js?v=3:12:5"
    assert redact_stack_frame(scope, frame) == "handler@https://cdn.other.test/a.js:12:5"


def test_redact_stack_frame_leaves_an_in_scope_url_alone():
    scope = _Scope("app.test")
    frame = "handler@https://app.test/a.js?v=3:12:5"
    assert redact_stack_frame(scope, frame) == frame


def test_redact_stack_frame_passes_non_strings_through():
    scope = _Scope("app.test")
    assert redact_stack_frame(scope, None) is None
    assert redact_stack_frame(scope, 42) == 42


# --- the allowlists -------------------------------------------------------

def test_url_payload_keys_are_the_keys_that_hold_urls():
    assert set(URL_PAYLOAD_KEYS) == {"url", "action", "from", "frame_url"}


def test_reduced_keep_keys_is_an_allowlist_not_a_denylist():
    """A denylist silently admits every payload key added later."""
    assert "body" not in REDUCED_KEEP_KEYS
    assert "value" not in REDUCED_KEEP_KEYS
    assert "headers" not in REDUCED_KEEP_KEYS
    assert "method" in REDUCED_KEEP_KEYS
