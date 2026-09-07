"""The workspace server's security properties.

These come first, and they are the requirement rather than a hardening pass.
The directory this serves is an **unredacted capture of an authenticated
session** -- live `Authorization` headers, full request and response bodies,
screenshots of authenticated pages. A read-only viewer for that is a viewer
that has to be correct about four things:

1. it listens on loopback and nowhere else
2. `/api/` needs the per-launch token, so another local process cannot read
   the capture just by knowing the port
3. no method mutates anything, because there is nothing to mutate
4. a path cannot escape the asset directory

`test_analysis_boundary.py` separately pins that none of this imports a
browser.
"""

from __future__ import annotations

import http.client
import shutil
import threading
from pathlib import Path

import pytest

from scriptscrap.analysis import DerivedStore, analyze_log
from scriptscrap.workspace.server import Workspace, WorkspaceConfig

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"


@pytest.fixture(scope="module")
def session_root(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("workspace") / "session"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")
    with DerivedStore(root / "session.sqlite") as store:
        store.write(analyze_log(root / "events.jsonl"))
    return root


@pytest.fixture(scope="module")
def workspace(session_root: Path):
    ws = Workspace(WorkspaceConfig(root=session_root))
    thread = threading.Thread(target=ws.serve_forever, daemon=True)
    thread.start()
    yield ws
    ws.shutdown()
    thread.join(timeout=5)


def request(workspace, path: str, *, method: str = "GET",
            token: str | None = None) -> tuple[int, bytes]:
    """One request against the live server, without a client library."""
    conn = http.client.HTTPConnection(*workspace.address, timeout=5)
    try:
        headers = {"Cookie": f"scriptscrap_token={token}"} if token else {}
        conn.request(method, path, headers=headers)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


# --- 1. loopback only -----------------------------------------------------

def test_binds_loopback_only(workspace):
    """Never 0.0.0.0. The capture must not be reachable from the network."""
    assert workspace.address[0] == "127.0.0.1"


def test_the_configured_host_cannot_be_widened(session_root):
    """Asking for a routable bind is refused rather than quietly honoured."""
    with pytest.raises(ValueError, match="loopback"):
        Workspace(WorkspaceConfig(root=session_root, host="0.0.0.0"))  # noqa: S104


# --- 2. the token ---------------------------------------------------------

def test_api_without_a_token_is_rejected(workspace):
    status, _ = request(workspace, "/api/sessions")
    assert status == 401


def test_api_with_a_wrong_token_is_rejected(workspace):
    status, _ = request(workspace, "/api/sessions", token="not-the-token")
    assert status == 401


def test_api_with_the_token_is_allowed(workspace):
    status, body = request(workspace, "/api/sessions", token=workspace.token)
    assert status == 200
    assert body


def test_the_token_is_not_guessable(workspace):
    assert len(workspace.token) >= 32


def test_the_landing_url_carries_the_token(workspace):
    assert f"t={workspace.token}" in workspace.url


# --- 3. read-only ---------------------------------------------------------

@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_write_methods_are_rejected(workspace, method):
    """Rejected even with a valid token: there is nothing to write."""
    status, _ = request(workspace, "/api/sessions", method=method,
                        token=workspace.token)
    assert status == 405


# --- 4. path containment --------------------------------------------------

@pytest.mark.parametrize("path", [
    "/../../../../etc/passwd",
    "/..%2f..%2f..%2fetc%2fpasswd",
    "/%2e%2e/%2e%2e/secret",
    "/....//....//secret",
    "/assets/../../../session.sqlite",
])
def test_traversal_cannot_escape_the_asset_directory(workspace, path):
    status, body = request(workspace, path)
    assert status in (400, 403, 404), f"{path} returned {status}"
    assert b"root:" not in body


def test_the_session_log_is_not_served_as_a_static_file(workspace):
    """The raw capture is reachable only through the token-gated API."""
    for path in ("/events.jsonl", "/session.sqlite", "/session_manifest.json"):
        status, _ = request(workspace, path)
        assert status in (400, 403, 404), f"{path} was served"


# --- the shell itself -----------------------------------------------------

def test_the_index_page_is_served(workspace):
    status, body = request(workspace, "/")
    assert status == 200
    assert b"<title>" in body


def test_an_unknown_api_route_is_a_404_not_a_500(workspace):
    status, _ = request(workspace, "/api/nonexistent", token=workspace.token)
    assert status == 404


def test_the_index_sets_the_token_cookie_so_it_leaves_the_address_bar(workspace):
    """The landing URL carries the token; after that it lives in a cookie.

    A token that stays in the address bar is a token that ends up in a
    screenshot of the very window that displays an unredacted capture.
    """
    conn = http.client.HTTPConnection(*workspace.address, timeout=5)
    try:
        conn.request("GET", f"/?t={workspace.token}")
        response = conn.getresponse()
        response.read()
        assert response.status == 200
        cookie = response.getheader("Set-Cookie") or ""
        assert f"scriptscrap_token={workspace.token}" in cookie
        assert "SameSite=Strict" in cookie
    finally:
        conn.close()


# --- end to end -----------------------------------------------------------

def test_a_conclusion_walks_back_to_its_raw_evidence_over_http(workspace):
    """The workspace's whole reason to exist, exercised through the socket:
    endpoint -> evidence id -> the raw event that supports it."""
    import json as _json

    status, body = request(workspace, "/api/endpoints", token=workspace.token)
    assert status == 200
    endpoints = _json.loads(body)["endpoints"]
    assert endpoints

    endpoint = endpoints[0]
    event_id = endpoint["evidence_ids"][0]

    status, body = request(
        workspace, f"/api/event?event_id={event_id}", token=workspace.token)
    assert status == 200
    event = _json.loads(body)["event"]
    assert event["event_id"] == event_id
    assert event["payload"], "evidence arrived without a payload"


def test_the_dynamic_event_route_works_too(workspace):
    import json as _json

    _, body = request(workspace, "/api/endpoints", token=workspace.token)
    event_id = _json.loads(body)["endpoints"][0]["evidence_ids"][0]

    status, body = request(workspace, f"/api/event/{event_id}", token=workspace.token)
    assert status == 200
    assert _json.loads(body)["event"]["event_id"] == event_id
