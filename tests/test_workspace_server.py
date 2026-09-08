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
import socket
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


SECURITY_HEADERS = ("Content-Security-Policy", "X-Content-Type-Options",
                    "Referrer-Policy", "Cache-Control")


def test_the_landing_url_redirects_so_the_token_leaves_the_address_bar(workspace):
    """The old test asserted only that a Set-Cookie header existed. The
    response was a 200, so the browser kept `?t=<token>` in the address bar and
    in history for the life of the session -- exactly what the code comment
    said it prevented.

    A token that stays in the address bar is a token that ends up in a
    screenshot of the very window that displays an unredacted capture.
    """
    conn = http.client.HTTPConnection(*workspace.address, timeout=5)
    try:
        conn.request("GET", f"/?t={workspace.token}")
        response = conn.getresponse()
        response.read()
        assert response.status == 303
        assert response.getheader("Location") == "/"
        cookie = response.getheader("Set-Cookie") or ""
        assert f"{workspace.token}" in cookie
        assert "HttpOnly" in cookie, "no script reads this cookie"
        assert "SameSite=Strict" in cookie
    finally:
        conn.close()


def test_the_redirect_target_is_the_application(workspace):
    status, body = request(workspace, "/", token=workspace.token)
    assert status == 200
    assert b"<title>" in body


@pytest.mark.parametrize("path", ["/", "/app.js", "/app.css", "/lib/api.js"])
def test_every_asset_response_carries_the_security_headers(workspace, path):
    conn = http.client.HTTPConnection(*workspace.address, timeout=5)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        response.read()
        for header in SECURITY_HEADERS:
            assert response.getheader(header), f"{path} has no {header}"
    finally:
        conn.close()


def test_the_landing_redirect_carries_the_security_headers(workspace):
    """The one page that executes the application's JS was the one page served
    without a Content-Security-Policy."""
    conn = http.client.HTTPConnection(*workspace.address, timeout=5)
    try:
        conn.request("GET", f"/?t={workspace.token}")
        response = conn.getresponse()
        response.read()
        for header in SECURITY_HEADERS:
            assert response.getheader(header), f"the landing response has no {header}"
    finally:
        conn.close()


def test_api_responses_are_not_cached(workspace):
    conn = http.client.HTTPConnection(*workspace.address, timeout=5)
    try:
        conn.request("GET", f"/api/sessions?t={workspace.token}")
        response = conn.getresponse()
        response.read()
        assert "no-store" in (response.getheader("Cache-Control") or "")
    finally:
        conn.close()


def test_head_on_the_landing_url_also_redirects(workspace):
    conn = http.client.HTTPConnection(*workspace.address, timeout=5)
    try:
        conn.request("HEAD", f"/?t={workspace.token}")
        response = conn.getresponse()
        assert response.status == 303
        assert response.read() == b""
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


# --- a malformed credential is an answer, not a crash (F10, F9) -----------

def _raw_request(workspace, path: str, headers: dict[str, str]) -> tuple[int, bytes]:
    """A request written to the socket verbatim.

    `http.client` encodes header values as latin-1 and raises before sending
    anything, so a test built on it proves only that the CLIENT rejects a
    hostile value. What must be established here is that the SERVER survives
    one, so the bytes go on the wire directly.
    """
    request = f"GET {path} HTTP/1.1\r\nHost: {workspace.address[0]}\r\n"
    for name, value in headers.items():
        request += f"{name}: {value}\r\n"
    request += "Connection: close\r\n\r\n"

    with socket.create_connection(workspace.address, timeout=5) as sock:
        sock.sendall(request.encode("utf-8"))
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    raw = b"".join(chunks)
    if not raw:
        pytest.fail("the server closed the connection without a response")
    head, _, body = raw.partition(b"\r\n\r\n")
    return int(head.split()[1]), body


@pytest.mark.parametrize("value", [
    # Non-ASCII: `compare_digest` raises TypeError comparing str like these.
    pytest.param("\u00e9\u00e9\u00e9", id="latin1-non-ascii"),
    pytest.param("\u4f60\u597d", id="utf8-non-ascii"),
    pytest.param("x" * 100_000, id="oversized"),
    pytest.param("", id="empty"),
    pytest.param("tok=en", id="embedded-separator"),
])
def test_a_malformed_token_is_rejected_without_a_traceback(workspace, value, capfd):
    """secrets.compare_digest rejects non-ASCII str with TypeError, raised
    from _authenticated -- which sits OUTSIDE the try/except that wraps the
    API handlers. The connection was dropped with no response and socketserver
    printed a stack trace with absolute source paths onto a console the design
    says is routinely screen-shared."""
    status, _ = _raw_request(workspace, "/api/sessions",
                             {"Cookie": f"scriptscrap_token={value}"})
    # 431 for the oversized header: BaseHTTPRequestHandler enforces its own
    # limit and answers before the handler is reached. That is an answer, which
    # is what this test is about -- not a dropped connection and a stack trace.
    assert status in (401, 431), status
    assert "Traceback" not in capfd.readouterr().err


def test_the_server_survives_a_malformed_token(workspace):
    _raw_request(workspace, "/api/sessions",
                 {"Cookie": "scriptscrap_token=\u00e9"})
    status, _ = request(workspace, "/api/sessions", token=workspace.token)
    assert status == 200


def test_an_unexpected_handler_error_is_a_500_not_a_dropped_connection(workspace,
                                                                      monkeypatch):
    def explode(_workspace, _query):
        raise RuntimeError("boom")

    monkeypatch.setitem(workspace.routes, "sessions", explode)
    status, body = request(workspace, "/api/sessions", token=workspace.token)
    assert status == 500
    assert b"RuntimeError" in body


def test_a_stale_cookie_does_not_beat_a_correct_token(workspace):
    """Browser cookies are not scoped by port, so 127.0.0.1:A and
    127.0.0.1:B share a jar. The cookie a previous `scriptscrap workspace`
    launch set was sent to the next one, and because the query token was
    consulted only when NO cookie was present, every panel 401'd on the second
    launch until the user cleared cookies by hand."""
    conn = http.client.HTTPConnection(*workspace.address, timeout=5)
    try:
        conn.request("GET", f"/api/sessions?t={workspace.token}",
                     headers={"Cookie": "scriptscrap_token=FROM-A-PREVIOUS-LAUNCH"})
        response = conn.getresponse()
        body = response.read()
        assert response.status == 200, body
        assert response.getheader("Set-Cookie"), \
            "a correct query token must refresh the stale cookie"
        assert workspace.token in response.getheader("Set-Cookie")
    finally:
        conn.close()


def test_an_empty_cookie_does_not_beat_a_correct_token(workspace):
    conn = http.client.HTTPConnection(*workspace.address, timeout=5)
    try:
        conn.request("GET", f"/api/sessions?t={workspace.token}",
                     headers={"Cookie": "scriptscrap_token="})
        assert conn.getresponse().status == 200
    finally:
        conn.close()


def test_two_consecutive_launches_are_both_usable(session_root):
    """The failure a real operator hits: launch, close, launch again."""
    first = Workspace(WorkspaceConfig(root=session_root))
    thread_a = threading.Thread(target=first.serve_forever, daemon=True)
    thread_a.start()
    second = Workspace(WorkspaceConfig(root=session_root))
    thread_b = threading.Thread(target=second.serve_forever, daemon=True)
    thread_b.start()
    try:
        # A browser holding the FIRST launch's cookie opens the SECOND's URL.
        conn = http.client.HTTPConnection(*second.address, timeout=5)
        try:
            conn.request("GET", f"/api/sessions?t={second.token}",
                         headers={"Cookie": f"scriptscrap_token={first.token}"})
            assert conn.getresponse().status == 200
        finally:
            conn.close()
    finally:
        first.shutdown()
        thread_a.join(timeout=5)
        second.shutdown()
        thread_b.join(timeout=5)


def test_a_wrong_token_with_no_cookie_is_still_rejected(workspace):
    status, _ = request(workspace, "/api/sessions?t=nope")
    assert status == 401


# --- lifecycle: serve() serves, shutdown() cannot deadlock (F7) -----------

def test_serve_returns_a_running_server(session_root):
    """`serve()`'s docstring says 'Start a workspace and hand back the running
    server'. It never called serve_forever, so connections sat in the accept
    backlog and the browser it opened hung on a blank page."""
    from scriptscrap.workspace import serve

    workspace = serve(session_root, port=0, open_browser=False)
    try:
        conn = http.client.HTTPConnection(*workspace.address, timeout=3)
        try:
            conn.request("GET", f"/api/sessions?t={workspace.token}")
            assert conn.getresponse().status == 200
        finally:
            conn.close()
    finally:
        workspace.shutdown()


def test_shutdown_returns_on_a_server_that_never_served(session_root):
    """BaseServer.shutdown() waits on an event only serve_forever() sets, so
    shutdown() on the object serve() returned blocked forever."""
    workspace = Workspace(WorkspaceConfig(root=session_root))
    done = threading.Event()
    threading.Thread(target=lambda: (workspace.shutdown(), done.set()),
                     daemon=True).start()
    assert done.wait(5), "shutdown() blocked on a server that never served"


def test_shutdown_is_idempotent(session_root):
    from scriptscrap.workspace import serve

    workspace = serve(session_root, port=0, open_browser=False)
    workspace.shutdown()
    workspace.shutdown()          # must not raise


def test_start_is_idempotent(session_root):
    workspace = Workspace(WorkspaceConfig(root=session_root))
    try:
        workspace.start()
        workspace.start()
        conn = http.client.HTTPConnection(*workspace.address, timeout=3)
        try:
            conn.request("GET", f"/api/sessions?t={workspace.token}")
            assert conn.getresponse().status == 200
        finally:
            conn.close()
    finally:
        workspace.shutdown()


def test_the_port_is_released_after_shutdown(session_root):
    from scriptscrap.workspace import serve

    workspace = serve(session_root, port=0, open_browser=False)
    host, port = workspace.address
    workspace.shutdown()
    probe = socket.socket()
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))          # must not raise
    finally:
        probe.close()
