"""Deterministic local web application used as a ScriptScrap test laboratory.

Standard library only. Two :class:`http.server.ThreadingHTTPServer` instances
run in daemon threads (a "main" origin and a second "cross" origin that differs
only by port), so the fixture can be started from inside a process that is
already running an asyncio Playwright loop without needing an event loop of its
own.

Determinism rules honoured here:

* no ``random``, no ``uuid``, no clock reads that reach a response;
* every identifier is a fixed literal from :mod:`scriptscrap.fixture.content`;
* the ``Date`` header is pinned to a constant and the ``Server`` header is a
  fixed string, so two runs are byte-identical at the wire level too;
* the ONLY value that differs between runs is the OS-assigned port, which
  appears in ``base_url``/``cross_origin_url`` and in the single cross-origin
  stylesheet link injected into the main page.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from scriptscrap.fixture import content

_HOST = "127.0.0.1"

# Pinned so responses are byte-identical across runs. Not a real timestamp.
_FIXED_DATE = "Thu, 01 Jan 2024 00:00:00 GMT"

CT_HTML = "text/html; charset=utf-8"
CT_CSS = "text/css; charset=utf-8"
CT_JS = "application/javascript; charset=utf-8"
CT_JSON = "application/json"
CT_PNG = "image/png"


@dataclass(frozen=True)
class _Response:
    """A fully materialised response, ready to be written to the socket."""

    status: int
    content_type: str
    body: bytes
    extra_headers: tuple[tuple[str, str], ...] = ()


def _json(payload: str, status: int = 200) -> _Response:
    return _Response(status, CT_JSON, payload.encode("utf-8"))


def _html(markup: str, status: int = 200) -> _Response:
    return _Response(status, CT_HTML, markup.encode("utf-8"))


_NOT_FOUND_HTML_RESPONSE = _html(content.NOT_FOUND_HTML, 404)
_NOT_FOUND_JSON_RESPONSE = _json(content.NOT_FOUND_JSON, 404)

# Marker: this route streams and therefore cannot go through the normal
# fixed-Content-Length emitter.
_SSE_SENTINEL = _Response(-1, "text/event-stream", b"")

# A fixed SSE script. Deterministic content; only the small inter-event delay
# is timing-related, and it exists so the stream is genuinely incremental
# rather than one buffered write.
SSE_SCRIPT: tuple[tuple[str | None, str], ...] = (
    (None, "fixture-sse-1"),
    ("progression", '{"pct": 50}'),
    (None, "fixture-sse-2"),
    ("progression", '{"pct": 100}'),
    ("fin", "fixture-sse-complete"),
)


# Three sibling items, so endpoint templating has evidence to work from.
# Each seeds something the analysis layer must handle:
#   reference  -- unique, correlates into /api/apply (must be FOUND)
#   statut     -- a small closed set (enum candidate), and "OK" is a common
#                 value that must NOT be treated as a dependency
#   note       -- present on ONE item only (observed-optional)
_ITEMS: dict[str, dict[str, Any]] = {
    "101": {"id": 101, "reference": "ITEMREF-AA0101", "statut": "OK",
            "libelle": "Item cent un", "actif": 1},
    "102": {"id": 102, "reference": "ITEMREF-BB0102", "statut": "ARCHIVE",
            "libelle": "Item cent deux", "actif": 1,
            "note": "note presente uniquement sur cet item"},
    "103": {"id": 103, "reference": "ITEMREF-CC0103", "statut": "OK",
            "libelle": "Item cent trois", "actif": 1},
}


def _item_payload(item_id: str) -> dict[str, Any]:
    item = _ITEMS.get(item_id)
    if item is None:
        return {"error": "not_found", "code": "E-FIXTURE-404", "id": item_id}
    return dict(item)


def _apply_payload(body: str | None) -> dict[str, Any]:
    reference = None
    if body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                reference = parsed.get("itemReference")
        except ValueError:
            pass
    return {"applied": True, "itemReference": reference, "statut": "OK", "actif": 1}


def _graphql_payload(body: str | None) -> dict[str, Any]:
    """Answer a GraphQL operation by name. Fixed responses, no schema."""
    operation = None
    variables: dict[str, Any] = {}
    if body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                operation = parsed.get("operationName")
                if isinstance(parsed.get("variables"), dict):
                    variables = parsed["variables"]
        except ValueError:
            pass
    if operation == "ValiderItem":
        return {
            "data": {
                "validerItem": {
                    "id": variables.get("id", "ITEM-0001"),
                    "statut": "VALIDE",
                }
            }
        }
    return {"errors": [{"message": "unknown operation", "operation": operation}]}


class _FixtureHandler(BaseHTTPRequestHandler):
    """Shared plumbing: recording, fixed headers, deterministic framing."""

    protocol_version = "HTTP/1.1"
    server_version = "ScriptScrapFixture/1"
    sys_version = ""

    # -- determinism ------------------------------------------------------- #
    def date_time_string(self, timestamp: float | None = None) -> str:
        return _FIXED_DATE

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        """Silence the stdlib access log (it is timestamped, hence unstable)."""

    # -- plumbing ---------------------------------------------------------- #
    @property
    def _fixture(self) -> FixtureServer:
        return self.server.fixture  # type: ignore[attr-defined]

    def _read_body(self) -> str | None:
        raw_length = self.headers.get("Content-Length")
        if not raw_length:
            return None
        try:
            length = int(raw_length)
        except ValueError:
            return None
        if length <= 0:
            return None
        return self.rfile.read(length).decode("utf-8", errors="replace")

    def _emit(self, response: _Response) -> None:
        if response.status == -1:
            self._emit_sse()
            return
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header(content.FIXTURE_VERSION_HEADER, content.FIXTURE_VERSION_VALUE)
        for name, value in response.extra_headers:
            self.send_header(name, value)
        self.end_headers()
        if response.body:
            self.wfile.write(response.body)

    def _emit_sse(self) -> None:
        """Stream a fixed sequence of Server-Sent Events.

        No Content-Length: the response is chunked-in-spirit and stays open
        until the script finishes, which is what makes the messages genuinely
        incremental rather than one buffered write.
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header(content.FIXTURE_VERSION_HEADER, content.FIXTURE_VERSION_VALUE)
        self.end_headers()
        try:
            for index, (name, data) in enumerate(SSE_SCRIPT, start=1):
                chunk = f"id: {index}\n"
                if name:
                    chunk += f"event: {name}\n"
                chunk += f"data: {data}\n\n"
                self.wfile.write(chunk.encode("utf-8"))
                self.wfile.flush()
                time.sleep(0.05)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        finally:
            self.close_connection = True

    def _handle(self, method: str) -> None:
        parts = urlsplit(self.path)
        body = self._read_body()
        self._fixture.record(
            method=method,
            path=parts.path,
            query=parts.query,
            headers=dict(self.headers.items()),
            body=body,
        )
        self._emit(self.route(method, parts.path, parts.query, body))

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        self._handle("POST")

    # -- overridden by the two concrete handlers --------------------------- #
    def route(self, method: str, path: str, query: str, body: str | None) -> _Response:
        raise NotImplementedError


class _MainHandler(_FixtureHandler):
    """Routes for the primary origin."""

    def route(self, method: str, path: str, query: str, body: str | None) -> _Response:
        if method == "POST":
            return self._route_post(path, body)
        return self._route_get(path, query)

    # -- GET --------------------------------------------------------------- #
    def _route_get(self, path: str, query: str) -> _Response:
        static = _STATIC_GET.get(path)
        if static is not None:
            return static

        if path == "/":
            return _html(self._fixture.main_page_html)
        if path == "/api/dossier":
            return _Response(
                200,
                CT_JSON,
                content.DOSSIER_JSON.encode("utf-8"),
                (("Set-Cookie", content.FIXTURE_SESSION_COOKIE),),
            )
        if path == "/api/redirect":
            return _Response(302, CT_JSON, b"", (("Location", "/api/redirected"),))
        if path == "/api/telecharger":
            # An attachment response, so the browser raises a download rather
            # than navigating.
            return _Response(
                200,
                "text/plain; charset=utf-8",
                b"fixture download body\n",
                (("Content-Disposition", 'attachment; filename="fixture-rapport.txt"'),),
            )
        if path == "/api/sse":
            return _SSE_SENTINEL
        if path == "/api/early.js":
            return _Response(200, "application/javascript; charset=utf-8",
                             content.EARLY_JS.encode("utf-8"))
        if path == "/api/big":
            # Deliberately over a small configured limit, so the size-limit
            # path is exercised rather than argued about.
            return _Response(200, "text/plain; charset=utf-8",
                             (b"BIGBODY" * 40000))
        if path in ("/api/twin-a", "/api/twin-b"):
            # Byte-identical bodies from two endpoints: content addressing must
            # store one blob, not two.
            return _json(content.TWIN_JSON)
        if path == "/api/setcookie":
            return _Response(
                200, CT_JSON, b'{"ok": true}',
                (
                    ("Set-Cookie",
                     "fixture_visible=FIXTURE_VISIBLE_0001; Path=/"),
                    # httpOnly: page JavaScript can never read this one, so only
                    # a browser-level sensor can observe it.
                    ("Set-Cookie",
                     "fixture_httponly=FIXTURE_HTTPONLY_TOKEN_0001; Path=/; HttpOnly"),
                ),
            )
        if path == "/api/delcookie":
            return _Response(
                200, CT_JSON, b'{"ok": true}',
                (("Set-Cookie",
                  "fixture_visible=; Path=/; Max-Age=0"),),
            )
        if path.startswith("/api/items/"):
            return _json(json.dumps(_item_payload(path.rsplit("/", 1)[-1])))
        if path.startswith("/api/"):
            return _NOT_FOUND_JSON_RESPONSE
        return _NOT_FOUND_HTML_RESPONSE

    # -- POST -------------------------------------------------------------- #
    def _route_post(self, path: str, body: str | None) -> _Response:
        if path == "/api/valider":
            return _json(json.dumps(_valider_payload(body)))
        if path == "/api/form":
            received = dict(parse_qsl(body or "", keep_blank_values=True))
            return _json(json.dumps({"status": "ok", "received": received}))
        if path == "/api/graphql":
            return _json(json.dumps(_graphql_payload(body)))
        if path == "/api/beacon":
            return _Response(204, CT_JSON, b"")
        if path == "/api/apply":
            return _json(json.dumps(_apply_payload(body)))
        return _NOT_FOUND_JSON_RESPONSE


class _CrossOriginHandler(_FixtureHandler):
    """Routes for the secondary origin: one stylesheet, deliberately no CORS."""

    def route(self, method: str, path: str, query: str, body: str | None) -> _Response:
        if method == "GET" and path == "/vendor.css":
            return _Response(200, CT_CSS, content.VENDOR_CSS.encode("utf-8"))
        return _NOT_FOUND_HTML_RESPONSE


def _valider_payload(body: str | None) -> dict[str, Any]:
    """Echo the ``missionId`` the browser sent back to it (correlation case)."""
    mission_id: Any = None
    if body:
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            mission_id = parsed.get("missionId")
    return {
        "status": "ok",
        "missionId": mission_id,
        "reference": content.VALIDER_REFERENCE,
    }


_STATIC_GET: dict[str, _Response] = {
    "/page2": _html(content.PAGE2_HTML),
    "/frame/outer": _html(content.FRAME_OUTER_HTML),
    "/frame/inner": _html(content.FRAME_INNER_HTML),
    "/assets/app.css": _Response(200, CT_CSS, content.APP_CSS.encode("utf-8")),
    "/assets/app.js": _Response(200, CT_JS, content.APP_JS.encode("utf-8")),
    "/assets/jquery-stub.js": _Response(200, CT_JS, content.JQUERY_STUB_JS.encode("utf-8")),
    "/api/referentiel": _json(content.REFERENTIEL_JSON),
    "/api/redirected": _json(content.REDIRECTED_JSON),
    "/api/error": _json(content.ERROR_JSON, 500),
    "/img/bg.png": _Response(200, CT_PNG, content.BG_PNG),
}


class _FixtureHTTPServer(ThreadingHTTPServer):
    """A :class:`ThreadingHTTPServer` that carries a back-reference."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        handler_cls: type[_FixtureHandler],
        fixture: FixtureServer,
    ) -> None:
        self.fixture = fixture
        super().__init__(address, handler_cls)


@dataclass
class FixtureServer:
    """Start/stop the two-origin deterministic fixture application.

    Usage::

        with FixtureServer() as fx:
            fx.base_url          # "http://127.0.0.1:<port>"  (no trailing slash)
            fx.cross_origin_url  # "http://127.0.0.1:<other>" (different origin)
            fx.requests          # everything the servers actually received
    """

    requests: list[dict[str, Any]] = field(default_factory=list)

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _main: _FixtureHTTPServer | None = field(default=None, repr=False)
    _cross: _FixtureHTTPServer | None = field(default=None, repr=False)
    _threads: list[threading.Thread] = field(default_factory=list, repr=False)
    _main_page_html: str = field(default="", repr=False)
    _ws: Any = field(default=None, repr=False)
    _dead_url: str = field(default="", repr=False)

    # -- lifecycle --------------------------------------------------------- #
    def start(self) -> FixtureServer:
        """Bind both origins on ephemeral ports and serve them in daemon threads."""
        if self._main is not None:
            return self

        from .wsserver import WebSocketEchoServer, reserve_dead_port

        self._main = _FixtureHTTPServer((_HOST, 0), _MainHandler, self)
        self._cross = _FixtureHTTPServer((_HOST, 0), _CrossOriginHandler, self)
        self._ws = WebSocketEchoServer()
        self._ws.start()
        self._dead_url = f"http://{_HOST}:{reserve_dead_port()}/jamais"
        self._main_page_html = content.render_main_page(
            self.cross_origin_url, self._ws.url, self._dead_url
        )

        for server in (self._main, self._cross):
            thread = threading.Thread(
                target=server.serve_forever,
                name=f"scriptscrap-fixture-{server.server_address[1]}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)
        return self

    def stop(self) -> None:
        """Shut both origins down and join their serving threads."""
        for server in (self._main, self._cross):
            if server is not None:
                server.shutdown()
                server.server_close()
        if self._ws is not None:
            self._ws.stop()
            self._ws = None
        for thread in self._threads:
            thread.join(timeout=5.0)
        self._threads.clear()
        self._main = None
        self._cross = None
        self._main_page_html = ""

    @property
    def websocket_url(self) -> str:
        if self._ws is None:
            raise RuntimeError("websocket_url is only available while the fixture is running")
        return self._ws.url

    @property
    def dead_url(self) -> str:
        """An in-scope loopback URL with nothing listening, for failure cases."""
        return self._dead_url

    def __enter__(self) -> FixtureServer:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()

    # -- addresses --------------------------------------------------------- #
    @property
    def base_url(self) -> str:
        return self._url(self._main, "base_url")

    @property
    def cross_origin_url(self) -> str:
        return self._url(self._cross, "cross_origin_url")

    @staticmethod
    def _url(server: _FixtureHTTPServer | None, name: str) -> str:
        if server is None:
            msg = f"FixtureServer is not started; {name} is unavailable"
            raise RuntimeError(msg)
        return f"http://{_HOST}:{server.server_address[1]}"

    @property
    def main_page_html(self) -> str:
        """The rendered main page (cross-origin URL already substituted)."""
        return self._main_page_html

    # -- recording --------------------------------------------------------- #
    def record(
        self,
        *,
        method: str,
        path: str,
        query: str,
        headers: dict[str, str],
        body: str | None,
    ) -> None:
        """Thread-safely append one received request to :attr:`requests`."""
        entry: dict[str, Any] = {
            "method": method,
            "path": path,
            "query": query,
            "headers": headers,
            "body": body,
        }
        with self._lock:
            self.requests.append(entry)

    def clear_requests(self) -> None:
        """Drop everything recorded so far."""
        with self._lock:
            self.requests.clear()
