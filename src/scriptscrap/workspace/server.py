"""The workspace HTTP server.

Stdlib only. A presentation layer does not get to add a runtime dependency to a
project whose pinned versions are part of its behavioural baseline, and the
things a framework would provide here -- routing over a dozen read-only routes,
JSON encoding, static files -- are a hundred lines.

What this serves is the reason it is shaped the way it is. A session directory
is an unredacted capture of an authenticated session, so:

* it binds loopback, and refuses to bind anything else
* every `/api/` route requires a token minted for this launch, because "only
  local processes can reach it" is not the same as "only you can reach it"
* there are no write methods, so there is no write path to get wrong
* static files resolve inside one directory and are checked to have stayed
  there; nothing under the session directory is reachable as a static file

The server holds no session state beyond the handles it opened at startup.
"""

from __future__ import annotations

import http.server
import json
import mimetypes
import secrets
import socketserver
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from http import HTTPStatus
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from . import api
from .session import SessionError, SessionHandle, discover_sessions

ASSETS = Path(__file__).parent / "assets"
# The cookie the token is carried in. A name, not a secret.
COOKIE_NAME = "scriptscrap_token"

# Loopback only. Not a default to be overridden -- a routable bind would put an
# unredacted authenticated capture on the network.
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


@dataclass
class WorkspaceConfig:
    root: Path
    host: str = "127.0.0.1"
    port: int = 0                       # 0 -> an ephemeral port
    token: str = field(default="")      # generated when empty


class _Handler(http.server.BaseHTTPRequestHandler):
    """Read-only request handling. `workspace` is injected by the server."""

    workspace: Workspace
    protocol_version = "HTTP/1.1"
    # Set by `_authenticated` when the match came from the URL rather than the
    # cookie. A class attribute so `_send` can read it on a request that never
    # reached authentication at all.
    _refresh_cookie = False

    # -- plumbing ----------------------------------------------------------
    def log_message(self, fmt: str, *args: object) -> None:
        """Silence per-request logging.

        Request paths carry session names and event ids, and this console is
        routinely screen-shared while the operator explains what they found.
        """

    def _security_headers(self) -> None:
        """The headers every response carries, whatever wrote it.

        One method rather than a block copied into each response path. The
        landing page wrote its own and was therefore the single page served
        with no Content-Security-Policy -- the one page that executes the
        application's JavaScript.
        """
        # The workspace renders captured application content. It must never be
        # able to load anything else, or reach back out to a captured host.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        # A token-bearing URL and an unredacted capture's JSON both belong in
        # exactly one place: this process's memory.
        self.send_header("Cache-Control", "no-store, max-age=0")

    def _send(self, status: HTTPStatus | int, body: bytes, content_type: str) -> None:
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        if self._refresh_cookie:
            self.send_header("Set-Cookie", self._cookie_header())
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _redirect(self, location: str, *, set_cookie: str | None = None) -> None:
        """See Other, so the browser re-requests without the query string.

        303 rather than 302: the token must not survive in the address bar or
        in history, and a 303 is the status that means 'the answer is at this
        other URL, go and GET it'.
        """
        self.send_response(int(HTTPStatus.SEE_OTHER))
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self._security_headers()
        self.end_headers()

    def _json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status: HTTPStatus, message: str) -> None:
        self._json({"error": message}, status=status)

    # -- method policy -----------------------------------------------------
    def _reject_write(self) -> None:
        """No route mutates anything, so no method that implies it is served."""
        self.send_response(int(HTTPStatus.METHOD_NOT_ALLOWED))
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = do_PUT = do_DELETE = do_PATCH = _reject_write

    def do_HEAD(self) -> None:
        self.do_GET()

    # -- authentication ----------------------------------------------------
    def _authenticated(self, query: dict[str, list[str]]) -> bool:
        """The launch token, from the cookie or the landing URL.

        Every candidate is checked, not just the first one found: a cookie from
        a PREVIOUS launch is sent to this one -- browser cookies are not scoped
        by port -- and consulting only the cookie meant a correct `?t=` in the
        URL was ignored and every panel 401'd.

        Compared as bytes with `compare_digest`, so a wrong token cannot be
        found one character at a time and a non-ASCII one is a mismatch rather
        than a TypeError.
        """
        expected = self.workspace.token.encode("utf-8")
        cookies = self._cookie_values()
        for candidate in [*cookies, *(v for v in query.get("t", []) if v)]:
            try:
                supplied = candidate.encode("utf-8")
            except (UnicodeError, AttributeError):
                continue
            if secrets.compare_digest(supplied, expected):
                # A match that did NOT come from the cookie means the cookie is
                # stale or absent. Refresh it, or the next request pays the
                # same cost.
                self._refresh_cookie = candidate not in cookies
                return True
        return False

    def _cookie_values(self) -> list[str]:
        """Every `scriptscrap_token` this request offered, in header order."""
        found: list[str] = []
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE_NAME and value:
                found.append(value)
        return found

    def _cookie_header(self) -> str:
        """The launch cookie. HttpOnly because no script reads it."""
        return (f"{COOKIE_NAME}={self.workspace.token}; Path=/; "
                "SameSite=Strict; HttpOnly")

    # -- routing -----------------------------------------------------------
    def do_GET(self) -> None:
        try:
            self._route()
        except Exception as exc:                       # noqa: BLE001
            # Nothing may reach socketserver: it prints a stack trace with
            # absolute source paths onto a console this design deliberately
            # keeps quiet, and drops the connection with no response.
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR,
                        f"{type(exc).__name__}: {exc}")

    def _route(self) -> None:
        split = urlsplit(self.path)
        path = unquote(split.path)
        query = parse_qs(split.query)

        if path.startswith("/api/"):
            if not self._authenticated(query):
                self._error(HTTPStatus.UNAUTHORIZED,
                            "missing or invalid token; open the URL the server printed")
                return
            self._serve_api(path[len("/api/"):], query)
            return

        self._serve_asset(path, query)

    def _serve_api(self, route: str, query: dict[str, list[str]]) -> None:
        try:
            handler = self.workspace.routes.get(route.rstrip("/"))
            if handler is None:
                handler, captured = self.workspace.match_dynamic(route)
                if handler is None:
                    self._error(HTTPStatus.NOT_FOUND, f"no such route: /api/{route}")
                    return
                query = {**query, **{k: [v] for k, v in captured.items()}}
            self._json(handler(self.workspace, query))
        except api.NotFound as exc:
            self._error(HTTPStatus.NOT_FOUND, str(exc))
        except api.BadRequest as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except Exception as exc:                       # noqa: BLE001
            # Surfaced, not swallowed: a stale evidence index or a missing log
            # is exactly what the reader needs told, and a blank panel would
            # look like an application that simply had nothing there.
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"{type(exc).__name__}: {exc}")

    def _serve_asset(self, path: str, query: dict[str, list[str]]) -> None:
        """Static files, resolved inside the asset directory and checked.

        Resolution happens before the containment check so that `..`, its
        encoded forms, absolute paths and symlinks are all judged by where the
        path actually lands rather than by what it looks like.
        """
        relative = path.lstrip("/") or "index.html"
        candidate = (ASSETS / relative).resolve()
        try:
            candidate.relative_to(ASSETS.resolve())
        except ValueError:
            self._error(HTTPStatus.FORBIDDEN, "path escapes the asset directory")
            return
        if not candidate.is_file():
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return

        body = candidate.read_bytes()
        if candidate.name == "index.html" and query.get("t"):
            # Move the token out of the URL and into a cookie, by REDIRECTING.
            # Serving 200 here left `?t=<token>` in the address bar and in
            # history for the life of the session, which is what this branch
            # exists to prevent.
            self._redirect("/", set_cookie=self._cookie_header())
            return

        guessed, _ = mimetypes.guess_type(candidate.name)
        self._send(HTTPStatus.OK, body, guessed or "application/octet-stream")


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Workspace:
    """A running, read-only view of one or more investigation sessions."""

    def __init__(self, config: WorkspaceConfig) -> None:
        if config.host not in LOOPBACK:
            raise ValueError(
                f"refusing to bind {config.host}: the workspace serves an unredacted "
                "capture and listens on loopback only")

        self.config = config
        self.token = config.token or secrets.token_urlsafe(32)
        self.sessions: list[SessionHandle] = discover_sessions(config.root)
        self.routes: dict[str, Callable] = dict(api.ROUTES)
        self._dynamic = api.DYNAMIC_ROUTES
        self._lock = threading.Lock()

        handler = type("_BoundHandler", (_Handler,), {"workspace": self})
        self.server = _Server((config.host, config.port), handler)

    # -- session access ----------------------------------------------------
    def session(self, name: str | None) -> SessionHandle:
        """One session by name; the only one when a name is not given."""
        if name is None:
            return self.sessions[0]
        for handle in self.sessions:
            if handle.name == name:
                return handle
        raise api.NotFound(f"no session named {name!r}")

    def match_dynamic(self, route: str) -> tuple[Callable | None, dict[str, str]]:
        """Match a route with a path parameter, e.g. `events/<event_id>`."""
        parts = route.rstrip("/").split("/")
        for pattern, handler in self._dynamic:
            expected = pattern.split("/")
            if len(expected) != len(parts):
                continue
            captured: dict[str, str] = {}
            for want, got in zip(expected, parts, strict=True):
                if want.startswith("<") and want.endswith(">"):
                    captured[want[1:-1]] = got
                elif want != got:
                    break
            else:
                return handler, captured
        return None, {}

    # -- lifecycle ---------------------------------------------------------
    @property
    def address(self) -> tuple[str, int]:
        host, port = self.server.server_address[:2]
        return str(host), int(port)

    @property
    def url(self) -> str:
        host, port = self.address
        return f"http://{host}:{port}/?t={self.token}"

    def serve_forever(self) -> None:
        self.server.serve_forever()

    def shutdown(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def serve(root: Path, *, port: int = 0, open_browser: bool = True) -> Workspace:
    """Start a workspace and hand back the running server."""
    workspace = Workspace(WorkspaceConfig(root=root, port=port))
    if open_browser:
        import webbrowser
        webbrowser.open(workspace.url)
    return workspace


__all__ = ["SessionError", "Workspace", "WorkspaceConfig", "serve"]
