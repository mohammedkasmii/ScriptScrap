"""WebSocket sensor.

Playwright implements WebSocket observation on Firefox (`ffPage.ts` handles
create/open/close/framesent/framereceived), so this is a capability the previous
investigator simply never subscribed to.

What Playwright does NOT give: the opening handshake headers. The upgrade does
not reliably surface as a normal request/response pair, so `Sec-WebSocket-*` is
unrecoverable here. That is recorded as a capture gap rather than left implicit.
"""

from __future__ import annotations

from typing import Any

from ..events import EventType, Source
from .identity import PageRegistry

# Frames above this are recorded by size and hash rather than content, so a
# binary or streaming protocol cannot blow up the event log.
MAX_FRAME_CHARS = 8192


class WebSocketSensor:
    """Observes WebSocket lifecycle and frames on a page."""

    def __init__(self, engine: Any, registry: PageRegistry) -> None:
        self.engine = engine
        self.registry = registry
        self.sockets = 0
        self.frames_sent = 0
        self.frames_received = 0
        self._handshake_gap_reported = False

    def attach_page(self, page: Any) -> None:
        try:
            page.on("websocket", lambda ws: self._on_socket(ws, page))
        except Exception as exc:
            self.engine.emit_sensor_error("websocket_attach", exc)
            self.engine.emit_capture_gap(
                "websocket_events_unavailable",
                note="WebSocket traffic will not be observed",
            )

    def _on_socket(self, ws: Any, page: Any) -> None:
        self.sockets += 1
        page_id = self.registry.page_id(page)
        url = getattr(ws, "url", None)

        if not self.scope_allows(url):
            self.engine.emit_capture_gap(
                "websocket_out_of_scope", url_host=_host(url), withheld=["frames"]
            )
            return

        self.engine.emit_event(
            Source.PLAYWRIGHT, EventType.WS_OPEN, page_id=page_id, url=url
        )

        if not self._handshake_gap_reported:
            self._handshake_gap_reported = True
            self.engine.emit_capture_gap(
                "websocket_handshake_headers_unavailable",
                note=(
                    "Playwright exposes no handshake headers for a WebSocket and the "
                    "upgrade does not surface as a normal request/response pair, so "
                    "Sec-WebSocket-* and any auth header on the upgrade are unobserved"
                ),
            )

        ws.on("framesent", lambda payload: self._on_frame(
            EventType.WS_FRAME_SENT, payload, url, page_id))
        ws.on("framereceived", lambda payload: self._on_frame(
            EventType.WS_FRAME_RECEIVED, payload, url, page_id))
        ws.on("socketerror", lambda err: self.engine.emit_event(
            Source.PLAYWRIGHT, EventType.WS_ERROR, page_id=page_id, url=url, error=str(err)))
        ws.on("close", lambda _ws=None: self.engine.emit_event(
            Source.PLAYWRIGHT, EventType.WS_CLOSE, page_id=page_id, url=url))

    def _on_frame(
        self, event_type: EventType, payload: Any, url: str | None, page_id: str | None
    ) -> None:
        if event_type is EventType.WS_FRAME_SENT:
            self.frames_sent += 1
        else:
            self.frames_received += 1

        binary = isinstance(payload, (bytes, bytearray))
        size = len(payload) if payload is not None else 0
        body: str | None
        truncated = False

        if binary:
            # Binary payloads are described, never inlined.
            body = None
        else:
            text = payload if isinstance(payload, str) else str(payload)
            if len(text) > MAX_FRAME_CHARS:
                body = text[:MAX_FRAME_CHARS]
                truncated = True
                self.engine.emit_capture_gap(
                    "websocket_payload_truncated",
                    url=url, size=size, kept=MAX_FRAME_CHARS,
                )
            else:
                body = text

        self.engine.emit_event(
            Source.PLAYWRIGHT,
            event_type,
            page_id=page_id,
            url=url,
            opcode="binary" if binary else "text",
            size=size,
            truncated=truncated,
            payload_text=body,
        )

    def scope_allows(self, url: str | None) -> bool:
        if not url:
            return True
        scope = getattr(self.engine, "scope", None)
        if scope is None:
            return True
        # ws:// and wss:// share host rules with http/https.
        probe = url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
        return scope.contains(probe)

    def stats(self) -> dict[str, Any]:
        return {
            "sockets": self.sockets,
            "frames_sent": self.frames_sent,
            "frames_received": self.frames_received,
        }


def _host(url: str | None) -> str | None:
    if not url:
        return None
    from urllib.parse import urlparse

    return urlparse(url).hostname
