"""Loopback WebSocket server that receives evidence from the extension.

A background page cannot call Python. It can open a WebSocket to loopback,
which is exempt from mixed-content blocking and unaffected by any page's CSP,
so that is the channel. The alternative, native messaging, would require writing
a host manifest and a Windows registry key before the browser starts -- invasive
for a tool whose whole point is leaving no trace.

Runs on its own thread so extension delivery is never blocked by the asyncio
loop driving Playwright. Batches are handed to a callback which is expected to
return quickly; the callback does the event emission.
"""

from __future__ import annotations

import contextlib
import json
import socket
import threading
from collections.abc import Callable
from typing import Any

from ..wsframe import OP_CLOSE, OP_PING, OP_PONG, OP_TEXT, encode, handshake_response, read_message

BatchHandler = Callable[[list[dict[str, Any]]], None]


class ExtensionTransport:
    """Accepts one extension connection and streams its batches to a handler."""

    def __init__(self, handler: BatchHandler, *, host: str = "127.0.0.1") -> None:
        self.handler = handler
        self.host = host
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, 0))
        self._sock.listen(4)
        self.port: int = self._sock.getsockname()[1]

        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._serve, name="scriptscrap-extension-transport", daemon=True)
        self._connections: list[socket.socket] = []
        self._lock = threading.Lock()

        self.batches_received = 0
        self.events_received = 0
        self.connections = 0
        self.decode_errors = 0
        self.last_error: str | None = None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> ExtensionTransport:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            for conn in self._connections:
                with contextlib.suppress(OSError):
                    conn.shutdown(socket.SHUT_RDWR)
                with contextlib.suppress(OSError):
                    conn.close()
            self._connections.clear()
        with contextlib.suppress(OSError):
            self._sock.close()
        self._thread.join(timeout=3.0)

    def __enter__(self) -> ExtensionTransport:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    @property
    def connected(self) -> bool:
        with self._lock:
            return bool(self._connections)

    def wait_for_connection(self, timeout: float = 10.0) -> bool:
        """Block until the extension connects. Returns False on timeout."""
        deadline = threading.Event()
        step = 0.05
        waited = 0.0
        while waited < timeout:
            if self.connected:
                return True
            deadline.wait(step)
            waited += step
        return False

    # -- serving -----------------------------------------------------------
    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self.connections += 1
            with self._lock:
                self._connections.append(conn)
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(None)
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                request += chunk

            response = handshake_response(request)
            if response is None:
                return
            conn.sendall(response)

            while not self._stop.is_set():
                message = read_message(conn)
                if message is None:
                    return
                opcode, payload = message
                if opcode == OP_CLOSE:
                    with contextlib.suppress(OSError):
                        conn.sendall(encode(b"", OP_CLOSE))
                    return
                if opcode == OP_PING:
                    conn.sendall(encode(payload, OP_PONG))
                    continue
                if opcode != OP_TEXT:
                    continue
                self._ingest(payload)
        except (OSError, ValueError) as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
        finally:
            with self._lock:
                if conn in self._connections:
                    self._connections.remove(conn)
            with contextlib.suppress(OSError):
                conn.close()

    def _ingest(self, payload: bytes) -> None:
        try:
            batch = json.loads(payload.decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError) as exc:
            self.decode_errors += 1
            self.last_error = f"batch decode: {exc}"
            return
        if not isinstance(batch, list):
            self.decode_errors += 1
            return
        self.batches_received += 1
        self.events_received += len(batch)
        try:
            self.handler(batch)
        except Exception as exc:  # a bad handler must not kill the transport
            self.last_error = f"handler: {type(exc).__name__}: {exc}"

    def stats(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "connections": self.connections,
            "connected": self.connected,
            "batches_received": self.batches_received,
            "events_received": self.events_received,
            "decode_errors": self.decode_errors,
            "last_error": self.last_error,
        }
