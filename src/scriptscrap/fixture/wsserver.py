"""A minimal RFC 6455 WebSocket echo server for the fixture.

Standard library only, and deliberately small: it implements exactly the subset
the WebSocket sensor needs to be exercised -- handshake, masked text frames from
the client, unmasked text and binary frames to the client, and a close
handshake. It is a test fixture, not a WebSocket implementation.

Deterministic by construction: every reply is a fixed function of the request.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import socket
import struct
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA


def reserve_dead_port() -> int:
    """A loopback port that is bound, read, and then closed.

    Used for the failed-request case. It must be on the fixture's own host so
    the request stays inside the investigation scope, and it must be a high
    port: browsers refuse low "bad ports" like 1 and 9 outright, so no request
    is ever made and no failure is observed.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _accept_key(client_key: str) -> str:
    digest = hashlib.sha1((client_key + GUID).encode("ascii")).digest()  # noqa: S324 - RFC 6455
    return base64.b64encode(digest).decode("ascii")


def _frame(payload: bytes, opcode: int = OP_TEXT) -> bytes:
    """Build an unmasked server frame."""
    header = bytes([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header += bytes([length])
    elif length < (1 << 16):
        header += bytes([126]) + struct.pack(">H", length)
    else:
        header += bytes([127]) + struct.pack(">Q", length)
    return header + payload


def _recv_exact(conn: socket.socket, count: int) -> bytes | None:
    buf = b""
    while len(buf) < count:
        chunk = conn.recv(count - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _read_frame(conn: socket.socket) -> tuple[int, bytes] | None:
    head = _recv_exact(conn, 2)
    if head is None:
        return None
    opcode = head[0] & 0x0F
    masked = bool(head[1] & 0x80)
    length = head[1] & 0x7F

    if length == 126:
        ext = _recv_exact(conn, 2)
        if ext is None:
            return None
        length = struct.unpack(">H", ext)[0]
    elif length == 127:
        ext = _recv_exact(conn, 8)
        if ext is None:
            return None
        length = struct.unpack(">Q", ext)[0]

    mask = b""
    if masked:
        got = _recv_exact(conn, 4)
        if got is None:
            return None
        mask = got

    payload = _recv_exact(conn, length) if length else b""
    if payload is None:
        return None
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


class WebSocketEchoServer:
    """Accepts one or more clients and replies with a fixed script.

    Protocol exercised, per client message:
      * a text echo,
      * one binary frame (so binary classification is tested),
      * a final `fixture-done` text frame after the second client message,
        which the page uses to close the socket.
    """

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def url(self) -> str:
        return f"ws://127.0.0.1:{self.port}/ws"

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._sock.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(10)
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                request += chunk

            key = None
            for line in request.decode("latin-1").split("\r\n"):
                if line.lower().startswith("sec-websocket-key:"):
                    key = line.split(":", 1)[1].strip()
            if not key:
                conn.close()
                return

            conn.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: " + _accept_key(key).encode("ascii") + b"\r\n"
                b"\r\n"
            )

            received = 0
            while not self._stop.is_set():
                frame = _read_frame(conn)
                if frame is None:
                    return
                opcode, payload = frame
                if opcode == OP_CLOSE:
                    conn.sendall(_frame(b"", OP_CLOSE))
                    return
                if opcode == OP_PING:
                    conn.sendall(_frame(payload, OP_PONG))
                    continue
                if opcode not in (OP_TEXT, OP_BINARY):
                    continue

                received += 1
                text = payload.decode("utf-8", "replace")
                conn.sendall(_frame(f"echo:{text}".encode()))
                conn.sendall(_frame(b"\x00\x01\x02\x03fixture-binary", OP_BINARY))
                if received >= 2:
                    conn.sendall(_frame(b"fixture-done"))
        except (OSError, UnicodeDecodeError):
            return
        finally:
            with contextlib.suppress(OSError):
                conn.close()
