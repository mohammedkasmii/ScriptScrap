"""Minimal RFC 6455 framing.

Shared by the fixture's echo server and the forensic extension transport. Both
need a WebSocket endpoint that speaks to a browser, and neither needs a
dependency to do it: the subset required is the handshake, masked client text
frames in, unmasked frames out, and a close.

Not a general WebSocket implementation. No extensions, no permessage-deflate,
no fragmentation reassembly beyond a single continuation chain.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import struct

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONTINUATION = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA


def accept_key(client_key: str) -> str:
    digest = hashlib.sha1(  # noqa: S324 - the handshake is defined to use SHA-1
        (client_key + GUID).encode("ascii"), usedforsecurity=False
    ).digest()
    return base64.b64encode(digest).decode("ascii")


def handshake_response(request: bytes) -> bytes | None:
    """Build the 101 response for an upgrade request, or None if malformed."""
    key = None
    for line in request.decode("latin-1").split("\r\n"):
        if line.lower().startswith("sec-websocket-key:"):
            key = line.split(":", 1)[1].strip()
    if not key:
        return None
    return (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + accept_key(key).encode("ascii") + b"\r\n"
        b"\r\n"
    )


def encode(payload: bytes, opcode: int = OP_TEXT) -> bytes:
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


def recv_exact(conn: socket.socket, count: int) -> bytes | None:
    buf = b""
    while len(buf) < count:
        chunk = conn.recv(count - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_frame(conn: socket.socket) -> tuple[int, bytes, bool] | None:
    """Read one frame. Returns (opcode, payload, is_final) or None at EOF."""
    head = recv_exact(conn, 2)
    if head is None:
        return None
    final = bool(head[0] & 0x80)
    opcode = head[0] & 0x0F
    masked = bool(head[1] & 0x80)
    length = head[1] & 0x7F

    if length == 126:
        ext = recv_exact(conn, 2)
        if ext is None:
            return None
        length = struct.unpack(">H", ext)[0]
    elif length == 127:
        ext = recv_exact(conn, 8)
        if ext is None:
            return None
        length = struct.unpack(">Q", ext)[0]

    mask = b""
    if masked:
        got = recv_exact(conn, 4)
        if got is None:
            return None
        mask = got

    payload = recv_exact(conn, length) if length else b""
    if payload is None:
        return None
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload, final


def read_message(conn: socket.socket) -> tuple[int, bytes] | None:
    """Read one logical message, reassembling continuation frames."""
    first = read_frame(conn)
    if first is None:
        return None
    opcode, payload, final = first
    if opcode in (OP_CLOSE, OP_PING, OP_PONG):
        return opcode, payload
    while not final:
        nxt = read_frame(conn)
        if nxt is None:
            return None
        _, chunk, final = nxt
        payload += chunk
    return opcode, payload
