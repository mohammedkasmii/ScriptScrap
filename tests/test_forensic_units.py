"""Offline units of the forensic layer: config, blobs, transport, inventory."""

from __future__ import annotations

import json
import socket
import threading

import pytest

from scriptscrap.analysis.scriptinfo import find_parse_time_calls, summarise_source
from scriptscrap.config import CaptureConfig, ForensicConfig, RewriteTarget
from scriptscrap.extension import ExtensionTransport, build_extension, cleanup_extension
from scriptscrap.storage import BlobRef, BlobSkipped, BlobStore
from scriptscrap.wsframe import OP_TEXT, encode, handshake_response

# --- configuration -------------------------------------------------------

def test_normal_is_the_default():
    config = CaptureConfig(target_url="https://example.test")
    assert config.mode == "normal"
    assert config.to_manifest()["sensors"]["extension"] is False


def test_forensic_does_not_imply_source_rewriting():
    """The invasive part has its own switch. This is the point of the design."""
    config = ForensicConfig(enabled=True)
    assert config.source_rewrite is False
    assert config.rewriting_active is False
    manifest = config.to_manifest()
    assert manifest["mode"] == "forensic"
    assert manifest["source_rewriting"]["enabled"] is False
    assert manifest["source_rewriting"]["active"] is False


def test_source_rewriting_requires_forensic_mode():
    with pytest.raises(ValueError, match="requires forensic mode"):
        ForensicConfig(enabled=False, source_rewrite=True)


def test_rewriting_is_only_active_with_targets():
    """Enabling the switch without naming a target changes nothing."""
    armed = ForensicConfig(enabled=True, source_rewrite=True)
    assert armed.rewriting_active is False
    targeted = ForensicConfig(
        enabled=True, source_rewrite=True,
        rewrite_targets=[RewriteTarget(script="app.js", functions=["doThing"])])
    assert targeted.rewriting_active is True
    assert targeted.to_manifest()["source_rewriting"]["targets"] == [
        {"script": "app.js", "functions": ["doThing"]}]


def test_manifest_discloses_what_was_enabled():
    config = CaptureConfig(
        target_url="https://example.test",
        forensic=ForensicConfig(enabled=True, capture_bodies=True))
    manifest = config.to_manifest()
    assert manifest["mode"] == "forensic"
    assert manifest["sensors"] == {
        "playwright": True, "runtime_probe": True, "extension": True}
    assert manifest["forensic"]["response_body_interception"] is True


# --- blob store ----------------------------------------------------------

def test_blob_is_content_addressed_and_deduplicated(tmp_path):
    store = BlobStore(tmp_path / "blobs")
    first = store.put(b"identical payload", media_type="application/json")
    second = store.put(b"identical payload", media_type="application/json")

    assert isinstance(first, BlobRef)
    assert isinstance(second, BlobRef)
    assert first.sha256 == second.sha256
    assert first.deduplicated is False
    assert second.deduplicated is True
    assert store.count() == 1, "identical bodies must produce one blob"
    assert store.stats()["blobs_written"] == 1
    assert store.stats()["deduplicated"] == 1


def test_blob_round_trips(tmp_path):
    store = BlobStore(tmp_path / "blobs")
    ref = store.put(b"\x00\x01binary\xff", media_type="application/octet-stream")
    assert isinstance(ref, BlobRef)
    assert store.get(ref.sha256) == b"\x00\x01binary\xff"
    assert store.exists(ref.sha256)


def test_oversized_body_is_skipped_with_a_reason(tmp_path):
    store = BlobStore(tmp_path / "blobs", max_bytes=16)
    result = store.put(b"x" * 64, media_type="text/plain")
    assert isinstance(result, BlobSkipped)
    assert result.reason == "configured_size_limit"
    assert result.size == 64
    assert result.limit == 16
    assert store.count() == 0
    # Never a silent omission: the reason travels with the event.
    assert result.to_dict()["status"] == "skipped"


def test_blob_write_leaves_no_partial_files(tmp_path):
    store = BlobStore(tmp_path / "blobs")
    store.put(b"a" * 1000)
    leftovers = list((tmp_path / "blobs").rglob("*.part"))
    assert leftovers == [], "temporary files must be renamed, never left behind"


# --- transport -----------------------------------------------------------

def test_transport_receives_a_batch():
    """Speak the protocol from a plain socket, as the extension would."""
    received: list[list[dict]] = []
    with ExtensionTransport(received.append) as transport:
        conn = socket.create_connection(("127.0.0.1", transport.port), timeout=5)
        conn.sendall(
            b"GET /extension HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            b"Sec-WebSocket-Version: 13\r\n\r\n")
        assert b"101" in conn.recv(1024)

        payload = json.dumps([{"type": "extension_request", "ordinal": 1,
                               "payload": {"url": "http://x/"}}]).encode()
        # Client frames must be masked.
        masked = bytearray(encode(payload, OP_TEXT))
        masked[1] |= 0x80
        header_len = 2 if len(payload) < 126 else 4
        body = bytes(b ^ 0 for b in payload)
        conn.sendall(bytes(masked[:header_len]) + b"\x00\x00\x00\x00" + body)

        deadline = threading.Event()
        for _ in range(100):
            if received:
                break
            deadline.wait(0.05)
        conn.close()

    assert received, "transport received no batch"
    assert received[0][0]["type"] == "extension_request"
    assert transport.stats()["events_received"] == 1


def test_handshake_rejects_a_request_without_a_key():
    assert handshake_response(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") is None


def test_transport_survives_a_bad_batch():
    received: list[list[dict]] = []
    with ExtensionTransport(received.append) as transport:
        transport._ingest(b"not json at all")
        transport._ingest(json.dumps({"not": "a list"}).encode())
        assert transport.decode_errors == 2
        assert transport.last_error


def test_transport_survives_a_failing_handler():
    """A handler crash must not take down evidence delivery."""
    def explode(_batch):
        raise RuntimeError("handler blew up")

    with ExtensionTransport(explode) as transport:
        transport._ingest(json.dumps([{"type": "x"}]).encode())
        assert "handler blew up" in (transport.last_error or "")


# --- extension build -----------------------------------------------------

def test_built_extension_is_loadable_and_configured(tmp_path):
    path = build_extension(port=4321, scope_hosts=["example.test"],
                           target_dir=tmp_path / "ext")
    names = {p.name for p in path.iterdir()}
    assert {"manifest.json", "background.js", "config.js"} <= names

    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["manifest_version"] == 2, "MV2 keeps blocking webRequest"
    assert "webRequestBlocking" in manifest["permissions"]

    config = (path / "config.js").read_text(encoding="utf-8")
    assert '"port": 4321' in config
    assert "example.test" in config
    cleanup_extension(path)
    assert not path.exists()


def test_rewrite_targets_are_absent_unless_enabled(tmp_path):
    path = build_extension(port=1, scope_hosts=["x.test"], target_dir=tmp_path / "e")
    config = (path / "config.js").read_text(encoding="utf-8")
    assert '"rewriteTargets": []' in config


# --- script inventory ----------------------------------------------------

def test_source_inventory_lists_what_the_file_declares():
    source = """
    function alpha(a) { return a; }
    const beta = function () {};
    const gamma = (x) => x;
    class Delta {}
    window.epsilon = 1;
    fetch("/api/thing");
    new WebSocket("wss://x.test/ws");
    //# sourceMappingURL=app.js.map
    """
    inventory = summarise_source(source)
    assert {"alpha", "beta", "gamma"} <= set(inventory["declared_functions"])
    assert "Delta" in inventory["declared_classes"]
    assert "epsilon" in inventory["window_assignments"]
    assert "fetch" in inventory["network_apis"]
    assert "WebSocket" in inventory["network_apis"]
    assert inventory["source_map"] == "app.js.map"
    assert "/api/thing" in inventory["url_literals"]


def test_inventory_describes_text_not_behaviour():
    assert "may never run" in summarise_source("function a(){}")["note"]


def test_parse_time_calls_are_detectable_in_source():
    """The blind spot injected instrumentation cannot close, found in the source."""
    source = (
        "function fixtureEarlyFunction(a, b) { return a + b; }\n"
        "window.fixtureEarlyFunction = fixtureEarlyFunction;\n"
        "window.__r = fixtureEarlyFunction(20, 22);\n"
        "function fixtureLateFunction(a) { return a; }\n"
    )
    found = find_parse_time_calls(source, ["fixtureEarlyFunction", "fixtureLateFunction"])
    assert found == ["fixtureEarlyFunction"]
