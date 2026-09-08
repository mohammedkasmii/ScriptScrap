"""Forensic layer against the real fixture, in a real Camoufox.

Two sessions, because the central claim of M4 is that the forensic layer is
OPTIONAL: one with the extension, one without, and the normal one must still
produce a complete normal capture.
"""

from __future__ import annotations

import pytest

from scriptscrap.analysis import analyze_log
from scriptscrap.events import EventLogReader, EventType

pytestmark = pytest.mark.browser


@pytest.fixture(scope="module")
def forensic_session(tmp_path_factory):
    from scriptscrap.testing.forensic_capture import capture_forensic

    out = tmp_path_factory.mktemp("forensic") / "output"
    inv, engine = capture_forensic(out)
    return {"dir": out, "engine": engine,
            "log": EventLogReader(out / "events.jsonl")}


# --- the extension is optional ------------------------------------------

def test_normal_mode_needs_no_extension(tmp_path_factory):
    """The load-bearing claim: normal capture works with no forensic layer."""
    from scriptscrap.testing.capture import capture

    out = tmp_path_factory.mktemp("normal") / "output"
    capture(out, headless=True)

    log = EventLogReader(out / "events.jsonl")
    assert log.validate() == []
    assert log.of_type(EventType.HTTP_REQUEST), "normal capture produced no traffic"
    assert log.of_type(EventType.USER_CLICK), "runtime probe did not run"
    # Nothing forensic anywhere.
    assert log.of_type(EventType.FORENSIC_SENSOR_STARTED) == []
    assert log.of_type(EventType.EXTENSION_REQUEST) == []
    assert log.of_type(EventType.RESPONSE_BODY_CAPTURED) == []
    assert not (out / "blobs").exists(), "normal mode must not create a blob store"

    manifest_health = analyze_log(out / "events.jsonl").health
    by_name = {s["sensor"]: s for s in manifest_health["sensors"]}
    assert by_name["extension_network"]["status"] == "not_applicable"


def test_analysis_works_on_a_forensic_session_too(forensic_session):
    result = analyze_log(forensic_session["dir"] / "events.jsonl")
    assert result.endpoints
    assert result.health["overall"]


# --- extension sensor ----------------------------------------------------

def test_extension_connected_and_declared_its_capabilities(forensic_session):
    log = forensic_session["log"]
    started = log.of_type(EventType.FORENSIC_SENSOR_STARTED)
    assert started, "the extension never connected"
    capabilities = started[0].payload["capabilities"]
    assert capabilities["filter_response_data"] is True
    assert capabilities["cookies"] is True
    assert capabilities["manifest_version"] == 2


def test_no_sensor_errors_in_a_healthy_forensic_run(forensic_session):
    errors = forensic_session["log"].of_type(EventType.SENSOR_ERROR)
    assert errors == [], f"forensic sensors reported errors: {[e.payload for e in errors]}"


def test_extension_sees_requests_and_responses(forensic_session):
    log = forensic_session["log"]
    assert log.of_type(EventType.EXTENSION_REQUEST)
    assert log.of_type(EventType.EXTENSION_RESPONSE)
    # Response headers arrive as a LIST, which is what preserves repeated
    # Set-Cookie headers that an object representation would collapse.
    with_headers = [e for e in log.of_type(EventType.EXTENSION_RESPONSE)
                    if e.payload.get("headers")]
    assert with_headers
    assert isinstance(with_headers[0].payload["headers"], list)


def test_extension_does_not_observe_its_own_transport(forensic_session):
    """Observer self-contamination: the sensor shares a host with the target."""
    for event in forensic_session["log"]:
        url = event.payload.get("url")
        if isinstance(url, str):
            assert "/extension" not in url or not url.startswith("ws://"), url


# --- response bodies + blobs ---------------------------------------------

def test_bodies_are_captured_into_content_addressed_blobs(forensic_session):
    log, out = forensic_session["log"], forensic_session["dir"]
    captured = log.of_type(EventType.RESPONSE_BODY_CAPTURED)
    assert captured, "no response bodies were captured"

    for event in captured:
        body = event.payload["body"]
        assert len(body["sha256"]) == 64
        assert body["size"] >= 0
        assert body["storage"].startswith("blobs/")
        assert (out / body["storage"]).exists(), "blob referenced but not on disk"


def test_identical_bodies_are_stored_once(forensic_session):
    """/api/twin-a and /api/twin-b return byte-identical payloads."""
    captured = forensic_session["log"].of_type(EventType.RESPONSE_BODY_CAPTURED)
    twins = [e for e in captured if "/api/twin-" in (e.payload.get("url") or "")]
    assert len(twins) == 2, "both twin endpoints should have been captured"
    hashes = {e.payload["body"]["sha256"] for e in twins}
    assert len(hashes) == 1, "identical payloads must share one blob"
    assert any(e.payload["body"]["deduplicated"] for e in twins)


def test_oversized_body_is_skipped_with_a_stated_reason(forensic_session):
    skipped = forensic_session["log"].of_type(EventType.RESPONSE_BODY_SKIPPED)
    assert skipped, "the oversized body was not reported as skipped"
    big = [e for e in skipped if "/api/big" in (e.payload.get("url") or "")]
    assert big, [e.payload.get("url") for e in skipped]
    payload = big[0].payload
    assert payload["reason"] == "configured_size_limit"
    assert payload["size"] > payload["limit"]


def test_response_bytes_were_not_altered(forensic_session):
    """Interception must pass the original bytes through unchanged."""
    log, out = forensic_session["log"], forensic_session["dir"]
    twin = next(e for e in log.of_type(EventType.RESPONSE_BODY_CAPTURED)
                if "/api/twin-a" in (e.payload.get("url") or ""))
    stored = (out / twin.payload["body"]["storage"]).read_bytes()
    assert b"FIXTURE-TWIN-PAYLOAD-0001" in stored
    import json as _json
    assert _json.loads(stored)["twin"] is True, "captured body is not valid JSON"


# --- early script visibility ---------------------------------------------

def test_parse_time_function_source_is_observable(forensic_session):
    """The M0 blind spot, closed at the source level.

    An injected interval hook cannot catch a function declared and called in the
    same parse. Capturing the SOURCE before Firefox parses it can still tell an
    investigator the function exists and ran.
    """
    from scriptscrap.analysis.scriptinfo import find_parse_time_calls

    log, out = forensic_session["log"], forensic_session["dir"]
    early = [e for e in log.of_type(EventType.SCRIPT_SOURCE)
             if "early.js" in (e.payload.get("url") or "")]
    assert early, "the early script's source was not captured"

    inventory = early[0].payload["inventory"]
    assert "fixtureEarlyFunction" in inventory["declared_functions"]
    assert "fetch" in inventory["network_apis"]

    source = (out / early[0].payload["body"]["storage"]).read_text(encoding="utf-8")
    found = find_parse_time_calls(
        source, ["fixtureEarlyFunction", "fixtureLateFunction"])
    assert found == ["fixtureEarlyFunction"], (
        "source analysis should identify exactly the function that is called "
        "during its own parse")


def test_runtime_hook_still_misses_the_parse_time_call(forensic_session):
    """The limitation is real and is NOT claimed to be fixed by observation."""
    hooks = forensic_session["log"].of_type(EventType.RUNTIME_HOOKS)
    assert hooks
    called = hooks[0].payload.get("functions") or []
    assert "fixtureEarlyFunction" not in called


# --- cookies -------------------------------------------------------------

def test_cookie_lifecycle_including_httponly(forensic_session):
    """The M2 blind spot: page JavaScript can never read an httpOnly cookie."""
    log = forensic_session["log"]
    changed = log.of_type(EventType.COOKIE_CHANGED)
    deleted = log.of_type(EventType.COOKIE_DELETED)
    assert changed, "no cookie changes observed"

    by_name = {e.payload.get("name"): e.payload for e in changed}
    assert "fixture_visible" in by_name
    assert "fixture_httponly" in by_name
    assert by_name["fixture_httponly"]["http_only"] is True
    assert by_name["fixture_httponly"]["visibility_source"] == "extension_cookie_api"
    assert any(e.payload.get("name") == "fixture_visible" for e in deleted)


# --- health + reconciliation on real evidence ----------------------------

def test_forensic_session_health_reports_the_extension(forensic_session):
    health = analyze_log(forensic_session["dir"] / "events.jsonl").health
    by_name = {s["sensor"]: s for s in health["sensors"]}
    extension = by_name["extension_network"]
    assert extension["status"] in ("healthy", "degraded")
    assert extension["metrics"]["bodies_captured"] > 0
    assert "body_capture_rate" in extension["metrics"]


def test_multi_sensor_activity_is_reconciled(forensic_session):
    result = analyze_log(forensic_session["dir"] / "events.jsonl")
    multi = [a for a in result.activities if a.sensor_count > 1]
    assert multi, "no activity was observed by more than one sensor"
    example = multi[0]
    assert example.relation in ("same_activity", "conflicts_with")
    assert len(example.evidence.event_ids) >= 2
    assert "ingest order" in example.evidence.signals["join"]


def test_manifest_discloses_forensic_mode(forensic_session):
    import json
    manifest = json.loads(
        (forensic_session["dir"] / "session_manifest.json").read_text(encoding="utf-8"))
    forensic = manifest["forensic"]
    assert forensic["mode"] == "forensic"
    assert forensic["response_body_interception"] is True
    assert forensic["source_rewriting"]["enabled"] is False
    assert forensic["source_rewriting"]["active"] is False
    assert manifest["sensors"]["extension"] is not None


# --- export safety -------------------------------------------------------

def test_shared_export_excludes_source_bodies_and_cookie_values(forensic_session, tmp_path):
    from scriptscrap.export import DatasetExporter

    result = analyze_log(forensic_session["dir"] / "events.jsonl")
    path = DatasetExporter().write(result, tmp_path / "shared")
    blob = path.read_text(encoding="utf-8")

    # Application source must never be exported.
    assert "function fixtureEarlyFunction" not in blob
    assert "FIXTURE-TWIN-PAYLOAD-0001" not in blob
    # Cookie values, especially the httpOnly one.
    assert "FIXTURE_HTTPONLY_TOKEN_0001" not in blob
    assert "FIXTURE_VISIBLE_0001" not in blob
    assert "FIXTURE_SESSION_TOKEN_0001" not in blob

    import json
    payload = json.loads(blob)
    # The script inventory is no longer exported at all. It used to carry the
    # URL, the declared function names and the URL literals found in the
    # source -- every one of them read off the application, and three of the
    # 28 fields the audit found leaking. The hash alone did not justify
    # shipping the rest, so the whole block is dropped rather than filtered.
    assert "scripts" not in payload
    assert "declared_functions" not in blob
    assert "url_literals" not in blob
    # Capture health still travels, as codes and counts rather than prose.
    assert payload["capture_health"]["overall_code"]
    assert "overall" not in payload["capture_health"], (
        "the prose verdict is derived, not a constant, so it is not exported")
