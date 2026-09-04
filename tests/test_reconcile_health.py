"""Sensor reconciliation and capture health. Offline, synthetic events."""

from __future__ import annotations

import itertools

from scriptscrap.analysis.health import HealthAnalyzer
from scriptscrap.analysis.reconcile import Reconciler, summarise
from scriptscrap.events import Event, EventType, Source

_seq = itertools.count(1)


def ev(event_type, payload, *, source=Source.PLAYWRIGHT, wall="2026-01-01T00:00:00.000+00:00"):
    n = next(_seq)
    return Event(session_id="s", event_id=f"evt-{n:05d}", seq=n, t_wall=wall,
                 t_mono=float(n), source=source, type=event_type, payload=payload,
                 page_id="p1", frame_id="f1")


URL = "http://h/api/thing"


# --- reconciliation ------------------------------------------------------

def test_three_sensors_on_one_request_become_one_activity():
    events = [
        ev(EventType.RUNTIME_FETCH, {"method": "POST", "url": URL}, source=Source.RUNTIME),
        ev(EventType.HTTP_REQUEST, {"method": "POST", "url": URL}),
        ev(EventType.EXTENSION_REQUEST, {"method": "POST", "url": URL},
           source=Source.EXTENSION),
    ]
    matches = Reconciler().analyze(events)
    assert len(matches) == 1
    match = matches[0]
    assert match.relation == "same_activity"
    assert set(match.sensors) == {"runtime", "playwright", "extension"}
    assert match.confidence > 0.9
    assert len(match.evidence.event_ids) == 3


def test_matching_never_uses_cross_sensor_ingest_order():
    events = [
        ev(EventType.HTTP_REQUEST, {"method": "GET", "url": URL}),
        ev(EventType.EXTENSION_REQUEST, {"method": "GET", "url": URL},
           source=Source.EXTENSION),
    ]
    match = Reconciler().analyze(events)[0]
    assert "ingest order" in match.evidence.signals["join"]


def test_extension_only_request_is_unmatched_and_that_is_the_point():
    """Traffic the other sensors could not see is the forensic layer's payload."""
    events = [ev(EventType.EXTENSION_REQUEST, {"method": "GET", "url": URL},
                 source=Source.EXTENSION)]
    match = Reconciler().analyze(events)[0]
    assert match.relation == "unmatched"
    assert list(match.sensors) == ["extension"]
    assert "cannot observe" in match.evidence.signals["interpretation"]


def test_agreeing_sensors_corroborate():
    events = [
        ev(EventType.HTTP_RESPONSE, {"method": "GET", "url": URL, "status": 200}),
        ev(EventType.EXTENSION_RESPONSE, {"method": "GET", "url": URL, "status": 200},
           source=Source.EXTENSION),
    ]
    match = Reconciler().analyze(events)[0]
    assert "status" in match.corroborations
    assert match.evidence.signals["status_agreement"] == (200,)


def test_disagreeing_sensors_produce_a_conflict_not_a_winner():
    """Both claims survive; nothing is silently chosen."""
    events = [
        ev(EventType.HTTP_RESPONSE, {"method": "GET", "url": URL, "status": 200}),
        ev(EventType.EXTENSION_RESPONSE, {"method": "GET", "url": URL, "status": 302},
           source=Source.EXTENSION),
    ]
    match = Reconciler().analyze(events)[0]
    assert match.relation == "conflicts_with"
    assert match.conflicts
    by_sensor = match.conflicts[0]["by_sensor"]
    assert by_sensor["playwright"] == [200]
    assert by_sensor["extension"] == [302]


def test_extension_body_is_recorded_as_filling_a_gap():
    events = [
        ev(EventType.HTTP_RESPONSE, {"method": "GET", "url": URL, "status": 200}),
        ev(EventType.RESPONSE_BODY_CAPTURED,
           {"url": URL, "body": {"sha256": "abc", "size": 10}}, source=Source.EXTENSION),
    ]
    match = Reconciler().analyze(events)[0]
    assert "body_available_from_extension" in match.corroborations


def test_summary_counts_relations():
    events = [
        ev(EventType.HTTP_REQUEST, {"method": "GET", "url": URL}),
        ev(EventType.EXTENSION_REQUEST, {"method": "GET", "url": URL},
           source=Source.EXTENSION),
        ev(EventType.EXTENSION_REQUEST, {"method": "GET", "url": "http://h/other"},
           source=Source.EXTENSION),
    ]
    summary = summarise(Reconciler().analyze(events))
    assert summary["activities"] == 2
    assert summary["multi_sensor"] == 1
    assert summary["unmatched_by_sensor"]["extension"] == 1


# --- capture health ------------------------------------------------------

def _healthy_normal_session():
    return [
        ev(EventType.HTTP_REQUEST, {"method": "GET", "url": URL}),
        ev(EventType.HTTP_RESPONSE, {"method": "GET", "url": URL, "status": 200}),
        ev(EventType.USER_CLICK, {"element": {"tag": "button"}}, source=Source.RUNTIME),
        ev(EventType.DOM_SNAPSHOT, {"url": URL}, source=Source.ENGINE),
        ev(EventType.STORAGE_SNAPSHOT, {"reason": "x"}),
    ]


def test_normal_session_reports_extension_as_not_applicable():
    """The extension being absent is not a failure when it was never enabled."""
    health = HealthAnalyzer().analyze(_healthy_normal_session())
    by_name = {s.name: s for s in health.sensors}
    assert by_name["extension_network"].status == "not_applicable"
    assert "forensic mode was not enabled" in by_name["extension_network"].reasons[0]
    assert health.overall.startswith("COMPLETE")


def test_missing_runtime_probe_is_unavailable_not_healthy():
    events = [
        ev(EventType.HTTP_REQUEST, {"method": "GET", "url": URL}),
        ev(EventType.DOM_SNAPSHOT, {"url": URL}, source=Source.ENGINE),
        ev(EventType.STORAGE_SNAPSHOT, {"reason": "x"}),
        ev(EventType.CAPTURE_GAP, {"reason": "runtime_probe_unavailable"},
           source=Source.ENGINE),
    ]
    health = HealthAnalyzer().analyze(events)
    by_name = {s.name: s for s in health.sensors}
    assert by_name["runtime_probe"].status == "unavailable"
    assert health.overall == "PARTIAL / SENSOR UNAVAILABLE"
    assert any("runtime_probe_unavailable" in n for n in health.notes)


def test_forensic_session_reports_extension_health_with_a_real_ratio():
    events = _healthy_normal_session() + [
        ev(EventType.FORENSIC_SENSOR_STARTED, {}, source=Source.EXTENSION),
        ev(EventType.EXTENSION_REQUEST, {"method": "GET", "url": URL},
           source=Source.EXTENSION),
        ev(EventType.RESPONSE_BODY_CAPTURED, {"url": URL}, source=Source.EXTENSION),
        ev(EventType.RESPONSE_BODY_CAPTURED, {"url": URL + "2"}, source=Source.EXTENSION),
        ev(EventType.RESPONSE_BODY_SKIPPED, {"url": URL + "3"}, source=Source.EXTENSION),
    ]
    by_name = {s.name: s for s in HealthAnalyzer().analyze(events).sensors}
    extension = by_name["extension_network"]
    assert extension.status == "degraded"
    # A denominator genuinely exists here, so a ratio means something.
    assert extension.metrics["body_capture_rate"] == round(2 / 3, 3)
    assert any("size limit" in r for r in extension.reasons)


def test_forensic_mode_with_no_connection_is_unavailable():
    health = HealthAnalyzer().analyze(_healthy_normal_session(), forensic=True)
    by_name = {s.name: s for s in health.sensors}
    assert by_name["extension_network"].status == "unavailable"
    assert "never connected" in by_name["extension_network"].reasons[0]


def test_no_websocket_is_not_applicable_rather_than_broken():
    by_name = {s.name: s for s in HealthAnalyzer().analyze(_healthy_normal_session()).sensors}
    assert by_name["websocket_sensor"].status == "not_applicable"


def test_source_rewriting_is_called_out_in_the_notes():
    events = _healthy_normal_session() + [
        ev(EventType.SOURCE_REWRITE,
           {"target": "doThing", "original_sha256": "a", "rewritten_sha256": "b"},
           source=Source.EXTENSION),
    ]
    health = HealthAnalyzer().analyze(events)
    assert any("not pure observation" in n for n in health.notes)


def test_health_explains_why_not_just_what():
    health = HealthAnalyzer().analyze(_healthy_normal_session())
    for sensor in health.sensors:
        if sensor.status in ("degraded", "unavailable", "not_applicable"):
            assert sensor.reasons, f"{sensor.name} gave a status with no reason"
