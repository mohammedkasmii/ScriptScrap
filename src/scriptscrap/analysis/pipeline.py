"""Analysis pipeline: events.jsonl in, derived knowledge out.

Pure and offline. Nothing in `scriptscrap.analysis` imports Playwright,
Camoufox, or `scriptscrap.sensors`, and a test enforces that. The practical
consequence is that analysis can be re-run on a recorded log from any machine,
and that its tests need no browser.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from ..events import Event, EventLogReader, EventType
from .correlation import CorrelationAnalyzer
from .endpoints import EndpointAnalyzer, endpoint_key_for_request
from .health import HealthAnalyzer
from .models import ANALYSIS_VERSION, AnalysisResult, Evidence, Finding
from .reconcile import Reconciler
from .schema import SchemaInferrer
from .selectors import SelectorAnalyzer
from .states import StateAnalyzer
from .technology import TechnologyAnalyzer, opaque_state_fields


def analyze_events(events: list[Event], session_id: str) -> AnalysisResult:
    """Derive everything from one event log."""
    result = AnalysisResult(
        session_id=session_id,
        event_count=len(events),
        analysis_version=ANALYSIS_VERSION,
    )

    result.technologies = TechnologyAnalyzer().analyze(events)
    opaque = opaque_state_fields(result.technologies)

    result.endpoints = EndpointAnalyzer().analyze(events)

    # Map each raw request/response event to the endpoint it belongs to, so
    # schemas and dependency edges are attributed to routes rather than URLs.
    endpoint_of = _attribute_events(events, result.endpoints)

    result.schemas = _infer_schemas(events, endpoint_of, opaque)
    result.dependencies = CorrelationAnalyzer().analyze(events, endpoint_of)
    result.ui_elements = SelectorAnalyzer().analyze(events)
    result.states, result.transitions = StateAnalyzer().analyze(events)
    # Forensic evidence, when present. A normal session yields empty lists and
    # a health report built from the sensors that did run -- analysis must
    # never require the extension.
    result.activities = Reconciler().analyze(events)
    result.health = HealthAnalyzer().analyze(events).to_dict()
    result.scripts = _script_inventory(events)

    result.findings = _findings(events, result)
    return result


def _script_inventory(events: list[Event]) -> list[dict]:
    """Captured script source, as metadata. Source text stays in blobs."""
    scripts = []
    for event in events:
        if event.type is not EventType.SCRIPT_SOURCE:
            continue
        payload = event.payload
        body = payload.get("body") or {}
        scripts.append({
            "url": payload.get("url"),
            "sha256": body.get("sha256"),
            "size": body.get("size") or (payload.get("inventory") or {}).get("size"),
            "media_type": payload.get("media_type"),
            "source_map": payload.get("source_map"),
            "inventory": payload.get("inventory") or {},
            "evidence_ids": [event.event_id],
        })
    return scripts


def analyze_log(path: str | Path) -> AnalysisResult:
    reader = EventLogReader(path)
    session_id = reader.events[0].session_id if reader.events else "unknown"
    return analyze_events(list(reader), session_id)


def _attribute_events(events: list[Event], endpoints) -> dict[str, str]:
    """event_id -> derived endpoint key."""
    by_url: dict[tuple[str, str], str] = {}
    mapping: dict[str, str] = {}

    for event in events:
        if event.type is EventType.HTTP_REQUEST:
            key = endpoint_key_for_request(event.payload, endpoints)
            if key:
                mapping[event.event_id] = key
                by_url[(event.payload.get("method", ""), event.payload.get("url", ""))] = key

    # Responses inherit their request's endpoint, matched on (method, url).
    for event in events:
        if event.type is EventType.HTTP_RESPONSE:
            key = by_url.get((event.payload.get("method", ""), event.payload.get("url", "")))
            if key:
                mapping[event.event_id] = key

    # The runtime probe's view of a request is the SAME activity the network
    # sensor saw, so it belongs to the same endpoint. Attributing it to a
    # pseudo-endpoint instead would make one request look like two places a
    # value appeared, which is the input to the "is this value distinctive?"
    # test -- and would have quietly weakened every dependency hypothesis.
    for event in events:
        if event.type in (EventType.RUNTIME_FETCH, EventType.RUNTIME_XHR):
            if event.payload.get("evidence_reduced"):
                continue          # out of scope: not our application's endpoint
            key = endpoint_key_for_request(event.payload, endpoints)
            if key:
                mapping[event.event_id] = key
    return mapping


def _infer_schemas(events, endpoint_of, opaque_fields):
    """One schema per (endpoint, direction), merged over every observation."""
    request_by: dict[str, SchemaInferrer] = defaultdict(SchemaInferrer)
    response_by: dict[tuple[str, str], SchemaInferrer] = defaultdict(SchemaInferrer)

    for event in events:
        key = endpoint_of.get(event.event_id)
        if not key:
            continue
        body = event.payload.get("body")
        if body is None:
            continue
        body = _mask_opaque(body, opaque_fields)

        if event.type is EventType.HTTP_REQUEST:
            request_by[key].observe(body, event.event_id)
        elif event.type is EventType.HTTP_RESPONSE:
            # Split by status: a 200 body and a 500 body are different shapes,
            # and merging them would invent a schema that never existed.
            status = str(event.payload.get("status", ""))
            response_by[(key, status)].observe(body, event.event_id)

    schemas = [inf.build(key, "request") for key, inf in sorted(request_by.items())]
    schemas.extend(
        inf.build(key, "response", status=status)
        for (key, status), inf in sorted(response_by.items())
    )
    return [s for s in schemas if s.fields or s.root_type != "unknown"]


def _mask_opaque(body, opaque_fields: set[str]):
    """Replace framework state blobs with a description of themselves."""
    if not opaque_fields or not isinstance(body, dict):
        return body
    masked = {}
    for key, value in body.items():
        if key in opaque_fields and isinstance(value, str):
            masked[key] = f"<state token: {len(value)} chars>"
        else:
            masked[key] = value
    return masked


def _findings(events: list[Event], result: AnalysisResult) -> list[Finding]:
    """Surface what the reader must know to judge the rest."""
    findings: list[Finding] = []

    gaps: dict[str, list[str]] = defaultdict(list)
    errors: dict[str, list[str]] = defaultdict(list)
    for event in events:
        if event.type is EventType.CAPTURE_GAP:
            gaps[str(event.payload.get("reason", "unknown"))].append(event.event_id)
        elif event.type is EventType.SENSOR_ERROR:
            errors[str(event.payload.get("where", "unknown"))].append(event.event_id)

    severity_of = {
        "service_worker_visibility_unavailable": "critical",
        "response_body_unavailable": "warning",
        "runtime_probe_unavailable": "critical",
    }
    for reason, ids in sorted(gaps.items()):
        findings.append(Finding(
            kind="capture_gap",
            severity=severity_of.get(reason, "info"),
            message=f"{reason}: {len(ids)} occurrence(s); evidence is incomplete here",
            count=len(ids),
            evidence=Evidence(event_ids=ids[:20]),
        ))
    for where, ids in sorted(errors.items()):
        findings.append(Finding(
            kind="sensor_error", severity="warning",
            message=f"sensor failure in {where}: {len(ids)} occurrence(s)",
            count=len(ids), evidence=Evidence(event_ids=ids[:20]),
        ))

    # A sensor that ran but lost a whole evidence family. This outranks every
    # other finding: it says a conclusion you are about to draw rests on
    # evidence nobody collected.
    for sensor in (result.health or {}).get("sensors", []):
        for blind_spot in sensor.get("blind_spots", []):
            findings.append(Finding(
                kind="sensor_blind_spot", severity="critical",
                message=f"{sensor['sensor']}: {blind_spot}", count=1,
            ))

    thin = [s for s in result.schemas if s.sample_count < 3]
    if thin:
        findings.append(Finding(
            kind="thin_sample", severity="info",
            message=(f"{len(thin)} schema(s) inferred from fewer than 3 observations; "
                     "treat optionality and enum candidates as unproven"),
            count=len(thin),
        ))

    single = [e for e in result.endpoints if e.templated and len(e.concrete_paths) < 2]
    if single:
        findings.append(Finding(
            kind="weak_templating", severity="info",
            message=(f"{len(single)} endpoint(s) templated from a single concrete path; "
                     "the parameter is a guess from value shape alone"),
            count=len(single),
        ))
    return findings
