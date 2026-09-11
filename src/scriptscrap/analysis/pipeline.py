"""Analysis pipeline: events.jsonl in, derived knowledge out.

Pure and offline. Nothing in `scriptscrap.analysis` imports Playwright,
Camoufox, or `scriptscrap.sensors`, and a test enforces that. The practical
consequence is that analysis can be re-run on a recorded log from any machine,
and that its tests need no browser.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from pathlib import Path

from ..events import Event, EventLogReader, EventType
from .correlation import CorrelationAnalyzer
from .endpoints import EndpointAnalyzer, endpoint_key_for_request
from .forms import FormCatalogAnalyzer
from .health import HealthAnalyzer
from .models import (
    ANALYSIS_VERSION,
    AnalysisResult,
    EventIndexRow,
    Evidence,
    Finding,
)
from .reconcile import Reconciler
from .schema import SchemaInferrer
from .segmentation import SegmentationAnalyzer
from .selectors import SelectorAnalyzer
from .states import StateAnalyzer
from .technology import TechnologyAnalyzer, opaque_state_fields
from .workflow import WorkflowAnalyzer


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
    result.workflow = WorkflowAnalyzer().analyze(events)
    # A long session, split into probable business activities. The ordered
    # workflow above is untouched: this is an interpretation laid over it.
    result.segments = SegmentationAnalyzer().analyze(events)
    # The forms the operator used, assembled from the scattered observations
    # of each one into a single per-form record.
    result.forms = FormCatalogAnalyzer().analyze(events)
    # Forensic evidence, when present. A normal session yields empty lists and
    # a health report built from the sensors that did run -- analysis must
    # never require the extension.
    result.activities = Reconciler().analyze(events)
    result.health = HealthAnalyzer().analyze(events).to_dict()
    result.scripts = _script_inventory(events)
    result.auth_headers = _auth_headers(events)

    result.findings = _findings(events, result)
    return result


def _auth_headers(events: list[Event]) -> dict[str, int]:
    """Which credential-bearing headers the application sent, and how often.

    NAMES only. The capture classifies a header as credential-bearing and
    records that it was present; it never records the value. That asymmetry is
    the whole point -- it is what lets a generated client state "this API
    authenticates with a Cookie header" without ever having held the operator's
    session.
    """
    counts: dict[str, int] = defaultdict(int)
    for event in events:
        if event.type is not EventType.HTTP_REQUEST:
            continue
        if event.payload.get("evidence_reduced"):
            continue          # out of scope: not our application's contract
        for name in event.payload.get("credential_header_names") or []:
            counts[str(name).lower()] += 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


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
    """Analyse a log on disk, and index where each event's evidence lives.

    `analyze_events` stays offset-free: a caller holding events in memory has
    no file for an offset to point into, and inventing one would be a lie.
    Offsets are attached here, where the file is.
    """
    reader = EventLogReader(path, with_offsets=True)
    session_id = reader.events[0].session_id if reader.events else "unknown"
    result = analyze_events(list(reader), session_id)
    result.findings.extend(_log_integrity_findings(reader))

    index: list[EventIndexRow] = []
    for event in reader.events:
        located = reader.offsets.get(event.event_id)
        if located is None:
            continue
        offset, length = located
        index.append(EventIndexRow(
            event_id=event.event_id,
            seq=event.seq,
            type=str(event.type),
            source=str(event.source),
            t_wall=event.t_wall,
            t_mono=event.t_mono,
            page_id=event.page_id,
            frame_id=event.frame_id,
            byte_offset=offset,
            byte_length=length,
        ))
    result.event_index = index

    log = Path(path)
    result.log_size = log.stat().st_size
    result.log_sha256 = _sha256_of(log)
    return result


def _log_integrity_findings(reader: EventLogReader) -> list[Finding]:
    """Structural defects in the log itself.

    `EventLogReader.validate` has detected these since M1 and nothing acted on
    them. A duplicated event id in particular makes every citation of that id
    ambiguous, and the evidence index resolves it with fetchone().
    """
    findings: list[Finding] = []
    for problem in reader.validate():
        if problem.kind == "duplicate_event_id":
            findings.append(Finding(
                kind="duplicate_event_id", severity="critical",
                message=(f"the log repeats an event id ({problem.detail}); every "
                         "citation of it is ambiguous and the evidence index "
                         "will refuse to store it"),
                count=1))
        elif problem.kind in ("duplicate_seq", "unordered", "sequence_gap"):
            findings.append(Finding(
                kind="log_integrity", severity="warning",
                message=f"{problem.kind}: {problem.detail}", count=1))
    return findings


def _sha256_of(path: Path) -> str:
    """Fingerprint the log the offsets were built from.

    Read in chunks: a session log is routinely tens of megabytes and there is
    no reason to hold one in memory to hash it.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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

    # A generated `.fill("")` for eighteen fields looks like a script that will
    # work. The capture does not hold input values and some steps have no
    # measured locator; both belong here, where the project already says what
    # it did not see.
    # The join from a step to its element is TOTAL by construction -- both use
    # `semantic_key` and the same tag gate -- so a step never fails to resolve.
    # What a step can lack is a LOCATOR: an element with no id, name, label,
    # text, dom_path or class yields zero locator candidates, and a generated
    # script can record that step and not replay it.
    without_locator = {e.key for e in result.ui_elements if not e.locators}
    unreplayable = [s for s in result.workflow
                    if s.element_key and s.element_key in without_locator]
    if unreplayable:
        findings.append(Finding(
            kind="unreplayable_step", severity="warning",
            message=(f"{len(unreplayable)} workflow step(s) reference an element "
                     "with no measured locator; a generated script records them "
                     "and cannot replay them"),
            count=len(unreplayable),
            evidence=Evidence(event_ids=[
                eid for s in unreplayable[:20] for eid in s.evidence.event_ids[:1]]),
        ))

    typed = [s for s in result.workflow if s.value_recorded]
    if typed:
        findings.append(Finding(
            kind="workflow_value_gap", severity="info",
            message=(f"{len(typed)} workflow step(s) typed or chose a value that "
                     "was not recorded by the capture; a generated script leaves "
                     "them empty rather than inventing one"),
            count=len(typed),
            evidence=Evidence(event_ids=[
                eid for s in typed[:20] for eid in s.evidence.event_ids[:1]]),
        ))
    return findings
