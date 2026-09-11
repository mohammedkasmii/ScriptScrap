"""Request handlers: derived knowledge in, JSON out.

Every handler is a plain function of `(workspace, query) -> dict`, so it is
testable without a socket. The server does routing and authentication; nothing
here knows it is being called over HTTP.

**These handlers derive nothing.** Every value is read from a column
`scriptscrap analyze` wrote, or from an event the log holds. When a view needs
a number that does not exist, the number belongs in the analysis layer with a
test behind it -- a figure computed in a request handler has no evidence trail
and cannot be reproduced by anyone reading the session offline.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from functools import lru_cache
from typing import Any

from ..analysis.events_index import EventStore, StaleIndexError
from .session import SessionHandle


class NotFound(LookupError):
    """No such session, route, or record."""


class BadRequest(ValueError):
    """The query asked for something malformed."""


class EvidenceUnavailable(LookupError):
    """This session has no raw log, so a payload cannot be served."""


# --- helpers --------------------------------------------------------------

def _loads(value: Any, default: Any = None) -> Any:
    """Columns hold JSON text; a malformed one is a bug worth seeing."""
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _one(query: dict[str, list[str]], key: str, default: str | None = None) -> str | None:
    values = query.get(key)
    return values[0] if values else default


def _int(query: dict[str, list[str]], key: str, default: int) -> int:
    raw = _one(query, key)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise BadRequest(f"{key} must be an integer, got {raw!r}") from None


def _handle(workspace, query) -> SessionHandle:
    return workspace.session(_one(query, "session"))


@contextmanager
def _read(handle: SessionHandle):
    """A read-only connection that is always closed.

    `with sqlite3.connect(...) as conn` commits or rolls back; it does not
    close. Twelve handlers wrote `try/finally: conn.close()` and one did not,
    which is the shape of a defect waiting for a slower garbage collector.
    """
    conn = handle.connect()
    try:
        yield conn
    finally:
        conn.close()


def _store(handle: SessionHandle) -> EventStore:
    if handle.log_path is None:
        raise EvidenceUnavailable(
            "this is a sanitised export: it carries derived knowledge only, and "
            "the raw events it was derived from stay in the local session "
            "directory. Open that session to drill through to evidence.")
    return EventStore(handle.db_path, handle.log_path)


@lru_cache(maxsize=4)
def _analysis_cached(log_path: str, size: int, mtime_ns: int):
    """Memoised by the log's identity, not by the session's.

    Keyed on size and mtime as well as path: an appended log is a different
    log, and serving a generator built from the previous one would describe a
    session that no longer exists.
    """
    from ..analysis import pipeline

    return pipeline.analyze_log(log_path)


def _analysis_for(handle: SessionHandle):
    """The AnalysisResult for one session, re-used across requests."""
    if handle.log_path is None:
        raise EvidenceUnavailable(
            "this is a sanitised export; it has no event log to analyse")
    stat = handle.log_path.stat()
    return _analysis_cached(str(handle.log_path), stat.st_size, stat.st_mtime_ns)


_analysis_for.cache_clear = _analysis_cached.cache_clear   # for tests


def _run_id(conn) -> int:
    """The newest run at THIS build's ANALYSIS_VERSION.

    A run from an older version is ignored rather than served: it is a set of
    conclusions the current code would not draw, and a view that rendered it
    would be citing live evidence for stale inference.
    """
    from ..analysis.models import ANALYSIS_VERSION

    row = conn.execute(
        "SELECT id FROM analysis_runs WHERE analysis_version = ? "
        "ORDER BY id DESC LIMIT 1", (ANALYSIS_VERSION,)).fetchone()
    if row is None:
        raise NotFound(
            f"this session has no analysis run at version {ANALYSIS_VERSION}; "
            "run `scriptscrap analyze`")
    return int(row["id"])


# --- sessions -------------------------------------------------------------

def sessions(workspace, query) -> dict:
    """Every session this workspace can open."""
    out = []
    for handle in workspace.sessions:
        with _read(handle) as conn:
            row = conn.execute(
                "SELECT session_id, created_at, event_count, analysis_version "
                "FROM analysis_runs ORDER BY id DESC LIMIT 1").fetchone()
        out.append({
            "name": handle.name,
            "session_id": row["session_id"] if row else None,
            "analysed_at": row["created_at"] if row else None,
            "event_count": row["event_count"] if row else 0,
            "analysis_version": row["analysis_version"] if row else None,
            "redaction": handle.redaction,
            "has_evidence": handle.has_evidence,
        })
    return {"sessions": out}


def session_overview(workspace, query) -> dict:
    """Counts, health, findings and the conditions of capture."""
    handle = _handle(workspace, query)
    with _read(handle) as conn:
        run_id = _run_id(conn)
        run = conn.execute(
            "SELECT * FROM analysis_runs WHERE id=?", (run_id,)).fetchone()

        def count(table: str) -> int:
            return int(conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE run_id=?",  # noqa: S608
                (run_id,)).fetchone()[0])

        counts = {
            name: count(name) for name in
            ("endpoints", "schemas", "dependencies", "ui_elements",
             "states", "state_transitions", "technologies", "findings", "events")
        }
        findings = [{
            "kind": r["kind"],
            "severity": r["severity"],
            "message": r["message"],
            "count": r["count"],
            "evidence_ids": _loads(r["evidence_ids"], []),
        } for r in conn.execute(
            "SELECT * FROM findings WHERE run_id=? ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, kind",
            (run_id,))]

    manifest = handle.manifest()
    by_type: dict[str, int] = {}
    by_source: dict[str, int] = {}
    span = None
    if handle.has_evidence:
        # A sanitised export has no log to count events in. The overview is
        # still the right page for it: everything else on it is derived.
        store = _store(handle)
        try:
            by_type = store.counts_by_type()
            by_source = store.counts_by_source()
            span = store.seq_range()
        finally:
            store.close()

    return {
        "name": handle.name,
        "session_id": run["session_id"],
        "analysed_at": run["created_at"],
        "analysis_version": run["analysis_version"],
        "event_count": run["event_count"],
        "log_size": run["log_size"],
        "redaction": handle.redaction,
        "has_evidence": handle.has_evidence,
        "counts": counts,
        "findings": findings,
        "events_by_type": by_type,
        "events_by_source": by_source,
        "seq_range": list(span) if span else None,
        # A manifest is how a reader judges everything else, so its absence is
        # reported rather than rendered as an empty panel.
        "manifest_present": manifest is not None,
        "health": (manifest or {}).get("capture_health"),
        "browser": (manifest or {}).get("browser"),
        "scope": (manifest or {}).get("scope"),
        "known_blind_spots": (manifest or {}).get("known_blind_spots", []),
        "event_spine": (manifest or {}).get("event_spine"),
    }


# --- endpoints ------------------------------------------------------------

def _endpoint_row(row) -> dict:
    return {
        "id": row["id"],
        "key": row["endpoint_key"],
        "method": row["method"],
        "template": row["template"],
        "kind": row["kind"],
        "templated": bool(row["templated"]),
        "observation_count": row["observation_count"],
        "concrete_paths": _loads(row["concrete_paths"], []),
        "statuses": _loads(row["statuses"], {}),
        "graphql_operation": row["graphql_operation"],
        "confidence": row["confidence"],
        "evidence_signals": _loads(row["evidence_signals"], {}),
        "evidence_ids": _loads(row["evidence_ids"], []),
    }


def endpoints(workspace, query) -> dict:
    handle = _handle(workspace, query)
    with _read(handle) as conn:
        run_id = _run_id(conn)
        rows = conn.execute(
            "SELECT * FROM endpoints WHERE run_id=? ORDER BY template, method",
            (run_id,)).fetchall()
        return {"endpoints": [_endpoint_row(r) for r in rows]}


def endpoint_detail(workspace, query) -> dict:
    """One endpoint with its parameters and inferred schemas."""
    handle = _handle(workspace, query)
    key = _one(query, "endpoint_key")
    if not key:
        raise BadRequest("endpoint_key is required")

    with _read(handle) as conn:
        run_id = _run_id(conn)
        row = conn.execute(
            "SELECT * FROM endpoints WHERE run_id=? AND endpoint_key=?",
            (run_id, key)).fetchone()
        if row is None:
            raise NotFound(f"no endpoint {key!r} in this session")
        detail = _endpoint_row(row)

        detail["params"] = [{
            "name": p["name"],
            "location": p["location"],
            "inferred_type": p["inferred_type"],
            "sample_count": p["sample_count"],
            "distinct_values": p["distinct_values"],
            "examples": _loads(p["examples"], []),
            "enum_candidate": _loads(p["enum_candidate"]),
        } for p in conn.execute(
            "SELECT * FROM endpoint_params WHERE endpoint_id=? ORDER BY location, name",
            (row["id"],))]

        detail["schemas"] = [
            _schema_row(conn, s) for s in conn.execute(
                "SELECT * FROM schemas WHERE run_id=? AND endpoint_key=? "
                "ORDER BY direction, status", (run_id, key))
        ]

        detail["dependencies"] = [{
            "source_endpoint": d["source_endpoint"],
            "source_field": d["source_field"],
            "target_endpoint": d["target_endpoint"],
            "target_field": d["target_field"],
            "mechanism": d["mechanism"],
            "confidence": d["confidence"],
            "evidence_ids": _loads(d["evidence_ids"], []),
        } for d in conn.execute(
            "SELECT * FROM dependencies WHERE run_id=? AND "
            "(source_endpoint=? OR target_endpoint=?)", (run_id, key, key))]
        return detail


def _schema_row(conn, row) -> dict:
    return {
        "direction": row["direction"],
        "status": row["status"],
        "sample_count": row["sample_count"],
        "root_type": row["root_type"],
        "evidence_ids": _loads(row["evidence_ids"], []),
        "fields": [{
            "path": f["path"],
            "inferred_type": f["inferred_type"],
            "types": _loads(f["types"], []),
            "present_count": f["present_count"],
            "sample_count": f["sample_count"],
            "null_count": f["null_count"],
            "observed_optional": bool(f["observed_optional"]),
            "enum_candidate": _loads(f["enum_candidate"]),
            "inferred_format": f["inferred_format"],
            "examples": _loads(f["examples"], []),
        } for f in conn.execute(
            "SELECT * FROM schema_fields WHERE schema_id=? ORDER BY path",
            (row["id"],))],
    }


# --- evidence -------------------------------------------------------------

def event(workspace, query) -> dict:
    """One raw event, by id. The end of every drill-through."""
    handle = _handle(workspace, query)
    event_id = _one(query, "event_id")
    if not event_id:
        raise BadRequest("event_id is required")

    store = _store(handle)
    try:
        found = store.get(event_id)
    except StaleIndexError as exc:
        # Never a blank panel: a stale index means the evidence on screen may
        # not belong to the conclusion that cited it.
        raise BadRequest(str(exc)) from None
    finally:
        store.close()

    if found is None:
        raise NotFound(f"no event {event_id!r} in this session")
    return {"event": found.to_dict()}


def events(workspace, query) -> dict:
    """Several events by id, in the order asked for."""
    handle = _handle(workspace, query)
    raw = _one(query, "ids", "")
    ids = [i for i in (raw or "").split(",") if i]
    if not ids:
        raise BadRequest("ids is required, comma separated")
    if len(ids) > 500:
        raise BadRequest("at most 500 ids per request")

    store = _store(handle)
    try:
        found = store.get_many(ids)
    except StaleIndexError as exc:
        raise BadRequest(str(exc)) from None
    finally:
        store.close()
    return {
        "events": [e.to_dict() for e in found],
        "requested": len(ids),
        "returned": len(found),
    }


# --- timeline -------------------------------------------------------------

MAX_TIMELINE_LIMIT = 500


def _csv(query: dict[str, list[str]], key: str) -> list[str] | None:
    raw = _one(query, key)
    if not raw:
        return None
    return [v for v in raw.split(",") if v]


def timeline(workspace, query) -> dict:
    """A filtered walk of the event log, envelopes only.

    Ordered by `seq`, never by timestamp: sensors deliver over different
    channels and their wall clocks disagree, so `seq` is the only total order
    the spine guarantees.

    Rows carry no payload. A collapsed row shows type, source and time; the
    payload arrives from `/api/event` when a row is opened, which is what keeps
    scrolling a nine-thousand-event session from costing nine thousand seeks.
    """
    handle = _handle(workspace, query)
    limit = _int(query, "limit", 200)
    if not 1 <= limit <= MAX_TIMELINE_LIMIT:
        raise BadRequest(f"limit must be between 1 and {MAX_TIMELINE_LIMIT}")
    after_seq = _int(query, "after_seq", -1)

    store = _store(handle)
    try:
        page = store.page_index(
            types=_csv(query, "types"),
            sources=_csv(query, "sources"),
            page_id=_one(query, "page_id"),
            after_seq=None if after_seq < 0 else after_seq,
            limit=limit,
        )
        facets = {
            "types": store.counts_by_type(),
            "sources": store.counts_by_source(),
        }
    finally:
        store.close()

    return {
        "rows": [{
            "event_id": row.event_id,
            "seq": row.seq,
            "type": row.type,
            "source": row.source,
            "t_wall": row.t_wall,
            "t_mono": row.t_mono,
            "page_id": row.page_id,
            "frame_id": row.frame_id,
        } for row in page.rows],
        "next_seq": page.next_seq,
        "total": page.total,
        "facets": facets,
    }


# --- states ---------------------------------------------------------------

def states(workspace, query) -> dict:
    """Observed application states and the transitions between them."""
    handle = _handle(workspace, query)
    with _read(handle) as conn:
        run_id = _run_id(conn)
        rows = [{
            "label": r["label"],
            "fingerprint": r["fingerprint"],
            "url_pattern": r["url_pattern"],
            "observation_count": r["observation_count"],
            "forms": _loads(r["forms"], []),
            "evidence_ids": _loads(r["evidence_ids"], []),
        } for r in conn.execute(
            "SELECT * FROM states WHERE run_id=? ORDER BY observation_count DESC, label",
            (run_id,))]

        # Transitions reference states by FINGERPRINT, not by label. A graph
        # that drew the raw column would show hashes for node names, so the
        # label is resolved here -- while keeping the fingerprint, because it
        # is the identity and two states can share a label.
        label_of = {r["fingerprint"]: r["label"] for r in rows}
        transitions = [{
            "from_state": t["from_state"],
            "to_state": t["to_state"],
            "from_label": label_of.get(t["from_state"], t["from_state"]),
            "to_label": label_of.get(t["to_state"], t["to_state"]),
            "trigger": t["trigger"],
            # The stable link. `trigger` is a human label; joining a view on it
            # matched nothing, so every transition read "no element recorded".
            "trigger_type": t["trigger_type"],
            "trigger_element_key": t["trigger_element_key"],
            "trigger_event_id": t["trigger_event_id"],
            "observation_count": t["observation_count"],
            "evidence_ids": _loads(t["evidence_ids"], []),
        } for t in conn.execute(
            "SELECT * FROM state_transitions WHERE run_id=? "
            "ORDER BY observation_count DESC", (run_id,))]
        return {"states": rows, "transitions": transitions}


# --- inferred activities --------------------------------------------------

def segments(workspace, query) -> dict:
    """The session split into probable business activities.

    Re-derived from the log per session, memoised on the log's identity like
    the generators are: segments are few and cheap, and keeping them out of the
    store means the SQL shape does not move for a view. A sanitised export has
    no log, so `_analysis_for` raises `EvidenceUnavailable` -- which the server
    turns into a 409 the reader can act on, not a blank panel.
    """
    handle = _handle(workspace, query)
    result = _analysis_for(handle)
    return {"segments": [{
        "index": s.index,
        "start_seq": s.start_seq,
        "end_seq": s.end_seq,
        "start_wall": s.start_wall,
        "end_wall": s.end_wall,
        "duration_ms": s.duration_ms,
        "label": s.label,
        "boundary_reason": s.boundary_reason,
        "outcome": s.outcome,
        "action_count": s.action_count,
        "action_kinds": s.action_kinds,
        "routes": s.routes,
        "forms": s.forms,
        "endpoints": s.endpoints,
        "confidence": s.confidence,
        "evidence_ids": s.evidence.event_ids,
    } for s in result.segments]}


# --- forms ----------------------------------------------------------------

def forms(workspace, query) -> dict:
    """The forms the operator used, with their controls and outcomes.

    Re-derived per session and memoised on the log's identity, like the
    activities view. A sanitised export has no log, so `_analysis_for` raises
    EvidenceUnavailable (409) rather than serving an empty panel.
    """
    handle = _handle(workspace, query)
    result = _analysis_for(handle)
    return {"forms": [{
        "form_id": f.form_id,
        "form_key": f.form_key,
        "page_id": f.page_id,
        "frame_id": f.frame_id,
        "frame_url": f.frame_url,
        "document_instance": f.document_instance,
        "route": f.route,
        "exact_route": f.exact_route,
        "action": f.action,
        "method": f.method,
        "submitted": f.submitted,
        "associated_request": f.associated_request,
        "outcome": f.outcome,
        "controls": [{
            "name": c.name,
            "tag": c.tag,
            "type": c.type,
            "role": c.role,
            "kind": c.kind,
            "label": c.label,
            "placeholder": c.placeholder,
            "required": c.required,
            "disabled": c.disabled,
            "readonly": c.readonly,
            "checked": c.checked,
            "option_value": c.option_value,
            "selected_label": c.selected_label,
            "options": c.options,
            "options_complete": c.options_complete,
            "final_value": c.final_value,
            "secret": c.secret,
            "listbox": c.listbox,
            "connection": c.connection,
        } for c in f.controls],
        "evidence_ids": f.evidence.event_ids,
    } for f in result.forms]}


# --- tables ---------------------------------------------------------------

def tables(workspace, query) -> dict:
    """The tables the operator worked, reconstructed from the interactions.

    Re-derived per session and memoised on the log's identity, like the other
    log-backed views; a sanitised export raises EvidenceUnavailable (409).
    """
    handle = _handle(workspace, query)
    result = _analysis_for(handle)
    return {"tables": [{
        "table_id": t.table_id,
        "table_key": t.table_key,
        "frame_id": t.frame_id,
        "caption": t.caption,
        "columns": t.columns,
        "rows": t.rows,
        "row_actions": t.row_actions,
        "operations": t.operations,
        "evidence_ids": t.evidence.event_ids,
    } for t in result.tables]}


# --- workflow -------------------------------------------------------------

def workflow(workspace, query) -> dict:
    """The observed workflow, in the order it happened.

    Ordered by `ordinal`, which analysis derived from `seq`. Never re-sorted
    here: a view that re-ordered the workflow would be inventing one.
    """
    handle = _handle(workspace, query)
    with _read(handle) as conn:
        run_id = _run_id(conn)
        return {"steps": [{
            "ordinal": r["ordinal"],
            "seq": r["seq"],
            "kind": r["kind"],
            "element_key": r["element_key"],
            "url_pattern": r["url_pattern"],
            "repeat_count": r["repeat_count"],
            "value_recorded": bool(r["value_recorded"]),
            "key": r["key"],
            "evidence_ids": _loads(r["evidence_ids"], []),
        } for r in conn.execute(
            "SELECT * FROM workflow_steps WHERE run_id=? ORDER BY ordinal",
            (run_id,))]}


# --- ui elements ----------------------------------------------------------

def ui_elements(workspace, query) -> dict:
    """Interactive elements, with every locator candidate and its stability.

    Unstable locators are kept rather than filtered. They are precisely what a
    generated script breaks on, so hiding them would hide the risk.
    """
    handle = _handle(workspace, query)
    with _read(handle) as conn:
        run_id = _run_id(conn)
        out = []
        for r in conn.execute(
            "SELECT * FROM ui_elements WHERE run_id=? "
            "ORDER BY observation_count DESC, element_key", (run_id,)
        ):
            out.append({
                "key": r["element_key"],
                "tag": r["tag"],
                "role": r["role"],
                "label": r["label"],
                "text": r["text"],
                "form": r["form"],
                "observation_count": r["observation_count"],
                "actions": _loads(r["actions"], []),
                "recommended": r["recommended"],
                "evidence_ids": _loads(r["evidence_ids"], []),
                "locators": [{
                    "strategy": s["strategy"],
                    "value": s["value"],
                    "resolved_count": s["resolved_count"],
                    "sample_count": s["sample_count"],
                    "stability": s["stability"],
                    "warning": s["warning"],
                } for s in conn.execute(
                    "SELECT * FROM selectors WHERE element_id=? "
                    "ORDER BY stability DESC, strategy", (r["id"],))],
            })
        return {"ui_elements": out}


# --- schemas --------------------------------------------------------------

def schemas(workspace, query) -> dict:
    handle = _handle(workspace, query)
    with _read(handle) as conn:
        run_id = _run_id(conn)
        rows = conn.execute(
            "SELECT * FROM schemas WHERE run_id=? ORDER BY endpoint_key, direction, status",
            (run_id,)).fetchall()
        return {"schemas": [
            {"endpoint_key": r["endpoint_key"], **_schema_row(conn, r)} for r in rows
        ]}


# --- dependencies ---------------------------------------------------------

def dependencies(workspace, query) -> dict:
    """Value-flow edges, plus the node set a graph needs to lay them out.

    Nodes come from the edges rather than from the endpoint table: a graph of
    every endpoint would be mostly isolated dots, and what this view is for is
    the endpoints that actually feed each other.
    """
    handle = _handle(workspace, query)
    with _read(handle) as conn:
        run_id = _run_id(conn)
        edges = [{
            "source_endpoint": d["source_endpoint"],
            "source_field": d["source_field"],
            "target_endpoint": d["target_endpoint"],
            "target_field": d["target_field"],
            "mechanism": d["mechanism"],
            "confidence": d["confidence"],
            "repeat_count": d["repeat_count"],
            "value_uniqueness": d["value_uniqueness"],
            "evidence_signals": _loads(d["evidence_signals"], {}),
            "evidence_ids": _loads(d["evidence_ids"], []),
        } for d in conn.execute(
            "SELECT * FROM dependencies WHERE run_id=? ORDER BY confidence DESC",
            (run_id,))]

        names = {e["source_endpoint"] for e in edges} | {e["target_endpoint"] for e in edges}
        observed = {
            r["endpoint_key"]: r["observation_count"] for r in conn.execute(
                "SELECT endpoint_key, observation_count FROM endpoints WHERE run_id=?",
                (run_id,))
        }
        nodes = {name: {"key": name, "observation_count": observed.get(name, 0)}
                 for name in sorted(names)}
        return {"nodes": nodes, "dependencies": edges}


# --- technology -----------------------------------------------------------

def technologies(workspace, query) -> dict:
    handle = _handle(workspace, query)
    with _read(handle) as conn:
        run_id = _run_id(conn)
        return {"technologies": [{
            "name": r["name"],
            "category": r["category"],
            "confidence": r["confidence"],
            "signals": _loads(r["signals"], []),
            "evidence_ids": _loads(r["evidence_ids"], []),
        } for r in conn.execute(
            "SELECT * FROM technologies WHERE run_id=? ORDER BY confidence DESC, name",
            (run_id,))]}


# --- generated starting points --------------------------------------------

def generate(workspace, query) -> dict:
    """Render a generator's output for the open session.

    Generated in memory and returned as text. The workspace writes nothing:
    it is read-only, and a viewer that dropped files into the operator's
    session directory would be neither.

    This re-runs analysis rather than reading the derived store, because the
    generators take an `AnalysisResult` and rebuilding one from SQL rows would
    be a second, drifting deserialiser for the same model. The result is
    memoised on the log's path, size and mtime, so re-rendering the view does
    not re-analyse a log that has not changed.
    """
    from ..generate import GeneratedSourceError, render_client, render_playwright

    handle = _handle(workspace, query)
    kind = _one(query, "kind", "client")
    renderers = {"client": render_client, "playwright": render_playwright}
    if kind not in renderers:
        raise BadRequest(f"unknown generator {kind!r}; try one of {sorted(renderers)}")

    result = _analysis_for(handle)
    try:
        source = renderers[kind](result, session_name=handle.name)
    except GeneratedSourceError as exc:
        # A generator that cannot produce valid Python is a 400 with the
        # reason, not a 500 with a traceback in a screen-shared console.
        raise BadRequest(str(exc)) from None
    return {
        "kind": kind,
        "filename": "generated_client.py" if kind == "client" else "observed_workflow.py",
        "source": source,
        "endpoints": len(result.endpoints),
        "states": len(result.states),
        "auth_headers": sorted(result.auth_headers),
    }


ROUTES = {
    "sessions": sessions,
    "generate": generate,
    "segments": segments,
    "forms": forms,
    "tables": tables,
    "session": session_overview,
    "endpoints": endpoints,
    "endpoint": endpoint_detail,
    "events": events,
    "event": event,
    "timeline": timeline,
    "states": states,
    "workflow": workflow,
    "ui_elements": ui_elements,
    "schemas": schemas,
    "dependencies": dependencies,
    "technologies": technologies,
}

# Routes with a path parameter, matched positionally by the server.
DYNAMIC_ROUTES = [
    ("event/<event_id>", event),
]
