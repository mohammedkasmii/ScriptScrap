"""SQLite store for derived knowledge.

    events.jsonl    source of truth, append-only, never rewritten
    session.sqlite  derived, rebuildable, safe to delete

Deleting the database and re-running analysis must reproduce it. That is not a
nice property to have, it is the test: if the store held anything that could not
be re-derived, it would have become a second source of truth.

Chosen over more elaborate stores because the queries this needs are joins and
aggregates over a few thousand rows, and a graph database or a columnar format
would add a dependency to answer questions SQLite answers in a single file.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import ANALYSIS_VERSION, AnalysisResult

SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS analysis_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       TEXT    NOT NULL,
    created_at       TEXT    NOT NULL,
    analysis_version INTEGER NOT NULL,
    event_count      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                INTEGER NOT NULL REFERENCES analysis_runs(id),
    endpoint_key          TEXT    NOT NULL,
    method                TEXT    NOT NULL,
    template              TEXT    NOT NULL,
    kind                  TEXT    NOT NULL,
    templated             INTEGER NOT NULL,
    observation_count     INTEGER NOT NULL,
    concrete_paths        TEXT    NOT NULL,
    statuses              TEXT    NOT NULL,
    graphql_operation     TEXT,
    graphql_operation_type TEXT,
    persisted_query_hash  TEXT,
    confidence            REAL    NOT NULL,
    evidence_signals      TEXT    NOT NULL,
    evidence_ids          TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoint_params (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id     INTEGER NOT NULL REFERENCES endpoints(id),
    name            TEXT    NOT NULL,
    location        TEXT    NOT NULL,
    inferred_type   TEXT    NOT NULL,
    sample_count    INTEGER NOT NULL,
    distinct_values INTEGER NOT NULL,
    examples        TEXT    NOT NULL,
    enum_candidate  TEXT
);

CREATE TABLE IF NOT EXISTS schemas (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       INTEGER NOT NULL REFERENCES analysis_runs(id),
    endpoint_key TEXT    NOT NULL,
    direction    TEXT    NOT NULL,
    status       TEXT,
    sample_count INTEGER NOT NULL,
    root_type    TEXT    NOT NULL,
    evidence_ids TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_fields (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    schema_id         INTEGER NOT NULL REFERENCES schemas(id),
    path              TEXT    NOT NULL,
    inferred_type     TEXT    NOT NULL,
    types             TEXT    NOT NULL,
    present_count     INTEGER NOT NULL,
    sample_count      INTEGER NOT NULL,
    null_count        INTEGER NOT NULL,
    observed_optional INTEGER NOT NULL,
    enum_candidate    TEXT,
    inferred_format   TEXT,
    examples          TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS dependencies (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           INTEGER NOT NULL REFERENCES analysis_runs(id),
    source_endpoint  TEXT    NOT NULL,
    source_field     TEXT    NOT NULL,
    target_endpoint  TEXT    NOT NULL,
    target_field     TEXT    NOT NULL,
    mechanism        TEXT    NOT NULL,
    confidence       REAL    NOT NULL,
    repeat_count     INTEGER NOT NULL,
    value_uniqueness INTEGER NOT NULL,
    evidence_signals TEXT    NOT NULL,
    evidence_ids     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS ui_elements (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            INTEGER NOT NULL REFERENCES analysis_runs(id),
    element_key       TEXT    NOT NULL,
    tag               TEXT    NOT NULL,
    role              TEXT,
    label             TEXT,
    text              TEXT,
    form              TEXT,
    observation_count INTEGER NOT NULL,
    actions           TEXT    NOT NULL,
    recommended       TEXT,
    evidence_ids      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS selectors (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    element_id     INTEGER NOT NULL REFERENCES ui_elements(id),
    strategy       TEXT    NOT NULL,
    value          TEXT    NOT NULL,
    resolved_count INTEGER NOT NULL,
    sample_count   INTEGER NOT NULL,
    stability      REAL    NOT NULL,
    warning        TEXT
);

CREATE TABLE IF NOT EXISTS states (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            INTEGER NOT NULL REFERENCES analysis_runs(id),
    fingerprint       TEXT    NOT NULL,
    label             TEXT    NOT NULL,
    url_pattern       TEXT    NOT NULL,
    observation_count INTEGER NOT NULL,
    forms             TEXT    NOT NULL,
    evidence_ids      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS state_transitions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            INTEGER NOT NULL REFERENCES analysis_runs(id),
    from_state        TEXT    NOT NULL,
    to_state          TEXT    NOT NULL,
    trigger           TEXT    NOT NULL,
    observation_count INTEGER NOT NULL,
    evidence_ids      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS technologies (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       INTEGER NOT NULL REFERENCES analysis_runs(id),
    name         TEXT    NOT NULL,
    category     TEXT    NOT NULL,
    confidence   REAL    NOT NULL,
    signals      TEXT    NOT NULL,
    evidence_ids TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       INTEGER NOT NULL REFERENCES analysis_runs(id),
    kind         TEXT    NOT NULL,
    severity     TEXT    NOT NULL,
    message      TEXT    NOT NULL,
    count        INTEGER NOT NULL,
    evidence_ids TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_endpoints_run  ON endpoints(run_id);
CREATE INDEX IF NOT EXISTS ix_schemas_run    ON schemas(run_id);
CREATE INDEX IF NOT EXISTS ix_deps_run       ON dependencies(run_id);
CREATE INDEX IF NOT EXISTS ix_elements_run   ON ui_elements(run_id);
CREATE INDEX IF NOT EXISTS ix_fields_schema  ON schema_fields(schema_id);
CREATE INDEX IF NOT EXISTS ix_selectors_elem ON selectors(element_id);
"""


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


class DerivedStore:
    """Writes an AnalysisResult into SQLite and reads it back."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    def __enter__(self) -> DerivedStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- writing -----------------------------------------------------------
    def write(self, result: AnalysisResult) -> int:
        """Persist one analysis run. Returns its run id."""
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO analysis_runs (session_id, created_at, analysis_version, event_count) "
            "VALUES (?, ?, ?, ?)",
            (result.session_id, datetime.now(UTC).isoformat(),
             result.analysis_version, result.event_count),
        )
        run_id = int(cur.lastrowid or 0)

        for endpoint in result.endpoints:
            cur.execute(
                "INSERT INTO endpoints (run_id, endpoint_key, method, template, kind, templated,"
                " observation_count, concrete_paths, statuses, graphql_operation,"
                " graphql_operation_type, persisted_query_hash, confidence,"
                " evidence_signals, evidence_ids)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, endpoint.key, endpoint.method, endpoint.template, endpoint.kind,
                 int(endpoint.templated), endpoint.observation_count,
                 _dumps(endpoint.concrete_paths), _dumps(endpoint.statuses),
                 endpoint.graphql_operation, endpoint.graphql_operation_type,
                 endpoint.persisted_query_hash, endpoint.confidence,
                 _dumps(endpoint.evidence.signals), _dumps(endpoint.evidence.event_ids)),
            )
            endpoint_id = int(cur.lastrowid or 0)
            for param in endpoint.params:
                cur.execute(
                    "INSERT INTO endpoint_params (endpoint_id, name, location, inferred_type,"
                    " sample_count, distinct_values, examples, enum_candidate)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (endpoint_id, param.name, param.location, param.inferred_type,
                     param.sample_count, param.distinct_values, _dumps(param.examples),
                     _dumps(param.enum_candidate) if param.enum_candidate else None),
                )

        for schema in result.schemas:
            cur.execute(
                "INSERT INTO schemas (run_id, endpoint_key, direction, status, sample_count,"
                " root_type, evidence_ids) VALUES (?,?,?,?,?,?,?)",
                (run_id, schema.endpoint_key, schema.direction, schema.status,
                 schema.sample_count, schema.root_type, _dumps(schema.evidence.event_ids)),
            )
            schema_id = int(cur.lastrowid or 0)
            for f in schema.fields:
                cur.execute(
                    "INSERT INTO schema_fields (schema_id, path, inferred_type, types,"
                    " present_count, sample_count, null_count, observed_optional,"
                    " enum_candidate, inferred_format, examples)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (schema_id, f.path, f.inferred_type, _dumps(f.types), f.present_count,
                     f.sample_count, f.null_count, int(f.observed_optional),
                     _dumps(f.enum_candidate) if f.enum_candidate else None,
                     f.inferred_format, _dumps(f.examples)),
                )

        for dep in result.dependencies:
            cur.execute(
                "INSERT INTO dependencies (run_id, source_endpoint, source_field,"
                " target_endpoint, target_field, mechanism, confidence, repeat_count,"
                " value_uniqueness, evidence_signals, evidence_ids)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, dep.source_endpoint, dep.source_field, dep.target_endpoint,
                 dep.target_field, dep.mechanism, dep.confidence, dep.repeat_count,
                 dep.value_uniqueness, _dumps(dep.evidence.signals),
                 _dumps(dep.evidence.event_ids)),
            )

        for element in result.ui_elements:
            recommended = element.recommended
            cur.execute(
                "INSERT INTO ui_elements (run_id, element_key, tag, role, label, text, form,"
                " observation_count, actions, recommended, evidence_ids)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, element.key, element.tag, element.role, element.label, element.text,
                 element.form, element.observation_count, _dumps(element.actions),
                 f"{recommended.strategy}={recommended.value}" if recommended else None,
                 _dumps(element.evidence.event_ids)),
            )
            element_id = int(cur.lastrowid or 0)
            for locator in element.locators:
                cur.execute(
                    "INSERT INTO selectors (element_id, strategy, value, resolved_count,"
                    " sample_count, stability, warning) VALUES (?,?,?,?,?,?,?)",
                    (element_id, locator.strategy, locator.value, locator.resolved_count,
                     locator.sample_count, locator.stability, locator.warning),
                )

        for state in result.states:
            cur.execute(
                "INSERT INTO states (run_id, fingerprint, label, url_pattern,"
                " observation_count, forms, evidence_ids) VALUES (?,?,?,?,?,?,?)",
                (run_id, state.fingerprint, state.label, state.url_pattern,
                 state.observation_count, _dumps(state.forms),
                 _dumps(state.evidence.event_ids)),
            )

        for transition in result.transitions:
            cur.execute(
                "INSERT INTO state_transitions (run_id, from_state, to_state, trigger,"
                " observation_count, evidence_ids) VALUES (?,?,?,?,?,?)",
                (run_id, transition.from_state, transition.to_state, transition.trigger,
                 transition.observation_count, _dumps(transition.evidence.event_ids)),
            )

        for tech in result.technologies:
            cur.execute(
                "INSERT INTO technologies (run_id, name, category, confidence, signals,"
                " evidence_ids) VALUES (?,?,?,?,?,?)",
                (run_id, tech.name, tech.category, tech.confidence, _dumps(tech.signals),
                 _dumps(tech.evidence.event_ids)),
            )

        for finding in result.findings:
            cur.execute(
                "INSERT INTO findings (run_id, kind, severity, message, count, evidence_ids)"
                " VALUES (?,?,?,?,?,?)",
                (run_id, finding.kind, finding.severity, finding.message, finding.count,
                 _dumps(finding.evidence.event_ids)),
            )

        self.conn.commit()
        return run_id

    # -- reading -----------------------------------------------------------
    def latest_run(self) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM analysis_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()

    def rows(self, table: str, run_id: int) -> list[sqlite3.Row]:
        if table not in ALLOWED_TABLES:
            raise ValueError(f"unknown table {table!r}")
        # Table names cannot be bound as parameters; the allow-list above is the
        # control, and run_id IS bound.
        query = f"SELECT * FROM {table} WHERE run_id = ? ORDER BY id"  # noqa: S608
        return list(self.conn.execute(query, (run_id,)))

    def children(self, table: str, fk: str, parent_id: int) -> list[sqlite3.Row]:
        if table not in ALLOWED_CHILD_TABLES or fk not in ALLOWED_FKS:
            raise ValueError(f"unknown child query {table!r}.{fk!r}")
        query = f"SELECT * FROM {table} WHERE {fk} = ? ORDER BY id"  # noqa: S608
        return list(self.conn.execute(query, (parent_id,)))


# Identifiers cannot be parameterised in SQL, so they are allow-listed instead
# of interpolated from caller input.
ALLOWED_TABLES = frozenset({
    "endpoints", "schemas", "dependencies", "ui_elements",
    "states", "state_transitions", "technologies", "findings",
})
ALLOWED_CHILD_TABLES = frozenset({"endpoint_params", "schema_fields", "selectors"})
ALLOWED_FKS = frozenset({"endpoint_id", "schema_id", "element_id"})

__all__ = ["ANALYSIS_VERSION", "DerivedStore"]
