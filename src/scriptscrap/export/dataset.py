"""Shareable export: derived knowledge, sanitised.

What goes in the shared export is decided field by field, deny by default, in
`policy.py`. This module only SERIALISES a result that has already been through
`sanitise()`. Nothing here redacts: if a value reaching this file is unsafe,
the defect is a disposition in the policy table, and a second scrubber here
would hide it.

Documents and artifacts are metadata only. Screenshots are never included.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..analysis.models import AnalysisResult
from .policy import sanitise
from .redact import Redactor

NOTICE = (
    "Derived knowledge only, sanitised field by field, deny by default. Route "
    "shapes and authored names survive. Every code -- method, kind, strategy, "
    "severity, sensor -- is checked against a closed vocabulary, and an "
    "unknown value fails the export rather than being emitted. Element labels "
    "and element text are NOT included in any form. Free text that is reported "
    "at all is reduced to a COARSE SIZE BUCKET (0, 1-10, 11-50, 51-200, 200+) "
    "plus a stable pseudonym, so repeated values stay correlatable; no exact "
    "length or word count is published. A locator that carried application "
    "text is replaced by a fixed marker rather than shaped, so it cannot be "
    "mistaken for one that still works. Credentials are removed. Raw bodies, "
    "screenshots, HTML snapshots, script inventories and the evidence index "
    "are NOT included and remain in the local session directory."
)


class DatasetExporter:
    """Writes a sanitised, shareable view of one analysis run."""

    def __init__(self, redactor: Redactor | None = None) -> None:
        self.redactor = redactor or Redactor()

    def build(self, result: AnalysisResult) -> dict[str, Any]:
        """Sanitise, then serialise. The two are separate on purpose."""
        return self.build_from_sanitised(sanitise(result, self.redactor))

    def build_from_sanitised(self, safe: AnalysisResult) -> dict[str, Any]:
        """Serialise a result that has ALREADY been through `sanitise`.

        Nothing here redacts. If a value in `safe` is unsafe, the defect is in
        `export/policy.py`, and putting a second scrubber here would hide it.
        """
        return {
            "schema": "scriptscrap/shared-dataset/2",
            "session_id": safe.session_id,
            "analysis_version": safe.analysis_version,
            "event_count": safe.event_count,
            "notice": NOTICE,
            "technologies": [
                {"name": t.name, "category": t.category,
                 "confidence": t.confidence, "signal_count": t.signal_count,
                 "evidence_ids": t.evidence.event_ids}
                for t in safe.technologies
            ],
            "endpoints": [
                {
                    "key": e.key, "method": e.method, "template": e.template,
                    "kind": e.kind, "templated": e.templated,
                    "observation_count": e.observation_count,
                    "confidence": e.confidence,
                    "statuses": e.statuses,
                    "concrete_paths": e.concrete_paths,
                    "graphql_operation": e.graphql_operation,
                    "graphql_operation_type": e.graphql_operation_type,
                    "params": [
                        {"name": p.name, "location": p.location,
                         "inferred_type": p.inferred_type,
                         "sample_count": p.sample_count,
                         "distinct_values": p.distinct_values,
                         "examples": p.examples,
                         "enum_candidate": p.enum_candidate}
                        for p in e.params
                    ],
                    "evidence_ids": e.evidence.event_ids,
                }
                for e in safe.endpoints
            ],
            "schemas": [
                {
                    "endpoint": s.endpoint_key, "direction": s.direction,
                    "status": s.status, "sample_count": s.sample_count,
                    "root_type": s.root_type,
                    "fields": [
                        {"path": f.path, "inferred_type": f.inferred_type,
                         "present": f"{f.present_count}/{f.sample_count}",
                         "occurrence_count": f.occurrence_count,
                         "observed_optional": f.observed_optional,
                         "null_count": f.null_count,
                         "inferred_format": f.inferred_format,
                         "enum_candidate": f.enum_candidate,
                         "examples": f.examples}
                        for f in s.fields
                    ],
                    "evidence_ids": s.evidence.event_ids,
                }
                for s in safe.schemas
            ],
            "dependencies": [
                {
                    "source": f"{d.source_endpoint} {d.source_field}",
                    "target": f"{d.target_endpoint} {d.target_field}",
                    "mechanism": d.mechanism, "confidence": d.confidence,
                    "repeat_count": d.repeat_count,
                    "value_uniqueness": d.value_uniqueness,
                    "evidence": d.evidence.signals,
                    "evidence_ids": d.evidence.event_ids,
                }
                for d in safe.dependencies
            ],
            "ui_elements": [
                {
                    "tag": u.tag, "role": u.role,
                    "form": u.form, "observation_count": u.observation_count,
                    "actions": u.actions,
                    "recommended": (
                        {"strategy": u.recommended.strategy,
                         "value": u.recommended.value,
                         "stability": round(u.recommended.stability, 3)}
                        if u.recommended else None),
                    "locators": [
                        {"strategy": loc.strategy, "value": loc.value,
                         "stability": round(loc.stability, 3),
                         "resolved": f"{loc.resolved_count}/{loc.sample_count}",
                         "warning_code": loc.warning_code}
                        for loc in u.locators
                    ],
                    "evidence_ids": u.evidence.event_ids,
                }
                for u in safe.ui_elements
            ],
            "states": [
                {"fingerprint": s.fingerprint, "label": s.label,
                 "url_pattern": s.url_pattern,
                 "observation_count": s.observation_count, "forms": s.forms,
                 "evidence_ids": s.evidence.event_ids}
                for s in safe.states
            ],
            "transitions": [
                {"from": t.from_state, "to": t.to_state,
                 "observation_count": t.observation_count,
                 "evidence": t.evidence.signals,
                 "evidence_ids": t.evidence.event_ids}
                for t in safe.transitions
            ],
            "findings": [
                {"kind": f.kind, "severity": f.severity, "count": f.count,
                 "evidence_ids": f.evidence.event_ids}
                for f in safe.findings
            ],
            "capture_health": safe.health,
            "auth_header_names": sorted(safe.auth_headers),
            "redaction": {**self.redactor.stats(), "policy_version": "2"},
        }

    def write(self, result: AnalysisResult, directory: str | Path) -> Path:
        target = Path(directory)
        target.mkdir(parents=True, exist_ok=True)
        payload = self.build(result)
        path = target / "dataset.json"
        path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return path
