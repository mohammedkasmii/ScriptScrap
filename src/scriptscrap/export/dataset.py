"""Shareable export: derived knowledge, sanitised.

What goes in the shared export is a whitelist, not a blacklist. Raw bodies,
screenshots and authenticated HTML are excluded because they cannot be made safe
by pattern matching -- their safety would depend on having anticipated every
shape a secret can take. Derived knowledge is included because it is already an
abstraction over those bodies: a schema says a field is a string of length 14,
not what the string was.

Documents and artifacts are metadata only. Screenshots are never included.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..analysis.models import AnalysisResult
from .redact import Redactor

# Signals that describe a value's shape rather than carry it are safe to keep;
# anything holding an observed value goes through the redactor.
_SAFE_SIGNAL_KEYS = frozenset({
    "observations", "distinct_concrete_paths", "templated_from_sibling_paths",
    "exact_value_match", "unique_value_match", "endpoints_touched",
    "field_name_similarity", "ordering_method", "temporal_distance_ms",
    "same_frame", "mechanism", "repeat_count", "strategies_measured",
    "route_shape", "trigger_type", "attribution", "interpretation",
    "state_fields", "operation_fields", "operations", "transport_paths",
})


class DatasetExporter:
    """Writes a sanitised, shareable view of one analysis run."""

    def __init__(self, redactor: Redactor | None = None) -> None:
        self.redactor = redactor or Redactor()

    def build(self, result: AnalysisResult) -> dict[str, Any]:
        r = self.redactor
        return {
            "schema": "scriptscrap/shared-dataset/1",
            "session_id": r.pseudonyms.fingerprint(result.session_id),
            "analysis_version": result.analysis_version,
            "event_count": result.event_count,
            "notice": (
                "Derived knowledge only. Credentials removed; identifiers and "
                "emails replaced by stable pseudonyms so value propagation stays "
                "analysable. Raw bodies, screenshots and HTML snapshots are NOT "
                "included and remain in the local session directory."
            ),
            "technologies": [
                {"name": t.name, "category": t.category, "confidence": t.confidence,
                 "signals": [r.scrub_text(s) for s in t.signals],
                 "evidence_ids": t.evidence.event_ids}
                for t in result.technologies
            ],
            "endpoints": [
                {
                    "key": e.key, "method": e.method, "template": e.template,
                    "kind": e.kind, "templated": e.templated,
                    "observation_count": e.observation_count,
                    "confidence": e.confidence,
                    "statuses": e.statuses,
                    "concrete_paths": [r.scrub_text(p) for p in e.concrete_paths],
                    "graphql_operation": e.graphql_operation,
                    "graphql_operation_type": e.graphql_operation_type,
                    "params": [
                        {"name": p.name, "location": p.location,
                         "inferred_type": p.inferred_type,
                         "sample_count": p.sample_count,
                         "distinct_values": p.distinct_values,
                         "examples": [r.scrub_example(v) for v in p.examples],
                         "enum_candidate": (
                             [r.scrub_example(v) for v in p.enum_candidate]
                             if p.enum_candidate else None),
                         }
                        for p in e.params
                    ],
                    "evidence_ids": e.evidence.event_ids,
                }
                for e in result.endpoints
            ],
            "schemas": [
                {
                    "endpoint": s.endpoint_key, "direction": s.direction,
                    "status": s.status, "sample_count": s.sample_count,
                    "root_type": s.root_type,
                    "fields": [
                        {"path": f.path, "inferred_type": f.inferred_type,
                         "present": f"{f.present_count}/{f.sample_count}",
                         "observed_optional": f.observed_optional,
                         "null_count": f.null_count,
                         "inferred_format": f.inferred_format,
                         "enum_candidate": (
                             [r.scrub_example(v) for v in f.enum_candidate]
                             if f.enum_candidate else None),
                         "examples": [r.scrub_example(v) for v in f.examples]}
                        for f in s.fields
                    ],
                    "evidence_ids": s.evidence.event_ids,
                }
                for s in result.schemas
            ],
            "dependencies": [
                {
                    "source": f"{d.source_endpoint} {d.source_field}",
                    "target": f"{d.target_endpoint} {d.target_field}",
                    "mechanism": d.mechanism, "confidence": d.confidence,
                    "repeat_count": d.repeat_count,
                    "value_uniqueness": d.value_uniqueness,
                    "evidence": self._safe_signals(d.evidence.signals),
                    "evidence_ids": d.evidence.event_ids,
                }
                for d in result.dependencies
            ],
            "ui_elements": [
                {
                    "tag": u.tag, "role": u.role,
                    "label": r.scrub_text(u.label) if u.label else None,
                    "text": r.scrub_text(u.text) if u.text else None,
                    "form": u.form, "observation_count": u.observation_count,
                    "actions": u.actions,
                    "recommended": (
                        {"strategy": u.recommended.strategy,
                         "value": r.scrub_text(u.recommended.value),
                         "stability": round(u.recommended.stability, 3)}
                        if u.recommended else None),
                    "locators": [
                        {"strategy": loc.strategy, "value": r.scrub_text(loc.value),
                         "stability": round(loc.stability, 3),
                         "resolved": f"{loc.resolved_count}/{loc.sample_count}",
                         "warning": loc.warning}
                        for loc in u.locators
                    ],
                    "evidence_ids": u.evidence.event_ids,
                }
                for u in result.ui_elements
            ],
            "states": [
                {"fingerprint": s.fingerprint, "label": s.label,
                 "url_pattern": s.url_pattern,
                 "observation_count": s.observation_count, "forms": s.forms,
                 "evidence_ids": s.evidence.event_ids}
                for s in result.states
            ],
            "transitions": [
                {"from": t.from_state, "to": t.to_state, "trigger": t.trigger,
                 "observation_count": t.observation_count,
                 "evidence": self._safe_signals(t.evidence.signals),
                 "evidence_ids": t.evidence.event_ids}
                for t in result.transitions
            ],
            "findings": [
                {"kind": f.kind, "severity": f.severity,
                 "message": r.scrub_text(f.message), "count": f.count,
                 "evidence_ids": f.evidence.event_ids}
                for f in result.findings
            ],
            # --- forensic evidence, sanitised ---------------------------
            # Script SOURCE is never exported. A target application's code is
            # its own; the hash lets a holder of the raw session prove which
            # file this describes, and the inventory says what is in it without
            # reproducing it.
            "scripts": [
                {
                    "url": r.scrub_text(s.get("url") or ""),
                    "sha256": s.get("sha256"),
                    "size": s.get("size"),
                    "media_type": s.get("media_type"),
                    "source_map": s.get("source_map"),
                    "declared_functions": (s.get("inventory") or {}).get(
                        "declared_functions", []),
                    "network_apis": (s.get("inventory") or {}).get("network_apis", []),
                    "url_literals": [
                        r.scrub_text(u)
                        for u in (s.get("inventory") or {}).get("url_literals", [])
                    ],
                    "evidence_ids": s.get("evidence_ids", []),
                    "note": "source text is NOT exported; it remains in the local blob store",
                }
                for s in result.scripts
            ],
            "capture_health": result.health,
            "reconciliation": self._reconciliation(result),
            "redaction": self.redactor.stats(),
        }

    @staticmethod
    def _reconciliation(result: AnalysisResult) -> dict[str, Any]:
        """Multi-sensor agreement, as counts and relationships only."""
        from ..analysis.reconcile import summarise

        summary = summarise(result.activities) if result.activities else {}
        conflicts = [
            {
                "activity": a.key,
                "relation": a.relation,
                "sensors": sorted(a.sensors),
                "conflicts": a.conflicts,
                "evidence_ids": a.evidence.event_ids,
            }
            for a in result.activities if a.conflicts
        ]
        return {"summary": summary, "conflicts": conflicts}

    def _safe_signals(self, signals: dict[str, Any]) -> dict[str, Any]:
        """Keep shape-describing signals; redact anything carrying a value."""
        out: dict[str, Any] = {}
        for key, value in signals.items():
            if key in _SAFE_SIGNAL_KEYS:
                out[key] = value
            else:
                out[key] = self.redactor.scrub(value, name=key)
        return out

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
