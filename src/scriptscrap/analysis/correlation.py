"""Dependency correlation: evidence-backed hypotheses, not binary edges.

The previous generation indexed every leaf value of every response and claimed a
dependency whenever the value reappeared. That produced inverted edges (the
index was last-write-wins), and a flood of false positives from values like
`"0"`, `"OK"` and `true` that appear everywhere.

This replaces it with **gate, then score**:

    gate    reject candidates that cannot be a dependency at all
    score   rank survivors by an evidence vector that is stored with the edge

The most important gate is temporal, and it is the one M2 made hard. `seq` is
INGEST order: sensors deliver over independent channels, so `A.seq < B.seq`
does NOT mean A happened before B when A and B came from different sensors.
Ordering therefore uses the strongest evidence available for each pair, and
records which kind was used:

    same_source_seq   both from one sensor -> its ingest order IS its own order
    probe_ordinal     both from the runtime probe -> exact in-page order
    wall_clock        different sensors -> timestamps, with a tolerance window
    unordered         cannot be established -> the candidate is dropped

Confidence is a deterministic function of the stored evidence vector. It is not
calibrated against ground truth, and it is not hidden: a reader who disagrees
with the weighting can recompute it from the evidence.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ..events import Event, EventType, Source
from .models import DependencyEdge, Evidence

# Values that carry no identity. A match on one of these is noise.
STOPWORD_VALUES = frozenset({
    "true", "false", "null", "none", "nil", "undefined",
    "0", "1", "-1", "00", "000", "yes", "no", "y", "n",
    "ok", "okay", "error", "success", "failure", "failed", "pending",
    "active", "inactive", "enabled", "disabled", "on", "off",
    "get", "post", "put", "delete", "patch",
    "asc", "desc", "all", "default", "unknown", "test",
})

MIN_VALUE_LENGTH = 4
MAX_VALUE_LENGTH = 200

# A value seen in more than this many distinct endpoints is ambient (a session
# id, a locale, a tenant) rather than a value one call handed to another.
MAX_ENDPOINTS_FOR_CANDIDATE = 6

# Cross-sensor timestamps cannot be trusted to fine resolution, so ordering
# within this window is treated as "cannot establish order".
CLOCK_TOLERANCE_MS = 50.0

# Beyond this, temporal proximity stops being evidence of anything.
PROXIMITY_WINDOW_MS = 120_000.0

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def normalize_field_tokens(field_path: str) -> set[str]:
    """`$.data.missionId` -> {'mission', 'id'}, so idMission matches missionId."""
    leaf = field_path.rsplit(".", 1)[-1].replace("[]", "")
    spaced = _CAMEL.sub(" ", leaf)
    tokens = {t for t in _TOKEN_SPLIT.split(spaced.lower()) if t}
    # Singularise crudely; good enough to match items/item.
    return {t[:-1] if len(t) > 3 and t.endswith("s") else t for t in tokens}


def field_name_similarity(a: str, b: str) -> float:
    """Jaccard over normalised tokens."""
    ta, tb = normalize_field_tokens(a), normalize_field_tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def _parse_wall(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp() * 1000.0
    except (TypeError, ValueError):
        return None


@dataclass(slots=True)
class ValueObservation:
    """One place a value was seen."""

    event_id: str
    seq: int
    source: Source
    endpoint: str
    field_path: str
    role: str                 # "producer" | "consumer"
    kind: str                 # response | request | dom | storage | user_input
    wall_ms: float | None
    probe_ordinal: int | None
    frame_id: str | None
    trace_hint: str | None    # runtime stack top, when available


class _Ordering:
    """Decides whether one observation can be said to precede another."""

    @staticmethod
    def compare(a: ValueObservation, b: ValueObservation) -> tuple[bool, str, float | None]:
        """(a_precedes_b, method, distance_ms)."""
        if a.source is b.source:
            # One sensor, one channel: its ingest order is its own order.
            if a.probe_ordinal is not None and b.probe_ordinal is not None:
                delta = None
                if a.wall_ms is not None and b.wall_ms is not None:
                    delta = b.wall_ms - a.wall_ms
                return a.probe_ordinal < b.probe_ordinal, "probe_ordinal", delta
            delta = (b.wall_ms - a.wall_ms) if (a.wall_ms and b.wall_ms) else None
            return a.seq < b.seq, "same_source_seq", delta

        # Different sensors: seq is meaningless here, fall back to wall clock.
        if a.wall_ms is None or b.wall_ms is None:
            return False, "unordered", None
        delta = b.wall_ms - a.wall_ms
        if delta <= CLOCK_TOLERANCE_MS:
            # Inside the tolerance the two are indistinguishable in time.
            return False, "unordered", delta
        return True, "wall_clock", delta


class CorrelationAnalyzer:
    """Builds scored dependency hypotheses from value propagation."""

    def __init__(self, *, min_confidence: float = 0.35) -> None:
        self.min_confidence = min_confidence
        self.rejected: list[dict[str, Any]] = []

    # -- entry point -------------------------------------------------------
    def analyze(self, events: list[Event], endpoint_of: dict[str, str]) -> list[DependencyEdge]:
        index = self._index_values(events, endpoint_of)
        edges: list[DependencyEdge] = []

        for value, observations in index.items():
            producers = [o for o in observations if o.role == "producer"]
            consumers = [o for o in observations if o.role == "consumer"]
            if not producers or not consumers:
                continue

            endpoints_touched = len({o.endpoint for o in observations})
            if endpoints_touched > MAX_ENDPOINTS_FOR_CANDIDATE:
                self.rejected.append({
                    "value_preview": value[:24],
                    "reason": "ambient_value",
                    "endpoints_touched": endpoints_touched,
                })
                continue

            for edge in self._pair(value, producers, consumers, endpoints_touched):
                edges.append(edge)

        merged = self._merge(edges)
        return sorted(merged, key=lambda e: (-e.confidence, e.label))

    # -- indexing ----------------------------------------------------------
    def _index_values(
        self, events: list[Event], endpoint_of: dict[str, str]
    ) -> dict[str, list[ValueObservation]]:
        """value -> where it was seen.

        An index rather than pairwise comparison: comparing every observation
        against every other is quadratic in the number of values, and a long
        session has a lot of values.
        """
        index: dict[str, list[ValueObservation]] = defaultdict(list)

        for event in events:
            payload = event.payload
            wall = _parse_wall(event.t_wall)
            probe_ordinal = payload.get("probe_ordinal")
            endpoint = endpoint_of.get(event.event_id, "")

            if event.type is EventType.HTTP_RESPONSE:
                self._harvest(index, payload.get("body"), "$", event, endpoint,
                              "producer", "response", wall, probe_ordinal, None)

            elif event.type is EventType.HTTP_REQUEST:
                self._harvest(index, payload.get("body"), "$", event, endpoint,
                              "consumer", "request", wall, probe_ordinal, None)
                # Query-string values are consumers too; the previous generation
                # ignored them entirely, which is where legacy portals live.
                url = payload.get("url") or ""
                if "?" in url:
                    from urllib.parse import parse_qsl, urlparse
                    for name, raw in parse_qsl(urlparse(url).query, keep_blank_values=True):
                        self._add(index, raw, event, endpoint, f"?{name}",
                                  "consumer", "request", wall, probe_ordinal, None)

            elif event.type in (EventType.RUNTIME_FETCH, EventType.RUNTIME_XHR):
                stack = payload.get("stack") or []
                trace = stack[0] if stack else None
                body = payload.get("body") or {}
                text = body.get("text") if isinstance(body, dict) else None
                if isinstance(text, str):
                    self._add(index, text, event, endpoint, "$body",
                              "consumer", "runtime", wall, probe_ordinal, trace)

            elif event.type is EventType.STORAGE_CHANGE:
                if payload.get("op") == "set":
                    self._add(index, payload.get("value"), event, endpoint,
                              f"{payload.get('store')}.{payload.get('key')}",
                              "producer", "storage", wall, probe_ordinal, None)

            elif event.type in (EventType.USER_INPUT, EventType.USER_CHANGE):
                value = (payload.get("value") or {}).get("value")
                element = payload.get("element") or {}
                self._add(index, value, event, "user", f"#{element.get('id') or element.get('name')}",
                          "producer", "user_input", wall, probe_ordinal, None)

        return index

    def _harvest(
        self, index, node: Any, path: str, event: Event, endpoint: str,
        role: str, kind: str, wall, probe_ordinal, trace, depth: int = 0,
    ) -> None:
        if depth > 8:
            return
        if isinstance(node, dict):
            for key, child in node.items():
                self._harvest(index, child, f"{path}.{key}", event, endpoint,
                              role, kind, wall, probe_ordinal, trace, depth + 1)
        elif isinstance(node, list):
            for item in node[:25]:
                self._harvest(index, item, f"{path}[]", event, endpoint,
                              role, kind, wall, probe_ordinal, trace, depth + 1)
        else:
            self._add(index, node, event, endpoint, path, role, kind,
                      wall, probe_ordinal, trace)

    def _add(self, index, value: Any, event: Event, endpoint: str, field_path: str,
             role: str, kind: str, wall, probe_ordinal, trace) -> None:
        text = self._candidate_value(value)
        if text is None:
            return
        index[text].append(ValueObservation(
            event_id=event.event_id, seq=event.seq, source=event.source,
            endpoint=endpoint or kind, field_path=field_path, role=role, kind=kind,
            wall_ms=wall, probe_ordinal=probe_ordinal, frame_id=event.frame_id,
            trace_hint=trace,
        ))

    @staticmethod
    def _candidate_value(value: Any) -> str | None:
        """Gate 1: is this value capable of identifying anything?"""
        if value is None or isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            # Small integers are counters and flags, not identities.
            if isinstance(value, int) and abs(value) < 1000:
                return None
            text = str(value)
        elif isinstance(value, str):
            text = value.strip()
        else:
            return None
        if not (MIN_VALUE_LENGTH <= len(text) <= MAX_VALUE_LENGTH):
            return None
        if text.lower() in STOPWORD_VALUES:
            return None
        # Pure punctuation or whitespace carries no identity.
        return text if any(ch.isalnum() for ch in text) else None

    # -- pairing and scoring -----------------------------------------------
    def _pair(self, value: str, producers, consumers, endpoints_touched: int):
        for consumer in consumers:
            best: tuple[float, DependencyEdge] | None = None
            for producer in producers:
                if producer.endpoint == consumer.endpoint and producer.field_path == consumer.field_path:
                    continue
                precedes, method, delta = _Ordering.compare(producer, consumer)
                if not precedes:
                    continue
                if delta is not None and abs(delta) > PROXIMITY_WINDOW_MS:
                    continue
                edge = self._score(value, producer, consumer, method, delta, endpoints_touched)
                if edge.confidence < self.min_confidence:
                    continue
                if best is None or edge.confidence > best[0]:
                    best = (edge.confidence, edge)
            if best:
                yield best[1]

    def _score(self, value, producer, consumer, order_method, delta_ms,
               endpoints_touched) -> DependencyEdge:
        evidence = Evidence()
        evidence.cite(producer.event_id, consumer.event_id)

        similarity = field_name_similarity(producer.field_path, consumer.field_path)
        unique = endpoints_touched <= 2
        same_frame = bool(producer.frame_id and producer.frame_id == consumer.frame_id)

        evidence.add("value_preview", value[:32])
        evidence.add("exact_value_match", True)
        evidence.add("unique_value_match", unique)
        evidence.add("endpoints_touched", endpoints_touched)
        evidence.add("field_name_similarity", round(similarity, 3))
        evidence.add("ordering_method", order_method)
        evidence.add("temporal_distance_ms", round(delta_ms, 1) if delta_ms is not None else None)
        evidence.add("same_frame", same_frame)
        if consumer.trace_hint:
            evidence.add("consumer_stack_top", consumer.trace_hint)

        # Transparent additive scoring. Each term is stored above, so the number
        # can always be recomputed and argued with.
        score = 0.30                                     # an exact value match
        score += 0.25 if unique else 0.0
        score += 0.20 * similarity
        score += {"probe_ordinal": 0.15, "same_source_seq": 0.10,
                  "wall_clock": 0.05}.get(order_method, 0.0)
        if delta_ms is not None and abs(delta_ms) <= 2000:
            score += 0.05
        if same_frame:
            score += 0.05
        if consumer.trace_hint:
            score += 0.05

        mechanism = self._mechanism(producer, consumer)
        evidence.add("mechanism", mechanism)

        return DependencyEdge(
            source_endpoint=producer.endpoint,
            source_field=producer.field_path,
            target_endpoint=consumer.endpoint,
            target_field=consumer.field_path,
            mechanism=mechanism,
            confidence=round(min(score, 0.99), 3),
            repeat_count=1,
            value_uniqueness=endpoints_touched,
            evidence=evidence,
        )

    @staticmethod
    def _mechanism(producer, consumer) -> str:
        """How the value plausibly travelled. `unknown` is a valid answer."""
        if producer.kind == "response" and consumer.kind in ("request", "runtime"):
            return "response_to_request"
        if producer.kind == "storage":
            return "storage_to_request"
        if producer.kind == "user_input":
            return "user_input_to_request"
        if producer.kind == "dom":
            return "response_to_dom_to_request"
        return "unknown"

    @staticmethod
    def _merge(edges: list[DependencyEdge]) -> list[DependencyEdge]:
        """Collapse repeats of the same relationship, raising confidence.

        Seeing the same edge in several independent flows is the strongest
        evidence available short of reading the source.
        """
        grouped: dict[tuple[str, str, str, str], DependencyEdge] = {}
        for edge in edges:
            key = (edge.source_endpoint, edge.source_field,
                   edge.target_endpoint, edge.target_field)
            existing = grouped.get(key)
            if existing is None:
                grouped[key] = edge
                continue
            existing.repeat_count += 1
            existing.evidence.cite(*edge.evidence.event_ids)
            existing.confidence = round(
                min(0.99, max(existing.confidence, edge.confidence)
                    + 0.03 * (existing.repeat_count - 1)), 3)
            existing.evidence.add("repeat_count", existing.repeat_count)
        return list(grouped.values())
