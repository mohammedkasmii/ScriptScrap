"""Endpoint intelligence: templating, query parameters, GraphQL identity.

The raw log records every concrete URL. This groups them into routes without
destroying the originals -- `concrete_paths` keeps what was actually seen, so a
wrong templating decision is always visible and reversible.

Templating is evidence-driven, never pattern-guessed in isolation. A segment
becomes a parameter only when sibling paths agree that it varies while the rest
of the path holds, which is why `/api/items/101` alone stays literal and
`/api/items/{id}` only appears once several siblings have been observed.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any
from urllib.parse import parse_qsl, urlparse

from ..events import Event, EventType
from .models import Endpoint, Evidence, ParamObservation

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
NUMERIC_RE = re.compile(r"^\d+$")
LONG_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
# e.g. ITEM-0001, M-FIXTURE-0001 -- a prefix plus a varying tail.
CODE_RE = re.compile(r"^[A-Za-z]{1,12}[-_][A-Za-z0-9-]{2,}$")

# A segment must vary across at least this many sibling paths before it is
# treated as a parameter. One observation is not a pattern.
MIN_SIBLINGS_TO_TEMPLATE = 2


def _looks_like_identifier(segment: str) -> str | None:
    """Name the identifier kind, or None if this looks like a fixed route word."""
    if NUMERIC_RE.match(segment):
        return "integer"
    if UUID_RE.match(segment):
        return "uuid"
    if LONG_HEX_RE.match(segment):
        return "hash"
    if CODE_RE.match(segment):
        return "code"
    return None


def _infer_scalar_type(value: str) -> str:
    if value == "":
        return "string"
    if NUMERIC_RE.match(value):
        return "integer"
    try:
        float(value)
    except ValueError:
        pass
    else:
        return "number"
    if value.lower() in {"true", "false"}:
        return "boolean"
    if UUID_RE.match(value):
        return "uuid"
    return "string"


def _merge_types(types: set[str]) -> str:
    if not types:
        return "unknown"
    if len(types) == 1:
        return next(iter(types))
    # integer observations are compatible with number observations.
    if types <= {"integer", "number"}:
        return "number"
    return "|".join(sorted(types))


class EndpointAnalyzer:
    """Groups raw request/response events into derived endpoints."""

    def __init__(self, *, min_siblings: int = MIN_SIBLINGS_TO_TEMPLATE) -> None:
        self.min_siblings = min_siblings

    def analyze(self, events: list[Event]) -> list[Endpoint]:
        rest, graphql = self._collect(events)
        endpoints = self._build_rest(rest)
        endpoints.extend(self._build_graphql(graphql))
        endpoints.sort(key=lambda e: e.key)
        return endpoints

    # -- collection --------------------------------------------------------
    def _collect(self, events: list[Event]) -> tuple[list[dict], list[dict]]:
        responses: dict[tuple[str, str], list[int]] = defaultdict(list)
        for event in events:
            if event.type is EventType.HTTP_RESPONSE:
                payload = event.payload
                key = (payload.get("method", ""), payload.get("url", ""))
                responses[key].append(payload.get("status", 0))

        rest: list[dict] = []
        graphql: list[dict] = []
        for event in events:
            if event.type is not EventType.HTTP_REQUEST:
                continue
            payload = event.payload
            url = payload.get("url") or ""
            method = payload.get("method") or "GET"
            parsed = urlparse(url)
            record = {
                "event_id": event.event_id,
                "method": method,
                "url": url,
                "path": parsed.path or "/",
                "query": parsed.query,
                "statuses": responses.get((method, url), []),
                "graphql": payload.get("graphql"),
            }
            if record["graphql"] and record["graphql"].get("operations"):
                graphql.append(record)
            else:
                rest.append(record)
        return rest, graphql

    # -- REST --------------------------------------------------------------
    def _build_rest(self, records: list[dict]) -> list[Endpoint]:
        # Group by (method, segment count, literal skeleton) so only paths that
        # could plausibly be the same route are compared.
        buckets: dict[tuple[str, int], list[dict]] = defaultdict(list)
        for record in records:
            segments = [s for s in record["path"].split("/") if s]
            record["segments"] = segments
            buckets[(record["method"], len(segments))].append(record)

        endpoints: list[Endpoint] = []
        for (method, _), bucket in buckets.items():
            for template, group in self._template_bucket(bucket).items():
                endpoints.append(self._make_endpoint(method, template, group))
        return endpoints

    def _template_bucket(self, bucket: list[dict]) -> dict[str, list[dict]]:
        """Decide, per segment position, whether the segment is an identifier."""
        if not bucket:
            return {}
        depth = len(bucket[0]["segments"])
        values_at: list[set[str]] = [set() for _ in range(depth)]
        for record in bucket:
            for index, segment in enumerate(record["segments"]):
                values_at[index].add(segment)

        param_at: list[str | None] = []
        for index in range(depth):
            distinct = values_at[index]
            kinds = {_looks_like_identifier(v) for v in distinct}
            identifier_kinds = {k for k in kinds if k}
            if not identifier_kinds or len(identifier_kinds) > 1 and None in kinds:
                param_at.append(None)
                continue
            all_identifier = None not in kinds
            # Template when several siblings vary here, OR when every observed
            # value is an unambiguous identifier shape (a lone UUID is still an
            # id even with one observation).
            if all_identifier and (
                len(distinct) >= self.min_siblings
                or identifier_kinds <= {"uuid", "hash"}
            ):
                param_at.append(next(iter(identifier_kinds)))
            else:
                param_at.append(None)

        grouped: dict[str, list[dict]] = defaultdict(list)
        for record in bucket:
            parts = []
            path_params: dict[str, str] = {}
            for index, segment in enumerate(record["segments"]):
                kind = param_at[index]
                if kind:
                    name = self._param_name(record["segments"], index)
                    parts.append("{" + name + "}")
                    path_params[name] = segment
                else:
                    parts.append(segment)
            record["path_params"] = path_params
            record["param_kinds"] = {
                self._param_name(record["segments"], i): param_at[i]
                for i in range(depth) if param_at[i]
            }
            grouped["/" + "/".join(parts) if parts else "/"].append(record)
        return grouped

    @staticmethod
    def _param_name(segments: list[str], index: int) -> str:
        """Name a path parameter after the collection that precedes it."""
        if index == 0:
            return "id"
        parent = segments[index - 1].rstrip("s") or "id"
        cleaned = re.sub(r"[^A-Za-z0-9]+", "", parent)
        return f"{cleaned}Id" if cleaned else "id"

    def _make_endpoint(self, method: str, template: str, group: list[dict]) -> Endpoint:
        evidence = Evidence()
        statuses: dict[str, int] = defaultdict(int)
        concrete: list[str] = []
        query_values: dict[str, list[str]] = defaultdict(list)
        path_values: dict[str, list[str]] = defaultdict(list)
        param_kinds: dict[str, str] = {}

        for record in group:
            evidence.cite(record["event_id"])
            if record["path"] not in concrete:
                concrete.append(record["path"])
            for status in record["statuses"]:
                statuses[str(status)] += 1
            for name, value in parse_qsl(record["query"], keep_blank_values=True):
                query_values[name].append(value)
            for name, value in record.get("path_params", {}).items():
                path_values[name].append(value)
            param_kinds.update(record.get("param_kinds", {}))

        params = [
            self._param(name, "query", values) for name, values in sorted(query_values.items())
        ]
        for name, values in sorted(path_values.items()):
            observation = self._param(name, "path", values)
            if param_kinds.get(name) in {"uuid", "hash", "code"}:
                observation.inferred_type = param_kinds[name]
            params.append(observation)

        templated = "{" in template
        evidence.add("observations", len(group))
        evidence.add("distinct_concrete_paths", len(concrete))
        if templated:
            evidence.add("templated_from_sibling_paths", len(concrete))

        return Endpoint(
            method=method,
            template=template,
            kind="rest",
            observation_count=len(group),
            concrete_paths=sorted(concrete)[:50],
            statuses=dict(sorted(statuses.items())),
            params=params,
            templated=templated,
            # Templating from a single concrete path is a weaker claim.
            confidence=1.0 if not templated else (0.9 if len(concrete) >= 2 else 0.6),
            evidence=evidence,
        )

    @staticmethod
    def _param(name: str, location: str, values: list[str]) -> ParamObservation:
        distinct = sorted(set(values))
        types = {_infer_scalar_type(v) for v in values}
        enum_candidate = None
        # A small, repeatedly-observed value set. Called a candidate, not an
        # enum: a small sample can make anything look closed.
        if len(values) >= 3 and 1 < len(distinct) <= 5 and len(distinct) * 2 <= len(values):
            enum_candidate = distinct
        return ParamObservation(
            name=name,
            location=location,
            inferred_type=_merge_types(types),
            sample_count=len(values),
            distinct_values=len(distinct),
            examples=distinct[:5],
            enum_candidate=enum_candidate,
        )

    # -- GraphQL -----------------------------------------------------------
    def _build_graphql(self, records: list[dict]) -> list[Endpoint]:
        grouped: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
        for record in records:
            for operation in record["graphql"]["operations"]:
                identity = (
                    operation.get("operation_type") or "unknown",
                    operation.get("operation_name")
                    or operation.get("persisted_query_hash")
                    or operation.get("document_hash")
                    or "anonymous",
                    operation.get("persisted_query_hash") or "",
                )
                grouped[identity].append({**record, "operation": operation})

        endpoints: list[Endpoint] = []
        for (op_type, op_name, persisted), group in grouped.items():
            evidence = Evidence()
            statuses: dict[str, int] = defaultdict(int)
            paths: list[str] = []
            for record in group:
                evidence.cite(record["event_id"])
                for status in record["statuses"]:
                    statuses[str(status)] += 1
                if record["path"] not in paths:
                    paths.append(record["path"])
            evidence.add("observations", len(group))
            evidence.add("transport_paths", paths)

            endpoints.append(Endpoint(
                method=group[0]["method"],
                # The operation is the identity; the URL is only transport.
                template=f"{paths[0] if paths else '/graphql'}#{op_type}:{op_name}",
                kind="graphql",
                observation_count=len(group),
                concrete_paths=paths,
                statuses=dict(sorted(statuses.items())),
                graphql_operation=op_name,
                graphql_operation_type=op_type,
                persisted_query_hash=persisted or None,
                confidence=1.0,
                evidence=evidence,
            ))
        return endpoints


def endpoint_key_for_request(payload: dict[str, Any], endpoints: list[Endpoint]) -> str | None:
    """Map a raw request payload back to the derived endpoint that covers it."""
    url = payload.get("url") or ""
    path = urlparse(url).path or "/"
    method = payload.get("method") or "GET"
    graphql = payload.get("graphql")
    if graphql and graphql.get("operations"):
        operation = graphql["operations"][0]
        op_type = operation.get("operation_type") or "unknown"
        op_name = (operation.get("operation_name")
                   or operation.get("persisted_query_hash")
                   or operation.get("document_hash") or "anonymous")
        return f"GRAPHQL {op_type} {op_name}"
    for endpoint in endpoints:
        if endpoint.kind == "rest" and endpoint.method == method and path in endpoint.concrete_paths:
            return endpoint.key
    return f"{method} {path}"
