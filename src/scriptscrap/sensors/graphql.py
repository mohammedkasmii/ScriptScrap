"""GraphQL recognition at observation level.

Every GraphQL call in an application shares one URL, so recording it as
`POST /graphql` collapses an entire API into a single endpoint. The operation is
the real identity, and it is already present in the request body.

This is deliberately a recogniser, not a parser. It reads `operationName`,
`variables` and the leading keyword of the document. Full schema inference is
M3; building a real GraphQL parser here would be scope that M3 then replaces.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# `query Foo(...)`, `mutation Foo`, `subscription Foo`, or an anonymous `{ ... }`.
_OPERATION = re.compile(
    r"^\s*(?:#[^\n]*\n\s*)*(query|mutation|subscription)\s*([A-Za-z_][A-Za-z0-9_]*)?",
    re.IGNORECASE,
)


def looks_like_graphql(url: str, body: Any) -> bool:
    """Cheap pre-check before any parsing work."""
    if isinstance(body, dict) and ("query" in body or "operationName" in body):
        return True
    if isinstance(body, list) and body and isinstance(body[0], dict) and "query" in body[0]:
        return True  # batched operations
    return "graphql" in (url or "").lower()


def describe(url: str, body: Any) -> dict[str, Any] | None:
    """Extract operation identity, or None when this is not GraphQL.

    Returns a dict describing one or more operations. Never raises.
    """
    try:
        if not looks_like_graphql(url, body):
            return None
        if isinstance(body, list):
            ops = [_describe_one(item) for item in body if isinstance(item, dict)]
            ops = [op for op in ops if op]
            if not ops:
                return None
            return {"batched": True, "operation_count": len(ops), "operations": ops}
        if isinstance(body, dict):
            one = _describe_one(body)
            if one:
                return {"batched": False, "operation_count": 1, "operations": [one]}
        # A GraphQL-looking URL whose body could not be read at all is still
        # worth marking, so the endpoint is not mistaken for a plain REST call.
        if "graphql" in (url or "").lower():
            return {"batched": False, "operation_count": 0, "operations": [],
                    "note": "graphql url with unparsed body"}
    except Exception:
        return None
    return None


def _describe_one(body: dict) -> dict[str, Any] | None:
    document = body.get("query")
    name = body.get("operationName")
    variables = body.get("variables")
    extensions = body.get("extensions") or {}

    persisted = None
    if isinstance(extensions, dict):
        pq = extensions.get("persistedQuery")
        if isinstance(pq, dict):
            persisted = pq.get("sha256Hash") or pq.get("sha256hash")

    if not document and not name and not persisted:
        return None

    op_type = None
    if isinstance(document, str):
        match = _OPERATION.match(document)
        if match:
            op_type = match.group(1).lower()
            if not name and match.group(2):
                name = match.group(2)
        elif document.lstrip().startswith("{"):
            op_type = "query"  # anonymous shorthand

    described: dict[str, Any] = {
        "operation_name": name,
        "operation_type": op_type,
        "variable_names": sorted(variables) if isinstance(variables, dict) else None,
        "variables": variables if isinstance(variables, dict) else None,
        "persisted_query_hash": persisted,
        "document_present": isinstance(document, str),
    }

    if isinstance(document, str):
        described["document"] = document
        # A stable id for an anonymous or renamed operation, so M3 can group
        # observations of the same query without relying on operationName.
        normalised = " ".join(document.split())
        described["document_hash"] = hashlib.sha256(
            normalised.encode("utf-8", "ignore")
        ).hexdigest()[:16]
    elif persisted:
        described["note"] = "persisted query: document was never sent over the wire"

    return described


def operation_label(described: dict[str, Any]) -> str | None:
    """A short identity for logs, e.g. 'mutation ValiderDevis'."""
    ops = described.get("operations") or []
    if not ops:
        return None
    first = ops[0]
    label = " ".join(
        part for part in (first.get("operation_type"), first.get("operation_name")) if part
    )
    if described.get("batched"):
        label += f" (+{described['operation_count'] - 1} more)"
    return label or None
