"""Schema inference from repeated observations.

The previous generation emitted `{"type": "object"}` with an example attached.
This merges every observation of a body into a per-field record of what was
actually seen, with counts, so a reader can tell the difference between "this
field is a string" and "this field was a string once".

Three deliberate restraints:

* **`observed_optional`, never `required`.** Absence in a sample proves optional.
  Presence in every sample proves nothing about the contract.
* **`enum_candidate`, never `enum`.** A small value set in a small sample is
  weak evidence, and the sample count is stored so the reader can judge.
* **Polymorphism is preserved.** Incompatible shapes are recorded as
  `string|object`, not flattened into whichever came last.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .models import Evidence, Schema, SchemaField

# Arrays are sampled, not enumerated: a 10 000-row response should cost the same
# as a 10-row one.
MAX_ARRAY_ITEMS = 25
MAX_EXAMPLES = 3
MAX_FIELDS = 400

ISO_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
URL = re.compile(r"^https?://", re.I)

# A value longer than this is treated as an opaque token rather than content:
# ASP.NET __VIEWSTATE would otherwise dominate every schema it appears in.
OPAQUE_TOKEN_LENGTH = 512


def json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "opaque_token" if len(value) > OPAQUE_TOKEN_LENGTH else "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def _detect_format(values: list[str]) -> str | None:
    """Only claim a format when every observed value agrees and there are enough."""
    if len(values) < 2:
        return None
    for name, pattern in (
        ("uuid", UUID), ("datetime", ISO_DATETIME), ("date", ISO_DATE),
        ("email", EMAIL), ("url", URL),
    ):
        if all(pattern.match(v) for v in values):
            return name
    return None


class _FieldAccumulator:
    """Two counters, because a field inside an array has two denominators.

    `occurrences` counts every value seen; `bodies` counts the bodies the path
    appeared in at all. For `$.items[].name` in one response holding six items
    those are 6 and 1, and only the second can be compared to the sample count.
    Reporting the first as presence produced `present 6/1`, which reads as a
    corrupt record rather than as an array.
    """

    __slots__ = ("types", "occurrences", "bodies", "nulls", "values", "examples")

    def __init__(self) -> None:
        self.types: dict[str, int] = defaultdict(int)
        self.occurrences = 0
        self.bodies = 0
        self.nulls = 0
        self.values: list[Any] = []
        self.examples: list[Any] = []

    def observe(self, value: Any) -> None:
        kind = json_type(value)
        self.types[kind] += 1
        self.occurrences += 1
        if value is None:
            self.nulls += 1
            return
        if isinstance(value, (str, int, float, bool)):
            if len(self.values) < 500:
                self.values.append(value)
            if len(self.examples) < MAX_EXAMPLES and value not in self.examples:
                self.examples.append(value)


class SchemaInferrer:
    """Merges repeated bodies into one evidence-backed schema."""

    def __init__(self) -> None:
        self._fields: dict[str, _FieldAccumulator] = defaultdict(_FieldAccumulator)
        self._root_types: dict[str, int] = defaultdict(int)
        self._samples = 0
        self._evidence = Evidence()
        self._seen_in_body: set[str] = set()

    def observe(self, body: Any, event_id: str | None = None) -> None:
        self._samples += 1
        self._root_types[json_type(body)] += 1
        if event_id:
            self._evidence.cite(event_id)
        self._seen_in_body = set()
        self._walk(body, "$")
        # Presence is per BODY, however many times the path occurred inside it.
        for path in self._seen_in_body:
            self._fields[path].bodies += 1

    def _walk(self, value: Any, path: str) -> None:
        if len(self._fields) >= MAX_FIELDS:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}"
                self._fields[child_path].observe(child)
                self._seen_in_body.add(child_path)
                self._walk(child, child_path)
        elif isinstance(value, list):
            # One merged description of the element shape, not one per index:
            # `$.items[]` says what an item looks like across every observation.
            item_path = f"{path}[]"
            for item in value[:MAX_ARRAY_ITEMS]:
                self._fields[item_path].observe(item)
                self._seen_in_body.add(item_path)
                self._walk(item, item_path)

    def build(self, endpoint_key: str, direction: str, status: str | None = None) -> Schema:
        fields: list[SchemaField] = []
        for path, acc in sorted(self._fields.items()):
            scalars = [v for v in acc.values if isinstance(v, str)]
            enum_candidate = None
            distinct = sorted({str(v) for v in acc.values})
            # Small closed-looking set, seen often enough to be worth flagging.
            # The denominator here is occurrences, not bodies: what makes a set
            # look closed is how many VALUES agreed, wherever they came from.
            if (acc.occurrences >= 3 and 1 < len(distinct) <= 6
                    and len(distinct) * 2 <= acc.occurrences):
                enum_candidate = distinct
            fields.append(SchemaField(
                path=path,
                types=dict(sorted(acc.types.items(), key=lambda kv: (-kv[1], kv[0]))),
                present_count=acc.bodies,
                occurrence_count=acc.occurrences,
                sample_count=self._samples,
                null_count=acc.nulls,
                enum_candidate=enum_candidate,
                inferred_format=_detect_format(scalars) if scalars else None,
                examples=acc.examples,
            ))

        root = max(self._root_types.items(), key=lambda kv: kv[1])[0] if self._root_types else "unknown"
        return Schema(
            endpoint_key=endpoint_key,
            direction=direction,
            sample_count=self._samples,
            root_type=root,
            fields=fields,
            status=status,
            evidence=self._evidence,
        )


def parent_path(path: str) -> str:
    """`$.a.b` -> `$.a`; `$.a[]` -> `$.a`."""
    if path.endswith("[]"):
        return path[:-2]
    return path.rsplit(".", 1)[0] if "." in path else "$"
