"""Derived knowledge models.

Everything here is an INFERENCE, never an observation. The distinction is
structural, not stylistic: raw events say what the browser did, these say what
we believe it means, and every one of them carries the `event_id`s that justify
it so a reader can go back and check.

Two rules that shape every model below:

1. **Nothing here is written into a raw event.** Analysis reads `events.jsonl`
   and writes a separate derived store, which can be deleted and rebuilt.
2. **Confidence is transparent, not calibrated.** A score is a deterministic
   function of an evidence vector that is stored alongside it. A reader who
   disagrees with the weighting can recompute from the evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Bumped when inference logic changes in a way that invalidates stored results.
ANALYSIS_VERSION = 1


@dataclass(slots=True)
class Evidence:
    """Why we believe something, and which raw events support it."""

    signals: dict[str, Any] = field(default_factory=dict)
    event_ids: list[str] = field(default_factory=list)

    def add(self, name: str, value: Any) -> None:
        self.signals[name] = value

    def cite(self, *event_ids: str) -> None:
        for eid in event_ids:
            if eid and eid not in self.event_ids:
                self.event_ids.append(eid)


@dataclass(slots=True)
class ParamObservation:
    """One query or path parameter, as observed."""

    name: str
    location: str            # "query" | "path"
    inferred_type: str
    sample_count: int
    distinct_values: int
    examples: list[str] = field(default_factory=list)
    enum_candidate: list[str] | None = None


@dataclass(slots=True)
class Endpoint:
    """A derived endpoint: a group of concrete requests believed to be one route."""

    method: str
    template: str
    kind: str                       # "rest" | "graphql"
    observation_count: int
    concrete_paths: list[str] = field(default_factory=list)
    statuses: dict[str, int] = field(default_factory=dict)
    params: list[ParamObservation] = field(default_factory=list)
    graphql_operation: str | None = None
    graphql_operation_type: str | None = None
    persisted_query_hash: str | None = None
    templated: bool = False
    confidence: float = 1.0
    evidence: Evidence = field(default_factory=Evidence)

    @property
    def key(self) -> str:
        if self.kind == "graphql":
            return f"GRAPHQL {self.graphql_operation_type or '?'} {self.graphql_operation or '?'}"
        return f"{self.method} {self.template}"


@dataclass(slots=True)
class SchemaField:
    """One JSON path within an inferred schema."""

    path: str
    types: dict[str, int]           # observed type -> count
    present_count: int              # BODIES the path appeared in: <= sample_count
    sample_count: int
    null_count: int = 0
    # Every value seen. For a path inside an array this exceeds present_count,
    # and the excess is array cardinality, not extra samples.
    occurrence_count: int = 0
    enum_candidate: list[str] | None = None
    inferred_format: str | None = None
    examples: list[Any] = field(default_factory=list)

    @property
    def values_per_body(self) -> float:
        """Average values seen per body the path appeared in; >1 means an array."""
        return self.occurrence_count / self.present_count if self.present_count else 0.0

    @property
    def inferred_type(self) -> str:
        """The observed types, most frequent first. Polymorphism is preserved."""
        if not self.types:
            return "unknown"
        ordered = sorted(self.types.items(), key=lambda kv: (-kv[1], kv[0]))
        return "|".join(name for name, _ in ordered)

    @property
    def observed_optional(self) -> bool:
        """Observed to be absent sometimes.

        Deliberately NOT called `required`: absence in a sample proves optional,
        but presence in every sample does not prove required.
        """
        return self.present_count < self.sample_count


@dataclass(slots=True)
class Schema:
    """An inferred schema for one endpoint direction."""

    endpoint_key: str
    direction: str                  # "request" | "response"
    sample_count: int
    root_type: str
    fields: list[SchemaField] = field(default_factory=list)
    status: str | None = None
    evidence: Evidence = field(default_factory=Evidence)


@dataclass(slots=True)
class DependencyEdge:
    """A hypothesis that one observation supplied a value used by another."""

    source_endpoint: str
    source_field: str
    target_endpoint: str
    target_field: str
    mechanism: str
    confidence: float
    repeat_count: int
    value_uniqueness: int           # how many distinct places the value was seen
    evidence: Evidence = field(default_factory=Evidence)

    @property
    def label(self) -> str:
        return (f"{self.source_endpoint} {self.source_field}"
                f" -> {self.target_endpoint} {self.target_field}")


@dataclass(slots=True)
class LocatorCandidate:
    """One way to find an element, with how often it actually held."""

    strategy: str
    value: str
    resolved_count: int
    sample_count: int
    warning: str | None = None

    @property
    def stability(self) -> float:
        return self.resolved_count / self.sample_count if self.sample_count else 0.0


@dataclass(slots=True)
class UIElement:
    """An interactive element the operator used, and how to find it again."""

    key: str
    tag: str
    role: str | None
    label: str | None
    text: str | None
    form: str | None
    observation_count: int
    actions: dict[str, int] = field(default_factory=dict)
    locators: list[LocatorCandidate] = field(default_factory=list)
    evidence: Evidence = field(default_factory=Evidence)

    @property
    def recommended(self) -> LocatorCandidate | None:
        """Most stable locator, ties broken by strategy preference.

        ID is NOT automatically preferred: a framework-generated id is often the
        least stable thing on the page.
        """
        if not self.locators:
            return None
        order = {"role_name": 0, "label": 1, "name": 2, "text": 3,
                 "id": 4, "css": 5, "structural": 6, "xpath": 7}
        usable = [loc for loc in self.locators if not loc.warning]
        pool = usable or self.locators
        return sorted(pool, key=lambda locator: (-locator.stability,
                                                 order.get(locator.strategy, 99)))[0]


@dataclass(slots=True)
class AppState:
    """A UI state observed during the session, identified structurally."""

    fingerprint: str
    label: str
    url_pattern: str
    observation_count: int
    forms: list[str] = field(default_factory=list)
    evidence: Evidence = field(default_factory=Evidence)


@dataclass(slots=True)
class StateTransition:
    from_state: str
    to_state: str
    trigger: str
    observation_count: int
    evidence: Evidence = field(default_factory=Evidence)


@dataclass(slots=True)
class Technology:
    name: str
    category: str
    confidence: float
    signals: list[str] = field(default_factory=list)
    evidence: Evidence = field(default_factory=Evidence)


@dataclass(slots=True)
class Finding:
    """Something the reader should know: a gap, a risk, a caveat."""

    kind: str
    severity: str                   # "info" | "warning" | "critical"
    message: str
    count: int = 1
    evidence: Evidence = field(default_factory=Evidence)


@dataclass(slots=True)
class AnalysisResult:
    """Everything one analysis run derived."""

    session_id: str
    event_count: int
    analysis_version: int = ANALYSIS_VERSION
    endpoints: list[Endpoint] = field(default_factory=list)
    schemas: list[Schema] = field(default_factory=list)
    dependencies: list[DependencyEdge] = field(default_factory=list)
    ui_elements: list[UIElement] = field(default_factory=list)
    states: list[AppState] = field(default_factory=list)
    transitions: list[StateTransition] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # Forensic-era additions. Empty on a normal session, which is what keeps
    # analysis working without the extension.
    activities: list[Any] = field(default_factory=list)
    health: dict[str, Any] | None = None
    scripts: list[dict[str, Any]] = field(default_factory=list)
