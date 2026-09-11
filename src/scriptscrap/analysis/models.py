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
# 2: the derived store gained an events index (envelope + byte offset) and the
#    run gained the log fingerprint those offsets are only valid against.
# 3: the derived model gained an ordered workflow and a machine-readable link
#    from a state transition to the element that triggered it.
# 4: analysis surfaces the log's own integrity problems as findings
#    (duplicate_event_id, log_integrity), which EventLogReader.validate had
#    detected since M1 with nothing acting on them.
ANALYSIS_VERSION = 4


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
    # The fixed constant behind `warning`. `warning` interpolates a framework
    # name or a count ("value changed across observations (3 distinct)") and is
    # therefore not exportable; this is.
    warning_code: str | None = None      # "framework_generated" | "value_varied"

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
    # A human-readable label: f"{type} #{element id/label/text}". It carries
    # page content, so it is for the local report and the workspace, and the
    # shared export drops it. The three fields below are the machine-readable
    # halves that survive.
    trigger: str
    observation_count: int
    # The bare EventType that caused the move -- "user_click",
    # "runtime_history" -- with no element name attached. A fixed constant, so
    # it is exportable and a reader still learns what kind of thing moved the
    # application.
    trigger_type: str | None = None
    # The element the trigger event happened on, as a semantic key that joins
    # to UIElement.key. `trigger` is a label and is NOT an identity: a
    # generator that joined on it matched nothing.
    trigger_element_key: str | None = None
    trigger_event_id: str | None = None
    evidence: Evidence = field(default_factory=Evidence)


WORKFLOW_KINDS = ("navigate", "click", "fill", "select", "check", "press", "submit")

# Keys that may be reproduced in a generated script. Navigation and control
# only: a keystroke is application-visible input and can be one character of a
# password, so the default is that it does not leave.
SAFE_KEYS = frozenset({
    "Enter", "Tab", "Escape", "Backspace", "Delete",
    "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight",
    "Home", "End", "PageUp", "PageDown",
})


@dataclass(slots=True, frozen=True)
class WorkflowStep:
    """One thing the operator did, in the order it happened.

    Deliberately NOT reconstructed by the generator. Order lives in `seq`,
    which the derived model does not otherwise carry, and reconstructing it
    from `AnalysisResult`'s frequency-sorted lists produced a script that
    replayed the session in observation-count order.

    `value_recorded` says a value was typed. It never says WHICH: the capture
    records that an input event happened on an element, not its content, and
    a generated `.fill("Alice")` would be an invention. It is always False on a
    `press` step -- a keystroke is not a missing value.

    `key` is set only when the capture recorded one AND it is in `SAFE_KEYS`.
    An unrecorded or non-allowlisted key stays None and the generator emits a
    TODO rather than substituting one: the session did not observe an Enter
    press, and writing one would put behaviour in the script that never
    happened.
    """

    ordinal: int
    seq: int
    kind: str
    element_key: str | None = None
    url_pattern: str | None = None
    repeat_count: int = 1
    value_recorded: bool = False
    key: str | None = None
    evidence: Evidence = field(default_factory=Evidence)


@dataclass(slots=True)
class Technology:
    name: str
    category: str
    confidence: float
    signals: list[str] = field(default_factory=list)
    # How many signals, not which. `signals` is built from
    # `sorted(webforms_state | webforms_ops)` and `sorted(graphql_ops)` --
    # field and operation names read off the application -- so the list itself
    # cannot leave the machine, and the count is what survives export.
    signal_count: int = 0
    evidence: Evidence = field(default_factory=Evidence)


@dataclass(slots=True)
class Finding:
    """Something the reader should know: a gap, a risk, a caveat."""

    kind: str
    severity: str                   # "info" | "warning" | "critical"
    message: str
    count: int = 1
    evidence: Evidence = field(default_factory=Evidence)


@dataclass(slots=True, frozen=True)
class EventIndexRow:
    """One event's envelope, plus where its line lives in the log.

    Deliberately no payload field. This row exists so evidence can be found,
    not so it can be stored somewhere else -- `events.jsonl` remains the only
    place an event's content lives.
    """

    event_id: str
    seq: int
    type: str
    source: str
    t_wall: str
    t_mono: float
    page_id: str | None
    frame_id: str | None
    byte_offset: int
    byte_length: int


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
    # The observed workflow, in `seq` order. Empty when no user action and no
    # navigation was recorded.
    workflow: list[WorkflowStep] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # Forensic-era additions. Empty on a normal session, which is what keeps
    # analysis working without the extension.
    activities: list[Any] = field(default_factory=list)
    # Automatically inferred business activities: a long session split into
    # probable tasks from idle gaps, form submissions and route structure.
    # An interpretation over the timeline, never a rewrite of it -- the ordered
    # workflow and event log stay intact beside this. Empty when no user action
    # was recorded.
    segments: list[Any] = field(default_factory=list)
    health: dict[str, Any] | None = None
    scripts: list[dict[str, Any]] = field(default_factory=list)
    # Credential-bearing header NAMES the application sent, and how often.
    # Names only -- the capture never records their values. This is what lets a
    # generated client say "this API needs a Cookie header, supply it from the
    # environment" without ever having held the operator's session.
    auth_headers: dict[str, int] = field(default_factory=dict)
    # The evidence index. One entry per event: the envelope plus where its line
    # lives in events.jsonl, so a conclusion can be walked back to its raw
    # evidence with a seek rather than a re-parse of the whole log. Empty when
    # the result was derived from events already in memory rather than a file.
    event_index: list[EventIndexRow] = field(default_factory=list)
    # The log those offsets were built from. An offset means nothing without
    # them, so they travel together.
    log_size: int | None = None
    log_sha256: str | None = None
