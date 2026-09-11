"""What may leave the machine, field by field.

The shared export used to be a whitelist of STRUCTURES: `dataset.py` chose
which model fields to serialise, and a handful of them were routed through the
redactor on the way. Any field nobody thought about was emitted verbatim, and
28 of them were -- including the text of every element an operator clicked.

This inverts it. Sanitisation happens once, on the MODEL, before anything is
serialised, and it is driven by a table with one entry per field of every model
dataclass. A field with no entry raises. That is the whole design: the failure
mode of forgetting is a build error, not a leak.

The dispositions are deliberately few, and none of them means "trust me". A
value is either a number, a member of a declared closed vocabulary, or
something this module transforms.
"""

from __future__ import annotations

import dataclasses
import re
from enum import StrEnum
from typing import Any

from ..analysis import models, technology
from ..analysis.identifiers import identifier_kind
from ..events import EventType
from .redact import Redactor, is_credential_name


class UnclassifiedField(RuntimeError):
    """A model field with no declared disposition. Refuse rather than emit."""


class Disposition(StrEnum):
    """What happens to one field's value on the way out.

    There is deliberately no "tool text" disposition. An earlier draft had one,
    on the theory that prose ScriptScrap generates is safe to emit verbatim.
    Checking that against the real capture disproved it: `Technology.signals`
    is `sorted(webforms_state | webforms_ops)` -- ASP.NET state field names and
    GraphQL operation names read off the application -- and every health
    "reason" and "note" is a derived string, not a constant. A disposition that
    means "trust me" is the shape of the defect this table exists to prevent.
    """

    STRUCTURAL = "structural"
    """Numbers, booleans, and containers of model dataclasses. **No bare
    strings.** An earlier draft used this for "values from a closed vocabulary
    this tool produces" and passed them through unchecked, which is how
    `UIElement.role` -- author-controlled ARIA, straight off the page -- would
    have been emitted verbatim. Every string now goes through a disposition
    that either validates it against a declared vocabulary or transforms it."""

    REASON_CODE = "reason_code"
    """One value from an explicitly declared, closed vocabulary.

    Membership is checked against `VOCABULARY[(class, field)]` for that EXACT
    field, and an unknown value raises `UnclassifiedField`. It is deliberately
    NOT a shape check: `CustomerAlice`, `tenant42` and `sk_live_abc123` are all
    whitespace-free tokens under 64 characters, and a rule that admitted them
    would be admitting captured values while claiming to admit constants.

    Vocabularies are derived from ScriptScrap-owned enums and constant tables
    wherever one exists, so a producer that adds a value has to add it here
    too."""

    ROUTE = "route"
    """A URL path or template. Route words survive; identifier-shaped segments
    become `{id}`; query and fragment are dropped."""

    NAME = "name"
    """A field, parameter or header name. Kept when it looks like an authored
    identifier and is not credential-named; pseudonymised otherwise.

    A STATED LIMIT: this cannot tell `username` from `CustomerAlice`. It is
    kept for the fields where the name IS the substance -- a schema field path,
    a query parameter -- because pseudonymising those leaves a schema block
    nobody can read. Fields where the name carries little (`UIElement.form`,
    `AppState.forms`) are DROPped instead. `ROUTE` has the same limit for the
    same reason; both are pinned by
    `test_the_documented_limits_of_route_and_name`."""

    LOCATOR = "locator"
    """A selector expression. A structurally-safe selector survives whole;
    anything carrying free text is REPLACED by a fixed marker, never shaped.
    A locator is the one field where a shape would be actively misleading --
    it looks like something you could still use."""

    BUCKET = "bucket"
    """Free text from the application, reduced to a coarse size bucket and a
    stable pseudonym. Buckets are `0`, `1-10`, `11-50`, `51-200`, `200+` --
    never an exact character or word count, which is a fingerprint of the
    value in its own right."""

    SAMPLE = "sample"
    """A captured sample value: `Redactor.scrub_example`. Short digit-free
    single tokens survive as vocabulary; everything else is pseudonymised."""

    FINGERPRINT = "fingerprint"
    """Hashed with the export's salt."""

    EVIDENCE = "evidence"
    """Event ids. ScriptScrap allocates them (`evt-00000001`), so they carry no
    application data."""

    COUNTS = "counts"
    """A mapping or sequence of numbers. **Strings are rejected by default.**

    Where a count mapping is legitimately string-keyed -- `Endpoint.statuses`,
    `SchemaField.types`, `UIElement.actions` -- that exact field declares its
    own key vocabulary in `COUNT_KEYS`, and an unknown key raises. Keys are
    never fed to the generic reason-code validator: a dictionary key from a
    captured body is not a constant because it happens to be a key."""

    SIGNALS = "signals"
    """`Evidence.signals`, projected onto a declared sub-schema.

    It is a free-form bag: numeric weights sit beside `attribution` (prose),
    `value_preview` (a CAPTURED VALUE, by definition -- `redact.py` says so),
    `consumer_stack_top` (a stack frame), and `state_fields` /
    `operation_fields` / `operations` (application field names). The retired
    `_SAFE_SIGNAL_KEYS` listed the last three as safe to emit verbatim; they
    are not."""

    HEALTH = "health"
    """The capture-health document, projected onto a declared sub-schema:
    counts, sensor names, statuses and gap codes survive; every free-form
    `reasons`, `notes` and `blind_spots` string is dropped and replaced by its
    count."""

    DROP = "drop"
    """Not emitted at all."""


# A path segment that reads as an authored route word rather than data.
_SAFE_SEGMENT = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
# An authored-looking field or parameter name.
_SAFE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\[\]-]{0,63}$")
# The templater's own placeholder, which is tool vocabulary.
_HOLE = re.compile(r"^\{[^{}]*\}$")
# A structurally-safe selector, and only these three shapes: `#id`, `.class`,
# `[attr="value"]`, or a tag name carrying one of them (`input.field`).
#
# A BARE word is deliberately not a shape: `selectors.py` stores the `label`
# strategy as the accessible name itself, so `AcmeInternalProject` arrives here
# looking like a perfectly tidy token and is in fact the words on the screen.
_SAFE_LOCATOR = re.compile(
    r"^[a-zA-Z0-9_-]{0,64}"                              # optional tag prefix
    r'(?:[#.][a-zA-Z0-9_-]{1,64}|\[[a-zA-Z0-9_-]{1,64}="[^"]{0,64}"\])+$'
)
# A locator whose value IS the element's visible text or accessible name.
# `selectors.py` builds these as `text=<repr>`, `role=x name="y"` and the bare
# label string, so they carry page content whatever shape they happen to have.
_TEXT_BEARING_LOCATOR = re.compile(r"^\s*(text|label|placeholder|role)\s*=", re.I)

# Coarse size buckets. Exact lengths are a fingerprint: a 20-character password
# and a 20-character surname are distinguishable from a 7-character one, and an
# exact count of either is a value the export was asked not to carry.
_BUCKETS = ((0, "0"), (10, "1-10"), (50, "11-50"), (200, "51-200"))

LOCATOR_OMITTED = "<locator omitted: contained application text>"


def size_bucket(text: str) -> str:
    """`""` -> "0", `"abc"` -> "1-10", ... , anything longer -> "200+"."""
    length = len(text)
    for limit, label in _BUCKETS:
        if length <= limit:
            return label
    return "200+"


# --- closed vocabularies --------------------------------------------------
#
# Every REASON_CODE field names its allowed values here. Derived from a
# ScriptScrap-owned enum or constant table wherever one exists, so a producer
# that adds a value has to come here too rather than silently widening what
# leaves the machine.

_EVENT_TYPES = frozenset(str(t) for t in EventType)
_TECHNOLOGY_NAMES = frozenset(
    {name for name, _category, _pattern, _base in technology._SIGNATURES}
    | {"ASP.NET WebForms", "GraphQL"}
)
_TECHNOLOGY_CATEGORIES = frozenset(
    {category for _name, category, _pattern, _base in technology._SIGNATURES}
    | {"framework", "api", "library"}
)
# pipeline.py's `_findings`, plus the kinds Plans C and E add.
_FINDING_KINDS = frozenset({
    "capture_gap", "sensor_error", "sensor_blind_spot", "thin_sample",
    "weak_templating", "unreplayable_step", "workflow_value_gap",
    "duplicate_event_id", "log_integrity",
})
# correlation.py's `_mechanism`.
_MECHANISMS = frozenset({
    "response_to_request", "storage_to_request", "user_input_to_request",
    "response_to_dom_to_request", "unknown",
})
# correlation.py's ordering comparison and states.py's trigger attribution.
_ORDERING_METHODS = frozenset({
    "probe_ordinal", "same_document_clock", "same_source_seq",
    "same_timeline_seq", "wall_clock", "unordered",
})
_ORDERING_RELATIONS = frozenset({"precedes", "ambiguous", "contradicted"})
# schema.py's type namer.
_JSON_TYPES = frozenset({
    "null", "boolean", "integer", "number", "string", "opaque_token",
    "array", "object", "unknown",
})
# The strategies SelectorAnalyzer can produce.
_LOCATOR_STRATEGIES = frozenset({
    "test_id", "role_name", "label", "placeholder", "name", "id", "text",
    "structural", "css",
})
# The elements a capture can record an interaction on. Author-controlled
# markup can name anything; only these leave.
_HTML_TAGS = frozenset({
    "a", "button", "input", "select", "textarea", "option", "label", "form",
    "div", "span", "li", "td", "th", "tr", "summary", "details", "img",
    "svg", "path", "p", "h1", "h2", "h3", "h4", "h5", "h6", "b", "strong",
    "em", "i", "ins", "pre", "ul", "ol", "table", "tbody", "thead", "section", "nav",
    "header", "footer", "main", "article", "aside", "iframe", "canvas",
})
# WAI-ARIA widget, document-structure and landmark roles. `role` is an
# author-supplied attribute -- `role="CustomerAlice"` is legal markup -- so it
# is validated, not trusted.
_ARIA_ROLES = frozenset({
    "alert", "alertdialog", "application", "article", "banner", "button",
    "cell", "checkbox", "columnheader", "combobox", "complementary",
    "contentinfo", "definition", "dialog", "directory", "document", "feed",
    "figure", "form", "grid", "gridcell", "group", "heading", "img", "link",
    "list", "listbox", "listitem", "log", "main", "marquee", "math", "menu",
    "menubar", "menuitem", "menuitemcheckbox", "menuitemradio", "navigation",
    "none", "note", "option", "presentation", "progressbar", "radio",
    "radiogroup", "region", "row", "rowgroup", "rowheader", "scrollbar",
    "search", "searchbox", "separator", "slider", "spinbutton", "status",
    "switch", "tab", "table", "tablist", "tabpanel", "term", "textbox",
    "timer", "toolbar", "tooltip", "tree", "treegrid", "treeitem",
})
_HTTP_METHODS = frozenset({
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE",
    "CONNECT",
})
# A three-digit HTTP status. The one place a PATTERN is allowed instead of an
# enumeration, because the domain is provably numeric and closed. Never used
# for a name.
_STATUS_CODE = re.compile(r"^[1-5][0-9]{2}$")
# A sha256 prefix, produced by states.py.
_FINGERPRINT_HEX = re.compile(r"^[0-9a-f]{6,64}$")
# schema.py's format detector.
_INFERRED_FORMATS = frozenset({
    "uuid", "iso8601", "email", "url", "date", "datetime", "jwt", "base64",
    "hex", "numeric_string",
})

VOCABULARY: dict[tuple[str, str], frozenset[str] | re.Pattern[str]] = {
    ("Endpoint", "method"): _HTTP_METHODS,
    ("Endpoint", "kind"): frozenset({"rest", "graphql"}),
    ("Endpoint", "graphql_operation_type"): frozenset(
        {"query", "mutation", "subscription"}),
    ("ParamObservation", "location"): frozenset({"query", "path"}),
    ("ParamObservation", "inferred_type"): _JSON_TYPES,
    ("Schema", "direction"): frozenset({"request", "response"}),
    ("Schema", "root_type"): _JSON_TYPES,
    ("Schema", "status"): _STATUS_CODE,
    ("SchemaField", "inferred_format"): _INFERRED_FORMATS,
    ("DependencyEdge", "mechanism"): _MECHANISMS,
    ("LocatorCandidate", "strategy"): _LOCATOR_STRATEGIES,
    ("LocatorCandidate", "warning_code"): frozenset(
        {"framework_generated", "value_varied"}),
    ("UIElement", "tag"): _HTML_TAGS,
    ("UIElement", "role"): _ARIA_ROLES,
    ("AppState", "fingerprint"): _FINGERPRINT_HEX,
    ("StateTransition", "from_state"): _FINGERPRINT_HEX,
    ("StateTransition", "to_state"): _FINGERPRINT_HEX,
    ("Technology", "name"): _TECHNOLOGY_NAMES,
    ("Technology", "category"): _TECHNOLOGY_CATEGORIES,
    ("Finding", "kind"): _FINDING_KINDS,
    ("Finding", "severity"): frozenset({"info", "warning", "critical"}),
    ("StateTransition", "trigger_type"): _EVENT_TYPES,
    ("WorkflowStep", "kind"): frozenset(models.WORKFLOW_KINDS),
    ("WorkflowStep", "key"): frozenset(models.SAFE_KEYS),
    # Plan C adds ("StateTransition", "trigger_type") and the two WorkflowStep
    # entries when it introduces those fields.
}

# The key vocabulary for each string-keyed COUNTS mapping. A key is validated
# against ITS OWN field's vocabulary; nothing is routed through the generic
# reason-code validator, because a key read off a captured body is not a
# constant merely by being a key.
COUNT_KEYS: dict[tuple[str, str], frozenset[str] | re.Pattern[str]] = {
    ("Endpoint", "statuses"): _STATUS_CODE,
    ("SchemaField", "types"): _JSON_TYPES,
    ("UIElement", "actions"): _EVENT_TYPES,
}

# Evidence.signals: which keys survive, and what each may hold.
_SIGNAL_NUMERIC = frozenset({
    "observations", "distinct_concrete_paths", "endpoints_touched",
    "field_name_similarity", "temporal_distance_ms", "repeat_count",
    "exact_value_match", "unique_value_match", "same_frame",
    "same_document_instance", "templated_from_sibling_paths",
})
_SIGNAL_CODED: dict[str, frozenset[str]] = {
    "mechanism": _MECHANISMS,
    "ordering_method": _ORDERING_METHODS,
    "ordering_relation": _ORDERING_RELATIONS,
    "trigger_type": _EVENT_TYPES,
    "strategies_measured": _LOCATOR_STRATEGIES,
}

# Free-form, and dropped. Each is replaced by its length under a `_count` key,
# so "this sensor reported three reasons" survives and the reasons do not.
_HEALTH_SUPPRESSED = ("reasons", "blind_spots", "notes")

# health.py's sensor names, statuses and metric keys, read off the real
# pipeline rather than guessed. A metric key is a dictionary key from a
# tool-owned dict, which is exactly the case COUNT_KEYS exists for: it is not
# a constant merely by being a key, so it is enumerated.
_SENSOR_NAMES = frozenset({
    "playwright_network", "runtime_probe", "dom_sensor", "storage_sensor",
    "websocket_sensor", "extension_network",
})
_SENSOR_STATUSES = frozenset({
    "healthy", "degraded", "blind", "not_enabled", "not_applicable",
})
_SENSOR_METRIC_KEYS = frozenset({
    "requests", "responses", "failed", "events", "runtime_calls",
    "user_actions", "listener_instrument_events", "patched_instrument_events",
    "playwright_xhr_fetch_requests", "screenshots", "snapshots", "writes",
    "cookie_events", "frames", "body_capture_rate", "bodies_captured",
    "bodies_skipped", "handshakes", "messages",
})
# Derived from what health.py's `_overall` can actually emit, normalised the
# same way `_health` normalises it (lowercase, non-alphanumerics -> "_"). The
# earlier set was a guess that never matched the producer -- it happened to
# contain `partial_high_coverage`, the one phrase every reference capture hit,
# so a fully-healthy session (all sensors green) failed the export the first
# time one occurred.
_OVERALL_CODES = frozenset({
    "complete_all_sensors_healthy",
    "partial_high_coverage",
    "partial_sensor_blind_spot",
    "partial_sensor_unavailable",
    "partial_sensor_blind_spot_sensor_unavailable",
    "unknown",
})
# reconcile.py's relation names, and the sensors an observation can come from.
_RELATIONS = frozenset({"same_activity", "unmatched", "conflicts_with"})
_SENSOR_SOURCES = frozenset({"playwright", "runtime", "extension", "engine"})
# The reconciliation block, level by level: a flat count, or a nested count
# map with its own key vocabulary. Enumerated rather than walked generically,
# because "it is a key" is not evidence that a string is a constant.
_RECONCILIATION_COUNTS = ("activities", "multi_sensor", "conflicts")
_RECONCILIATION_MAPS = {
    "by_relation": _RELATIONS,
    "observations_by_sensor": _SENSOR_SOURCES,
    "unmatched_by_sensor": _SENSOR_SOURCES,
}
# Reason codes the capture layer emits, from the emitters and the real capture.
# A code not listed here is DROPPED from the export and counted, not raised: a
# health projection that refused to build because capture grew a new gap reason
# would take the whole export down over a field nobody reads for its value.
_CAPTURE_GAP_CODES = frozenset({
    "out_of_scope", "frame_out_of_scope", "visual_capture_out_of_scope",
    "response_body_unavailable", "stylesheet_not_readable",
    "indexed_db_not_captured", "cache_storage_not_captured",
    "indexed_db_values_not_captured", "cache_storage_bodies_not_captured",
    "dialog_choice_unobservable",
    "websocket_handshake_headers_unavailable", "websocket_payload_truncated",
    "service_worker_visibility_unavailable", "runtime_probe_unavailable",
    "runtime_buffers_read_once_at_exit",
})
# The `where=` argument of every EventLog.sensor_error call site.
_SENSOR_ERROR_SITES = frozenset({
    "background_dom_scanner", "capture_visual_state", "console_text",
    "cookie_snapshot", "extension_record_ingest", "forensic_layer_start",
    "lifecycle_attach_context", "runtime_batch_decode",
    "runtime_main_world_install", "runtime_record_ingest",
    "runtime_sensor_attach", "storage_snapshot", "websocket_attach",
    "runtime_drain", "scan_all_frames",
})


POLICY: dict[tuple[str, str], Disposition] = {
    # --- Evidence ------------------------------------------------------
    ("Evidence", "signals"): Disposition.SIGNALS,
    ("Evidence", "event_ids"): Disposition.EVIDENCE,

    # --- ParamObservation ----------------------------------------------
    ("ParamObservation", "name"): Disposition.NAME,
    ("ParamObservation", "location"): Disposition.REASON_CODE,
    ("ParamObservation", "inferred_type"): Disposition.REASON_CODE,
    ("ParamObservation", "sample_count"): Disposition.COUNTS,
    ("ParamObservation", "distinct_values"): Disposition.COUNTS,
    ("ParamObservation", "examples"): Disposition.SAMPLE,
    ("ParamObservation", "enum_candidate"): Disposition.SAMPLE,

    # --- Endpoint -------------------------------------------------------
    ("Endpoint", "method"): Disposition.REASON_CODE,
    ("Endpoint", "template"): Disposition.ROUTE,
    ("Endpoint", "kind"): Disposition.REASON_CODE,
    ("Endpoint", "observation_count"): Disposition.COUNTS,
    ("Endpoint", "concrete_paths"): Disposition.ROUTE,
    ("Endpoint", "statuses"): Disposition.COUNTS,       # keys: COUNT_KEYS
    ("Endpoint", "params"): Disposition.STRUCTURAL,     # recursed into
    ("Endpoint", "graphql_operation"): Disposition.NAME,
    ("Endpoint", "graphql_operation_type"): Disposition.REASON_CODE,
    ("Endpoint", "persisted_query_hash"): Disposition.FINGERPRINT,
    ("Endpoint", "templated"): Disposition.COUNTS,
    ("Endpoint", "confidence"): Disposition.COUNTS,
    ("Endpoint", "evidence"): Disposition.STRUCTURAL,   # recursed into

    # --- SchemaField ----------------------------------------------------
    ("SchemaField", "path"): Disposition.NAME,
    ("SchemaField", "types"): Disposition.COUNTS,       # keys: COUNT_KEYS
    ("SchemaField", "present_count"): Disposition.COUNTS,
    ("SchemaField", "sample_count"): Disposition.COUNTS,
    ("SchemaField", "null_count"): Disposition.COUNTS,
    ("SchemaField", "occurrence_count"): Disposition.COUNTS,
    ("SchemaField", "enum_candidate"): Disposition.SAMPLE,
    ("SchemaField", "inferred_format"): Disposition.REASON_CODE,
    ("SchemaField", "examples"): Disposition.SAMPLE,

    # --- Schema ---------------------------------------------------------
    ("Schema", "endpoint_key"): Disposition.ROUTE,
    ("Schema", "direction"): Disposition.REASON_CODE,
    ("Schema", "sample_count"): Disposition.COUNTS,
    ("Schema", "root_type"): Disposition.REASON_CODE,
    ("Schema", "fields"): Disposition.STRUCTURAL,       # recursed into
    ("Schema", "status"): Disposition.REASON_CODE,
    ("Schema", "evidence"): Disposition.STRUCTURAL,     # recursed into

    # --- DependencyEdge -------------------------------------------------
    ("DependencyEdge", "source_endpoint"): Disposition.ROUTE,
    ("DependencyEdge", "source_field"): Disposition.NAME,
    ("DependencyEdge", "target_endpoint"): Disposition.ROUTE,
    ("DependencyEdge", "target_field"): Disposition.NAME,
    ("DependencyEdge", "mechanism"): Disposition.REASON_CODE,
    ("DependencyEdge", "confidence"): Disposition.COUNTS,
    ("DependencyEdge", "repeat_count"): Disposition.COUNTS,
    ("DependencyEdge", "value_uniqueness"): Disposition.COUNTS,
    ("DependencyEdge", "evidence"): Disposition.STRUCTURAL,

    # --- LocatorCandidate -----------------------------------------------
    ("LocatorCandidate", "strategy"): Disposition.REASON_CODE,
    ("LocatorCandidate", "value"): Disposition.LOCATOR,
    ("LocatorCandidate", "resolved_count"): Disposition.COUNTS,
    ("LocatorCandidate", "sample_count"): Disposition.COUNTS,
    # The prose warning interpolates a count and a framework name; the code
    # beside it is the fixed constant, and it is what survives.
    ("LocatorCandidate", "warning"): Disposition.DROP,
    ("LocatorCandidate", "warning_code"): Disposition.REASON_CODE,

    # --- UIElement -------------------------------------------------------
    # FINGERPRINT, not DROP. The key is tag|role|label|text|name|type|form, so
    # it cannot go out verbatim -- but it is also the JOIN between an element,
    # the workflow steps that touched it and the transitions it triggered.
    # Dropping it made every key None, which collapsed the join: a sanitised
    # Playwright script gave every step the last element's locator, and the
    # sanitised store could not be written at all (element_key is NOT NULL).
    # A salted digest keeps the join and carries none of the text.
    ("UIElement", "key"): Disposition.FINGERPRINT,
    # Both come straight off the page. `role` in particular is an author-
    # supplied attribute -- `role="CustomerAlice"` is legal markup -- so both
    # are checked against a vocabulary rather than trusted for looking tidy.
    ("UIElement", "tag"): Disposition.REASON_CODE,
    ("UIElement", "role"): Disposition.REASON_CODE,
    # An element's accessible name and its text are the application's own
    # content -- a password shown on a login page, a rendered table of names.
    # Neither is emitted in any form: what a shareable export is for is which
    # elements exist, how stable their locators were, and how often they were
    # used, and none of that needs the words on the screen.
    ("UIElement", "label"): Disposition.DROP,
    ("UIElement", "text"): Disposition.DROP,
    # A form's id/name attribute is author-controlled and indistinguishable
    # from a customer or tenant name. Unlike a schema field path it carries
    # almost nothing a reader needs -- the state fingerprint already groups
    # elements by form -- so it is dropped rather than kept on the hope that
    # it looks like an identifier.
    ("UIElement", "form"): Disposition.DROP,
    ("UIElement", "observation_count"): Disposition.COUNTS,
    ("UIElement", "actions"): Disposition.COUNTS,       # keys: COUNT_KEYS
    ("UIElement", "locators"): Disposition.STRUCTURAL,  # recursed into
    ("UIElement", "evidence"): Disposition.STRUCTURAL,

    # --- AppState ---------------------------------------------------------
    ("AppState", "fingerprint"): Disposition.REASON_CODE,  # a sha256 prefix
    ("AppState", "label"): Disposition.ROUTE,              # derived from the shape
    ("AppState", "url_pattern"): Disposition.ROUTE,
    ("AppState", "observation_count"): Disposition.COUNTS,
    ("AppState", "forms"): Disposition.DROP,        # see UIElement.form
    ("AppState", "evidence"): Disposition.STRUCTURAL,

    # --- StateTransition --------------------------------------------------
    ("StateTransition", "from_state"): Disposition.REASON_CODE,
    ("StateTransition", "to_state"): Disposition.REASON_CODE,
    # `trigger` is a human label built as f"{type} #{element id/label/text}",
    # so it carries page content. Plan C adds `trigger_type` -- the bare
    # EventType, with no element name attached -- as the exportable half.
    ("StateTransition", "trigger"): Disposition.DROP,
    ("StateTransition", "trigger_type"): Disposition.REASON_CODE,
    ("StateTransition", "trigger_element_key"): Disposition.FINGERPRINT,
    ("StateTransition", "trigger_event_id"): Disposition.EVIDENCE,
    ("StateTransition", "observation_count"): Disposition.COUNTS,
    ("StateTransition", "evidence"): Disposition.STRUCTURAL,

    # --- Technology --------------------------------------------------------
    ("Technology", "name"): Disposition.REASON_CODE,   # a fixed fingerprint table
    ("Technology", "category"): Disposition.REASON_CODE,
    ("Technology", "confidence"): Disposition.COUNTS,
    # NOT tool text. `signals` is built from `sorted(webforms_state |
    # webforms_ops)` and `sorted(graphql_ops)` -- ASP.NET state field names and
    # GraphQL operation names read off the application. The count survives; the
    # names do not.
    ("Technology", "signals"): Disposition.DROP,
    ("Technology", "signal_count"): Disposition.COUNTS,
    ("Technology", "evidence"): Disposition.STRUCTURAL,

    # --- Finding -----------------------------------------------------------
    ("Finding", "kind"): Disposition.REASON_CODE,
    ("Finding", "severity"): Disposition.REASON_CODE,
    # Every finding message interpolates a count and sometimes a reason read
    # off the log ("sensor failure in {where}"). kind + severity + count +
    # evidence_ids say the same thing without the interpolation.
    ("Finding", "message"): Disposition.DROP,
    ("Finding", "count"): Disposition.COUNTS,
    ("Finding", "evidence"): Disposition.STRUCTURAL,

    # --- EventIndexRow -----------------------------------------------------
    ("EventIndexRow", "event_id"): Disposition.DROP,
    ("EventIndexRow", "seq"): Disposition.DROP,
    ("EventIndexRow", "type"): Disposition.DROP,
    ("EventIndexRow", "source"): Disposition.DROP,
    ("EventIndexRow", "t_wall"): Disposition.DROP,
    ("EventIndexRow", "t_mono"): Disposition.DROP,
    ("EventIndexRow", "page_id"): Disposition.DROP,
    ("EventIndexRow", "frame_id"): Disposition.DROP,
    ("EventIndexRow", "byte_offset"): Disposition.DROP,
    ("EventIndexRow", "byte_length"): Disposition.DROP,

    # --- AnalysisResult ----------------------------------------------------
    ("AnalysisResult", "session_id"): Disposition.FINGERPRINT,
    ("AnalysisResult", "event_count"): Disposition.COUNTS,
    ("AnalysisResult", "analysis_version"): Disposition.COUNTS,
    ("AnalysisResult", "endpoints"): Disposition.STRUCTURAL,
    ("AnalysisResult", "schemas"): Disposition.STRUCTURAL,
    ("AnalysisResult", "dependencies"): Disposition.STRUCTURAL,
    ("AnalysisResult", "ui_elements"): Disposition.STRUCTURAL,
    ("AnalysisResult", "states"): Disposition.STRUCTURAL,
    ("AnalysisResult", "transitions"): Disposition.STRUCTURAL,
    ("AnalysisResult", "workflow"): Disposition.STRUCTURAL,

    # --- WorkflowStep ------------------------------------------------------
    ("WorkflowStep", "ordinal"): Disposition.COUNTS,
    ("WorkflowStep", "seq"): Disposition.COUNTS,
    ("WorkflowStep", "kind"): Disposition.REASON_CODE,
    ("WorkflowStep", "element_key"): Disposition.FINGERPRINT,
    ("WorkflowStep", "url_pattern"): Disposition.ROUTE,
    ("WorkflowStep", "repeat_count"): Disposition.COUNTS,
    ("WorkflowStep", "value_recorded"): Disposition.COUNTS,
    # Constrained to SAFE_KEYS where it is set. REASON_CODE asserts that at the
    # export boundary too, against the same frozenset -- one definition, and a
    # value from anywhere else fails loudly rather than being trusted for
    # looking like a key name.
    ("WorkflowStep", "key"): Disposition.REASON_CODE,
    ("WorkflowStep", "evidence"): Disposition.STRUCTURAL,
    ("AnalysisResult", "technologies"): Disposition.STRUCTURAL,
    ("AnalysisResult", "findings"): Disposition.STRUCTURAL,
    ("AnalysisResult", "activities"): Disposition.DROP,
    # Inferred activity segments carry route shapes, form ids and endpoint
    # paths -- application-authored text. A shareable export drops them and the
    # reader consults the local session; a sanitised segment view is future
    # work, and DROP is the safe default until each of its fields is classified.
    ("AnalysisResult", "segments"): Disposition.DROP,
    # The form catalog carries labels, option text and final values -- the
    # application's own content and, for a text field, whatever the operator
    # typed. It is dropped from a shareable export and read from the local
    # session; a sanitised catalog is future work.
    ("AnalysisResult", "forms"): Disposition.DROP,
    # The table catalog carries cell contents -- business data straight off the
    # screen. Dropped from a shareable export; read from the local session.
    ("AnalysisResult", "tables"): Disposition.DROP,
    # NOT counts. Verified against the real capture: capture_health holds
    # `overall: "PARTIAL / HIGH COVERAGE"`, eight `sensors[].reasons` strings
    # and two `notes` strings, all with whitespace. A COUNTS disposition would
    # have raised UnclassifiedField on every real export.
    ("AnalysisResult", "health"): Disposition.HEALTH,
    ("AnalysisResult", "scripts"): Disposition.DROP,
    ("AnalysisResult", "auth_headers"): Disposition.NAME,
    ("AnalysisResult", "event_index"): Disposition.DROP,
    ("AnalysisResult", "log_size"): Disposition.DROP,
    ("AnalysisResult", "log_sha256"): Disposition.DROP,
}

_MODEL_CLASSES = (
    models.AnalysisResult, models.Endpoint, models.ParamObservation,
    models.Schema, models.SchemaField, models.DependencyEdge,
    models.LocatorCandidate, models.UIElement, models.AppState,
    models.StateTransition, models.Technology, models.Finding,
    models.Evidence, models.EventIndexRow, models.WorkflowStep,
)


def missing_dispositions() -> list[str]:
    """Every model field with no declared disposition. Empty is the invariant."""
    return sorted(
        f"{cls.__name__}.{field.name}"
        for cls in _MODEL_CLASSES
        for field in dataclasses.fields(cls)
        if (cls.__name__, field.name) not in POLICY
    )


def missing_vocabularies() -> list[str]:
    """Every REASON_CODE field with no closed vocabulary. Empty is the invariant.

    A code with no declared set of values is not a code; it is a string
    somebody hoped was a constant.
    """
    gaps = [f"{cls}.{field} (REASON_CODE, no VOCABULARY entry)"
            for (cls, field), disposition in POLICY.items()
            if disposition is Disposition.REASON_CODE
            and (cls, field) not in VOCABULARY]
    gaps += [f"{cls}.{field} (VOCABULARY entry is empty)"
             for (cls, field), allowed in VOCABULARY.items()
             if isinstance(allowed, frozenset) and not allowed]
    return sorted(gaps)


def disposition_for(class_name: str, field_name: str) -> Disposition:
    try:
        return POLICY[(class_name, field_name)]
    except KeyError:
        raise UnclassifiedField(
            f"{class_name}.{field_name} has no export disposition. Classify it "
            f"in export/policy.py; a field nobody classified is not safe to "
            f"share.") from None


# --- transformations ------------------------------------------------------

def _in_vocabulary(text: str, allowed: frozenset[str] | re.Pattern[str]) -> bool:
    if isinstance(allowed, frozenset):
        return text in allowed
    return bool(allowed.match(text))


def _route(value: str, redactor: Redactor) -> str:
    """Keep the shape, drop the data. Query and fragment never survive."""
    path = str(value).split("?", 1)[0].split("#", 1)[0]
    out = []
    for segment in path.split("/"):
        # An empty segment is the separator itself; a hole is the templater's
        # own placeholder; a safe segment is an authored route word. Everything
        # else is data.
        if not segment or _HOLE.match(segment) or (
            _SAFE_SEGMENT.match(segment) and identifier_kind(segment) is None
        ):
            out.append(segment)
        else:
            out.append("{id}")
    return "/".join(out)


def _name(value: str, redactor: Redactor) -> str:
    text = str(value)
    if is_credential_name(text):
        return "<redacted: credential name>"
    if _SAFE_NAME.match(text) and identifier_kind(text) is None:
        return text
    return redactor.pseudonym_for(text, "NAME")


def _bucket(value: str, redactor: Redactor) -> str:
    """A coarse size bucket and a stable pseudonym. Never a value.

    The bucket is `0` / `1-10` / `11-50` / `51-200` / `200+`. An exact
    character count is itself a fingerprint of the value -- it distinguishes a
    7-character password from a 20-character one, and a surname from a full
    name -- so the export does not carry one.
    """
    text = str(value)
    if not text:
        return "<text: 0>"
    return f"<text: {size_bucket(text)} {redactor.pseudonym_for(text, 'TEXT')}>"


def _locator(value: str, redactor: Redactor) -> str:
    """Keep a structurally-safe selector; REPLACE anything else outright.

    `#login-form` and `[name="user"]` are how a reader finds the element again
    and carry no data. `text='SuperSecretPassword!'` carries the page.

    A shape is deliberately NOT offered here. `text=<text: 11-50 TEXT_003>`
    reads like something you could still use, and the one thing a shareable
    export must not do is hand someone a locator that looks usable and is not.
    A fixed marker says what happened.
    """
    text = str(value)
    # A locator built on one of these strategies carries page TEXT by
    # construction -- `text='SuperSecretPassword!'`, `label='Customer name'` --
    # so it goes whatever shape it happens to have. Checked first, because
    # `text='AcmeInternalProject'` is whitespace-free and would otherwise pass
    # every structural test below.
    if _TEXT_BEARING_LOCATOR.match(text):
        return LOCATOR_OMITTED
    if any(ch.isspace() for ch in text) or not _SAFE_LOCATOR.match(text):
        return LOCATOR_OMITTED
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_-]*", text)
    if not tokens or any(identifier_kind(t) is not None for t in tokens):
        return LOCATOR_OMITTED
    return text


def _reason_code(value: object, *, where: str,
                 allowed: frozenset[str] | re.Pattern[str] | None) -> str:
    """One value from a declared, closed vocabulary. Anything else raises.

    Deliberately NOT a shape check. `CustomerAlice`, `tenant42`,
    `AcmeInternalProject` and `sk_live_abc123` are all whitespace-free tokens
    under 64 characters; a rule that admitted them would be admitting captured
    values while claiming to admit constants. Membership in the vocabulary for
    THIS EXACT FIELD is the whole test.
    """
    if allowed is None:
        raise UnclassifiedField(
            f"{where} is classified REASON_CODE but declares no vocabulary. "
            f"Add one to VOCABULARY in export/policy.py; a code with no closed "
            f"set of values is not a code.")
    text = str(value)
    if not _in_vocabulary(text, allowed):
        raise UnclassifiedField(
            f"{where} is classified REASON_CODE and {text[:60]!r} is not in its "
            f"vocabulary. Either a producer added a value and did not declare "
            f"it, or a captured value reached a field that is supposed to hold "
            f"a constant.")
    return text


def _counts(value: Any, *, where: str,
            keys: frozenset[str] | re.Pattern[str] | None = None) -> Any:
    """Numbers, and nothing else unless a key vocabulary says otherwise.

    Strings are rejected by default -- including dictionary KEYS. A key read
    off a captured body is not a constant merely by being a key, so a
    string-keyed count mapping declares its own vocabulary in `COUNT_KEYS` and
    is validated against that, never through the generic reason-code path.
    """
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, str):
        raise UnclassifiedField(
            f"{where} is classified COUNTS but holds the string {value[:40]!r}. "
            f"COUNTS is numbers. If this field is a string-keyed count mapping, "
            f"declare its key vocabulary in COUNT_KEYS.")
    if isinstance(value, dict):
        if keys is None and value:
            raise UnclassifiedField(
                f"{where} is a string-keyed COUNTS mapping with no entry in "
                f"COUNT_KEYS. Declare the keys it may hold.")
        out: dict[str, Any] = {}
        for key, item in value.items():
            text = str(key)
            if keys is None or not _in_vocabulary(text, keys):
                raise UnclassifiedField(
                    f"{where} has key {text[:40]!r}, which is not in its "
                    f"declared key vocabulary.")
            out[text] = _counts(item, where=f"{where}[{text}]")
        return out
    if isinstance(value, (list, tuple)):
        return [_counts(v, where=where) for v in value]
    raise UnclassifiedField(f"{where} holds an unclassifiable {type(value).__name__}")


def _signals(value: Any, *, where: str) -> dict[str, Any]:
    """`Evidence.signals`, projected onto its declared sub-schema.

    A free-form bag: numeric weights sit beside `attribution` (prose),
    `value_preview` (a captured value by definition), `consumer_stack_top` (a
    stack frame) and `state_fields` / `operation_fields` / `operations`
    (application field names). Declared numeric keys pass, declared coded keys
    are validated, everything else is dropped -- including keys nobody has
    classified, because a signal bag gaining a key must not be able to widen
    the export by itself.
    """
    if not isinstance(value, dict):
        return {}
    out: dict[str, Any] = {}
    dropped = 0
    for key, item in value.items():
        name = str(key)
        if name in _SIGNAL_NUMERIC and isinstance(item, (int, float, bool)):
            out[name] = item
        elif name in _SIGNAL_CODED:
            allowed = _SIGNAL_CODED[name]
            candidates = item if isinstance(item, list) else [item]
            kept = [str(c) for c in candidates if _in_vocabulary(str(c), allowed)]
            if len(kept) != len(candidates):
                dropped += 1
                continue
            out[name] = kept if isinstance(item, list) else kept[0]
        else:
            dropped += 1
    if dropped:
        out["signals_dropped"] = dropped
    return out


def _numeric_map(value: Any, allowed: frozenset[str]) -> tuple[dict[str, Any], int]:
    """A count map filtered to its declared keys, and how many were dropped."""
    if not isinstance(value, dict):
        return {}, 0
    kept = {str(k): v for k, v in value.items()
            if str(k) in allowed and isinstance(v, (int, float))}
    return kept, len(value) - len(kept)


def _reconciliation(value: dict[str, Any]) -> dict[str, Any]:
    """The multi-sensor agreement block, level by level.

    Enumerated rather than walked generically: `by_relation` is keyed by
    reconcile.py's relation names and the two `*_by_sensor` maps by sensor
    names, and "it is a dictionary key" is not evidence that a string is a
    constant.
    """
    out: dict[str, Any] = {}
    for key in _RECONCILIATION_COUNTS:
        if isinstance(value.get(key), (int, float)):
            out[key] = value[key]
    for key, allowed in _RECONCILIATION_MAPS.items():
        if key in value:
            kept, dropped = _numeric_map(value[key], allowed)
            out[key] = kept
            if dropped:
                out[f"{key}_undeclared"] = dropped
    return out


def _health(value: Any, redactor: Redactor) -> dict[str, Any]:
    """Project capture health onto a declared sub-schema.

    Verified against the real capture: `overall` is `"PARTIAL / HIGH COVERAGE"`,
    `sensors[].reasons` holds strings like `"10 runtime sensor error(s)"`, and
    `notes` holds `"131 activity/activities seen only by runtime"`. Every one
    is derived, not a constant -- health.py builds them with f-strings and
    `reason.replace("_", " ")` -- so none of them leaves.

    What leaves is what was already structured: gap codes and their counts,
    sensor names, statuses, metrics, and a count of each suppressed list.
    """
    if not isinstance(value, dict):
        return {}
    out: dict[str, Any] = {}
    # Count maps whose KEYS are gap codes and sensor-error sites. Unknown keys
    # are DROPPED and counted rather than raised: a health projection that
    # refused to build because capture grew a new gap reason would take the
    # whole export down over a field nobody reads for its value.
    for key, allowed in (("capture_gaps", _CAPTURE_GAP_CODES),
                         ("sensor_errors", _SENSOR_ERROR_SITES)):
        if key in value and isinstance(value[key], dict):
            kept, omitted = _numeric_map(value[key], allowed)
            out[key] = kept
            if omitted:
                out[f"{key}_undeclared"] = omitted
    if isinstance(value.get("reconciliation"), dict):
        out["reconciliation"] = _reconciliation(value["reconciliation"])
    if "overall" in value:
        # `_overall` returns one of a small set of phrases containing spaces
        # and a slash. The CODE is exported; the phrase is not.
        out["overall_code"] = _reason_code(
            re.sub(r"[^a-z0-9]+", "_", str(value["overall"]).lower()).strip("_"),
            where="health.overall", allowed=_OVERALL_CODES)
    for key in _HEALTH_SUPPRESSED:
        if key in value:
            out[f"{key}_count"] = len(value[key] or [])
    sensors = []
    for sensor in value.get("sensors") or []:
        row: dict[str, Any] = {}
        if "sensor" in sensor:
            row["sensor"] = _reason_code(sensor["sensor"],
                                         where="health.sensors.sensor",
                                         allowed=_SENSOR_NAMES)
        if "status" in sensor:
            row["status"] = _reason_code(sensor["status"],
                                         where="health.sensors.status",
                                         allowed=_SENSOR_STATUSES)
        if "metrics" in sensor:
            # Keys as well as values: a metric name is a dictionary key from a
            # tool-owned dict, and that is not evidence it is a constant.
            kept, omitted = _numeric_map(sensor["metrics"], _SENSOR_METRIC_KEYS)
            row["metrics"] = kept
            if omitted:
                row["metrics_undeclared"] = omitted
        for key in _HEALTH_SUPPRESSED:
            if key in sensor:
                row[f"{key}_count"] = len(sensor[key] or [])
        sensors.append(row)
    if sensors:
        out["sensors"] = sensors
    return out


def _empty_like(value: Any) -> Any:
    if isinstance(value, list):
        return []
    if isinstance(value, dict):
        return {}
    return None


def _apply(disposition: Disposition, value: Any, redactor: Redactor,
           *, key: tuple[str, str]) -> Any:
    where = f"{key[0]}.{key[1]}"
    if disposition is Disposition.DROP:
        return _empty_like(value)
    if value is None:
        return None
    if disposition is Disposition.COUNTS:
        return _counts(value, where=where, keys=COUNT_KEYS.get(key))
    if disposition is Disposition.SIGNALS:
        return _signals(value, where=where)
    if disposition is Disposition.HEALTH:
        return _health(value, redactor)
    if disposition is Disposition.EVIDENCE:
        return value if isinstance(value, str) else list(value)
    if disposition is Disposition.STRUCTURAL:
        if isinstance(value, str):
            raise UnclassifiedField(
                f"{where} is classified STRUCTURAL but holds a string. "
                f"STRUCTURAL is numbers, booleans and model containers; a "
                f"string needs a disposition that validates or transforms it.")
        return value
    if disposition is Disposition.REASON_CODE:
        allowed = VOCABULARY.get(key)
        if isinstance(value, list):
            return [_reason_code(v, where=where, allowed=allowed) for v in value]
        return _reason_code(value, where=where, allowed=allowed)
    if disposition is Disposition.FINGERPRINT:
        return redactor.pseudonyms.fingerprint(str(value))

    per_value = {
        Disposition.ROUTE: _route,
        Disposition.NAME: _name,
        Disposition.BUCKET: _bucket,
        Disposition.LOCATOR: _locator,
        Disposition.SAMPLE: lambda v, r: r.scrub_example(v),
    }[disposition]

    if isinstance(value, str):
        return per_value(value, redactor)
    if isinstance(value, list):
        return [per_value(v, redactor) if isinstance(v, str) else v for v in value]
    if isinstance(value, dict):
        return {per_value(k, redactor) if isinstance(k, str) else k: v
                for k, v in value.items()}
    return value


def _is_model_container(value: Any) -> bool:
    if dataclasses.is_dataclass(value):
        return True
    return bool(value) and isinstance(value, list) and dataclasses.is_dataclass(value[0])


def _recurse(value: Any, redactor: Redactor) -> Any:
    if dataclasses.is_dataclass(value):
        return _sanitise_dataclass(value, redactor)
    return [_sanitise_dataclass(v, redactor) for v in value]


def _sanitise_dataclass(instance: Any, redactor: Redactor) -> Any:
    """Rebuild one model dataclass with every field's disposition applied."""
    name = type(instance).__name__
    kwargs: dict[str, Any] = {}
    for field in dataclasses.fields(instance):
        value = getattr(instance, field.name)
        key = (name, field.name)
        disposition = disposition_for(*key)
        if disposition is Disposition.STRUCTURAL and _is_model_container(value):
            kwargs[field.name] = _recurse(value, redactor)
        else:
            kwargs[field.name] = _apply(disposition, value, redactor, key=key)
    return type(instance)(**kwargs)


def sanitise(result: models.AnalysisResult,
             redactor: Redactor) -> models.AnalysisResult:
    """One sanitisation boundary for the whole export.

    Everything downstream -- `dataset.json` and `export/shared/report.md` --
    is serialised from the result this returns, so there is one place to test
    and one place to get wrong.
    """
    unclassified = missing_dispositions()
    if unclassified:
        raise UnclassifiedField(
            "model fields with no export disposition: " + ", ".join(unclassified))
    unvalidated = missing_vocabularies()
    if unvalidated:
        raise UnclassifiedField(
            "reason codes with no closed vocabulary: " + ", ".join(unvalidated))
    return _sanitise_dataclass(result, redactor)
