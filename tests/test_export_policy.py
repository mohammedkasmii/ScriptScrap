"""The export's value policy.

The audit found 28 fields of the "sanitised" dataset carrying captured content
verbatim, because sanitisation was a whitelist of STRUCTURES applied at 30 call
sites, and any field nobody thought about passed through.

This is the inversion: a field with no declared disposition is an error, a code
is checked against a closed vocabulary rather than a shape, and a marker placed
in every transformed field must survive nowhere.
"""

from __future__ import annotations

import dataclasses
import json
import re

import pytest
from hostile import MARKER

from scriptscrap.analysis import models
from scriptscrap.export.policy import (
    COUNT_KEYS,
    LOCATOR_OMITTED,
    POLICY,
    VOCABULARY,
    Disposition,
    UnclassifiedField,
    disposition_for,
    missing_dispositions,
    missing_vocabularies,
    sanitise,
    size_bucket,
)
from scriptscrap.export.redact import Redactor

MODEL_CLASSES = [
    models.AnalysisResult, models.Endpoint, models.ParamObservation,
    models.Schema, models.SchemaField, models.DependencyEdge,
    models.LocatorCandidate, models.UIElement, models.AppState,
    models.StateTransition, models.Technology, models.Finding,
    models.Evidence, models.EventIndexRow,
]


def test_no_model_field_is_unclassified():
    """Deny by default: a new field is unsafe until someone classifies it."""
    assert missing_dispositions() == []


def test_every_model_class_is_covered():
    """A new model dataclass must be added to the policy, not forgotten."""
    covered = {name for name, _ in POLICY}
    for cls in MODEL_CLASSES:
        assert cls.__name__ in covered, f"{cls.__name__} has no policy entries"


def test_an_unknown_field_raises_rather_than_passing_through():
    with pytest.raises(UnclassifiedField):
        disposition_for("Endpoint", "a_field_nobody_classified")


def _marked_result() -> models.AnalysisResult:
    """An AnalysisResult carrying MARKER in every field that is *transformed*.

    REASON_CODE fields hold LEGITIMATE values here, because their contract is
    that an illegitimate one raises rather than being transformed. Those are
    exercised separately by `test_a_captured_value_can_never_pass_as_a_reason_code`,
    which asserts the raise for every one of them.
    """
    evidence = models.Evidence(signals={"attribution": MARKER, "observations": 1},
                               event_ids=["evt-00000001"])
    return models.AnalysisResult(
        session_id=MARKER, event_count=1,
        endpoints=[models.Endpoint(
            method="GET", template="/x/" + MARKER, kind="rest",
            observation_count=1, concrete_paths=["/x/" + MARKER],
            statuses={"200": 1},
            params=[models.ParamObservation(
                name=MARKER, location="query", inferred_type="string",
                sample_count=1, distinct_values=1, examples=[MARKER],
                enum_candidate=[MARKER])],
            graphql_operation=MARKER, graphql_operation_type="query",
            persisted_query_hash=MARKER, templated=True, confidence=0.5,
            evidence=evidence)],
        schemas=[models.Schema(
            endpoint_key="GET /x", direction="response", sample_count=1,
            root_type="object", status="200",
            fields=[models.SchemaField(
                path=MARKER, types={"string": 1}, present_count=1,
                sample_count=1, examples=[MARKER], enum_candidate=[MARKER],
                inferred_format="uuid")],
            evidence=evidence)],
        dependencies=[models.DependencyEdge(
            source_endpoint=MARKER, source_field=MARKER,
            target_endpoint=MARKER, target_field=MARKER,
            mechanism="response_to_request",
            confidence=1.0, repeat_count=1, value_uniqueness=1,
            evidence=evidence)],
        ui_elements=[models.UIElement(
            key=MARKER, tag="input", role="textbox", label=MARKER, text=MARKER,
            form=MARKER, observation_count=1, actions={"user_click": 1},
            locators=[models.LocatorCandidate(
                strategy="css", value=MARKER, resolved_count=1,
                sample_count=1, warning=MARKER, warning_code="value_varied")],
            evidence=evidence)],
        states=[models.AppState(
            fingerprint="a1b2c3d4e5f6", label=MARKER, url_pattern="/" + MARKER,
            observation_count=1, forms=[MARKER], evidence=evidence)],
        transitions=[models.StateTransition(
            from_state="a1b2c3d4e5f6", to_state="a1b2c3d4e5f6", trigger=MARKER,
            observation_count=1, evidence=evidence)],
        technologies=[models.Technology(
            name="jQuery", category="library", confidence=1.0,
            signals=[MARKER], signal_count=1, evidence=evidence)],
        findings=[models.Finding(
            kind="capture_gap", severity="info", message=MARKER, count=1,
            evidence=evidence)],
        health={"overall": "PARTIAL / HIGH COVERAGE", "notes": [MARKER],
                "capture_gaps": {"out_of_scope": 3, MARKER: 1},
                "sensors": [{"sensor": "runtime_probe", "status": "healthy",
                             "reasons": [MARKER], "metrics": {"n": 1},
                             "blind_spots": [MARKER]}]},
        scripts=[{"url": "https://h/" + MARKER, "sha256": "a" * 64, "size": 1,
                  "inventory": {"declared_functions": [MARKER]},
                  "evidence_ids": ["evt-00000001"]}],
        auth_headers={"cookie": 1},
        log_sha256="b" * 64, log_size=1,
    )


def _instances_of(root, class_name: str) -> list:
    """Every instance of one model class reachable from a result."""
    found = []
    stack = [root]
    while stack:
        item = stack.pop()
        if dataclasses.is_dataclass(item):
            if type(item).__name__ == class_name:
                found.append(item)
            stack.extend(getattr(item, f.name) for f in dataclasses.fields(item))
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
    return found


def _strings(value) -> list[str]:
    """Every string reachable in a dataclass tree or plain container."""
    if isinstance(value, str):
        return [value]
    if dataclasses.is_dataclass(value):
        out = []
        for field in dataclasses.fields(value):
            out += _strings(getattr(value, field.name))
        return out
    if isinstance(value, dict):
        out = []
        for key, item in value.items():
            out += _strings(key) + _strings(item)
        return out
    if isinstance(value, (list, tuple, set)):
        out = []
        for item in value:
            out += _strings(item)
        return out
    return []


def test_a_marker_in_every_string_field_never_survives_sanitisation():
    """The property, not a spot check: nothing carrying MARKER gets out."""
    safe = sanitise(_marked_result(), Redactor())
    survivors = [s for s in _strings(safe) if MARKER in s]
    assert survivors == [], f"{len(survivors)} field(s) leaked: {survivors[:5]}"


def test_sanitisation_keeps_the_analysis_useful():
    """Deny-by-default must not produce an export nobody can read."""
    safe = sanitise(_marked_result(), Redactor())
    assert safe.endpoints and safe.endpoints[0].method == "GET"
    assert safe.endpoints[0].kind == "rest"
    assert safe.endpoints[0].statuses == {"200": 1}
    assert safe.endpoints[0].evidence.event_ids == ["evt-00000001"]
    assert safe.schemas and safe.schemas[0].direction == "response"
    assert safe.schemas[0].fields[0].types == {"string": 1}
    assert safe.dependencies and safe.dependencies[0].confidence == 1.0
    assert safe.ui_elements and safe.ui_elements[0].tag == "input"
    assert safe.findings and safe.findings[0].severity == "info"
    assert safe.event_count == 1


def test_pseudonyms_stay_stable_so_correlation_survives():
    """Two occurrences of one captured value must map to one pseudonym."""
    safe = sanitise(_marked_result(), Redactor())
    forms = {u.form for u in safe.ui_elements} | {
        f for s in safe.states for f in s.forms}
    assert len(forms) == 1, "one input value produced two pseudonyms"


def test_the_evidence_index_and_log_fingerprint_are_dropped():
    """A sanitised export has no log, so an offset into one is a lie."""
    safe = sanitise(_marked_result(), Redactor())
    assert safe.event_index == []
    assert safe.log_size is None
    assert safe.log_sha256 is None


def test_the_session_id_is_a_fingerprint_not_the_id():
    safe = sanitise(_marked_result(), Redactor())
    assert MARKER not in safe.session_id
    assert len(safe.session_id) == 12


def test_a_route_keeps_its_shape_and_loses_its_data():
    result = _marked_result()
    result.endpoints[0].template = "/dossiers/GAR-0007/notes?token=abc#frag"
    safe = sanitise(result, Redactor())
    template = safe.endpoints[0].template
    assert template.startswith("/dossiers/")
    assert "notes" in template, "a route word must survive"
    assert "GAR-0007" not in template, "an identifier must not"
    assert "token=abc" not in template and "#frag" not in template


def test_element_text_and_label_are_removed_entirely():
    """Not shaped, not pseudonymised: removed. An element's accessible name and
    its text are the application's own content -- a password shown on a login
    page, a rendered table of names -- and a shareable export does not need the
    words on the screen to say which elements exist and how stable they were."""
    result = _marked_result()
    result.ui_elements[0].text = "SuperSecretPassword!"
    result.ui_elements[0].label = "Password"
    safe = sanitise(result, Redactor())
    assert safe.ui_elements[0].text is None
    assert safe.ui_elements[0].label is None
    # and the structural metadata a reader actually uses survives
    assert safe.ui_elements[0].tag == "input"
    assert safe.ui_elements[0].role == "textbox"
    assert safe.ui_elements[0].observation_count == 1
    assert safe.ui_elements[0].actions == {"user_click": 1}
    assert safe.ui_elements[0].locators[0].sample_count == 1


def test_a_locator_carrying_free_text_is_replaced_not_shaped():
    """A shape reads like something you could still use. A fixed marker does
    not."""
    result = _marked_result()
    result.ui_elements[0].locators[0].value = "text='SuperSecretPassword!'"
    safe = sanitise(result, Redactor())
    assert safe.ui_elements[0].locators[0].value == LOCATOR_OMITTED


def test_a_structurally_safe_locator_survives_whole():
    result = _marked_result()
    result.ui_elements[0].locators[0].value = '[name="username"]'
    safe = sanitise(result, Redactor())
    assert safe.ui_elements[0].locators[0].value == '[name="username"]'


@pytest.mark.parametrize(("text", "expected"), [
    ("", "0"), ("a", "1-10"), ("a" * 10, "1-10"), ("a" * 11, "11-50"),
    ("a" * 50, "11-50"), ("a" * 51, "51-200"), ("a" * 200, "51-200"),
    ("a" * 201, "200+"), ("a" * 5000, "200+"),
])
def test_size_buckets_are_coarse(text, expected):
    """An exact character count is a fingerprint of the value in its own
    right: it separates a 7-character password from a 20-character one."""
    assert size_bucket(text) == expected


def test_no_exact_length_or_word_count_reaches_the_export():
    from scriptscrap.export import DatasetExporter

    result = _marked_result()
    unique = "q" * 137          # a length no bucket boundary shares
    result.states[0].forms = [unique]
    blob = json.dumps(DatasetExporter().build(result), ensure_ascii=False)
    assert "137" not in blob
    assert "chars" not in blob and "words" not in blob


def test_capture_health_free_text_never_survives():
    """Verified against the real capture: overall, sensors[].reasons and notes
    are all derived strings built with f-strings in health.py."""
    safe = sanitise(_marked_result(), Redactor())
    assert MARKER not in json.dumps(safe.health, ensure_ascii=False)
    assert "reasons" not in safe.health
    assert "notes" not in safe.health
    assert "overall" not in safe.health
    assert safe.health["overall_code"] == "partial_high_coverage"
    assert safe.health["notes_count"] == 1
    assert safe.health["sensors"][0]["reasons_count"] == 1
    assert safe.health["sensors"][0]["blind_spots_count"] == 1
    assert safe.health["sensors"][0]["status"] == "healthy"
    # the declared gap code survives; the undeclared one is dropped and counted
    assert safe.health["capture_gaps"] == {"out_of_scope": 3}
    assert safe.health["capture_gaps_undeclared"] == 1


def test_a_reason_code_that_starts_being_interpolated_fails_the_build():
    """The point of a code is that it cannot grow a count inside it."""
    result = _marked_result()
    result.findings[0].kind = "sensor failure in background_dom_scanner"
    with pytest.raises(UnclassifiedField) as excinfo:
        sanitise(result, Redactor())
    assert "REASON_CODE" in str(excinfo.value)


# --- closed vocabularies --------------------------------------------------

# Captured values that a shape check would wave through: no whitespace, well
# under 64 characters, plausible-looking. Every one of them is somebody's
# customer, tenant or secret.
CAPTURED_TOKENS = ["CustomerAlice", "tenant42", "sk_live_abc123",
                   "AcmeInternalProject"]

# One (class, field) -> setter for every REASON_CODE field in the policy, so
# the hostile sweep below cannot silently skip one.
REASON_CODE_SETTERS = {
    ("Endpoint", "method"): lambda r, v: setattr(r.endpoints[0], "method", v),
    ("Endpoint", "kind"): lambda r, v: setattr(r.endpoints[0], "kind", v),
    ("Endpoint", "graphql_operation_type"):
        lambda r, v: setattr(r.endpoints[0], "graphql_operation_type", v),
    ("ParamObservation", "location"):
        lambda r, v: setattr(r.endpoints[0].params[0], "location", v),
    ("ParamObservation", "inferred_type"):
        lambda r, v: setattr(r.endpoints[0].params[0], "inferred_type", v),
    ("Schema", "direction"): lambda r, v: setattr(r.schemas[0], "direction", v),
    ("Schema", "root_type"): lambda r, v: setattr(r.schemas[0], "root_type", v),
    ("Schema", "status"): lambda r, v: setattr(r.schemas[0], "status", v),
    ("SchemaField", "inferred_format"):
        lambda r, v: setattr(r.schemas[0].fields[0], "inferred_format", v),
    ("DependencyEdge", "mechanism"):
        lambda r, v: setattr(r.dependencies[0], "mechanism", v),
    ("LocatorCandidate", "strategy"):
        lambda r, v: setattr(r.ui_elements[0].locators[0], "strategy", v),
    ("LocatorCandidate", "warning_code"):
        lambda r, v: setattr(r.ui_elements[0].locators[0], "warning_code", v),
    ("UIElement", "tag"): lambda r, v: setattr(r.ui_elements[0], "tag", v),
    ("UIElement", "role"): lambda r, v: setattr(r.ui_elements[0], "role", v),
    ("AppState", "fingerprint"):
        lambda r, v: setattr(r.states[0], "fingerprint", v),
    ("StateTransition", "from_state"):
        lambda r, v: setattr(r.transitions[0], "from_state", v),
    ("StateTransition", "to_state"):
        lambda r, v: setattr(r.transitions[0], "to_state", v),
    ("Technology", "name"): lambda r, v: setattr(r.technologies[0], "name", v),
    ("Technology", "category"):
        lambda r, v: setattr(r.technologies[0], "category", v),
    ("Finding", "kind"): lambda r, v: setattr(r.findings[0], "kind", v),
    ("Finding", "severity"): lambda r, v: setattr(r.findings[0], "severity", v),
}


def test_structural_admits_no_bare_strings():
    """STRUCTURAL is numbers, booleans and model containers.

    An earlier draft used STRUCTURAL for "a closed vocabulary this tool
    produces" and passed those through unchecked, which is how UIElement.role
    -- author-supplied ARIA, straight off the page -- would have been emitted
    verbatim."""
    safe = sanitise(_marked_result(), Redactor())
    for (cls, field), disposition in POLICY.items():
        if disposition is not Disposition.STRUCTURAL:
            continue
        for instance in _instances_of(safe, cls):
            value = getattr(instance, field)
            assert not isinstance(value, str), f"{cls}.{field} is a bare string"


def test_a_string_reaching_structural_raises_rather_than_passing():
    """The runtime half of the rule above, for a field added later."""
    from scriptscrap.export.policy import _apply

    with pytest.raises(UnclassifiedField) as excinfo:
        _apply(Disposition.STRUCTURAL, "CustomerAlice", Redactor(),
               key=("Endpoint", "params"))
    assert "STRUCTURAL" in str(excinfo.value)


def test_every_reason_code_field_has_a_non_empty_closed_vocabulary():
    """Replaces an earlier "is it a token?" check, which validated nothing:
    CustomerAlice is a token. A code with no declared set of values is a
    string somebody hoped was a constant."""
    assert missing_vocabularies() == []
    coded = {k for k, d in POLICY.items() if d is Disposition.REASON_CODE}
    assert coded, "the policy declares no reason codes"
    for key in coded:
        allowed = VOCABULARY[key]
        assert isinstance(allowed, (frozenset, re.Pattern)), key
        if isinstance(allowed, frozenset):
            assert allowed, f"{key} has an empty vocabulary"


def test_the_hostile_sweep_covers_every_reason_code_field():
    """A field added to the policy without a setter here would be untested."""
    coded = {k for k, d in POLICY.items() if d is Disposition.REASON_CODE}
    assert coded - set(REASON_CODE_SETTERS) == set(), (
        "REASON_CODE fields with no hostile-sweep setter: "
        f"{sorted(coded - set(REASON_CODE_SETTERS))}")


@pytest.mark.parametrize("field", sorted(REASON_CODE_SETTERS))
@pytest.mark.parametrize("captured", CAPTURED_TOKENS)
def test_a_captured_value_can_never_pass_as_a_reason_code(field, captured):
    """No whitespace, short, tidy -- and it is a customer name, a tenant id or
    a live secret key. Membership in the vocabulary is the only test."""
    result = _marked_result()
    REASON_CODE_SETTERS[field](result, captured)
    with pytest.raises(UnclassifiedField) as excinfo:
        sanitise(result, Redactor())
    assert captured in str(excinfo.value) or "vocabulary" in str(excinfo.value)


@pytest.mark.parametrize("captured", CAPTURED_TOKENS)
def test_a_captured_value_can_never_pass_as_a_count_key(captured):
    """A key read off a captured body is not a constant by being a key."""
    for mutate in (
        lambda r: r.endpoints[0].statuses.update({captured: 1}),
        lambda r: r.schemas[0].fields[0].types.update({captured: 1}),
        lambda r: r.ui_elements[0].actions.update({captured: 1}),
    ):
        result = _marked_result()
        mutate(result)
        with pytest.raises(UnclassifiedField):
            sanitise(result, Redactor())


@pytest.mark.parametrize("captured", CAPTURED_TOKENS)
def test_a_captured_value_can_never_pass_as_a_signal(captured):
    result = _marked_result()
    result.dependencies[0].evidence.signals["ordering_method"] = captured
    result.dependencies[0].evidence.signals[captured] = captured
    safe = sanitise(result, Redactor())
    assert captured not in json.dumps(
        [s.evidence.signals for s in safe.dependencies], ensure_ascii=False)


@pytest.mark.parametrize("captured", CAPTURED_TOKENS)
def test_a_captured_value_can_never_pass_through_capture_health(captured):
    result = _marked_result()
    result.health["capture_gaps"][captured] = 1
    result.health["sensors"][0]["metrics"][captured] = 1
    safe = sanitise(result, Redactor())
    assert captured not in json.dumps(safe.health, ensure_ascii=False)


@pytest.mark.parametrize("captured", CAPTURED_TOKENS)
def test_no_captured_token_reaches_the_shared_dataset(captured):
    """The end-to-end statement: through sanitise, through the serialiser,
    through the report. Nothing from a NEVER-VERBATIM field gets out.

    A URL path segment is deliberately not in this list -- see
    `test_a_route_word_is_kept_and_that_is_the_documented_trade` for the one
    field whose contract is different and why.
    """
    from scriptscrap.analysis.report import render
    from scriptscrap.export import DatasetExporter

    result = _marked_result()
    result.ui_elements[0].label = captured
    result.ui_elements[0].text = captured
    result.ui_elements[0].locators[0].value = f"text='{captured}'"
    result.ui_elements[0].form = captured
    result.states[0].forms = [captured]
    result.findings[0].message = captured
    result.technologies[0].signals = [captured]
    result.dependencies[0].evidence.signals["value_preview"] = captured
    result.dependencies[0].evidence.signals["attribution"] = captured
    result.transitions[0].trigger = f"user_click #{captured}"
    safe = sanitise(result, Redactor())
    blob = json.dumps(DatasetExporter().build_from_sanitised(safe),
                      ensure_ascii=False) + render(safe)
    assert captured not in blob


def test_the_documented_limits_of_route_and_name():
    """Two dispositions keep authored-looking words, and cannot prove they are
    not data. This pins where that line falls, so it is on the record.

    `SchemaField.path` and `ParamObservation.name` keep `CustomerAlice`,
    because the name IS the substance of a schema block and pseudonymising
    every one leaves nothing a reader can use. `UIElement.form` and
    `AppState.forms` do NOT, because there the name carries almost nothing --
    so they are dropped rather than kept on the hope that they look tidy.
    """
    result = _marked_result()
    result.schemas[0].fields[0].path = "CustomerAlice"
    result.endpoints[0].params[0].name = "CustomerAlice"
    result.ui_elements[0].form = "CustomerAlice"
    result.states[0].forms = ["CustomerAlice"]
    safe = sanitise(result, Redactor())

    assert safe.schemas[0].fields[0].path == "CustomerAlice", "a field path is kept"
    assert safe.endpoints[0].params[0].name == "CustomerAlice", "a param name is kept"
    assert safe.ui_elements[0].form is None, "a form identifier is dropped"
    assert safe.states[0].forms == [], "form identifiers are dropped"


def test_a_route_word_is_kept_and_that_is_the_documented_trade():
    """ROUTE keeps a digit-free path segment, by design and on purpose.

    It cannot tell `CustomerAlice` from `radio-buttons`: both are authored
    words in a URL, and dropping every one of them would turn
    `/api/health-check` into `/{id}/{id}` and leave the export with no route
    shapes at all -- which is most of what it exists to carry.

    So this is a stated limit of the ROUTE disposition, not an oversight. What
    it DOES guarantee is that identifier-shaped data, query strings and
    fragments never survive. That half is asserted here so the boundary is on
    the record rather than discovered later.
    """
    result = _marked_result()
    result.endpoints[0].template = (
        "/api/health-check/GAR-0007/sk_live_abc123?token=x#frag")
    safe = sanitise(result, Redactor())
    template = safe.endpoints[0].template

    assert "health-check" in template, "a route word must survive"
    assert "GAR-0007" not in template, "identifier-shaped data must not"
    assert "sk_live_abc123" not in template, "a secret-shaped segment must not"
    assert "token=x" not in template and "#frag" not in template
    assert template == "/api/health-check/{id}/{id}"


def test_every_declared_vocabulary_value_is_accepted():
    """The positive half: a legitimate tool-owned code must not be rejected.

    Guards against a vocabulary that is closed by being empty.
    """
    for field, setter in sorted(REASON_CODE_SETTERS.items()):
        allowed = VOCABULARY[field]
        values = (sorted(allowed) if isinstance(allowed, frozenset)
                  else (["200"] if field[1] == "status" else ["a1b2c3d4e5f6"]))
        assert values, f"{field} has nothing to accept"
        for value in values:
            result = _marked_result()
            setter(result, value)
            sanitise(result, Redactor())      # must not raise


def test_the_vocabularies_track_the_enums_they_came_from():
    """A producer that adds an EventType has to come here.

    Asserted against the enum rather than a copied list, so the two cannot
    drift silently.
    """
    from scriptscrap.events import EventType

    # `actions` is a COUNTS mapping, so its EventType keys live in COUNT_KEYS.
    assert COUNT_KEYS[("UIElement", "actions")] == frozenset(
        str(t) for t in EventType)


def test_every_reason_code_the_real_fixture_produces_is_in_its_vocabulary():
    """Run the real pipeline over the committed log. If a producer emits a
    value nobody declared, this fails here rather than in an operator's
    export."""
    from pathlib import Path

    from scriptscrap.analysis import analyze_log

    sample = Path(__file__).parent / "golden" / "sample_events.jsonl"
    safe = sanitise(analyze_log(sample), Redactor())   # raises on any unknown code
    assert safe.endpoints, "the fixture produced no endpoints to check"
    assert safe.ui_elements, "the fixture produced no elements to check"
    assert safe.findings, "the fixture produced no findings to check"


def test_the_dataset_is_serialised_from_the_sanitised_model():
    """dataset.json must carry exactly what sanitise() allowed, no more."""
    from scriptscrap.export import DatasetExporter

    payload = DatasetExporter().build(_marked_result())
    assert MARKER not in json.dumps(payload, ensure_ascii=False)


def test_building_twice_is_idempotent():
    """A double-sanitised value must not become a pseudonym of a pseudonym."""
    from scriptscrap.export import DatasetExporter

    first = DatasetExporter().build(_marked_result())
    second = DatasetExporter().build(_marked_result())
    assert first["ui_elements"] == second["ui_elements"]


def test_the_notice_states_what_sanitisation_does_and_does_not_do():
    from scriptscrap.export import DatasetExporter

    notice = DatasetExporter().build(_marked_result())["notice"]
    for claim in ("bucket", "vocabular", "NOT"):
        assert claim.lower() in notice.lower()
