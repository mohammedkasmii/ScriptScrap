"""Analysis inference over synthetic event logs. No browser, no fixture.

Synthetic events are used deliberately: they let a test state exactly which
evidence is present, which is the only way to prove that a rejection happened
for the intended reason rather than by accident.
"""

from __future__ import annotations

import itertools

from scriptscrap.analysis import (
    CorrelationAnalyzer,
    EndpointAnalyzer,
    SchemaInferrer,
    SelectorAnalyzer,
    StateAnalyzer,
    TechnologyAnalyzer,
    analyze_events,
    field_name_similarity,
    generated_id_warning,
    route_shape,
)
from scriptscrap.events import Event, EventType, Source

_seq = itertools.count(1)


def ev(event_type, payload, *, source=Source.PLAYWRIGHT, frame="f1",
       page="p1", wall="2026-01-01T00:00:00.000+00:00"):
    n = next(_seq)
    return Event(
        session_id="s", event_id=f"evt-{n:05d}", seq=n,
        t_wall=wall, t_mono=float(n), source=source, type=event_type,
        payload=payload, page_id=page, frame_id=frame,
    )


def req(url, method="GET", body=None, graphql=None, **extra):
    payload = {"method": method, "url": url, "path": url.split("?")[0].split("://")[-1],
               "resource_type": "fetch", **extra}
    payload["path"] = "/" + url.split("://")[-1].split("/", 1)[1].split("?")[0] \
        if "://" in url else url.split("?")[0]
    if body is not None:
        payload["body"] = body
    if graphql is not None:
        payload["graphql"] = graphql
    return ev(EventType.HTTP_REQUEST, payload)


def resp(url, status=200, body=None, method="GET"):
    payload = {"method": method, "url": url, "status": status,
               "path": "/" + url.split("://")[-1].split("/", 1)[1].split("?")[0]
               if "://" in url else url.split("?")[0]}
    if body is not None:
        payload["body"] = body
    return ev(EventType.HTTP_RESPONSE, payload)


# --- endpoints ----------------------------------------------------------

def test_sibling_paths_are_templated():
    events = [req(f"http://h/api/items/{n}") for n in (101, 102, 103)]
    endpoints = EndpointAnalyzer().analyze(events)
    templated = [e for e in endpoints if e.templated]
    assert templated, [e.key for e in endpoints]
    assert templated[0].template == "/api/items/{itemId}"
    assert templated[0].observation_count == 3
    # The raw values must survive templating.
    assert set(templated[0].concrete_paths) == {
        "/api/items/101", "/api/items/102", "/api/items/103"}


def test_a_single_numeric_path_is_not_templated():
    """One observation is not a pattern."""
    endpoints = EndpointAnalyzer().analyze([req("http://h/api/items/101")])
    assert all(not e.templated for e in endpoints)
    assert endpoints[0].template == "/api/items/101"


def test_a_lone_uuid_is_templated_on_shape_alone():
    events = [req("http://h/api/x/3f2504e0-4f89-11d3-9a0c-0305e82c3301")]
    endpoints = EndpointAnalyzer().analyze(events)
    assert endpoints[0].templated
    assert endpoints[0].confidence < 1.0, "single-path templating must be less confident"


def test_query_parameters_are_kept_and_typed():
    events = [req("http://h/search?page=1&type=A"),
              req("http://h/search?page=2&type=B"),
              req("http://h/search?page=3&type=A")]
    endpoint = EndpointAnalyzer().analyze(events)[0]
    params = {p.name: p for p in endpoint.params}
    assert params["page"].inferred_type == "integer"
    assert params["type"].inferred_type == "string"
    assert params["page"].sample_count == 3
    assert params["type"].examples == ["A", "B"]
    # 3 samples over 2 distinct values is too thin to call a closed set: each
    # value must recur before the set looks closed rather than merely small.
    assert params["type"].enum_candidate is None


def test_enum_candidate_appears_once_values_recur():
    events = [req(f"http://h/search?type={t}") for t in ("A", "B", "A", "B", "A", "B")]
    endpoint = EndpointAnalyzer().analyze(events)[0]
    assert {p.name: p for p in endpoint.params}["type"].enum_candidate == ["A", "B"]


def test_graphql_operations_are_separate_endpoints():
    gql = lambda name, kind: {  # noqa: E731
        "batched": False, "operation_count": 1,
        "operations": [{"operation_name": name, "operation_type": kind,
                        "document_hash": "abc"}]}
    events = [req("http://h/graphql", "POST", graphql=gql("GetItem", "query")),
              req("http://h/graphql", "POST", graphql=gql("SaveItem", "mutation"))]
    keys = {e.key for e in EndpointAnalyzer().analyze(events)}
    assert "GRAPHQL query GetItem" in keys
    assert "GRAPHQL mutation SaveItem" in keys, keys


# --- schema -------------------------------------------------------------

def test_optionality_is_observed_not_assumed():
    inf = SchemaInferrer()
    inf.observe({"id": 1, "name": "a"}, "e1")
    inf.observe({"id": 2, "name": "b", "note": "x"}, "e2")
    inf.observe({"id": 3, "name": "c"}, "e3")
    fields = {f.path: f for f in inf.build("E", "response").fields}
    assert fields["$.note"].observed_optional is True
    assert fields["$.note"].present_count == 1
    assert fields["$.id"].observed_optional is False
    assert fields["$.id"].present_count == 3


def test_polymorphic_field_is_preserved_not_flattened():
    inf = SchemaInferrer()
    inf.observe({"v": "text"})
    inf.observe({"v": 12})
    inf.observe({"v": None})
    field = {f.path: f for f in inf.build("E", "response").fields}["$.v"]
    assert set(field.inferred_type.split("|")) == {"string", "integer", "null"}
    assert field.null_count == 1


def test_enum_candidate_needs_repetition():
    inf = SchemaInferrer()
    for value in ["OK", "ARCHIVE", "OK", "ARCHIVE", "OK", "OK"]:
        inf.observe({"statut": value})
    field = {f.path: f for f in inf.build("E", "response").fields}["$.statut"]
    assert field.enum_candidate == ["ARCHIVE", "OK"]


def test_all_distinct_values_are_not_an_enum():
    inf = SchemaInferrer()
    for value in ["a1", "b2", "c3", "d4", "e5"]:
        inf.observe({"ref": value})
    field = {f.path: f for f in inf.build("E", "response").fields}["$.ref"]
    assert field.enum_candidate is None


def test_formats_require_agreement():
    inf = SchemaInferrer()
    inf.observe({"when": "2026-01-01T10:00:00"})
    inf.observe({"when": "2026-02-02T11:00:00"})
    inf.observe({"mixed": "2026-01-01T10:00:00"})
    inf.observe({"mixed": "not a date"})
    fields = {f.path: f for f in inf.build("E", "response").fields}
    assert fields["$.when"].inferred_format == "datetime"
    assert fields["$.mixed"].inferred_format is None


def test_arrays_merge_into_one_element_description():
    inf = SchemaInferrer()
    inf.observe({"items": [{"id": 1}, {"id": 2, "extra": True}]})
    paths = {f.path for f in inf.build("E", "response").fields}
    assert "$.items[].id" in paths
    assert "$.items[].extra" in paths
    assert "$.items[0].id" not in paths, "array indices must not become fields"


def test_huge_string_is_an_opaque_token_not_content():
    inf = SchemaInferrer()
    inf.observe({"__VIEWSTATE": "x" * 5000})
    field = {f.path: f for f in inf.build("E", "request").fields}["$.__VIEWSTATE"]
    assert field.inferred_type == "opaque_token"


# --- correlation ---------------------------------------------------------

def _endpoint_map(events):
    return {e.event_id: e.payload.get("path", "?") for e in events}


def test_unique_value_propagation_is_found():
    events = [
        resp("http://h/api/item", body={"reference": "ITEMREF-AA0101"}),
        req("http://h/api/apply", "POST", body={"itemReference": "ITEMREF-AA0101"}),
    ]
    edges = CorrelationAnalyzer().analyze(events, _endpoint_map(events))
    assert edges, "the seeded dependency was not found"
    edge = edges[0]
    assert edge.source_field == "$.reference"
    assert edge.target_field == "$.itemReference"
    assert edge.mechanism == "response_to_request"
    assert edge.confidence > 0.6
    assert len(edge.evidence.event_ids) == 2


def test_common_status_value_is_rejected():
    """The false positive the previous correlator produced constantly."""
    events = [
        resp("http://h/api/item", body={"statut": "OK"}),
        req("http://h/api/apply", "POST", body={"statut": "OK"}),
    ]
    edges = CorrelationAnalyzer().analyze(events, _endpoint_map(events))
    assert edges == [], f"a stopword value produced an edge: {[e.label for e in edges]}"


def test_small_integers_are_rejected():
    events = [
        resp("http://h/api/item", body={"actif": 1, "count": 42}),
        req("http://h/api/apply", "POST", body={"actif": 1, "count": 42}),
    ]
    edges = CorrelationAnalyzer().analyze(events, _endpoint_map(events))
    assert edges == [], f"small integers produced edges: {[e.label for e in edges]}"


def test_ambient_value_seen_everywhere_is_rejected():
    """A session token appears in every call; that is not a dependency."""
    token = "SESSIONVALUE-ABCDEF123456"
    events = [resp("http://h/api/a", body={"tok": token})]
    events += [req(f"http://h/api/{n}", "POST", body={"tok": token}) for n in "bcdefgh"]
    edges = CorrelationAnalyzer().analyze(events, _endpoint_map(events))
    assert edges == [], f"ambient value produced edges: {[e.label for e in edges]}"


def test_a_value_appearing_only_after_the_consumer_is_not_a_source():
    """Ordering gate: the producer must plausibly precede the consumer."""
    consumer = req("http://h/api/apply", "POST", body={"ref": "ITEMREF-ZZ9999"})
    producer = resp("http://h/api/item", body={"ref": "ITEMREF-ZZ9999"})
    events = [consumer, producer]  # consumer observed first
    edges = CorrelationAnalyzer().analyze(events, _endpoint_map(events))
    assert all(e.source_endpoint != "/api/item" for e in edges), \
        "an edge was created against the observed order"


def test_cross_sensor_events_without_timestamps_are_not_ordered():
    """`seq` must not be used to order events from different sensors."""
    same = "2026-01-01T00:00:00.000+00:00"
    producer = ev(EventType.STORAGE_CHANGE,
                  {"op": "set", "store": "localStorage", "key": "k",
                   "value": "TOKENVALUE-QQ7777"},
                  source=Source.RUNTIME, wall=same)
    consumer = ev(EventType.HTTP_REQUEST,
                  {"method": "POST", "url": "http://h/api/x", "path": "/api/x",
                   "body": {"k": "TOKENVALUE-QQ7777"}},
                  source=Source.PLAYWRIGHT, wall=same)
    events = [producer, consumer]
    edges = CorrelationAnalyzer().analyze(events, _endpoint_map(events))
    assert edges == [], "identical timestamps across sensors must not imply order"


def test_field_name_similarity_normalises_naming_styles():
    assert field_name_similarity("$.missionId", "$.mission_id") == 1.0
    assert field_name_similarity("$.missionId", "$.idMission") == 1.0
    assert field_name_similarity("$.missionId", "$.garageCode") == 0.0
    assert 0 < field_name_similarity("$.itemReference", "$.reference") < 1.0


def test_repeated_observation_raises_confidence():
    single = [resp("http://h/a", body={"ref": "AAAREF-000111"}),
              req("http://h/b", "POST", body={"ref": "AAAREF-000111"})]
    one = CorrelationAnalyzer().analyze(single, _endpoint_map(single))[0]

    many = []
    for n in range(4):
        many.append(resp("http://h/a", body={"ref": f"AAAREF-00011{n}"}))
        many.append(req("http://h/b", "POST", body={"ref": f"AAAREF-00011{n}"}))
    repeated = CorrelationAnalyzer().analyze(many, _endpoint_map(many))[0]

    assert repeated.repeat_count > one.repeat_count
    assert repeated.confidence > one.confidence


def test_every_edge_cites_its_evidence():
    events = [resp("http://h/a", body={"ref": "BBBREF-000222"}),
              req("http://h/b", "POST", body={"ref": "BBBREF-000222"})]
    for edge in CorrelationAnalyzer().analyze(events, _endpoint_map(events)):
        assert edge.evidence.event_ids
        assert "ordering_method" in edge.evidence.signals
        assert "field_name_similarity" in edge.evidence.signals


# --- selectors -----------------------------------------------------------

def _click(element):
    return ev(EventType.USER_CLICK, {"element": element}, source=Source.RUNTIME)


def test_generated_ids_are_flagged():
    assert generated_id_warning("ctl00_ContentPlaceHolder_btn")
    assert generated_id_warning("sc-aBcDeF12")
    assert generated_id_warning("css-1a2b3c4d")
    assert generated_id_warning("widget_1234567")
    assert generated_id_warning("btn-valider") is None


def test_stability_is_measured_and_unstable_id_is_not_recommended():
    events = [
        _click({"tag": "button", "role": None, "label": "Action instable",
                "text": "Action instable", "id": f"ctl00_generated_{n}_a1b2c3d4",
                "name": None, "type": None, "form": None,
                "class": "btn", "dom_path": "div > button"})
        for n in range(1, 5)
    ]
    element = SelectorAnalyzer().analyze(events)[0]
    assert element.observation_count == 4
    by_strategy = {loc.strategy: loc for loc in element.locators}
    assert by_strategy["id"].stability < 0.5, "a changing id must score badly"
    assert by_strategy["label"].stability == 1.0
    assert element.recommended.strategy != "id"
    assert element.recommended.stability == 1.0


def test_stable_element_keeps_all_strategies():
    events = [
        _click({"tag": "button", "role": "button", "label": "Valider",
                "text": "Valider", "id": "btn-valider", "name": None,
                "type": None, "form": "frm", "class": "primary",
                "dom_path": "form > button"})
        for _ in range(3)
    ]
    element = SelectorAnalyzer().analyze(events)[0]
    assert all(loc.stability == 1.0 for loc in element.locators)
    assert element.recommended.strategy == "role_name"


# --- states --------------------------------------------------------------

def test_route_shape_strips_data_but_keeps_structure():
    assert route_shape("http://h/items/4471?x=1") == "/items/{id}"
    assert route_shape("http://h/items/ITEM-0001") == "/items/{id}"
    assert route_shape("http://h/#/detail/101") == "/#/detail/{id}"
    assert route_shape("http://h/search") == "/search"


def test_states_and_transitions_are_derived():
    events = [
        ev(EventType.NAVIGATION_COMMITTED, {"url": "http://h/liste"}),
        ev(EventType.USER_SUBMIT, {"element": {"id": "frm", "tag": "form"},
                                   "frame_url": "http://h/liste"}, source=Source.RUNTIME),
        ev(EventType.NAVIGATION_COMMITTED, {"url": "http://h/resultats"}),
        ev(EventType.NAVIGATION_COMMITTED, {"url": "http://h/detail/101"}),
    ]
    states, transitions = StateAnalyzer().analyze(events)
    assert len(states) == 3
    assert {s.url_pattern for s in states} == {"/liste", "/resultats", "/detail/{id}"}
    assert len(transitions) == 2
    assert all(t.evidence.event_ids for t in transitions)
    assert any("attribution" in t.evidence.signals for t in transitions)


def test_records_of_the_same_screen_collapse_to_one_state():
    events = [ev(EventType.NAVIGATION_COMMITTED, {"url": f"http://h/detail/{n}"})
              for n in (101, 102, 103)]
    states, _ = StateAnalyzer().analyze(events)
    assert len(states) == 1
    assert states[0].observation_count == 3


# --- technology ----------------------------------------------------------

def test_webforms_detected_from_postback_fields():
    events = [req("http://h/Default.aspx", "POST",
                  body={"__VIEWSTATE": "x" * 2000, "__EVENTTARGET": "btn"})]
    tech = {t.name: t for t in TechnologyAnalyzer().analyze(events)}
    assert "ASP.NET WebForms" in tech
    assert tech["ASP.NET WebForms"].confidence >= 0.9
    assert tech["ASP.NET WebForms"].evidence.event_ids


def test_graphql_detected_from_operations():
    events = [req("http://h/graphql", "POST", graphql={
        "batched": False, "operation_count": 1,
        "operations": [{"operation_name": "GetX", "operation_type": "query"}]})]
    names = {t.name for t in TechnologyAnalyzer().analyze(events)}
    assert "GraphQL" in names


def test_jquery_detected_from_bound_handlers():
    """Runtime evidence, not a script URL: the engine does not capture script loads."""
    events = [ev(EventType.RUNTIME_HOOKS,
                 {"jquery_bound_selectors": ["#a", ".b", "#c"], "hook_calls": 0},
                 source=Source.RUNTIME)]
    tech = {t.name: t for t in TechnologyAnalyzer().analyze(events)}
    assert "jQuery" in tech
    assert tech["jQuery"].confidence >= 0.9
    assert "3 selectors" in " ".join(tech["jQuery"].signals)


def test_no_technology_claimed_without_evidence():
    assert TechnologyAnalyzer().analyze([req("http://h/api/plain")]) == []


# --- pipeline ------------------------------------------------------------

def test_viewstate_is_masked_out_of_schemas():
    events = [
        req("http://h/Default.aspx", "POST",
            body={"__VIEWSTATE": "y" * 3000, "__EVENTTARGET": "btnSave"}),
        resp("http://h/Default.aspx", 200, body={"ok": True}, method="POST"),
    ]
    result = analyze_events(events, "s")
    request_schemas = [s for s in result.schemas if s.direction == "request"]
    viewstate = [f for s in request_schemas for f in s.fields if "VIEWSTATE" in f.path]
    assert viewstate
    assert "state token" in str(viewstate[0].examples), viewstate[0].examples


def test_findings_report_capture_gaps():
    events = [
        ev(EventType.CAPTURE_GAP, {"reason": "service_worker_visibility_unavailable"}),
        ev(EventType.CAPTURE_GAP, {"reason": "response_body_unavailable"}),
        ev(EventType.SENSOR_ERROR, {"where": "storage_snapshot", "error": "boom"}),
    ]
    findings = {f.kind: f for f in analyze_events(events, "s").findings}
    assert "capture_gap" in findings
    assert "sensor_error" in findings
    critical = [f for f in analyze_events(events, "s").findings if f.severity == "critical"]
    assert critical, "a service-worker gap must be critical"
