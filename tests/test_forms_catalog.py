"""Offline form and control catalog.

The capture already records what an employee did with a form -- the fields they
typed into (final value per field), the option they chose, the boxes they
checked, and the submit that closed it. This assembles those scattered
observations into one catalog per form: its controls, their labels/types/
options/state, the final values, the submit, the request it produced and the
outcome that followed.

Synthetic events, so a test states exactly what was observed. A secret field's
value is never present -- only that something was entered.
"""

from __future__ import annotations

import itertools

from scriptscrap.analysis import analyze_events
from scriptscrap.analysis.forms import FormCatalogAnalyzer
from scriptscrap.events import Event, EventType, Source

_seq = itertools.count(1)


def _reset():
    global _seq
    _seq = itertools.count(1)


def ev(etype, payload, *, source=Source.RUNTIME, frame="f1"):
    n = next(_seq)
    return Event(session_id="s", event_id=f"evt-{n:08d}", seq=n,
                 t_wall=f"2026-01-01T00:00:{n % 60:02d}+00:00", t_mono=float(n),
                 source=source, type=etype, payload=payload,
                 page_id="p1", frame_id=frame)


def field_input(name, value, form="order", **el):
    return ev(EventType.USER_INPUT, {
        "value": {"value": value},
        "element": {"tag": "input", "type": "text", "name": name, "id": name,
                    "label": name.title(), "form": form, **el}})


def select_change(name, value, text, form="order"):
    return ev(EventType.USER_CHANGE, {
        "value": {"value": value, "selected": [{"value": value, "text": text}]},
        "element": {"tag": "select", "name": name, "id": name, "form": form,
                    "label": name.title()}})


def checkbox(name, checked, form="order"):
    return ev(EventType.USER_CHANGE, {
        "value": {"checked": checked, "value": "on"},
        "element": {"tag": "input", "type": "checkbox", "name": name, "id": name,
                    "form": form, "checked": checked}})


def secret(name, form="order"):
    return ev(EventType.USER_INPUT, {
        "value": {"redacted": True, "reason": "secret_field", "length": 9},
        "element": {"tag": "input", "type": "password", "name": name, "id": name,
                    "form": form}})


def submit(form="order", action="/api/order", method="POST", fields=None):
    return ev(EventType.USER_SUBMIT, {
        "element": {"tag": "form", "id": form}, "action": action, "method": method,
        "fields": fields or []})


def request(path, method="POST"):
    return ev(EventType.HTTP_REQUEST, {
        "method": method, "url": f"http://h{path}", "path": path,
        "resource_type": "fetch"}, source=Source.PLAYWRIGHT)


def navigate(url):
    return ev(EventType.NAVIGATION_COMMITTED, {"url": url}, source=Source.PLAYWRIGHT)


def _catalog(events):
    return FormCatalogAnalyzer().analyze(events)


def test_an_empty_session_has_no_forms():
    _reset()
    assert _catalog([]) == []


def test_a_form_lists_the_controls_the_operator_used():
    _reset()
    forms = _catalog([
        field_input("customer", "Alice"),
        field_input("amount", "42"),
        submit(),
    ])
    assert len(forms) == 1
    form = forms[0]
    assert form.form_id == "order"
    controls = {c.name: c for c in form.controls}
    assert {"customer", "amount"} <= set(controls)
    assert controls["customer"].label == "Customer"


def test_the_final_typed_value_is_recorded():
    _reset()
    forms = _catalog([
        field_input("customer", "Al"),
        field_input("customer", "Alice"),   # the operator kept typing
        submit(),
    ])
    control = {c.name: c for c in forms[0].controls}["customer"]
    assert control.final_value == "Alice"


def test_a_secret_field_records_that_something_was_entered_never_the_value():
    _reset()
    forms = _catalog([secret("pw"), submit()])
    control = {c.name: c for c in forms[0].controls}["pw"]
    assert control.secret is True
    assert control.final_value is None
    assert "pw" in {c.name for c in forms[0].controls}


def test_native_select_options_and_choice_are_captured():
    _reset()
    forms = _catalog([select_change("city", "mar", "Marrakech"), submit()])
    control = {c.name: c for c in forms[0].controls}["city"]
    assert control.tag == "select"
    assert control.final_value == "mar"
    assert control.selected_label == "Marrakech"


def test_checkbox_state_is_captured():
    _reset()
    forms = _catalog([checkbox("accept", True), submit()])
    control = {c.name: c for c in forms[0].controls}["accept"]
    assert control.checked is True


def test_submit_is_linked_to_its_request_and_outcome():
    _reset()
    forms = _catalog([
        field_input("customer", "Alice"),
        submit(action="/api/order", method="POST"),
        request("/api/order", "POST"),
        navigate("http://h/order/confirmed"),
    ])
    form = forms[0]
    assert form.submitted is True
    assert form.associated_request is not None
    assert form.associated_request["path"] == "/api/order"
    assert form.outcome is not None
    assert form.outcome["kind"] == "navigation"


def test_forms_are_exposed_on_the_analysis_result():
    _reset()
    result = analyze_events([field_input("customer", "Alice"), submit()], "s")
    assert result.forms
    assert result.forms[0].form_id == "order"


def test_every_form_cites_its_evidence():
    _reset()
    forms = _catalog([field_input("customer", "Alice"), submit()])
    assert forms[0].evidence.event_ids
