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


def dom_forms(forms, frame_url="http://h/", frame="f1"):
    """A DOM_FORMS event as the scanner emits it."""
    return ev(EventType.DOM_FORMS,
              {"url": frame_url, "frames": [{"frame_url": frame_url, "forms": forms}]},
              source=Source.ENGINE, frame=frame)


def combo_click(trigger_id, controls, form=None, role="combobox", **extra):
    return ev(EventType.USER_CLICK, {
        "element": {"tag": "div", "id": trigger_id, "role": role, "form": form,
                    "aria": {"aria-controls": controls, **extra}}})


def option_click(option_id, text, role="option"):
    return ev(EventType.USER_CLICK, {
        "element": {"tag": "li", "id": option_id, "role": role, "text": text}})


def _catalog(events):
    return FormCatalogAnalyzer().analyze(events)


# --- DOM_FORMS: untouched controls and full option sets -------------------

def test_untouched_visible_controls_are_included_from_dom_forms():
    _reset()
    forms = _catalog([dom_forms([{
        "index": 0, "id": "order", "action": "/api/order", "method": "POST",
        "fields": [
            {"tag": "input", "type": "text", "id": "customer", "name": "customer",
             "label": "Customer", "required": True, "disabled": False, "readonly": False},
            {"tag": "input", "type": "text", "id": "memo", "name": "memo",
             "label": "Memo", "required": False, "disabled": True, "readonly": False},
        ],
    }])])
    assert len(forms) == 1
    controls = {c.name: c for c in forms[0].controls}
    # Neither field was ever touched, but both are catalogued.
    assert set(controls) == {"customer", "memo"}
    assert controls["customer"].required is True
    assert controls["customer"].label == "Customer"
    assert controls["memo"].disabled is True


def test_full_native_select_options_come_from_dom_forms():
    _reset()
    forms = _catalog([dom_forms([{
        "index": 0, "id": "order", "action": "/o", "method": "POST",
        "fields": [{
            "tag": "select", "id": "city", "name": "city", "label": "City",
            "value": "cas",
            "options": [
                {"value": "cas", "text": "Casablanca", "selected": True},
                {"value": "rab", "text": "Rabat", "selected": False},
                {"value": "mar", "text": "Marrakech", "selected": False},
            ],
        }],
    }])])
    city = {c.name: c for c in forms[0].controls}["city"]
    assert city.options_complete is True
    assert {o["value"] for o in city.options} == {"cas", "rab", "mar"}
    assert any(o["text"] == "Marrakech" for o in city.options)


def test_only_the_selected_option_is_not_claimed_as_all_options():
    """From a user change alone we saw one option; that is not the full set."""
    _reset()
    forms = _catalog([select_change("city", "mar", "Marrakech"), submit()])
    city = {c.name: c for c in forms[0].controls}["city"]
    assert city.selected_label == "Marrakech"
    assert city.options_complete is False, "must not claim all options from one observation"


def test_dom_forms_inventory_merges_with_later_user_input():
    _reset()
    forms = _catalog([
        dom_forms([{"index": 0, "id": "order", "action": "/o", "method": "POST",
                    "fields": [{"tag": "input", "type": "text", "id": "customer",
                                "name": "customer", "label": "Customer"}]}]),
        field_input("customer", "Alice"),
        submit(),
    ])
    control = {c.name: c for c in forms[0].controls}["customer"]
    assert control.label == "Customer"       # from DOM_FORMS
    assert control.final_value == "Alice"     # merged from the user input


# --- radio groups and checkboxes ------------------------------------------

def test_a_radio_group_records_each_option_and_the_chosen_one():
    _reset()
    forms = _catalog([
        dom_forms([{"index": 0, "id": "order", "action": "/o", "method": "POST",
                    "fields": [
                        {"tag": "input", "type": "radio", "id": "s-bris",
                         "name": "sinistre", "value": "bris", "checked": False},
                        {"tag": "input", "type": "radio", "id": "s-choc",
                         "name": "sinistre", "value": "choc", "checked": True},
                    ]}]),
    ])
    controls = {c.name for c in forms[0].controls}
    # Both radio inputs are present (a group), keyed by their ids/names.
    assert {"s-bris", "s-choc"} <= controls or "sinistre" in controls


# --- custom ARIA combobox (incl. portalled listbox) -----------------------

def test_a_custom_aria_combobox_connects_trigger_to_chosen_option():
    _reset()
    forms = _catalog([
        combo_click("agent-combo", controls="agent-list", form="order"),
        option_click("opt-agent-2", "Agent Deux"),
        submit(),
    ])
    comboboxes = [c for f in forms for c in f.controls if c.kind == "combobox"]
    assert comboboxes, "the ARIA combobox was not catalogued"
    combo = comboboxes[0]
    assert combo.selected_label == "Agent Deux"
    # We saw only the chosen option, so completeness is NOT claimed.
    assert combo.options_complete is False


def test_a_portalled_combobox_still_connects_by_aria_controls():
    """The listbox is not a DOM ancestor of the trigger; the connection is by
    aria-controls and click proximity, so a portalled listbox still links."""
    _reset()
    forms = _catalog([
        combo_click("assignee", controls="assignee-listbox", role="combobox"),
        option_click("assignee-opt-3", "Carol"),
    ])
    comboboxes = [c for f in forms for c in f.controls if c.kind == "combobox"]
    assert comboboxes and comboboxes[0].selected_label == "Carol"


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
