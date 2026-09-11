"""Form identity and correlation must be unique and page-aware.

The old catalog keyed a form by its id alone (or `@formless@<frame>`), so two
tabs each showing `id="form1"` collapsed into one entry, two anonymous forms in
one document merged, and a submit in one tab could be handed another tab's
navigation as its outcome. These are the cross-page reproductions that must all
pass before multipage form capture is called correct.
"""

from __future__ import annotations

import itertools

from scriptscrap.analysis.forms import FormCatalogAnalyzer
from scriptscrap.events import Event, EventType, Source

_seq = itertools.count(1)


def _reset():
    global _seq
    _seq = itertools.count(1)


def ev(etype, payload, *, source=Source.RUNTIME, page="p1", frame="f1",
       frame_url="http://h/", origin=None):
    n = next(_seq)
    body = dict(payload)
    body.setdefault("frame_url", frame_url)
    # The document instance an observation belongs to (performance.timeOrigin).
    if origin is not None:
        body.setdefault("probe_time_origin", origin)
    return Event(session_id="s", event_id=f"evt-{n:08d}", seq=n,
                 t_wall=f"2026-01-01T00:00:{n % 60:02d}+00:00", t_mono=float(n),
                 source=source, type=etype, payload=body, page_id=page, frame_id=frame)


def submit(form_id, *, page, frame, action="/api/x", method="POST", dom_path=None,
           frame_url="http://h/", origin=None, fields=None):
    element = {"tag": "form", "id": form_id, "dom_path": dom_path}
    return ev(EventType.USER_SUBMIT,
              {"element": element, "action": action, "method": method,
               "fields": fields or []},
              page=page, frame=frame, frame_url=frame_url, origin=origin)


def dom_forms(forms, *, page, frame, frame_url="http://h/", origin=None):
    frame_entry = {"frame_url": frame_url, "frame_id": frame, "forms": forms}
    if origin is not None:
        frame_entry["time_origin"] = origin
    return ev(EventType.DOM_FORMS,
              {"page_id": page, "url": frame_url, "frames": [frame_entry]},
              source=Source.ENGINE, page=page, frame=frame, frame_url=frame_url)


def radio_change(name, value, label, *, page, frame, form="f", origin=None):
    return ev(EventType.USER_CHANGE,
              {"value": {"checked": True, "value": value},
               "element": {"tag": "input", "type": "radio", "id": None,
                           "name": name, "label": label, "form": form}},
              page=page, frame=frame, origin=origin)


def cb_field(cid, name, value, path, label=None, checked=False):
    return {"tag": "input", "type": "checkbox", "id": cid, "name": name,
            "value": value, "path": path, "label": label, "checked": checked}


def checkbox_change(name, value, checked, *, cid=None, dom_path=None, label=None,
                    form="f", page, frame, origin=None):
    return ev(EventType.USER_CHANGE,
              {"value": {"checked": checked, "value": value},
               "element": {"tag": "input", "type": "checkbox", "id": cid,
                           "name": name, "label": label, "dom_path": dom_path,
                           "form": form}},
              page=page, frame=frame, origin=origin)


def runtime_submit(form_id, *, page, frame, via="submit", form_path=None,
                   action="/api/x", method="POST", frame_url="http://h/",
                   origin=None):
    return ev(EventType.RUNTIME_FORM_SUBMIT,
              {"via": via, "action": action, "method": method, "form": form_id,
               "form_path": form_path},
              page=page, frame=frame, frame_url=frame_url, origin=origin)


def request(path, *, page, frame, method="POST"):
    return ev(EventType.HTTP_REQUEST,
              {"method": method, "url": f"http://h{path}", "path": path,
               "resource_type": "fetch"}, source=Source.PLAYWRIGHT, page=page, frame=frame)


def navigate(url, *, page, frame):
    return ev(EventType.NAVIGATION_COMMITTED, {"url": url},
              source=Source.PLAYWRIGHT, page=page, frame=frame)


def _catalog(events):
    return FormCatalogAnalyzer().analyze(events)


# --- identity -------------------------------------------------------------

def test_same_form_id_in_two_tabs_stays_separate():
    _reset()
    forms = _catalog([
        submit("form1", page="pA", frame="fA"),
        submit("form1", page="pB", frame="fB"),
    ])
    assert len(forms) == 2, [f.form_key for f in forms]
    pages = {f.page_id for f in forms}
    assert pages == {"pA", "pB"}


def test_same_form_id_in_two_frames_stays_separate():
    _reset()
    forms = _catalog([
        submit("form1", page="pA", frame="fMain"),
        submit("form1", page="pA", frame="fChild"),
    ])
    assert len(forms) == 2, [f.form_key for f in forms]
    assert {f.frame_id for f in forms} == {"fMain", "fChild"}


def test_two_anonymous_forms_in_one_document_stay_separate():
    _reset()
    forms = _catalog([dom_forms([
        {"index": 0, "id": None, "path": "body > form:nth-of-type(1)",
         "action": "/a", "method": "POST",
         "fields": [{"tag": "input", "type": "text", "id": "a", "name": "a"}]},
        {"index": 1, "id": None, "path": "body > form:nth-of-type(2)",
         "action": "/b", "method": "POST",
         "fields": [{"tag": "input", "type": "text", "id": "b", "name": "b"}]},
    ], page="pA", frame="fA")])
    assert len(forms) == 2, [f.form_key for f in forms]


def test_two_anonymous_form_submits_in_one_document_stay_separate():
    _reset()
    forms = _catalog([
        submit(None, page="pA", frame="fA", dom_path="body > form:nth-of-type(1)"),
        submit(None, page="pA", frame="fA", dom_path="body > form:nth-of-type(2)"),
    ])
    assert len(forms) == 2, [f.form_key for f in forms]


def test_entry_carries_page_and_frame_attribution():
    _reset()
    forms = _catalog([submit("order", page="pX", frame="fY")])
    assert forms[0].page_id == "pX"
    assert forms[0].frame_id == "fY"


def test_named_form_merges_across_dom_scan_and_user_events_in_one_document():
    _reset()
    forms = _catalog([
        dom_forms([{"index": 0, "id": "order", "path": "body > form",
                    "action": "/o", "method": "POST",
                    "fields": [{"tag": "input", "type": "text", "id": "customer",
                                "name": "customer", "label": "Customer"}]}],
                  page="pA", frame="fA"),
        ev(EventType.USER_INPUT,
           {"value": {"value": "Alice"},
            "element": {"tag": "input", "id": "customer", "name": "customer",
                        "form": "order"}}, page="pA", frame="fA"),
        submit("order", page="pA", frame="fA"),
    ])
    assert len(forms) == 1, [f.form_key for f in forms]
    control = {c.name: c for c in forms[0].controls}["customer"]
    assert control.label == "Customer"
    assert control.final_value == "Alice"


# --- page-aware correlation ----------------------------------------------

def test_a_submit_is_not_correlated_with_another_tabs_navigation():
    _reset()
    forms = _catalog([
        submit("orderA", page="pA", frame="fA", action="/api/a"),
        request("/api/a", page="pA", frame="fA"),
        # A navigation in ANOTHER tab must never be this form's outcome.
        navigate("http://h/other-tab", page="pB", frame="fB"),
    ])
    a = next(f for f in forms if f.form_id == "orderA")
    assert a.outcome is None or a.outcome.get("kind") != "navigation", a.outcome


def test_simultaneous_submits_in_two_tabs_each_get_their_own_outcome():
    _reset()
    forms = _catalog([
        submit("formA", page="pA", frame="fA", action="/api/a"),
        submit("formB", page="pB", frame="fB", action="/api/b"),
        request("/api/a", page="pA", frame="fA"),
        request("/api/b", page="pB", frame="fB"),
        navigate("http://h/done-a", page="pA", frame="fA"),
        navigate("http://h/done-b", page="pB", frame="fB"),
    ])
    a = next(f for f in forms if f.form_id == "formA")
    b = next(f for f in forms if f.form_id == "formB")
    assert a.associated_request["path"] == "/api/a"
    assert b.associated_request["path"] == "/api/b"
    assert a.outcome and "done-a" in a.outcome["route"]
    assert b.outcome and "done-b" in b.outcome["route"]


def test_a_submit_correlates_to_its_own_frame_request():
    _reset()
    forms = _catalog([
        submit("order", page="pA", frame="fA", action="/api/order"),
        request("/api/order", page="pA", frame="fA"),
        navigate("http://h/confirmed", page="pA", frame="fA"),
    ])
    entry = forms[0]
    assert entry.associated_request["path"] == "/api/order"
    assert entry.outcome["kind"] == "navigation"


def combo_trigger(trigger_id, controls, *, page, frame, region=None, form=None):
    return ev(EventType.USER_CLICK,
              {"element": {"tag": "div", "id": trigger_id, "role": "combobox",
                           "form": form, "region": region,
                           "aria": {"aria-controls": controls}}},
              page=page, frame=frame)


def combo_option(option_id, text, listbox, *, page, frame):
    return ev(EventType.USER_CLICK,
              {"element": {"tag": "li", "id": option_id, "role": "option",
                           "text": text, "listbox": listbox}},
              page=page, frame=frame)


# --- ARIA combobox correlation -------------------------------------------

def test_a_combobox_option_in_another_tab_is_never_connected():
    _reset()
    forms = _catalog([
        combo_trigger("agent", "agent-list", page="pA", frame="fA", region="panel"),
        # The option is clicked in a DIFFERENT tab: it must not be joined to the
        # trigger from tab A.
        combo_option("opt-b", "Bob", "other-list", page="pB", frame="fB"),
    ])
    comboboxes = [c for f in forms for c in f.controls if c.kind == "combobox"]
    assert comboboxes == [], "an option from another tab was connected"


def test_an_exact_aria_controls_match_is_marked_exact():
    _reset()
    forms = _catalog([
        combo_trigger("agent", "agent-list", page="pA", frame="fA", region="panel"),
        combo_option("opt-2", "Agent Two", "agent-list", page="pA", frame="fA"),
    ])
    combo = next(c for f in forms for c in f.controls if c.kind == "combobox")
    assert combo.selected_label == "Agent Two"
    assert combo.connection == "aria-controls"
    assert combo.listbox == "agent-list"


def test_a_proximity_match_within_a_frame_is_marked_heuristic():
    _reset()
    forms = _catalog([
        combo_trigger("agent", "agent-list", page="pA", frame="fA", region="panel"),
        # The option reports no listbox and its own aria-controls is absent, so
        # only same-frame proximity connects it -- and it must say so.
        combo_option("opt-2", "Agent Two", None, page="pA", frame="fA"),
    ])
    combo = next(c for f in forms for c in f.controls if c.kind == "combobox")
    assert combo.connection == "proximity_same_frame"


def test_a_formless_combobox_is_grouped_by_a_captured_region_not_the_frame():
    _reset()
    forms = _catalog([
        combo_trigger("agent", "agent-list", page="pA", frame="fA", region="filters"),
        combo_option("opt-2", "Agent Two", "agent-list", page="pA", frame="fA"),
    ])
    entry = next(f for f in forms if any(c.kind == "combobox" for c in f.controls))
    # The region, not the whole frame, is in the key.
    assert "region:filters" in entry.form_key
    assert "@formless@" not in entry.form_key


# --- document-instance identity ------------------------------------------

def _named_form(form_id, path="body > form"):
    return {"index": 0, "id": form_id, "path": path, "action": "/x", "method": "POST",
            "fields": [{"tag": "input", "type": "text", "id": "field", "name": "field"}]}


def test_two_same_id_forms_across_a_same_frame_navigation_do_not_merge():
    """/claims/new form1, then navigate the SAME page/frame to /customers/new
    form1. A full navigation is a NEW document instance (a new time origin), so
    the two forms must stay separate even though page, frame and id all match."""
    _reset()
    forms = _catalog([
        dom_forms([_named_form("form1")], page="p1", frame="f1",
                  frame_url="http://h/claims/new", origin=1000),
        dom_forms([_named_form("form1")], page="p1", frame="f1",
                  frame_url="http://h/customers/new", origin=2000),
    ])
    assert len(forms) == 2, [f.form_key for f in forms]


def test_same_id_form_in_two_documents_at_one_route_stays_separate():
    """A reload of the same route is a new document instance too: same page,
    frame, route and id, but a different time origin keeps them separate."""
    _reset()
    forms = _catalog([
        dom_forms([_named_form("form1")], page="p1", frame="f1",
                  frame_url="http://h/claims/new", origin=1000),
        dom_forms([_named_form("form1")], page="p1", frame="f1",
                  frame_url="http://h/claims/new", origin=2000),
    ])
    assert len(forms) == 2, [f.form_key for f in forms]


def test_same_id_form_across_two_spa_routes_stays_separate():
    """An SPA route change is NOT a new document (same time origin), so document
    instance alone cannot separate them -- the route does. Forms are grouped by
    occurrence: (page, frame, document instance, route, form identity)."""
    _reset()
    forms = _catalog([
        dom_forms([_named_form("form1")], page="p1", frame="f1",
                  frame_url="http://h/claims/new", origin=1000),
        dom_forms([_named_form("form1")], page="p1", frame="f1",
                  frame_url="http://h/customers/new", origin=1000),
    ])
    assert len(forms) == 2, [f.form_key for f in forms]


def test_named_form_still_merges_within_one_document_and_route():
    """The other side of the guarantee: repeated observations of the SAME form
    in one document at one route stay ONE entry."""
    _reset()
    forms = _catalog([
        dom_forms([_named_form("order")], page="p1", frame="f1",
                  frame_url="http://h/orders/new", origin=1000),
        dom_forms([_named_form("order")], page="p1", frame="f1",
                  frame_url="http://h/orders/new", origin=1000),
    ])
    assert len(forms) == 1, [f.form_key for f in forms]


# --- anonymous form event correlation ------------------------------------

def test_anonymous_inventory_input_and_submit_merge_into_one_entry():
    """DOM inventory, an input on a field, and the submit -- all for one
    anonymous form -- resolve to the SAME key via the form's structural path."""
    _reset()
    path = "body > div > form"
    forms = _catalog([
        dom_forms([{"index": 0, "id": None, "path": path, "action": "/a",
                    "method": "POST",
                    "fields": [{"tag": "input", "type": "text", "id": None,
                                "name": "note", "label": "Note"}]}],
                  page="p1", frame="f1", frame_url="http://h/wizard", origin=7),
        ev(EventType.USER_INPUT,
           {"value": {"value": "hello"},
            "element": {"tag": "input", "type": "text", "name": "note",
                        "form": "(unnamed)", "form_path": path}},
           page="p1", frame="f1", frame_url="http://h/wizard", origin=7),
        submit(None, page="p1", frame="f1", dom_path=path,
               frame_url="http://h/wizard", origin=7),
    ])
    assert len(forms) == 1, [f.form_key for f in forms]
    note = next(c for c in forms[0].controls if c.name == "note")
    assert note.final_value == "hello"
    assert forms[0].submitted is True


def test_two_anonymous_forms_stay_separate_via_input_paths():
    """Two anonymous forms in one document, each with an input, stay separate --
    the owning-form path in the input fingerprint distinguishes them."""
    _reset()
    p1 = "body > form:nth-of-type(1)"
    p2 = "body > form:nth-of-type(2)"
    forms = _catalog([
        ev(EventType.USER_INPUT,
           {"value": {"value": "one"},
            "element": {"tag": "input", "name": "a", "form": "(unnamed)",
                        "form_path": p1}}, page="p1", frame="f1", origin=1),
        ev(EventType.USER_INPUT,
           {"value": {"value": "two"},
            "element": {"tag": "input", "name": "b", "form": "(unnamed)",
                        "form_path": p2}}, page="p1", frame="f1", origin=1),
    ])
    assert len(forms) == 2, [f.form_key for f in forms]


# --- radio groups and repeated-name checkboxes ---------------------------

def test_two_idless_radios_sharing_a_name_are_one_group_with_options():
    _reset()
    forms = _catalog([dom_forms([
        {"index": 0, "id": "plan-form", "path": "body > form", "action": "/p",
         "method": "POST", "fields": [
            {"tag": "input", "type": "radio", "id": None, "name": "plan",
             "value": "basic", "label": "Basic", "checked": False},
            {"tag": "input", "type": "radio", "id": None, "name": "plan",
             "value": "pro", "label": "Pro", "checked": True},
        ]}], page="p1", frame="f1", origin=1)])
    radios = [c for c in forms[0].controls if c.type == "radio"]
    assert len(radios) == 1, "a radio group must be one logical control"
    grp = radios[0]
    assert grp.kind == "radio_group"
    assert {o["value"] for o in grp.options} == {"basic", "pro"}
    assert grp.selected_label == "Pro"
    assert grp.final_value == "pro"


def test_idless_checkboxes_sharing_a_name_stay_distinct():
    _reset()
    forms = _catalog([dom_forms([
        {"index": 0, "id": "topping-form", "path": "body > form", "action": "/t",
         "method": "POST", "fields": [
            {"tag": "input", "type": "checkbox", "id": None, "name": "topping",
             "value": "cheese", "label": "Cheese", "checked": True},
            {"tag": "input", "type": "checkbox", "id": None, "name": "topping",
             "value": "olives", "label": "Olives", "checked": False},
            {"tag": "input", "type": "checkbox", "id": None, "name": "topping",
             "value": "ham", "label": "Ham", "checked": True},
        ]}], page="p1", frame="f1", origin=1)])
    boxes = [c for c in forms[0].controls if c.type == "checkbox"]
    assert len(boxes) == 3, "checkboxes sharing a name must stay distinct choices"
    checked = {c.option_value for c in boxes if c.checked}
    assert checked == {"cheese", "ham"}


def test_a_single_named_checkbox_stays_one_control():
    """Preserve normal single-checkbox behaviour."""
    _reset()
    forms = _catalog([dom_forms([
        {"index": 0, "id": "consent-form", "path": "body > form", "action": "/c",
         "method": "POST", "fields": [
            {"tag": "input", "type": "checkbox", "id": "agree", "name": "agree",
             "value": "yes", "label": "I agree", "checked": True},
        ]}], page="p1", frame="f1", origin=1)])
    boxes = [c for c in forms[0].controls if c.type == "checkbox"]
    assert len(boxes) == 1
    assert boxes[0].checked is True


def test_radio_group_reflects_the_last_selected_option_over_time():
    _reset()
    forms = _catalog([
        dom_forms([{"index": 0, "id": "plan-form", "path": "body > form",
                    "action": "/p", "method": "POST", "fields": [
            {"tag": "input", "type": "radio", "id": None, "name": "plan",
             "value": "basic", "label": "Basic", "checked": True},
            {"tag": "input", "type": "radio", "id": None, "name": "plan",
             "value": "pro", "label": "Pro", "checked": False},
        ]}], page="p1", frame="f1", origin=1),
        radio_change("plan", "pro", "Pro", page="p1", frame="f1",
                     form="plan-form", origin=1),
        radio_change("plan", "basic", "Basic", page="p1", frame="f1",
                     form="plan-form", origin=1),
        radio_change("plan", "pro", "Pro", page="p1", frame="f1",
                     form="plan-form", origin=1),
    ])
    grp = next(c for c in forms[0].controls if c.type == "radio")
    assert grp.final_value == "pro"
    assert grp.selected_label == "Pro"
    assert {o["value"] for o in grp.options} == {"basic", "pro"}
    # Exactly one option is marked selected at the end.
    assert [o["value"] for o in grp.options if o.get("checked")] == ["pro"]


# --- duplicate checkbox identity -----------------------------------------

def test_checkboxes_same_name_and_on_value_different_ids_stay_distinct():
    """Two checkboxes sharing name AND the implicit "on" value are distinct
    elements; their ids keep them apart."""
    _reset()
    forms = _catalog([dom_forms([
        {"index": 0, "id": "f", "path": "body > form", "action": "/x",
         "method": "POST", "fields": [
            cb_field("box-a", "opt", "on", "body > form > input#box-a", "Alpha"),
            cb_field("box-b", "opt", "on", "body > form > input#box-b", "Beta"),
        ]}], page="p1", frame="f1", origin=1)])
    boxes = [c for c in forms[0].controls if c.type == "checkbox"]
    assert len(boxes) == 2, [(c.name, c.option_value, c.label) for c in boxes]
    assert {c.label for c in boxes} == {"Alpha", "Beta"}


def test_idless_checkboxes_same_name_value_different_paths_stay_distinct():
    """No ids and the same name/value: the structural DOM path keeps them
    distinct."""
    _reset()
    pa = "body > form > label:nth-of-type(1) > input"
    pb = "body > form > label:nth-of-type(2) > input"
    forms = _catalog([dom_forms([
        {"index": 0, "id": "f", "path": "body > form", "action": "/x",
         "method": "POST", "fields": [
            cb_field(None, "opt", "on", pa, "Alpha"),
            cb_field(None, "opt", "on", pb, "Beta"),
        ]}], page="p1", frame="f1", origin=1)])
    boxes = [c for c in forms[0].controls if c.type == "checkbox"]
    assert len(boxes) == 2, [(c.name, c.option_value, c.label) for c in boxes]


def test_checkbox_live_checked_change_merges_into_the_right_choice():
    """A change event resolves to the SAME checkbox its inventory created, so a
    live toggle lands on the right choice and does not spawn a duplicate."""
    _reset()
    pa = "body > form > label:nth-of-type(1) > input"
    pb = "body > form > label:nth-of-type(2) > input"
    forms = _catalog([
        dom_forms([{"index": 0, "id": "f", "path": "body > form", "action": "/x",
                    "method": "POST", "fields": [
            cb_field(None, "opt", "on", pa, "Alpha", checked=False),
            cb_field(None, "opt", "on", pb, "Beta", checked=False),
        ]}], page="p1", frame="f1", origin=1),
        checkbox_change("opt", "on", True, dom_path=pa, page="p1", frame="f1",
                        origin=1),
    ])
    boxes = {c.label: c for c in forms[0].controls if c.type == "checkbox"}
    assert len(boxes) == 2
    assert boxes["Alpha"].checked is True
    assert boxes["Beta"].checked is False


def test_a_single_idless_checkbox_stays_one_control():
    """Preserve single-checkbox behaviour when there is no id."""
    _reset()
    forms = _catalog([dom_forms([
        {"index": 0, "id": "f", "path": "body > form", "action": "/x",
         "method": "POST", "fields": [
            cb_field(None, "agree", "on", "body > form > input", "I agree",
                     checked=True),
        ]}], page="p1", frame="f1", origin=1)])
    boxes = [c for c in forms[0].controls if c.type == "checkbox"]
    assert len(boxes) == 1
    assert boxes[0].checked is True


# --- anonymous programmatic form submission ------------------------------

def test_anonymous_programmatic_submit_merges_with_inventory():
    """A form.submit() on an anonymous form carries the form's structural path,
    so it merges with the same entry the DOM inventory and inputs built."""
    _reset()
    path = "html > body > form"
    forms = _catalog([
        dom_forms([{"index": 0, "id": None, "path": path, "action": "/x",
                    "method": "POST", "fields": [
            {"tag": "input", "type": "text", "id": None, "name": "memo",
             "path": path + " > input"}]}],
                  page="p1", frame="f1", frame_url="http://h/wiz", origin=1),
        ev(EventType.USER_INPUT,
           {"value": {"value": "typed"},
            "element": {"tag": "input", "name": "memo", "form": "(unnamed)",
                        "form_path": path}},
           page="p1", frame="f1", frame_url="http://h/wiz", origin=1),
        runtime_submit(None, page="p1", frame="f1", form_path=path,
                       frame_url="http://h/wiz", origin=1),
    ])
    assert len(forms) == 1, [f.form_key for f in forms]
    assert forms[0].submitted is True
    memo = next(c for c in forms[0].controls if c.name == "memo")
    assert memo.final_value == "typed"


def test_requestsubmit_native_and_wrapper_are_not_double_counted():
    """requestSubmit() fires a native submit event AND the wrapper observation.
    Only one is counted -- the native event, which also carries the fields."""
    _reset()
    us = submit("order", page="p1", frame="f1")
    rs = runtime_submit("order", page="p1", frame="f1", via="requestSubmit")
    forms = _catalog([us, rs])
    assert len(forms) == 1
    entry = forms[0]
    assert entry.submitted is True
    # The requestSubmit wrapper event was not separately merged.
    assert rs.event_id not in entry.evidence.event_ids


# --- exact SPA occurrence identity ---------------------------------------

def test_two_exact_spa_locations_of_a_same_id_form_do_not_merge():
    """/claims/123 and /claims/456 are the same structural shape but different
    records; in one SPA document (one time origin) they must stay separate."""
    _reset()
    forms = _catalog([
        dom_forms([_named_form("entity-form")], page="p1", frame="f1",
                  frame_url="http://h/claims/123", origin=1000),
        dom_forms([_named_form("entity-form")], page="p1", frame="f1",
                  frame_url="http://h/claims/456", origin=1000),
    ])
    assert len(forms) == 2, [f.form_key for f in forms]
    # Structural shape is shared; the exact route separates them.
    assert {f.route for f in forms} == {"/claims/{id}"}
    assert {f.exact_route for f in forms} == {"/claims/123", "/claims/456"}


def test_repeated_observations_at_one_exact_spa_location_merge():
    _reset()
    forms = _catalog([
        dom_forms([_named_form("entity-form")], page="p1", frame="f1",
                  frame_url="http://h/claims/123", origin=1000),
        dom_forms([_named_form("entity-form")], page="p1", frame="f1",
                  frame_url="http://h/claims/123", origin=1000),
    ])
    assert len(forms) == 1, [f.form_key for f in forms]


def test_outcome_is_left_uncorrelated_when_identity_is_insufficient():
    """A submit with no page/frame identity must not borrow a global nav."""
    _reset()
    forms = _catalog([
        ev(EventType.USER_SUBMIT,
           {"element": {"tag": "form", "id": "ghost"}, "action": "/api/g",
            "fields": []}, page=None, frame=None),
        navigate("http://h/somewhere", page="pZ", frame="fZ"),
    ])
    entry = next(f for f in forms if f.form_id == "ghost")
    assert entry.outcome is None or entry.outcome.get("kind") == "uncorrelated"
