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
       frame_url="http://h/"):
    n = next(_seq)
    body = dict(payload)
    body.setdefault("frame_url", frame_url)
    return Event(session_id="s", event_id=f"evt-{n:08d}", seq=n,
                 t_wall=f"2026-01-01T00:00:{n % 60:02d}+00:00", t_mono=float(n),
                 source=source, type=etype, payload=body, page_id=page, frame_id=frame)


def submit(form_id, *, page, frame, action="/api/x", method="POST", dom_path=None):
    element = {"tag": "form", "id": form_id, "dom_path": dom_path}
    return ev(EventType.USER_SUBMIT,
              {"element": element, "action": action, "method": method, "fields": []},
              page=page, frame=frame)


def dom_forms(forms, *, page, frame, frame_url="http://h/"):
    return ev(EventType.DOM_FORMS,
              {"page_id": page, "url": frame_url,
               "frames": [{"frame_url": frame_url, "frame_id": frame, "forms": forms}]},
              source=Source.ENGINE, page=page, frame=frame)


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
