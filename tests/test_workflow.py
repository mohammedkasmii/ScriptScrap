"""The observed workflow: what happened, in the order it happened.

The generator used to reconstruct this at render time from two lists that were
sorted by observation count and shared no identifier, which produced 107 clicks,
zero fills and 47 unjoined transitions on a real capture.
"""

from __future__ import annotations

import pytest

from scriptscrap.analysis import semantic_key
from scriptscrap.analysis.models import SAFE_KEYS, WORKFLOW_KINDS
from scriptscrap.analysis.selectors import SelectorAnalyzer
from scriptscrap.analysis.states import StateAnalyzer
from scriptscrap.analysis.workflow import WorkflowAnalyzer
from scriptscrap.events import Event, EventType, Source


def _event(seq: int, etype: EventType, element: dict, **payload) -> Event:
    return Event(
        session_id="s", event_id=f"evt-{seq:08d}", seq=seq,
        t_wall=f"2026-01-01T00:00:{seq:02d}+00:00", t_mono=float(seq),
        source=Source.RUNTIME, type=etype,
        payload={"element": element, **payload})


def _nav(seq: int, url: str) -> Event:
    return Event(session_id="s", event_id=f"evt-{seq:08d}", seq=seq,
                 t_wall=f"2026-01-01T00:00:{seq:02d}+00:00", t_mono=float(seq),
                 source=Source.PLAYWRIGHT, type=EventType.NAVIGATION_COMMITTED,
                 payload={"url": url})


TEXT = {"tag": "input", "role": "textbox", "label": "Nom", "text": None,
        "name": "nom", "type": "text", "form": "frm"}
SELECT = {"tag": "select", "role": "combobox", "label": "Ville", "text": None,
          "name": "ville", "type": None, "form": "frm"}
CHECK = {"tag": "input", "role": "checkbox", "label": "Accord", "text": None,
         "name": "accord", "type": "checkbox", "form": "frm"}
BUTTON = {"tag": "button", "role": "button", "label": "Envoyer", "text": "Envoyer",
          "name": "", "type": "submit", "form": "frm"}


# --- one definition of element identity (C1) ------------------------------

def test_the_analyzer_groups_by_the_public_semantic_key():
    """One definition of 'the same element', used by every consumer."""
    element = {"tag": "input", "role": "textbox", "label": "Nom",
               "text": None, "name": "nom", "type": "text", "form": "frm"}
    events = [_event(1, EventType.USER_INPUT, element),
              _event(2, EventType.USER_CHANGE, element)]
    elements = SelectorAnalyzer().analyze(events)
    assert len(elements) == 1
    assert elements[0].key == semantic_key(element)


def test_semantic_key_ignores_a_regenerated_id():
    """The key must not include the id, or an unstable id looks like two
    elements and its instability becomes invisible."""
    first = {"tag": "button", "role": "button", "label": "Save", "text": "Save",
             "name": "", "type": "submit", "form": "frm", "id": "ctl00_a"}
    second = {**first, "id": "ctl00_b"}
    assert semantic_key(first) == semantic_key(second)


def test_semantic_key_is_stable_across_missing_optional_fields():
    assert semantic_key({"tag": "a"}) == semantic_key(
        {"tag": "a", "role": None, "label": None, "text": None,
         "name": None, "type": None, "form": None})


# --- the ordered action model (C2) ----------------------------------------

def test_every_kind_is_derived_from_the_event_and_the_element():
    events = [
        _nav(1, "http://h/login"),
        _event(2, EventType.USER_INPUT, TEXT),
        _event(3, EventType.USER_CHANGE, SELECT),
        _event(4, EventType.USER_CHANGE, CHECK),
        _event(5, EventType.USER_KEY, TEXT, key="Enter"),
        _event(6, EventType.USER_CLICK, BUTTON),
        _event(7, EventType.USER_SUBMIT, BUTTON),
    ]
    steps = WorkflowAnalyzer().analyze(events)
    assert [s.kind for s in steps] == [
        "navigate", "fill", "select", "check", "press", "click", "submit"]
    assert all(s.kind in WORKFLOW_KINDS for s in steps)


def test_steps_are_ordered_by_seq_not_by_frequency():
    """The generator used two frequency-sorted lists and produced the workflow
    in observation-count order."""
    events = [
        _nav(1, "http://h/a"),
        _event(2, EventType.USER_CLICK, BUTTON),
        _event(3, EventType.USER_CLICK, BUTTON),
        _nav(4, "http://h/b"),
        _event(5, EventType.USER_INPUT, TEXT),
    ]
    steps = WorkflowAnalyzer().analyze(events)
    assert [s.seq for s in steps] == sorted(s.seq for s in steps)
    assert [s.ordinal for s in steps] == list(range(len(steps)))
    assert steps[0].kind == "navigate" and steps[0].url_pattern == "/a"


def test_consecutive_typing_on_one_element_collapses():
    events = [_event(seq, EventType.USER_INPUT, TEXT) for seq in range(1, 6)]
    steps = WorkflowAnalyzer().analyze(events)
    assert len(steps) == 1
    assert steps[0].repeat_count == 5
    assert len(steps[0].evidence.event_ids) == 5


def test_the_same_element_touched_again_after_something_else_is_two_steps():
    events = [
        _event(1, EventType.USER_INPUT, TEXT),
        _event(2, EventType.USER_CLICK, BUTTON),
        _event(3, EventType.USER_INPUT, TEXT),
    ]
    steps = WorkflowAnalyzer().analyze(events)
    assert len(steps) == 3
    assert [s.repeat_count for s in steps] == [1, 1, 1]


def test_every_step_joins_to_a_ui_element():
    """The join the generator could not make."""
    events = [
        _event(1, EventType.USER_INPUT, TEXT),
        _event(2, EventType.USER_CLICK, BUTTON),
    ]
    steps = WorkflowAnalyzer().analyze(events)
    elements = {e.key for e in SelectorAnalyzer().analyze(events)}
    unresolved = [s.element_key for s in steps
                  if s.element_key is not None and s.element_key not in elements]
    assert unresolved == [], unresolved


def test_a_navigation_carries_a_route_shape_not_a_url():
    steps = WorkflowAnalyzer().analyze([_nav(1, "http://h/items/4471?token=x")])
    assert steps[0].url_pattern == "/items/{id}"


def test_a_value_is_recorded_as_having_happened_never_as_a_value():
    """The capture does not hold input values; inventing one would be a lie."""
    events = [_event(1, EventType.USER_INPUT, TEXT, value={"value": "Alice Benali"})]
    step = WorkflowAnalyzer().analyze(events)[0]
    assert step.value_recorded is True
    assert "Alice" not in repr(step)


@pytest.mark.parametrize("key", sorted(SAFE_KEYS))
def test_an_allowlisted_key_that_was_recorded_is_kept(key):
    step = WorkflowAnalyzer().analyze(
        [_event(1, EventType.USER_KEY, TEXT, key=key)])[0]
    assert step.kind == "press"
    assert step.key == key


@pytest.mark.parametrize("key", ["a", "7", "!", "Shift", "F5", "Control+c", "é"])
def test_a_key_that_is_not_allowlisted_is_never_kept(key):
    """A keystroke can be one character of a password."""
    step = WorkflowAnalyzer().analyze(
        [_event(1, EventType.USER_KEY, TEXT, key=key)])[0]
    assert step.kind == "press"
    # The field, not a substring of repr(): a one-character key like "a"
    # appears inside element_key and kind by coincidence.
    assert step.key is None


def test_an_unrecorded_key_is_never_invented():
    """No substituting "Enter" for a key the session did not observe."""
    step = WorkflowAnalyzer().analyze([_event(1, EventType.USER_KEY, TEXT)])[0]
    assert step.kind == "press"
    assert step.key is None


def test_a_press_never_sets_value_recorded():
    """value_recorded means "a value was typed and the capture does not hold
    it". A key press is not that, and letting it set the flag would inflate the
    workflow_value_gap finding with steps that have no missing value."""
    for payload in ({}, {"key": "Enter"}, {"key": "a"}, {"value": {"value": "x"}}):
        step = WorkflowAnalyzer().analyze(
            [_event(1, EventType.USER_KEY, TEXT, **payload)])[0]
        assert step.value_recorded is False, payload


def test_an_element_without_a_tag_is_skipped_like_the_selector_analyzer_does():
    events = [_event(1, EventType.USER_CLICK, {"role": "button"})]
    assert WorkflowAnalyzer().analyze(events) == []


def test_an_empty_session_yields_an_empty_workflow():
    assert WorkflowAnalyzer().analyze([]) == []


# --- a transition names the element that triggered it (C3) ----------------

def test_a_transition_names_the_element_that_triggered_it():
    """`by_key.get(transition.trigger)` never matched: `trigger` is
    "user_click #Delete" and UIElement.key is a semantic key. 47 of 47
    transitions on the real capture fell through to 'no element was recorded'
    -- several of them naming an element that WAS recorded."""
    events = [
        _nav(1, "http://h/a"),
        _event(2, EventType.USER_CLICK, BUTTON),
        _nav(3, "http://h/b"),
    ]
    _, transitions = StateAnalyzer().analyze(events)
    assert transitions
    transition = transitions[0]
    assert transition.trigger_element_key == semantic_key(BUTTON)
    assert transition.trigger_event_id == "evt-00000002"
    assert transition.trigger_type == "user_click"

    elements = {e.key for e in SelectorAnalyzer().analyze(events)}
    assert transition.trigger_element_key in elements


def test_a_transition_with_no_candidate_says_so_with_none_not_a_string():
    events = [_nav(1, "http://h/a"), _nav(2, "http://h/b")]
    _, transitions = StateAnalyzer().analyze(events)
    assert transitions
    assert transitions[0].trigger_element_key is None
    assert transitions[0].trigger_event_id is None
    assert transitions[0].trigger_type is None
    assert transitions[0].trigger == "unknown"


def test_a_navigation_triggered_transition_has_an_event_but_no_element():
    """runtime_history carries no element; the event id is still evidence."""
    history = Event(session_id="s", event_id="evt-00000002", seq=2,
                    t_wall="2026-01-01T00:00:02+00:00", t_mono=2.0,
                    source=Source.RUNTIME, type=EventType.RUNTIME_HISTORY,
                    payload={"url": "http://h/b"})
    events = [_nav(1, "http://h/a"), history]
    _, transitions = StateAnalyzer().analyze(events)
    assert transitions
    assert transitions[0].trigger_element_key is None
    assert transitions[0].trigger_event_id == "evt-00000002"
    assert transitions[0].trigger_type == "runtime_history"


# --- findings over the workflow (C6) --------------------------------------

def test_a_step_whose_element_has_no_locator_becomes_a_finding():
    from scriptscrap.analysis import analyze_events

    orphan = {"tag": "div", "role": None, "label": None, "text": None,
              "name": None, "type": None, "form": None}
    result = analyze_events([_event(1, EventType.USER_CLICK, orphan)], "s")
    kinds = {f.kind for f in result.findings}
    assert "unreplayable_step" in kinds or not result.workflow, (
        "a step that cannot be replayed must be stated, not emitted silently")


def test_the_values_the_capture_did_not_record_are_stated_once():
    from scriptscrap.analysis import analyze_events

    events = [_event(seq, EventType.USER_INPUT, TEXT, value={"value": "x"})
              for seq in range(1, 4)]
    result = analyze_events(events, "s")
    gaps = [f for f in result.findings if f.kind == "workflow_value_gap"]
    assert len(gaps) == 1
    assert gaps[0].count == 1          # one collapsed step, not three events
    assert "not recorded" in gaps[0].message


def test_a_press_step_does_not_carry_the_key_that_was_pressed():
    """A key is application-visible input and could be part of a password."""
    events = [_event(1, EventType.USER_KEY, TEXT, key="a")]
    step = WorkflowAnalyzer().analyze(events)[0]
    assert step.kind == "press"
    assert step.key is None
