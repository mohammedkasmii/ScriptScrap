"""Element identity and locator ranking.

Two failures the mission calls out directly:

* Unrelated unlabeled inputs must not merge into one UIElement. The old
  semantic key was `tag|role|label|text|name|type|form`, so two nameless search
  boxes -- or two blank inputs at different points in a form -- collapsed into a
  single element and their real instability became invisible.
* `data-testid` (and `data-test` / `data-cy`) is the most stable locator a
  page offers, and it was not a strategy at all.

Synthetic events, so a test states exactly which signals are present.
"""

from __future__ import annotations

import itertools

from scriptscrap.analysis.models import (
    Evidence,
    LocatorCandidate,
    UIElement,
)
from scriptscrap.analysis.selectors import SelectorAnalyzer, semantic_key
from scriptscrap.events import Event, EventType, Source

_seq = itertools.count(1)


def click(element: dict) -> Event:
    n = next(_seq)
    return Event(
        session_id="s", event_id=f"evt-{n:05d}", seq=n,
        t_wall="2026-01-01T00:00:00+00:00", t_mono=float(n),
        source=Source.RUNTIME, type=EventType.USER_CLICK,
        payload={"element": element}, page_id="p1", frame_id="f1")


# --- identity: do not merge unrelated anonymous inputs -------------------

def test_two_inputs_with_different_placeholders_are_two_elements():
    a = {"tag": "input", "type": "search", "placeholder": "Search customer"}
    b = {"tag": "input", "type": "search", "placeholder": "Search order"}
    assert semantic_key(a) != semantic_key(b)
    elements = SelectorAnalyzer().analyze([click(a), click(b)])
    assert len(elements) == 2


def test_two_anonymous_inputs_at_different_positions_are_two_elements():
    """No id, name, label or placeholder: only the structural path separates
    them, and it must, or two unrelated fields become one."""
    a = {"tag": "input", "type": "text", "dom_path": "form > input:nth-of-type(1)"}
    b = {"tag": "input", "type": "text", "dom_path": "form > input:nth-of-type(2)"}
    assert semantic_key(a) != semantic_key(b)


def test_a_named_element_still_groups_across_a_regenerated_id():
    """The id stays out of the key: an element whose id regenerates is still
    one element, so its instability is measurable."""
    first = {"tag": "button", "label": "Save", "text": "Save", "name": "",
             "type": "submit", "form": "frm", "id": "ctl00_a"}
    second = {**first, "id": "ctl00_b"}
    assert semantic_key(first) == semantic_key(second)


def test_the_key_is_stable_across_missing_optional_fields():
    assert semantic_key({"tag": "a"}) == semantic_key(
        {"tag": "a", "role": None, "label": None, "text": None,
         "name": None, "type": None, "form": None, "placeholder": None})


# --- test-id becomes a strategy ------------------------------------------

def test_data_testid_becomes_a_locator():
    element = {"tag": "button", "label": "Submit claim",
               "dataset": {"testid": "claim-submit"}}
    ui = SelectorAnalyzer().analyze([click(element)])[0]
    by_strategy = {loc.strategy: loc for loc in ui.locators}
    assert "test_id" in by_strategy
    assert by_strategy["test_id"].value == "claim-submit"


def test_data_test_and_data_cy_are_also_test_ids():
    for key in ("test", "cy"):
        element = {"tag": "button", "label": "Go", "dataset": {key: "the-hook"}}
        ui = SelectorAnalyzer().analyze([click(element)])[0]
        assert "test_id" in {loc.strategy for loc in ui.locators}


def test_a_placeholder_becomes_a_locator():
    element = {"tag": "input", "type": "search", "placeholder": "Search customer"}
    ui = SelectorAnalyzer().analyze([click(element)])[0]
    assert "placeholder" in {loc.strategy for loc in ui.locators}


# --- ranking: test-id wins -----------------------------------------------

def _stable(strategy: str, value: str) -> LocatorCandidate:
    return LocatorCandidate(strategy=strategy, value=value,
                            resolved_count=3, sample_count=3)


def test_test_id_outranks_role_name_when_both_are_stable():
    element = UIElement(
        key="k", tag="button", role="button", label="Submit", text="Submit",
        form=None, observation_count=3,
        locators=[_stable("role_name", 'role=button name="Submit"'),
                  _stable("test_id", "claim-submit"),
                  _stable("label", "Submit")],
        evidence=Evidence())
    assert element.recommended.strategy == "test_id"


def test_placeholder_is_preferred_over_a_bare_name():
    element = UIElement(
        key="k", tag="input", role=None, label=None, text=None, form=None,
        observation_count=3,
        locators=[_stable("name", '[name="q"]'),
                  _stable("placeholder", "Search customer")],
        evidence=Evidence())
    assert element.recommended.strategy == "placeholder"
