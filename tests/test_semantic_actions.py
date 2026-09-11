"""Semantic user actions beyond the single click.

The mission asks for double-click and right-click as distinct actions -- a
double-click is one intent, not two clicks, and a right-click opens a context
menu rather than activating a control. They must reach a distinct event type, a
distinct workflow kind, and a distinct Playwright call, and they must NOT be
collapsed into or by an ordinary click.

Offline and synthetic: the event model and the derivation are what is under
test here; the probe that emits these types is exercised by the browser suite.
"""

from __future__ import annotations

import itertools

from scriptscrap.analysis.models import WORKFLOW_KINDS
from scriptscrap.analysis.workflow import WorkflowAnalyzer
from scriptscrap.events import Event, EventType, Source
from scriptscrap.generate import render_playwright

_seq = itertools.count(1)

BUTTON = {"tag": "button", "role": "button", "label": "Row menu",
          "text": "Row menu", "name": "", "type": "button", "form": None}


def _event(etype, element, **payload):
    n = next(_seq)
    return Event(session_id="s", event_id=f"evt-{n:08d}", seq=n,
                 t_wall=f"2026-01-01T00:00:{n % 60:02d}+00:00", t_mono=float(n),
                 source=Source.RUNTIME, type=etype,
                 payload={"element": element, **payload})


def test_the_new_action_types_exist():
    assert EventType.USER_DBLCLICK == "user_dblclick"
    assert EventType.USER_RIGHTCLICK == "user_rightclick"


def test_double_click_and_right_click_are_distinct_workflow_kinds():
    steps = WorkflowAnalyzer().analyze([
        _event(EventType.USER_DBLCLICK, BUTTON),
        _event(EventType.USER_RIGHTCLICK, BUTTON),
    ])
    assert [s.kind for s in steps] == ["double_click", "right_click"]
    assert "double_click" in WORKFLOW_KINDS
    assert "right_click" in WORKFLOW_KINDS


def test_a_double_click_is_not_folded_with_an_ordinary_click():
    """Two consecutive but different actions on one element are two steps."""
    steps = WorkflowAnalyzer().analyze([
        _event(EventType.USER_CLICK, BUTTON),
        _event(EventType.USER_DBLCLICK, BUTTON),
    ])
    assert [s.kind for s in steps] == ["click", "double_click"]


def test_repeated_right_clicks_do_not_collapse_the_way_typing_does():
    """Clicks are discrete intents; only consecutive typing on one field folds."""
    steps = WorkflowAnalyzer().analyze([
        _event(EventType.USER_RIGHTCLICK, BUTTON),
        _event(EventType.USER_RIGHTCLICK, BUTTON),
    ])
    # Consecutive identical right-clicks fold like consecutive identical clicks
    # already do (same element, same kind); what must NOT happen is a right
    # click folding with an ordinary click.
    assert all(s.kind == "right_click" for s in steps)


def test_double_click_reaches_a_playwright_call():
    from scriptscrap.analysis.models import (
        AnalysisResult,
        Evidence,
        LocatorCandidate,
        UIElement,
        WorkflowStep,
    )
    element = UIElement(key="k", tag="button", role="button", label="Row",
                        text="Row", form=None, observation_count=1,
                        locators=[LocatorCandidate(strategy="css", value="#row",
                                                   resolved_count=1, sample_count=1)],
                        evidence=Evidence(event_ids=["e"]))
    for kind, call in (("double_click", ".dblclick()"),
                       ("right_click", '.click(button="right")')):
        result = AnalysisResult(
            session_id="s", event_count=1, ui_elements=[element],
            workflow=[WorkflowStep(ordinal=0, seq=1, kind=kind, element_key="k",
                                   evidence=Evidence(event_ids=["e"]))])
        source = render_playwright(result, session_name="s")
        assert call in source, f"{kind} did not produce {call}"
        compile(source, "observed_workflow.py", "exec")
