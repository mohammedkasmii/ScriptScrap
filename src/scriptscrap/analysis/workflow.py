"""The observed workflow: what the operator did, in the order they did it.

Two things the generator could not do for itself, and therefore did wrong:

**Order.** `seq` is the spine's only total order. `AnalysisResult.states` and
`.ui_elements` are sorted by observation count, because that is the useful
order for reading them -- and a generator that walked those lists emitted the
session in frequency order. Order is derived here, where the events are.

**Action.** Which action was performed is a property of the event type and the
element, and the generator had neither: it inspected `UIElement.actions`, whose
keys are event-type names (`user_input`), against a vocabulary of bare verbs
(`input`). Every element rendered as a click.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..events import Event, EventType
from .models import SAFE_KEYS, Evidence, WorkflowStep
from .selectors import semantic_key
from .states import route_shape

NAVIGATION_TYPES = (EventType.NAVIGATION_COMMITTED, EventType.RUNTIME_HISTORY)

ACTION_TYPES = (
    EventType.USER_CLICK, EventType.USER_DBLCLICK, EventType.USER_RIGHTCLICK,
    EventType.USER_INPUT, EventType.USER_CHANGE,
    EventType.USER_SUBMIT, EventType.USER_KEY, EventType.RUNTIME_FORM_SUBMIT,
)

_TOGGLE_TYPES = frozenset({"checkbox", "radio"})


@dataclass(frozen=True, slots=True)
class _Raw:
    """One un-collapsed observation, before consecutive folding."""

    seq: int
    kind: str
    element_key: str | None
    url_pattern: str | None
    value_recorded: bool
    key: str | None
    event_id: str


def _kind(event: Event, element: dict) -> str:
    """The action, from the event type and what it was performed on."""
    if event.type in (EventType.USER_SUBMIT, EventType.RUNTIME_FORM_SUBMIT):
        return "submit"
    if event.type is EventType.USER_DBLCLICK:
        return "double_click"
    if event.type is EventType.USER_RIGHTCLICK:
        return "right_click"
    if event.type is EventType.USER_KEY:
        return "press"
    input_type = str(element.get("type") or "").lower()
    if event.type is EventType.USER_CHANGE:
        if str(element.get("tag") or "").lower() == "select":
            return "select"
        return "check" if input_type in _TOGGLE_TYPES else "fill"
    if event.type is EventType.USER_INPUT:
        return "fill"
    return "check" if input_type in _TOGGLE_TYPES else "click"


def _safe_key(event: Event) -> str | None:
    """The key that was pressed, if it is one we may reproduce.

    A keystroke is application-visible input: it can be one character of a
    password typed into a field. So the default is None, and only a recorded,
    allowlisted navigation or control key survives. Nothing is substituted for
    a key the capture did not record -- a generated `press("Enter")` for an
    unknown key is behaviour the session never observed.
    """
    recorded = event.payload.get("key")
    if isinstance(recorded, str) and recorded in SAFE_KEYS:
        return recorded
    return None


class WorkflowAnalyzer:
    """Derives the ordered action model from the event log."""

    def analyze(self, events: list[Event]) -> list[WorkflowStep]:
        raw: list[_Raw] = []

        for event in sorted(events, key=lambda e: e.seq):
            if event.type in NAVIGATION_TYPES:
                url = event.payload.get("url")
                if not url:
                    continue
                raw.append(_Raw(event.seq, "navigate", None,
                                route_shape(str(url)), False, None,
                                event.event_id))
                continue

            if event.type not in ACTION_TYPES:
                continue
            element = event.payload.get("element")
            # Same gate as SelectorAnalyzer: an element with no tag is not one
            # this can find again, so it is not a step.
            if not isinstance(element, dict) or not element.get("tag"):
                continue
            kind = _kind(event, element)
            raw.append(_Raw(
                event.seq, kind, semantic_key(element), None,
                # A press has no missing VALUE, whatever else it has.
                kind != "press" and "value" in event.payload,
                _safe_key(event) if kind == "press" else None,
                event.event_id))

        return self._collapse(raw)

    @staticmethod
    def _collapse(raw: list[_Raw]) -> list[WorkflowStep]:
        """Fold consecutive identical steps.

        Typing five characters emits five `user_input` events on one element,
        and five `.fill()` calls would be five ways to say one thing. Only
        CONSECUTIVE steps fold: the same button clicked again after a
        navigation is a second visit, not a repeat.

        Two presses fold only if they carried the SAME key -- Tab then Enter is
        two different things and must not become "Tab x2".
        """
        steps: list[WorkflowStep] = []
        for item in raw:
            previous = steps[-1] if steps else None
            if (previous is not None
                    and previous.kind == item.kind
                    and previous.element_key == item.element_key
                    and previous.url_pattern == item.url_pattern
                    and previous.key == item.key):
                previous.evidence.cite(item.event_id)
                steps[-1] = WorkflowStep(
                    ordinal=previous.ordinal, seq=previous.seq, kind=item.kind,
                    element_key=item.element_key, url_pattern=item.url_pattern,
                    repeat_count=previous.repeat_count + 1,
                    value_recorded=previous.value_recorded or item.value_recorded,
                    key=previous.key, evidence=previous.evidence)
                continue
            evidence = Evidence()
            evidence.cite(item.event_id)
            steps.append(WorkflowStep(
                ordinal=len(steps), seq=item.seq, kind=item.kind,
                element_key=item.element_key, url_pattern=item.url_pattern,
                repeat_count=1, value_recorded=item.value_recorded,
                key=item.key, evidence=evidence))
        return steps
