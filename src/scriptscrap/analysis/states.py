"""Application state reconstruction from observed navigation and structure.

Scope is deliberately narrow: this reconstructs the states that were VISITED,
not the application's state machine. A human drove the session, so the graph
shows the paths that human walked and nothing about the ones they did not. The
report says so, and the model refuses to imply otherwise.

A state's identity is STRUCTURAL. The route shape and the set of forms present
identify a screen; the dossier number in the URL does not. Otherwise every
record viewed would look like a different state and the graph would be a list.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse

from ..events import Event, EventType
from .identifiers import identifier_kind
from .models import AppState, Evidence, StateTransition
from .selectors import semantic_key

# Events that can plausibly cause a state change.
TRIGGER_TYPES = (
    EventType.USER_SUBMIT, EventType.USER_CLICK,
    EventType.USER_DBLCLICK, EventType.USER_RIGHTCLICK,
    EventType.RUNTIME_HISTORY, EventType.RUNTIME_FORM_SUBMIT,
)


def _wall_ms(event: Event) -> float | None:
    """Wall-clock milliseconds for an event, or None if unparseable."""
    try:
        return datetime.fromisoformat(event.t_wall).timestamp() * 1000.0
    except (TypeError, ValueError):
        return None


def route_shape(url: str) -> str:
    """`/items/4471?x=1` -> `/items/{id}`. Data removed, structure kept."""
    parsed = urlparse(url)
    segments = []
    for segment in (parsed.path or "/").split("/"):
        if not segment:
            continue
        segments.append("{id}" if identifier_kind(segment) else segment)
    shape = "/" + "/".join(segments)
    # A hash route is structure in an SPA, so its shape is kept too.
    if parsed.fragment:
        fragment_segments = [
            "{id}" if identifier_kind(s) else s
            for s in parsed.fragment.split("/") if s
        ]
        if fragment_segments:
            shape += "#/" + "/".join(fragment_segments)
    return shape


class StateAnalyzer:
    """Derives observed states and the transitions between them."""

    def analyze(self, events: list[Event]) -> tuple[list[AppState], list[StateTransition]]:
        forms_by_url = self._forms_by_url(events)
        timeline = self._timeline(events, forms_by_url)

        states: dict[str, AppState] = {}
        for entry in timeline:
            state = states.get(entry["fingerprint"])
            if state is None:
                states[entry["fingerprint"]] = AppState(
                    fingerprint=entry["fingerprint"],
                    label=entry["label"],
                    url_pattern=entry["shape"],
                    observation_count=1,
                    forms=entry["forms"],
                    evidence=Evidence(signals={"route_shape": entry["shape"]},
                                      event_ids=[entry["event_id"]]),
                )
            else:
                state.observation_count += 1
                state.evidence.cite(entry["event_id"])

        transitions = self._transitions(timeline, events)
        return (
            sorted(states.values(), key=lambda s: (-s.observation_count, s.label)),
            transitions,
        )

    def _forms_by_url(self, events: list[Event]) -> dict[str, list[str]]:
        """Form identities seen per route shape, from user_submit evidence."""
        forms: dict[str, set[str]] = defaultdict(set)
        for event in events:
            if event.type is EventType.USER_SUBMIT:
                element = event.payload.get("element") or {}
                name = element.get("id") or element.get("name")
                if name:
                    forms[route_shape(event.payload.get("frame_url") or "")].add(str(name))
            elif event.type in (EventType.USER_INPUT, EventType.USER_CHANGE):
                element = event.payload.get("element") or {}
                if element.get("form"):
                    forms[route_shape(event.payload.get("frame_url") or "")].add(
                        str(element["form"]))
        return {shape: sorted(names) for shape, names in forms.items()}

    def _timeline(self, events: list[Event], forms_by_url: dict[str, list[str]]) -> list[dict]:
        """Ordered list of state occupancies, one per navigation."""
        entries: list[dict] = []
        for event in events:
            url = None
            if event.type is EventType.NAVIGATION_COMMITTED or event.type is EventType.RUNTIME_HISTORY:
                url = event.payload.get("url")
            if not url:
                continue
            shape = route_shape(url)
            forms = forms_by_url.get(shape, [])
            fingerprint = hashlib.sha256(
                (shape + "|" + ",".join(forms)).encode("utf-8")
            ).hexdigest()[:12]
            entries.append({
                "event_id": event.event_id,
                "seq": event.seq,
                "wall_ms": _wall_ms(event),
                "shape": shape,
                "forms": forms,
                "fingerprint": fingerprint,
                "label": self._label(shape, forms),
            })
        return entries

    @staticmethod
    def _label(shape: str, forms: list[str]) -> str:
        # ASCII only: labels travel through consoles, reports and exports.
        name = shape.strip("/").replace("/", " > ") or "root"
        return f"{name} ({len(forms)} form{'s' if len(forms) != 1 else ''})" if forms else name

    @staticmethod
    def _candidate_trigger(previous: dict, current: dict, triggers: list[Event]):
        """Nearest plausible trigger between two states.

        Ingest order is tried first, but it systematically fails for SPA routes:
        Playwright's navigation event reaches Python before the runtime probe's
        batched click that caused it, so a seq window between the two states
        contains no candidate at all. Wall-clock ordering recovers those without
        appealing to cross-sensor ingest order, which M3 forbids as evidence.
        """
        by_seq = [e for e in triggers if previous["seq"] < e.seq < current["seq"]]
        if by_seq:
            return by_seq[-1], "same_timeline_seq"

        start, end = previous.get("wall_ms"), current.get("wall_ms")
        if start is None or end is None:
            return None, "unordered"
        by_clock = [
            e for e in triggers
            if (ms := _wall_ms(e)) is not None and start <= ms <= end
        ]
        if by_clock:
            return by_clock[-1], "wall_clock"
        return None, "unordered"

    def _transitions(self, timeline: list[dict], events: list[Event]) -> list[StateTransition]:
        """Pair consecutive states and attribute the trigger that preceded the move.

        The trigger is found by sequence position within the SAME sensor family
        where possible; a user action and a navigation come from different
        sensors, so this is stated as the nearest preceding candidate, not as a
        proven cause.
        """
        triggers = [e for e in events if e.type in TRIGGER_TYPES]
        merged: dict[tuple[str, str, str, str | None], StateTransition] = {}

        for previous, current in zip(timeline, timeline[1:], strict=False):
            if previous["fingerprint"] == current["fingerprint"]:
                continue
            candidate, method = self._candidate_trigger(previous, current, triggers)
            trigger = "unknown"
            trigger_type = trigger_element_key = trigger_event_id = None
            evidence = Evidence()
            evidence.cite(previous["event_id"], current["event_id"])
            if candidate is not None:
                evidence.add("ordering_method", method)
                element = candidate.payload.get("element") or {}
                target = element.get("id") or element.get("label") or element.get("text") or ""
                trigger = f"{candidate.type}{f' #{target}' if target else ''}"
                # The machine-readable halves. `trigger` above is a label and
                # is NOT an identity: a generator that joined on it matched
                # nothing, on 47 of 47 transitions in a real capture.
                trigger_event_id = candidate.event_id
                trigger_type = str(candidate.type)
                trigger_element_key = (
                    semantic_key(element)
                    if isinstance(element, dict) and element.get("tag") else None)
                evidence.cite(candidate.event_id)
                evidence.add("trigger_type", str(candidate.type))
                evidence.add(
                    "attribution",
                    "nearest preceding candidate in ingest order; cross-sensor "
                    "ordering is not proof of causation",
                )
            else:
                evidence.add("attribution", "no candidate trigger observed between states")

            key = (previous["fingerprint"], current["fingerprint"], trigger,
                   trigger_element_key)
            existing = merged.get(key)
            if existing is None:
                merged[key] = StateTransition(
                    from_state=previous["fingerprint"], to_state=current["fingerprint"],
                    trigger=trigger, observation_count=1,
                    trigger_type=trigger_type,
                    trigger_element_key=trigger_element_key,
                    trigger_event_id=trigger_event_id,
                    evidence=evidence,
                )
            else:
                existing.observation_count += 1
                existing.evidence.cite(*evidence.event_ids)

        return sorted(merged.values(), key=lambda t: (-t.observation_count, t.trigger))
