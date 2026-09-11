"""Offline form and control catalog.

A form is filled across many scattered observations -- an input event per
keystroke, a change event per selection, a submit at the end, an HTTP request
just after, a navigation that follows. This assembles them, per form, into one
record of what the employee actually did: which controls the form has, their
labels/types/options/state, the final value in each, the submit that closed it,
the request it produced and the outcome that followed.

Two rules, the same as everywhere else in the analysis layer:

* **Final, not every keystroke.** The last value observed on a field is its
  final value; the intermediate ones are collapsed. A secret field records that
  something was entered and its length, never the value.
* **Everything cites its evidence.** Each form and each correlated request
  carries the event ids behind it, so a reader can walk back to the log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..events import Event, EventType
from .models import Evidence
from .states import route_shape

# A request that lands within this many events after a submit, in the same
# frame, is taken to be the one the submit produced. A window in `seq`, not
# time: within one frame the probe and the network sensor are close, and a
# generous bound keeps a slow round trip attributable without reaching across
# unrelated activity.
_REQUEST_WINDOW = 40

_VALUE_TYPES = (EventType.USER_INPUT, EventType.USER_CHANGE)
_SUBMIT_TYPES = (EventType.USER_SUBMIT, EventType.RUNTIME_FORM_SUBMIT)
_REQUEST_EVENT_TYPES = (EventType.HTTP_REQUEST, EventType.RUNTIME_FETCH,
                        EventType.RUNTIME_XHR)


@dataclass(slots=True)
class FormControl:
    """One control in a form, and what the operator left it at."""

    name: str
    tag: str
    type: str | None = None
    label: str | None = None
    placeholder: str | None = None
    required: bool = False
    disabled: bool = False
    readonly: bool = False
    checked: bool | None = None
    selected_label: str | None = None
    options: list[dict[str, Any]] = field(default_factory=list)
    final_value: str | None = None
    # True when the field is a secret: the value is never recorded, only that
    # something was entered.
    secret: bool = False


@dataclass(slots=True)
class FormCatalogEntry:
    """One form the operator used, assembled from every observation of it."""

    form_key: str
    form_id: str | None
    frame_id: str | None
    action: str | None = None
    method: str | None = None
    controls: list[FormControl] = field(default_factory=list)
    submitted: bool = False
    associated_request: dict[str, Any] | None = None
    outcome: dict[str, Any] | None = None
    evidence: Evidence = field(default_factory=Evidence)


class FormCatalogAnalyzer:
    """Builds the form/control catalog from the event log."""

    def analyze(self, events: list[Event]) -> list[FormCatalogEntry]:
        ordered = sorted(events, key=lambda e: e.seq)
        forms: dict[str, FormCatalogEntry] = {}
        controls: dict[str, dict[str, FormControl]] = {}

        for event in ordered:
            if event.type in _VALUE_TYPES:
                self._observe_value(event, forms, controls)
            elif event.type in _SUBMIT_TYPES:
                self._observe_submit(event, forms, controls, ordered)

        result = []
        for key, entry in forms.items():
            entry.controls = [controls[key][name] for name in sorted(controls[key])]
            result.append(entry)
        # Submitted forms first, then by how many controls they carry.
        result.sort(key=lambda f: (not f.submitted, -len(f.controls), f.form_key))
        return result

    # -- assembly ----------------------------------------------------------
    def _entry(self, forms, controls, key, form_id, frame_id) -> FormCatalogEntry:
        entry = forms.get(key)
        if entry is None:
            entry = FormCatalogEntry(form_key=key, form_id=form_id, frame_id=frame_id)
            forms[key] = entry
            controls[key] = {}
        return entry

    def _observe_value(self, event, forms, controls) -> None:
        element = event.payload.get("element") or {}
        form_id = element.get("form")
        name = element.get("name") or element.get("id")
        if not form_id or not name:
            return
        key = f"{event.frame_id}|{form_id}"
        entry = self._entry(forms, controls, key, str(form_id), event.frame_id)
        entry.evidence.cite(event.event_id)

        control = controls[key].get(str(name))
        if control is None:
            control = FormControl(name=str(name), tag=str(element.get("tag") or "input"))
            controls[key][str(name)] = control
        control.type = element.get("type") or control.type
        control.label = element.get("label") or control.label
        control.placeholder = element.get("placeholder") or control.placeholder
        control.required = bool(element.get("required")) or control.required
        control.disabled = bool(element.get("disabled")) or control.disabled
        control.readonly = bool(element.get("readonly")) or control.readonly

        value = event.payload.get("value") or {}
        if value.get("redacted"):
            control.secret = True
            control.final_value = None
            return
        if "checked" in value:
            control.checked = bool(value.get("checked"))
        selected = value.get("selected")
        if isinstance(selected, list) and selected:
            control.options = selected
            control.selected_label = selected[0].get("text")
        # The final value is last-write-wins: the operator's last observed entry.
        if isinstance(value.get("value"), str):
            control.final_value = value["value"]

    def _observe_submit(self, event, forms, controls, ordered) -> None:
        element = event.payload.get("element") or {}
        form_id = element.get("id") or element.get("name") or event.payload.get("form")
        if not form_id:
            return
        key = f"{event.frame_id}|{form_id}"
        entry = self._entry(forms, controls, key, str(form_id), event.frame_id)
        entry.evidence.cite(event.event_id)
        entry.submitted = True
        entry.action = event.payload.get("action") or entry.action
        entry.method = (event.payload.get("method") or entry.method or "GET")

        # Fields present at submit time, including ones never individually
        # observed being edited (a pre-filled hidden field, say).
        for f in event.payload.get("fields") or []:
            fname = f.get("name")
            if not fname:
                continue
            control = controls[key].get(str(fname))
            if control is None:
                control = FormControl(name=str(fname),
                                      tag=str(f.get("tag") or "input"),
                                      type=f.get("type"))
                controls[key][str(fname)] = control
            fvalue = f.get("value") or {}
            if fvalue.get("redacted"):
                control.secret = True
            elif isinstance(fvalue.get("value"), str) and control.final_value is None:
                control.final_value = fvalue["value"]

        self._correlate(entry, event, ordered)

    def _correlate(self, entry, submit_event, ordered) -> None:
        """Link a submit to the request it produced and the outcome that
        followed: a request in the same frame just after, and a navigation or a
        response status after that."""
        window = [e for e in ordered
                  if submit_event.seq < e.seq <= submit_event.seq + _REQUEST_WINDOW]
        request = next(
            (e for e in window
             if e.type in _REQUEST_EVENT_TYPES
             and not e.payload.get("evidence_reduced")
             and (e.frame_id == submit_event.frame_id or e.frame_id is None)),
            None)
        if request is not None:
            entry.associated_request = {
                "method": request.payload.get("method"),
                "path": request.payload.get("path") or request.payload.get("url"),
                "event_id": request.event_id,
            }
            entry.evidence.cite(request.event_id)

        nav = next((e for e in window
                    if e.type is EventType.NAVIGATION_COMMITTED and e.payload.get("url")),
                   None)
        if nav is not None:
            entry.outcome = {
                "kind": "navigation",
                "route": route_shape(str(nav.payload["url"])),
                "event_id": nav.event_id,
            }
            entry.evidence.cite(nav.event_id)
            return
        # No navigation: the response status is the outcome we can state.
        response = next(
            (e for e in window
             if e.type is EventType.HTTP_RESPONSE
             and (not request or e.payload.get("path") == entry_path(entry))),
            None)
        if response is not None:
            entry.outcome = {
                "kind": "response",
                "status": response.payload.get("status"),
                "event_id": response.event_id,
            }
            entry.evidence.cite(response.event_id)


def entry_path(entry: FormCatalogEntry) -> str | None:
    return (entry.associated_request or {}).get("path")


__all__ = ["FormCatalogAnalyzer", "FormCatalogEntry", "FormControl"]
