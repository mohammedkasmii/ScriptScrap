"""Offline form and control catalog.

A form is described by many scattered observations: the DOM scan that inventories
every visible control (touched or not, with the full native-select option set),
an input event per keystroke, a change per selection, a submit at the end, an
HTTP request just after, a navigation that follows. This assembles them, per
form, into one record of everything observed: which controls the form has, their
labels/types/options/state, the final value in each, the submit that closed it,
the request it produced and the outcome that followed.

Rules, the same as everywhere else in the analysis layer:

* **Everything visible, not only what was touched.** DOM_FORMS seeds the catalog
  with every control the scan saw, so an untouched field still appears -- and a
  native select carries its whole option list, values and visible labels.
* **Final, not every keystroke.** The last value observed on a field is its
  final value; a secret field records only that something was entered.
* **Do not overclaim.** A native select inventoried by the DOM scan has a
  complete option set (`options_complete`); a custom control seen only being
  chosen does not, and says so.
* **Custom ARIA controls too.** A combobox is a trigger plus a listbox connected
  by `aria-controls`, and the option the operator clicked -- joined by proximity
  and identity, so a portalled listbox that is not a DOM child still links.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..events import Event, EventType
from .models import Evidence
from .states import route_shape

_REQUEST_WINDOW = 40
_COMBO_WINDOW = 12          # clicks between a combobox trigger and its option

_VALUE_TYPES = (EventType.USER_INPUT, EventType.USER_CHANGE)
_SUBMIT_TYPES = (EventType.USER_SUBMIT, EventType.RUNTIME_FORM_SUBMIT)
_REQUEST_EVENT_TYPES = (EventType.HTTP_REQUEST, EventType.RUNTIME_FETCH,
                        EventType.RUNTIME_XHR)
_CLICK_TYPES = (EventType.USER_CLICK, EventType.USER_DBLCLICK,
                EventType.USER_RIGHTCLICK)


@dataclass(slots=True)
class FormControl:
    """One control in a form, and what the operator left it at."""

    name: str
    tag: str
    type: str | None = None
    role: str | None = None
    kind: str = "native"            # "native" | "combobox"
    label: str | None = None
    placeholder: str | None = None
    required: bool = False
    disabled: bool = False
    readonly: bool = False
    checked: bool | None = None
    selected_label: str | None = None
    options: list[dict[str, Any]] = field(default_factory=list)
    # True only when the full option set was inventoried (a native select in a
    # DOM scan). A custom control seen only being chosen is NOT complete.
    options_complete: bool = False
    final_value: str | None = None
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
        self._forms: dict[str, FormCatalogEntry] = {}
        self._controls: dict[str, dict[str, FormControl]] = {}

        # 1. Seed from every DOM scan: all visible controls, full option sets.
        for event in ordered:
            if event.type is EventType.DOM_FORMS:
                self._seed_from_dom(event)

        # 2. Merge the operator's own observations: typed values, selections,
        #    checkbox state, and the submit and its outcome.
        for event in ordered:
            if event.type in _VALUE_TYPES:
                self._merge_value(event)
            elif event.type in _SUBMIT_TYPES:
                self._merge_submit(event, ordered)

        # 3. Custom ARIA comboboxes: trigger -> chosen option.
        self._merge_comboboxes(ordered)

        result = []
        for key, entry in self._forms.items():
            entry.controls = [self._controls[key][name]
                              for name in sorted(self._controls[key])]
            result.append(entry)
        result.sort(key=lambda f: (not f.submitted, -len(f.controls), f.form_key))
        return result

    # -- keys --------------------------------------------------------------
    @staticmethod
    def _key(form_id: str | None, frame_ref: str | None) -> str:
        if form_id:
            return str(form_id)
        return f"@formless@{frame_ref or '?'}"

    def _entry(self, key: str, form_id: str | None, frame_id: str | None) -> FormCatalogEntry:
        entry = self._forms.get(key)
        if entry is None:
            entry = FormCatalogEntry(form_key=key, form_id=form_id, frame_id=frame_id)
            self._forms[key] = entry
            self._controls[key] = {}
        return entry

    def _control(self, key: str, name: str, tag: str) -> FormControl:
        control = self._controls[key].get(name)
        if control is None:
            control = FormControl(name=name, tag=tag)
            self._controls[key][name] = control
        return control

    # -- 1. DOM scan seed --------------------------------------------------
    def _seed_from_dom(self, event: Event) -> None:
        for frame in event.payload.get("frames") or []:
            frame_url = frame.get("frame_url")
            for form in frame.get("forms") or []:
                form_id = form.get("id")
                key = self._key(form_id, frame_url)
                entry = self._entry(key, form_id, event.frame_id)
                entry.evidence.cite(event.event_id)
                entry.action = form.get("action") or entry.action
                entry.method = (form.get("method") or entry.method or "GET")
                for f in form.get("fields") or []:
                    self._seed_control(key, f)

    def _seed_control(self, key: str, f: dict) -> None:
        name = f.get("id") or f.get("name")
        if not name:
            return
        control = self._control(key, str(name), str(f.get("tag") or "input"))
        control.type = f.get("type") or control.type
        control.label = f.get("label") or control.label
        control.placeholder = f.get("placeholder") or control.placeholder
        control.required = bool(f.get("required")) or control.required
        control.disabled = bool(f.get("disabled")) or control.disabled
        control.readonly = bool(f.get("readonly")) or control.readonly
        if "checked" in f:
            control.checked = bool(f.get("checked"))
        if f.get("secret"):
            control.secret = True
        options = f.get("options")
        if isinstance(options, list) and options:
            # A DOM scan sees the WHOLE option set.
            control.options = [{"value": o.get("value"), "text": o.get("text")}
                               for o in options]
            control.options_complete = True
            for o in options:
                if o.get("selected"):
                    control.selected_label = o.get("text")
        value = f.get("value")
        # The current value at scan time; a later user event overrides it.
        if isinstance(value, str) and value and control.final_value is None:
            control.final_value = value

    # -- 2. user value merge ----------------------------------------------
    def _merge_value(self, event: Event) -> None:
        element = event.payload.get("element") or {}
        form_id = element.get("form")
        name = element.get("id") or element.get("name")
        if not name:
            return
        frame_ref = event.payload.get("frame_url") or event.frame_id
        key = self._key(form_id, frame_ref)
        entry = self._entry(key, str(form_id) if form_id else None, event.frame_id)
        entry.evidence.cite(event.event_id)

        control = self._control(key, str(name), str(element.get("tag") or "input"))
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
            control.selected_label = selected[0].get("text")
            # Seen being chosen: not the complete option set unless a DOM scan
            # already inventoried it.
        if isinstance(value.get("value"), str):
            control.final_value = value["value"]

    def _merge_submit(self, event: Event, ordered: list[Event]) -> None:
        element = event.payload.get("element") or {}
        form_id = element.get("id") or element.get("name") or event.payload.get("form")
        if not form_id:
            return
        frame_ref = event.payload.get("frame_url") or event.frame_id
        key = self._key(str(form_id), frame_ref)
        entry = self._entry(key, str(form_id), event.frame_id)
        entry.evidence.cite(event.event_id)
        entry.submitted = True
        entry.action = event.payload.get("action") or entry.action
        entry.method = event.payload.get("method") or entry.method or "GET"

        for f in event.payload.get("fields") or []:
            fname = f.get("name") or f.get("id")
            if not fname:
                continue
            control = self._control(key, str(fname), str(f.get("tag") or "input"))
            fvalue = f.get("value") or {}
            if fvalue.get("redacted"):
                control.secret = True
            elif isinstance(fvalue.get("value"), str) and control.final_value is None:
                control.final_value = fvalue["value"]

        self._correlate(entry, event, ordered)

    def _correlate(self, entry, submit_event, ordered) -> None:
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
            entry.outcome = {"kind": "navigation",
                             "route": route_shape(str(nav.payload["url"])),
                             "event_id": nav.event_id}
            entry.evidence.cite(nav.event_id)
            return
        response = next(
            (e for e in window if e.type is EventType.HTTP_RESPONSE
             and (not request or e.payload.get("path") == entry_path(entry))),
            None)
        if response is not None:
            entry.outcome = {"kind": "response",
                             "status": response.payload.get("status"),
                             "event_id": response.event_id}
            entry.evidence.cite(response.event_id)

    # -- 3. ARIA comboboxes ------------------------------------------------
    def _merge_comboboxes(self, ordered: list[Event]) -> None:
        pending = None       # (entry_key, control_name, trigger_event, form_id, frame, trigger_el)
        clicks_since = 0
        for event in ordered:
            if event.type not in _CLICK_TYPES:
                continue
            element = event.payload.get("element") or {}
            aria = element.get("aria") or {}
            role = element.get("role")
            is_trigger = (role == "combobox"
                          or aria.get("aria-haspopup") == "listbox"
                          or (aria.get("aria-controls") and role != "option"))
            if is_trigger:
                form_id = element.get("form")
                frame_ref = event.payload.get("frame_url") or event.frame_id
                key = self._key(form_id, frame_ref)
                name = str(element.get("id") or element.get("label")
                           or aria.get("aria-controls") or "combobox")
                pending = (key, name, event, form_id, event.frame_id, element)
                clicks_since = 0
                continue
            if role == "option" and pending is not None and clicks_since < _COMBO_WINDOW:
                key, name, trigger_event, form_id, frame_id, trigger_el = pending
                entry = self._entry(key, str(form_id) if form_id else None, frame_id)
                entry.evidence.cite(trigger_event.event_id, event.event_id)
                control = self._control(key, name, str(trigger_el.get("tag") or "div"))
                control.kind = "combobox"
                control.role = "combobox"
                control.label = trigger_el.get("label") or control.label
                text = element.get("text") or element.get("label")
                control.selected_label = text
                opt = {"value": element.get("id") or text, "text": text}
                if opt not in control.options:
                    control.options.append(opt)
                # Only the chosen option was observed; the listbox was not
                # enumerated, so the set is NOT complete.
                control.options_complete = False
                pending = None
            clicks_since += 1


def entry_path(entry: FormCatalogEntry) -> str | None:
    return (entry.associated_request or {}).get("path")


__all__ = ["FormCatalogAnalyzer", "FormCatalogEntry", "FormControl"]
