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
    # For a combobox: the listbox it drives, and how trigger and option were
    # connected -- an exact aria-controls match, or a same-frame proximity guess.
    listbox: str | None = None
    connection: str | None = None


@dataclass(slots=True)
class FormCatalogEntry:
    """One form the operator used, assembled from every observation of it.

    Identity is unique across the whole session: `form_key` combines the page,
    the frame/document, and the form (its id/name, or -- for an anonymous form
    -- its index and structural path). Two tabs each showing `id="form1"`, and
    two anonymous forms in one frame, are therefore distinct entries.
    """

    form_key: str
    form_id: str | None
    frame_id: str | None
    page_id: str | None = None
    frame_url: str | None = None
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
    def _identity(form_id: str | None, index=None, path: str | None = None) -> str:
        """The form half of the key, within a document.

        A real id/name identifies the form. Without one, the form's index in the
        document plus its structural path do -- so two anonymous forms in one
        frame stay distinct. `(unnamed)` is the probe's placeholder for "no id",
        so it is treated as absent.
        """
        if form_id and form_id != "(unnamed)":
            return f"id:{form_id}"
        if index is not None:
            return f"idx:{index}" + (f"@{path}" if path else "")
        if path:
            return f"path:{path}"
        return "anon"

    @staticmethod
    def _key(page_id, frame_id, identity: str) -> str:
        # Page AND frame/document: frame ids are session-unique, and the page id
        # keeps two frames that could not be told apart still separate.
        return f"{page_id or '?'}::{frame_id or '?'}::{identity}"

    def _entry(self, key: str, form_id: str | None, page_id, frame_id,
               frame_url=None) -> FormCatalogEntry:
        entry = self._forms.get(key)
        if entry is None:
            entry = FormCatalogEntry(
                form_key=key,
                form_id=form_id if form_id and form_id != "(unnamed)" else None,
                page_id=page_id, frame_id=frame_id, frame_url=frame_url)
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
        page_id = event.payload.get("page_id") or event.page_id
        for frame in event.payload.get("frames") or []:
            frame_url = frame.get("frame_url")
            # Per-frame id when the scan recorded it, so forms in different
            # frames of one page do not collide; fall back to the event's frame.
            frame_id = frame.get("frame_id") or event.frame_id
            for form in frame.get("forms") or []:
                form_id = form.get("id") or form.get("name")
                identity = self._identity(form_id, form.get("index"), form.get("path"))
                key = self._key(page_id, frame_id, identity)
                entry = self._entry(key, form_id, page_id, frame_id, frame_url)
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
        identity = self._identity(form_id)
        key = self._key(event.page_id, event.frame_id, identity)
        entry = self._entry(key, form_id, event.page_id, event.frame_id,
                            event.payload.get("frame_url"))
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
        dom_path = element.get("dom_path")
        # A submit always has a form element; an anonymous one is identified by
        # its structural path, so two anonymous submits in one document stay
        # separate.
        if not form_id and not dom_path:
            return
        identity = self._identity(form_id, path=dom_path)
        key = self._key(event.page_id, event.frame_id, identity)
        entry = self._entry(key, form_id, event.page_id, event.frame_id,
                            event.payload.get("frame_url"))
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
        """Correlate submit -> request -> response/navigation, WITHIN the
        submitting page and frame.

        A frame id is session-unique, so matching it pins the request/navigation
        to the same document that submitted -- another tab's request or another
        tab's navigation can never be adopted. Without a frame/page identity on
        the submit there is nothing to scope to, so the outcome is left
        uncorrelated and said to be so, rather than borrowing a global event.
        """
        sframe = submit_event.frame_id
        spage = submit_event.page_id
        if sframe is None and spage is None:
            entry.outcome = {"kind": "uncorrelated",
                             "reason": "the submit carried no page or frame "
                                       "identity to scope its outcome to"}
            return

        def same_document(e) -> bool:
            # Frame id is unique per document across the whole session; when it
            # is present on both, it is the precise test. Otherwise fall back to
            # the page id, never wider.
            if sframe is not None and e.frame_id is not None:
                return e.frame_id == sframe
            if spage is not None and e.page_id is not None:
                return e.page_id == spage
            return False

        window = [e for e in ordered
                  if submit_event.seq < e.seq <= submit_event.seq + _REQUEST_WINDOW]

        request = next(
            (e for e in window
             if e.type in _REQUEST_EVENT_TYPES
             and not e.payload.get("evidence_reduced")
             and same_document(e)),
            None)
        if request is not None:
            entry.associated_request = {
                "method": request.payload.get("method"),
                "path": request.payload.get("path") or request.payload.get("url"),
                "event_id": request.event_id,
            }
            entry.evidence.cite(request.event_id)

        nav = next((e for e in window
                    if e.type is EventType.NAVIGATION_COMMITTED
                    and e.payload.get("url") and same_document(e)),
                   None)
        if nav is not None:
            entry.outcome = {"kind": "navigation",
                             "route": route_shape(str(nav.payload["url"])),
                             "event_id": nav.event_id}
            entry.evidence.cite(nav.event_id)
            return
        response = next(
            (e for e in window if e.type is EventType.HTTP_RESPONSE
             and same_document(e)
             and (not request or e.payload.get("path") == entry_path(entry))),
            None)
        if response is not None:
            entry.outcome = {"kind": "response",
                             "status": response.payload.get("status"),
                             "event_id": response.event_id}
            entry.evidence.cite(response.event_id)

    # -- 3. ARIA comboboxes ------------------------------------------------
    @staticmethod
    def _region_identity(element: dict) -> str:
        """The captured region a control belongs to -- a real form/fieldset/
        dialog/section/region id, or the control's own id. NEVER the frame.

        `element.form` is a real <form>; `element.region` is the closest
        role=form / fieldset / dialog / section / region the probe recorded. A
        control with neither is keyed by its own id, which is still an element
        identity, not the whole document.
        """
        form_id = element.get("form")
        if form_id and form_id != "(unnamed)":
            return f"id:{form_id}"
        region = element.get("region")
        if region:
            return f"region:{region}"
        own = element.get("id")
        if own:
            return f"region@{own}"
        return "region:?"

    def _merge_comboboxes(self, ordered: list[Event]) -> None:
        # Pending trigger PER (page, frame): an option click can only ever
        # connect to a trigger in its OWN page and frame, never another tab's.
        pending: dict[tuple, dict] = {}
        clicks_since: dict[tuple, int] = {}

        for event in ordered:
            if event.type not in _CLICK_TYPES:
                continue
            element = event.payload.get("element") or {}
            aria = element.get("aria") or {}
            role = element.get("role")
            scope = (event.page_id, event.frame_id)

            is_trigger = (role == "combobox"
                          or aria.get("aria-haspopup") == "listbox"
                          or (aria.get("aria-controls") and role != "option"))
            if is_trigger:
                pending[scope] = {
                    "event": event, "element": element,
                    "controls": aria.get("aria-controls"),
                    "region": self._region_identity(element),
                    "name": str(element.get("id") or element.get("label")
                                or aria.get("aria-controls") or "combobox"),
                }
                clicks_since[scope] = 0
                continue

            if role == "option":
                trig = pending.get(scope)
                if trig is None or clicks_since.get(scope, 0) >= _COMBO_WINDOW:
                    clicks_since[scope] = clicks_since.get(scope, 0) + 1
                    continue
                # Exact match: the option's owning listbox equals the trigger's
                # aria-controls. Otherwise a proximity fallback -- but only
                # within this same page/frame, and marked heuristic.
                opt_listbox = element.get("listbox") or (aria.get("aria-controls"))
                controls = trig["controls"]
                exact = bool(controls) and controls == opt_listbox
                connection = "aria-controls" if exact else "proximity_same_frame"

                key = self._key(event.page_id, event.frame_id, trig["region"])
                entry = self._entry(
                    key,
                    trig["element"].get("form")
                    if trig["element"].get("form") not in (None, "(unnamed)") else None,
                    event.page_id, event.frame_id, event.payload.get("frame_url"))
                entry.evidence.cite(trig["event"].event_id, event.event_id)
                control = self._control(key, trig["name"],
                                        str(trig["element"].get("tag") or "div"))
                control.kind = "combobox"
                control.role = "combobox"
                control.label = trig["element"].get("label") or control.label
                control.listbox = opt_listbox
                control.connection = connection
                text = element.get("text") or element.get("label")
                control.selected_label = text
                opt = {"value": element.get("id") or text, "text": text}
                if opt not in control.options:
                    control.options.append(opt)
                # Only the chosen option was observed; the listbox was not
                # enumerated, so the set is NOT complete.
                control.options_complete = False
                pending.pop(scope, None)
            clicks_since[scope] = clicks_since.get(scope, 0) + 1


def entry_path(entry: FormCatalogEntry) -> str | None:
    return (entry.associated_request or {}).get("path")


__all__ = ["FormCatalogAnalyzer", "FormCatalogEntry", "FormControl"]
