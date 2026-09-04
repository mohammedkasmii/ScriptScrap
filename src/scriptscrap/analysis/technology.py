"""Lightweight technology detection.

Detection is only worth doing where it changes how evidence is read. Three
examples, and the reason each earns its place:

* **ASP.NET WebForms** -- `__VIEWSTATE` is a base64 blob that can be hundreds of
  kilobytes. Treated as data it drowns every schema it appears in; recognised as
  a state token it becomes a single fact, and `__EVENTTARGET` becomes the field
  that actually identifies the operation.
* **GraphQL** -- one URL, many operations. Already handled at capture; detecting
  it here tells the reader why the endpoint list looks the way it does.
* **jQuery** -- explains where event handlers live when the DOM shows none.

This is not, and should not become, a Wappalyzer clone. A framework that does
not change how the evidence is interpreted does not need a signature.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from ..events import Event, EventType
from .models import Evidence, Technology

# ASP.NET WebForms postback fields. Their VALUES are opaque state, but their
# PRESENCE is a strong signal and __EVENTTARGET carries real meaning.
WEBFORMS_STATE_FIELDS = frozenset({
    "__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION",
    "__PREVIOUSPAGE", "__VIEWSTATEENCRYPTED",
})
WEBFORMS_OPERATION_FIELDS = frozenset({"__EVENTTARGET", "__EVENTARGUMENT"})

_SIGNATURES: tuple[tuple[str, str, re.Pattern[str], float], ...] = (
    ("jQuery", "library", re.compile(r"\bjquery(\.min)?\.js|/jquery[-.]", re.I), 0.9),
    ("React", "framework", re.compile(r"\breact(-dom)?(\.production|\.development)?\.js|__REACT_DEVTOOLS", re.I), 0.85),
    ("Angular", "framework", re.compile(r"\b(angular|zone)\.js|ng-version|_ngcontent", re.I), 0.85),
    ("Vue", "framework", re.compile(r"\bvue(\.runtime)?(\.min)?\.js|__VUE__", re.I), 0.85),
    ("Next.js", "framework", re.compile(r"/_next/static/|__NEXT_DATA__", re.I), 0.9),
)


class TechnologyAnalyzer:
    """Evidence-driven fingerprinting over the event log."""

    def analyze(self, events: list[Event]) -> list[Technology]:
        hits: dict[str, Technology] = {}
        webforms_state: set[str] = set()
        webforms_ops: set[str] = set()
        webforms_events: list[str] = []
        graphql_ops: set[str] = set()
        graphql_events: list[str] = []
        jquery_selectors = 0

        for event in events:
            payload = event.payload

            # -- URL / body signatures ---------------------------------
            haystack = " ".join(
                str(payload.get(k) or "") for k in ("url", "path", "text", "message")
            )
            for name, category, pattern, base in _SIGNATURES:
                if pattern.search(haystack):
                    tech = hits.get(name)
                    if tech is None:
                        tech = Technology(name=name, category=category,
                                          confidence=base, evidence=Evidence())
                        hits[name] = tech
                    tech.evidence.cite(event.event_id)
                    signal = f"matched {pattern.pattern[:40]}"
                    if signal not in tech.signals:
                        tech.signals.append(signal)

            # -- GraphQL ------------------------------------------------
            graphql = payload.get("graphql")
            if graphql and graphql.get("operations"):
                graphql_events.append(event.event_id)
                for operation in graphql["operations"]:
                    label = " ".join(filter(None, (operation.get("operation_type"),
                                                   operation.get("operation_name"))))
                    if label:
                        graphql_ops.add(label)

            # -- ASP.NET WebForms --------------------------------------
            for name in self._field_names(payload):
                if name in WEBFORMS_STATE_FIELDS:
                    webforms_state.add(name)
                    webforms_events.append(event.event_id)
                elif name in WEBFORMS_OPERATION_FIELDS:
                    webforms_ops.add(name)
                    webforms_events.append(event.event_id)

            # -- jQuery runtime evidence -------------------------------
            if event.type is EventType.RUNTIME_HOOKS:
                selectors = payload.get("jquery_bound_selectors") or []
                jquery_selectors += len(selectors)

        if webforms_state or webforms_ops:
            evidence = Evidence()
            evidence.cite(*webforms_events[:25])
            evidence.add("state_fields", sorted(webforms_state))
            evidence.add("operation_fields", sorted(webforms_ops))
            evidence.add(
                "interpretation",
                "VIEWSTATE-family values are opaque state tokens, not payload data; "
                "__EVENTTARGET identifies the operation",
            )
            hits["ASP.NET WebForms"] = Technology(
                name="ASP.NET WebForms", category="framework",
                confidence=0.95 if webforms_state and webforms_ops else 0.8,
                signals=sorted(webforms_state | webforms_ops), evidence=evidence,
            )

        if graphql_ops:
            evidence = Evidence()
            evidence.cite(*graphql_events[:25])
            evidence.add("operations", sorted(graphql_ops))
            hits["GraphQL"] = Technology(
                name="GraphQL", category="api",
                confidence=0.99, signals=sorted(graphql_ops), evidence=evidence,
            )

        if jquery_selectors:
            tech = hits.get("jQuery") or Technology(
                name="jQuery", category="library", confidence=0.7, evidence=Evidence())
            tech.signals.append(f"{jquery_selectors} selectors with bound handlers")
            tech.confidence = max(tech.confidence, 0.9)
            hits["jQuery"] = tech

        return sorted(hits.values(), key=lambda t: (-t.confidence, t.name))

    @staticmethod
    def _field_names(payload: dict[str, Any]) -> set[str]:
        """Field names visible in a request body, form submit, or query."""
        names: set[str] = set()
        body = payload.get("body")
        if isinstance(body, dict):
            names.update(str(k) for k in body)
        elif isinstance(body, str) and "=" in body:
            names.update(part.split("=", 1)[0] for part in body.split("&") if part)
        for field in payload.get("fields") or []:
            if isinstance(field, dict) and field.get("name"):
                names.add(str(field["name"]))
        url = payload.get("url") or ""
        if "?" in url:
            names.update(
                part.split("=", 1)[0] for part in url.split("?", 1)[1].split("&") if part
            )
        return names


def opaque_state_fields(technologies: list[Technology]) -> set[str]:
    """Fields whose values should be summarised rather than schema-inferred."""
    for tech in technologies:
        if tech.name == "ASP.NET WebForms":
            return set(WEBFORMS_STATE_FIELDS)
    return set()


def field_counts_by_endpoint(events: list[Event]) -> dict[str, dict[str, int]]:
    """Small helper used by the report to show which endpoints carry which fields."""
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for event in events:
        if event.type is not EventType.HTTP_REQUEST:
            continue
        path = event.payload.get("path") or "/"
        for name in TechnologyAnalyzer._field_names(event.payload):
            counts[path][name] += 1
    return {k: dict(v) for k, v in counts.items()}
