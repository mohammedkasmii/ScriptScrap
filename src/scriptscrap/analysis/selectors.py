"""Selector intelligence from repeated observations of the same element.

Stability is MEASURED, not assumed. Elements are grouped by the signals least
likely to change (role, accessible name, label, form), and then each locator
strategy is scored by how often it actually held across those observations.

This is why ID is not automatically preferred: a framework-generated id
(`ctl00_...`, `ng-...`, a styled-components hash) changes between renders, so it
scores badly on exactly the pages where it looks most authoritative.

Input is the element fingerprints M2 records on user-action events -- i.e. the
elements an operator actually used, which are the ones worth automating.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from ..events import Event, EventType
from .models import Evidence, LocatorCandidate, UIElement

USER_ACTION_TYPES = (
    EventType.USER_CLICK, EventType.USER_INPUT,
    EventType.USER_CHANGE, EventType.USER_SUBMIT, EventType.USER_KEY,
)

# Patterns whose presence means an id/class was generated, not authored.
_GENERATED: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aspnet_webforms", re.compile(r"^ctl\d{2}[_$]")),
    ("angular", re.compile(r"^ng-|^_ngcontent|^cdk-")),
    ("react_styled", re.compile(r"^sc-[a-zA-Z0-9]{6,}$")),
    ("emotion", re.compile(r"^css-[a-z0-9]{6,}$")),
    ("hash_suffix", re.compile(r"[-_][0-9a-f]{8,}$", re.I)),
    ("random_digits", re.compile(r"^[a-zA-Z]+[-_]?\d{5,}$")),
)


def generated_id_warning(value: str | None) -> str | None:
    """Name the framework that generated this identifier, if one did."""
    if not value:
        return None
    for name, pattern in _GENERATED:
        if pattern.search(value):
            return f"looks framework-generated ({name}); unstable across renders"
    return None


def semantic_key(element: dict[str, Any]) -> str:
    """Group observations that are plausibly the same logical element.

    Built only from signals a re-render is unlikely to change. Notably it does
    NOT include the id: if it did, an element whose id regenerates would look
    like two different elements and its instability would be invisible.
    """
    parts = [
        element.get("tag") or "",
        element.get("role") or "",
        (element.get("label") or "").strip()[:60],
        (element.get("text") or "").strip()[:60],
        element.get("name") or "",
        element.get("type") or "",
        element.get("form") or "",
    ]
    return "|".join(parts)


class SelectorAnalyzer:
    """Derives locator candidates and measures which ones held."""

    def analyze(self, events: list[Event]) -> list[UIElement]:
        groups: dict[str, list[Event]] = defaultdict(list)
        for event in events:
            if event.type not in USER_ACTION_TYPES:
                continue
            element = event.payload.get("element")
            if not isinstance(element, dict) or not element.get("tag"):
                continue
            groups[semantic_key(element)].append(event)

        results = [self._build(key, group) for key, group in groups.items()]
        results.sort(key=lambda e: (-e.observation_count, e.key))
        return results

    def _build(self, key: str, group: list[Event]) -> UIElement:
        evidence = Evidence()
        actions: dict[str, int] = defaultdict(int)
        # strategy -> value -> times that exact value was observed
        seen: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        first = group[0].payload["element"]

        for event in group:
            element = event.payload["element"]
            evidence.cite(event.event_id)
            actions[str(event.type)] += 1

            role, name = element.get("role"), element.get("label") or element.get("text")
            if role and name:
                seen["role_name"][f'role={role} name="{name}"'] += 1
            elif element.get("tag") in ("button", "a") and name:
                seen["role_name"][f'role={element["tag"]} name="{name}"'] += 1
            if element.get("label"):
                seen["label"][str(element["label"])] += 1
            if element.get("name"):
                seen["name"][f'[name="{element["name"]}"]'] += 1
            if element.get("id"):
                seen["id"][f'#{element["id"]}'] += 1
            if element.get("text"):
                seen["text"][f'text={element["text"]!r}'] += 1
            if element.get("dom_path"):
                seen["structural"][str(element["dom_path"])] += 1
            classes = (element.get("class") or "").split()
            if classes and element.get("tag"):
                seen["css"][f'{element["tag"]}.{".".join(classes[:2])}'] += 1

        total = len(group)
        locators: list[LocatorCandidate] = []
        for strategy, values in seen.items():
            # The best single value for this strategy, and how often it held.
            value, count = max(values.items(), key=lambda kv: kv[1])
            warning = generated_id_warning(value) if strategy in ("id", "css", "structural") else None
            # The prose warning interpolates a framework name or a count, so it
            # cannot be exported. The code beside it is a fixed constant and is
            # what a shareable dataset carries instead.
            warning_code = "framework_generated" if warning else None
            if len(values) > 1 and warning is None:
                warning = f"value changed across observations ({len(values)} distinct)"
                warning_code = "value_varied"
            locators.append(LocatorCandidate(
                strategy=strategy, value=value,
                resolved_count=count, sample_count=total, warning=warning,
                warning_code=warning_code,
            ))
        locators.sort(key=lambda locator: (-locator.stability, locator.strategy))

        evidence.add("observations", total)
        evidence.add("strategies_measured", sorted(seen))

        return UIElement(
            key=key,
            tag=first.get("tag") or "",
            role=first.get("role"),
            label=first.get("label"),
            text=first.get("text"),
            form=first.get("form"),
            observation_count=total,
            actions=dict(sorted(actions.items())),
            locators=locators,
            evidence=evidence,
        )
