"""What the exit-time introspection actually records.

The investigator reads dropdown catalogues, jQuery handler maps and JS hook
call records into memory at exit, and emitted only their KEYS. The option
lists, the bound event types and the per-call-site counts were collected and
then discarded -- `dropdown_catalogs.json` and `jquery_events.json` were the
only record of them.
"""

from __future__ import annotations

import pytest

from scriptscrap.events import EventLogReader, EventType

pytestmark = pytest.mark.browser


def _hooks(output):
    reader = EventLogReader(output / "events.jsonl")
    events = reader.of_type(EventType.RUNTIME_HOOKS)
    assert events, "no runtime_hooks event was emitted"
    return events[-1].payload


def test_a_dropdown_carries_its_options_not_only_its_name(investigation_output):
    payload = _hooks(investigation_output)
    catalogs = payload["dropdown_catalog_options"]
    assert catalogs, "no dropdown catalogue was recorded"

    # `p2-etat`, not `ville`: introspection runs once at exit on the top frame,
    # so a full navigation destroys every catalogue collected before it. That
    # limitation is pinned by test_dropdown_catalogs_reflect_only_the_final
    # _document; what matters here is that the surviving one carries its
    # OPTIONS, which is what the retirement discarded.
    etat = catalogs.get("p2-etat")
    assert etat is not None, f"the final document's select is missing: {sorted(catalogs)}"
    labels = {option["label"] for option in etat}
    assert len(labels) > 1, f"only one option recorded: {labels}"
    assert all(isinstance(o, dict) and {"id", "label"} <= o.keys() for o in etat)


def test_the_summary_keys_still_exist_so_nothing_reading_them_breaks(investigation_output):
    payload = _hooks(investigation_output)
    assert set(payload["dropdown_catalogs"]) == set(payload["dropdown_catalog_options"])
    assert set(payload["jquery_bound_selectors"]) == set(payload["jquery_bound_events"])


def test_jquery_handlers_carry_the_event_types_they_are_bound_to(investigation_output):
    payload = _hooks(investigation_output)
    bound = payload["jquery_bound_events"]
    if not bound:
        pytest.skip("the fixture page bound no jQuery handlers in this run")
    assert all(isinstance(v, list) for v in bound.values())
    assert any(v for v in bound.values()), "every selector recorded an empty event list"


def test_hook_calls_are_counted_per_function(investigation_output):
    payload = _hooks(investigation_output)
    per_function = payload["hook_calls_by_function"]
    assert set(per_function) == set(payload["functions"])
    assert sum(per_function.values()) == payload["hook_calls"]
