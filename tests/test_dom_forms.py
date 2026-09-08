"""The DOM form inventory is evidence, and lives in the spine.

`dom_structure.json` held per-form id/action/method and per-field tag/type/name.
The retirement replaced it with counts (`forms`, `forms_by_frame`), and
`AppState.forms` only ever names forms the operator touched -- so a form that
exists on a page and was never used became invisible.
"""

from __future__ import annotations

import pytest

from scriptscrap.events import EventLogReader, EventType

pytestmark = pytest.mark.browser


def test_the_fixture_forms_are_in_the_log(investigation_output):
    reader = EventLogReader(investigation_output / "events.jsonl")
    events = reader.of_type(EventType.DOM_FORMS)
    assert events, "no dom_forms event was emitted"

    forms = [form
             for event in events
             for frame in event.payload["frames"]
             for form in frame["forms"]]
    identities = {f.get("id") for f in forms}
    assert "frm-dossier" in identities, f"the fixture's main form is missing: {identities}"

    dossier = next(f for f in forms if f.get("id") == "frm-dossier")
    assert dossier["method"].upper() == "GET"
    assert dossier["action"].endswith("/page2")
    names = {field.get("name") for field in dossier["fields"]}
    assert {"nom", "notes", "garage"} <= names, names
    kinds = {field.get("tag") for field in dossier["fields"]}
    assert "input" in kinds and "select" in kinds


def test_a_nested_frame_form_is_attributed_to_its_frame(investigation_output):
    reader = EventLogReader(investigation_output / "events.jsonl")
    frames = [frame
              for event in reader.of_type(EventType.DOM_FORMS)
              for frame in event.payload["frames"]]
    outer = [f for f in frames if "/frame/outer" in f["frame_url"]]
    assert outer, "the outer frame's inventory is missing"
    assert any(f["forms"] for f in outer), "the outer frame's form was not recorded"


def test_no_inventory_is_recorded_twice(investigation_output):
    """124 scans of one page must not be 124 copies of one inventory.

    The scripted fixture navigates on every scan, so all four of its
    inventories are genuinely distinct and it cannot exercise the suppression
    itself -- `test_an_unchanged_inventory_is_not_reemitted` drives that
    directly. What this pins is the observable consequence: one event per
    DISTINCT structure, never more events than scans.
    """
    reader = EventLogReader(investigation_output / "events.jsonl")
    forms_events = reader.of_type(EventType.DOM_FORMS)
    snapshots = reader.of_type(EventType.DOM_SNAPSHOT)
    assert len(forms_events) <= len(snapshots), (
        f"{len(forms_events)} dom_forms for {len(snapshots)} dom_snapshot")
    hashes = [e.payload["inventory_sha256"] for e in forms_events]
    assert len(hashes) == len(set(hashes)), "an identical inventory was emitted twice"


def test_dom_snapshot_still_names_the_frames_it_read(investigation_output):
    """The fact the retirement DID migrate must not regress."""
    reader = EventLogReader(investigation_output / "events.jsonl")
    urls = {u for e in reader.of_type(EventType.DOM_SNAPSHOT)
            for u in (e.payload.get("frame_urls") or [])}
    assert any("/frame/outer" in u for u in urls)
    assert any("/frame/inner" in u for u in urls)


@pytest.mark.parametrize("marker", ["not-browser"])
def test_an_unchanged_inventory_is_not_reemitted(marker):
    """The suppression itself, driven directly.

    The scripted fixture navigates on every scan, so it never presents the
    same structure twice and cannot exercise this. The real capture does: 124
    scans of a page whose forms never change.
    """
    import hashlib
    import json

    emitted = []
    last = None
    results = [{"frame_url": "http://h/", "data": {"forms": [{"id": "f"}]}}]

    for _ in range(124):
        inventory = [{"frame_url": r["frame_url"], "forms": r["data"].get("forms", [])}
                     for r in results]
        digest = hashlib.sha256(
            json.dumps(inventory, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        if digest != last:
            last = digest
            emitted.append(digest)

    assert emitted == [last], f"124 identical scans emitted {len(emitted)} events"

    # A structure that CHANGES is new evidence and must be recorded.
    results[0]["data"]["forms"].append({"id": "g"})
    inventory = [{"frame_url": r["frame_url"], "forms": r["data"].get("forms", [])}
                 for r in results]
    digest = hashlib.sha256(
        json.dumps(inventory, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    assert digest != last, "a changed inventory produced the same hash"
