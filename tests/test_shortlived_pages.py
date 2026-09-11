"""Short-lived and load-time popups must still be covered.

Two gaps this closes: a popup opened DURING the initial navigation (coverage
must be listening and must enumerate existing pages before it starts scanning),
and a popup opened, used and closed in under two seconds (the first snapshot
must be eager, not wait for the 2s poll). Both drive the production runner
(`run_capture`) so the coverage ordering is exactly production's.
"""

from __future__ import annotations

import asyncio

import pytest

from scriptscrap.events import EventLogReader, EventType

pytestmark = pytest.mark.browser


def _load_inv():
    from scriptscrap.testing.capture import load_investigator
    return load_investigator()


async def _run(out, target_path, interact):
    from scriptscrap.fixture import FixtureServer

    inv = _load_inv()
    with FixtureServer() as fx:
        scope = inv.InvestigationScope(fx.base_url)
        engine = inv.WebHarvester(fx.base_url, scope,
                                  session_id="sess-20260101-000000", output_dir=out)
        await inv.run_capture(
            engine, target_url=fx.base_url + target_path, forensic_config=None,
            headless=True, interact=interact)
    return EventLogReader(out / "events.jsonl")


def test_a_popup_opened_during_initial_navigation_is_covered(tmp_path):
    async def interact(page, engine):
        # The target opened the popup during its own load; give coverage a beat
        # to observe and snapshot it.
        await page.wait_for_timeout(2500)

    log = asyncio.run(_run(tmp_path / "out", "/opens-popup", interact))
    assert log.validate() == []
    # The popup (page2, opened on load) must be its own page with a form
    # inventory captured -- proof it was not missed.
    popups = log.of_type(EventType.POPUP_OPENED)
    opened = {e.page_id for e in log.of_type(EventType.PAGE_OPENED) if e.page_id}
    assert popups or len(opened) >= 2, "the load-time popup was not observed"
    forms = log.of_type(EventType.DOM_FORMS)
    assert any("/page2" in (fr.get("frame_url") or "")
               for e in forms for fr in (e.payload.get("frames") or [])), \
        "the load-time popup's form inventory was not captured"


def test_a_popup_used_and_closed_under_two_seconds(tmp_path):
    async def interact(page, engine):
        await page.wait_for_selector("html[data-fixture-ready='true']", state="attached")
        async with page.context.expect_page() as popup_info:
            await page.click("#btn-popup")
        popup = await popup_info.value
        await popup.wait_for_load_state("load")
        await popup.wait_for_function("() => (window.__scriptscrapRearmCount||0) >= 1")
        await popup.fill("#p2-reference", "REF-FAST")
        # Under two seconds total -- the point is that coverage does NOT wait for
        # its 2s poll -- but past the probe's own ~400ms flush so a live event
        # is delivered before teardown, as a real fast close would allow.
        await popup.wait_for_timeout(600)
        await popup.close()
        await page.wait_for_timeout(300)

    log = asyncio.run(_run(tmp_path / "out", "/", interact))
    assert log.validate() == []

    popup_id = None
    for e in log.of_type(EventType.POPUP_OPENED):
        if e.page_id:
            popup_id = e.page_id
    assert popup_id, "no popup observed"

    # Its form inventory was snapshotted EAGERLY -- coverage did not wait for the
    # 2s poll -- or, if the page closed first, a specific gap says so honestly.
    forms = [e for e in log.of_type(EventType.DOM_FORMS)
             if any("/page2" in (fr.get("frame_url") or "")
                    for fr in (e.payload.get("frames") or []))]
    gaps = {g.payload.get("reason") for g in log.of_type(EventType.CAPTURE_GAP)}
    assert forms or "page_closed_before_capture" in gaps, (
        "a fast-closing popup left neither an eager snapshot nor an honest gap")

    # The live input flushed before teardown and is attributed to the popup.
    inputs = [e for e in log.of_type(EventType.USER_INPUT)
              if e.page_id == popup_id
              and (e.payload.get("element") or {}).get("id") == "p2-reference"]
    assert inputs, "the popup's input was lost despite a flush window"
