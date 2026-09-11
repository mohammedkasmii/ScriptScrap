"""Every in-scope page/tab/popup gets complete capture coverage.

The old investigator ran a single scanner on the initial page and drained only
that page at the end, so everything a popup held was lost. PageCoverage now runs
a scanner per page and drains every remaining in-scope page on session end.

This drives the real coverage machinery -- attach_engine_to_page +
PageCoverage, exactly as main() does -- opens a popup, fills and submits a form
in it, and verifies the popup's actions, form inventory, storage snapshot,
page/frame identity and navigation outcome are all captured.
"""

from __future__ import annotations

import asyncio

import pytest

from scriptscrap.events import EventLogReader, EventType

pytestmark = pytest.mark.browser


async def _run(tmp_path):
    from camoufox.addons import DefaultAddons
    from camoufox.async_api import AsyncCamoufox

    from scriptscrap.fixture import FixtureServer
    from scriptscrap.testing.capture import load_investigator

    out = tmp_path / "output"
    inv = load_investigator()

    with FixtureServer() as fx:
        scope = inv.InvestigationScope(fx.base_url)
        engine = inv.WebHarvester(fx.base_url, scope,
                                  session_id="sess-20260101-000000", output_dir=out)
        engine.record_launch_options({"headless": True})

        async with AsyncCamoufox(
            headless=True, humanize=False, os="windows", geoip=False,
            exclude_addons=[DefaultAddons.UBO], main_world_eval=True,
        ) as browser:
            page = await browser.new_page()
            await inv.attach_engine_to_page(page, engine)

            coverage = inv.PageCoverage(engine)
            coverage.start(page.context, page)

            await page.goto(fx.base_url + "/", wait_until="load")
            await page.wait_for_selector("html[data-fixture-ready='true']",
                                         state="attached")

            # Open the popup and work its form.
            async with page.context.expect_page() as popup_info:
                await page.click("#btn-popup")
            popup = await popup_info.value
            await popup.wait_for_load_state("load")
            # A real employee interacts after the page settles; the isolated
            # probe is re-armed for the popup once it loads. Wait for that
            # re-arm deterministically (its counter) rather than racing it, the
            # way a human's think-time would.
            await popup.wait_for_function(
                "() => (window.__scriptscrapRearmCount || 0) >= 1")
            await popup.fill("#p2-reference", "REF-POPUP-1")
            await popup.select_option("#p2-etat", "clos")
            # Give the per-popup scanner a cycle to inventory the form before we
            # navigate it away by submitting.
            await popup.wait_for_timeout(2600)
            await popup.click("#btn-page2-submit")
            await popup.wait_for_load_state("load")

            # End the session the way main() does: drains EVERY in-scope page.
            await coverage.stop()
            engine.outcome = "clean"

        engine.close_events()
        return EventLogReader(out / "events.jsonl")


@pytest.fixture(scope="module")
def log(tmp_path_factory) -> EventLogReader:
    return asyncio.run(_run(tmp_path_factory.mktemp("multipage")))


def _payloads(log, event_type):
    return list(log.of_type(event_type))


def test_the_popup_is_a_distinct_page(log):
    popups = _payloads(log, EventType.POPUP_OPENED)
    assert popups, "no popup_opened event"
    opened = _payloads(log, EventType.PAGE_OPENED)
    page_ids = {e.page_id for e in opened if e.page_id}
    assert len(page_ids) >= 2, f"popup should be its own page, saw {page_ids}"


def _popup_page_id(log):
    # The popup's id is the event's envelope page_id, not a payload field.
    for e in log.of_type(EventType.POPUP_OPENED):
        if e.page_id:
            return e.page_id
    return None


def test_actions_in_the_popup_are_captured_with_its_identity(log):
    popup_id = _popup_page_id(log)
    assert popup_id, "popup page id not recorded"
    inputs = [e for e in log.of_type(EventType.USER_INPUT) if e.page_id == popup_id]
    assert any((e.payload.get("element") or {}).get("id") == "p2-reference"
               for e in inputs), "the popup's field input was not captured"
    submits = [e for e in log.of_type(EventType.USER_SUBMIT) if e.page_id == popup_id]
    assert submits, "the popup's form submit was not captured on its page"


def test_the_popup_form_inventory_is_captured(log):
    forms = _payloads(log, EventType.DOM_FORMS)
    assert forms, "no DOM_FORMS at all"
    seen = any(
        "/page2" in (frame.get("frame_url") or "")
        and any(f.get("id") == "frm-page2" for f in frame.get("forms") or [])
        for event in forms
        for frame in event.payload.get("frames") or []
    )
    assert seen, "the popup's form was never inventoried by its scanner"


def test_the_popup_gets_a_storage_snapshot(log):
    popup_id = _popup_page_id(log)
    snaps = [e for e in log.of_type(EventType.STORAGE_SNAPSHOT) if e.page_id == popup_id]
    assert snaps, "the popup was never storage-snapshotted (drain-all on end)"


def test_the_popup_outcome_is_its_navigation(log):
    popup_id = _popup_page_id(log)
    navs = [e for e in log.of_type(EventType.NAVIGATION_COMMITTED)
            if e.page_id == popup_id and "/page2" in (e.payload.get("url") or "")]
    assert navs, "the popup's submit navigation (its outcome) was not captured"


def test_the_log_is_intact_across_two_pages(log):
    assert log.validate() == []
