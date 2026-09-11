"""Hover menus, drag/drop, dialogs, and virtualized-table scrolling.

The agency workflow needs these observed, each within the prime directive:
listeners are passive, bounded and deduplicated, and a JavaScript dialog -- which
the automation layer intercepts, so the employee's real choice is unobservable
-- is recorded as the recorder's own handling plus an explicit capture gap,
never as a choice the operator made.
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

            await page.goto(fx.base_url + "/interactions", wait_until="load")
            await page.wait_for_selector("html[data-fixture-interactions-ready='true']",
                                         state="attached")

            # Hover-opened menu.
            await page.hover("#menu-trigger")
            await page.wait_for_timeout(150)

            # A JavaScript dialog: the click triggers confirm(), which the
            # recorder observes and dismisses.
            await page.click("#btn-confirm")
            await page.wait_for_timeout(150)

            # Drag and drop. Playwright cannot drive native HTML5 DnD on Firefox
            # (drag_and_drop uses synthetic mouse events that do not fire native
            # dragstart/drop), so the fixture button fires the real DragEvent
            # sequence a browser produces during a drag -- the same listener path
            # a real employee's drag exercises.
            await page.click("#sim-drag")
            await page.wait_for_timeout(600)

            # Scroll the virtualized table so new rows are rendered and
            # harvested. Several steps reveal different windows of rows.
            for top in (300, 700, 1100):
                await page.eval_on_selector("#virt-wrap", f"el => el.scrollTo(0, {top})")
                await page.wait_for_timeout(400)   # past the 300ms scroll debounce

            await coverage.stop()
            engine.outcome = "clean"

        engine.close_events()
        return EventLogReader(out / "events.jsonl")


@pytest.fixture(scope="module")
def log(tmp_path_factory) -> EventLogReader:
    return asyncio.run(_run(tmp_path_factory.mktemp("rich")))


def _payloads(log, event_type):
    return [e.payload for e in log.of_type(event_type)]


def test_the_log_is_intact(log):
    assert log.validate() == []


def test_hover_over_a_menu_trigger_is_recorded(log):
    hovers = _payloads(log, EventType.USER_HOVER)
    assert hovers, "no user_hover events"
    assert any((h.get("element") or {}).get("id") == "menu-trigger" for h in hovers)


def test_hover_is_deduplicated(log):
    """A menu trigger hovered repeatedly is not logged on every pointer move."""
    hovers = [h for h in _payloads(log, EventType.USER_HOVER)
              if (h.get("element") or {}).get("id") == "menu-trigger"]
    assert 1 <= len(hovers) <= 3, f"hover not bounded/deduplicated: {len(hovers)}"


def test_a_javascript_dialog_is_observed_and_honestly_handled(log):
    dialogs = _payloads(log, EventType.DIALOG)
    assert dialogs, "no dialog event"
    d = dialogs[0]
    assert d["dialog_type"] in ("confirm", "beforeunload", "alert", "prompt")
    assert "archivage" in (d.get("message") or "")
    assert d["handling"] == "dismissed"
    assert d["handled_by"] == "recorder"
    # The honest gap: the employee's real choice cannot be observed.
    reasons = {g.payload["reason"] for g in log.of_type(EventType.CAPTURE_GAP)}
    assert "dialog_choice_unobservable" in reasons


def test_drag_and_drop_records_source_and_destination(log):
    drags = _payloads(log, EventType.USER_DRAG)
    assert drags, "no user_drag events"
    starts = [d for d in drags if d.get("phase") == "start"]
    drops = [d for d in drags if d.get("phase") == "drop"]
    assert starts and (starts[0].get("drag_source") or {}).get("id") == "drag-src"
    assert drops, "no drop observed"
    assert (drops[0].get("drag_destination") or {}).get("id") == "drop-target"


def test_scrolling_a_virtualized_table_harvests_new_rows(log):
    scrolls = _payloads(log, EventType.USER_SCROLL)
    assert scrolls, "no user_scroll events"
    assert any(s.get("table", {}).get("visible_rows") for s in scrolls)


def test_rich_interactions_record_provenance(log):
    """isTrusted is on every hover/drag/scroll, and a synthetic drag is honestly
    NOT marked as a trusted employee action.

    Note the asymmetry: a synthetic DragEvent dispatched by script has
    isTrusted === false, so a drag that was not a real human drag is flagged.
    A scroll event, however, is dispatched by the browser with isTrusted ===
    true even when the scroll position was set programmatically -- the flag
    cannot distinguish a programmatic scroll there -- so it is recorded but not
    asserted false. The table catalog never says "the employee scrolled"; it
    records rows observed_via scroll, which is a fact regardless of the driver.
    """
    for etype in (EventType.USER_HOVER, EventType.USER_DRAG, EventType.USER_SCROLL):
        for p in _payloads(log, etype):
            assert "trusted" in p, f"{etype} lost its isTrusted provenance"
    # The fixture button dispatches synthetic DragEvents -- not a real drag.
    assert all(p.get("trusted") is False for p in _payloads(log, EventType.USER_DRAG)), \
        "a synthetic drag was recorded as a trusted employee action"


def test_the_table_catalog_accumulates_virtualized_rows(log):
    from scriptscrap.analysis import analyze_events

    result = analyze_events(list(log), "s")
    table = next((t for t in result.tables if t.table_id == "virt-table"), None)
    assert table is not None, [t.table_id for t in result.tables]
    # More rows than fit in one window of ~12, gathered across scrolls, and
    # deduplicated by their stable data-id.
    assert len(table.rows) > 12, f"only {len(table.rows)} rows harvested"
    ids = [r["row_id"] for r in table.rows if r.get("row_id")]
    assert len(ids) == len(set(ids)), "virtualized rows were not deduplicated"
    assert any(r.get("observed_via") == "scroll" for r in table.rows)
