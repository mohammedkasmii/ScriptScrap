"""The 2-second background scanner, covered separately from the golden master.

The scanner drives periodic capture in a real interactive session, but its
cadence is wall-clock dependent, so including it in the golden master would
produce a baseline that changes with machine speed. Excluding it entirely would
leave production code untested, so it gets its own test with timing-tolerant
assertions.

Its replacement by semantic triggers is M2 work.
"""

from __future__ import annotations

import asyncio

import pytest

from scriptscrap.events import EventLogReader, EventType

pytestmark = pytest.mark.browser


async def _run(tmp_path) -> tuple[int, EventLogReader]:
    from camoufox.addons import DefaultAddons
    from camoufox.async_api import AsyncCamoufox

    from scriptscrap.fixture import FixtureServer
    from scriptscrap.testing.capture import load_investigator

    out = tmp_path / "output"
    inv = load_investigator(out)

    with FixtureServer() as fixture:
        scope = inv.InvestigationScope(fixture.base_url)
        engine = inv.WebHarvester(fixture.base_url, scope,
                                  session_id="sess-20260101-000000", output_dir=out)
        engine.record_launch_options({"headless": True})

        async with AsyncCamoufox(
            headless=True, humanize=False, os="windows", geoip=False,
            exclude_addons=[DefaultAddons.UBO],
            # attach_engine_to_page installs the probe's patched half through a
            # main-world evaluate. Without this the browser refuses it and the
            # sensor correctly reports a blind spot.
            main_world_eval=True,
        ) as browser:
            page = await browser.new_page()
            await inv.attach_engine_to_page(page, engine)
            await page.goto(fixture.base_url + "/", wait_until="load")

            task = asyncio.create_task(inv.background_dom_scanner(page, engine))
            try:
                # The scanner polls every 2s and only acts when the page content
                # hash changes, so force a change and allow two poll windows.
                await asyncio.sleep(2.5)
                await page.click("#btn-ajouter")
                await page.wait_for_selector("#champ-dynamique", state="attached")
                await asyncio.sleep(2.5)
            finally:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task

        engine.close_events()
        return engine.step_counter - 1, EventLogReader(out / "events.jsonl")


@pytest.fixture(scope="module")
def scanner_run(tmp_path_factory):
    return asyncio.run(_run(tmp_path_factory.mktemp("scanner")))


def test_scanner_captures_without_being_asked(scanner_run):
    snapshots, _ = scanner_run
    assert snapshots >= 1, "scanner produced no visual capture at all"


def test_scanner_reacts_to_a_dom_change(scanner_run):
    """It takes an initial snapshot, then another once the content hash moves."""
    snapshots, _ = scanner_run
    assert snapshots >= 2, (
        f"scanner captured {snapshots} snapshot(s); expected an initial one plus "
        "at least one triggered by the DOM change"
    )


def test_scanner_emits_events_and_no_sensor_errors(scanner_run):
    _, reader = scanner_run
    assert reader.of_type(EventType.SCREENSHOT), "no screenshot events emitted"
    assert reader.of_type(EventType.DOM_SNAPSHOT), "no DOM snapshot events emitted"
    errors = reader.of_type(EventType.SENSOR_ERROR)
    assert errors == [], f"scanner reported sensor errors: {[e.payload for e in errors]}"


def test_scanner_cancellation_does_not_surface_as_a_sensor_error(scanner_run):
    """Cancellation is a normal shutdown, not a failure to observe."""
    _, reader = scanner_run
    where = {e.payload.get("where") for e in reader.of_type(EventType.SENSOR_ERROR)}
    assert "background_dom_scanner" not in where
