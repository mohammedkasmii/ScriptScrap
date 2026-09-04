"""Scripted forensic capture against the fixture.

Same investigator, same wiring, plus the extension. Deliberately a separate
entry point from `capture.py` so the normal-mode golden master keeps describing
normal mode, and so a test can assert that the extension is genuinely optional
by running the same fixture without it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import ModuleType

from ..config import ForensicConfig
from .capture import FIXED_SESSION_ID, load_investigator


async def run_forensic_investigation(
    output_dir: Path,
    *,
    headless: bool = True,
    forensic: ForensicConfig | None = None,
) -> tuple[ModuleType, object]:
    """Drive the fixture with the forensic layer enabled.

    Returns (investigator module, engine) so a test can read sensor stats.
    """
    from camoufox.addons import DefaultAddons
    from camoufox.async_api import AsyncCamoufox

    from ..fixture import FixtureServer

    inv = load_investigator(output_dir)
    config = forensic or ForensicConfig(
        enabled=True,
        # Small on purpose: the fixture's /api/big must cross it so the
        # size-limit path is exercised rather than assumed.
        max_body_bytes=64 * 1024,
        max_blob_bytes=64 * 1024,
    )

    with FixtureServer() as fixture:
        base = fixture.base_url
        scope = inv.InvestigationScope(base)
        engine = inv.WebHarvester(base, scope, session_id=FIXED_SESSION_ID)

        launch_options = {
            "headless": headless,
            "humanize": False,
            "os": "windows",
            "geoip": False,
            "enable_cache": False,
            "exclude_addons": [DefaultAddons.UBO],
        }
        # Must run BEFORE launch: the extension is built with the transport
        # port baked in, and a background script takes no arguments.
        launch_options.update(inv.start_forensic_layer(engine, config))
        engine.record_launch_options(launch_options)

        try:
            async with AsyncCamoufox(**launch_options) as browser:
                page = await browser.new_page()
                await inv.attach_engine_to_page(page, engine)

                if engine.extension_transport is not None:
                    engine.extension_transport.wait_for_connection(timeout=15)

                await page.goto(base + "/", wait_until="load")
                await page.wait_for_function("window.__fixtureReady === true")

                # Early-script case: source is observable even though the call
                # already happened during parse.
                await page.add_script_tag(url="/api/early.js")
                await page.wait_for_function(
                    "typeof window.__fixtureEarlyResult !== 'undefined'")

                # Bodies: normal, oversized, and a duplicate pair.
                await page.evaluate("""async () => {
                    await fetch('/api/items/101');
                    await fetch('/api/twin-a');
                    await fetch('/api/twin-b');
                    await fetch('/api/big');
                    await fetch('/api/setcookie');
                    await fetch('/api/delcookie');
                }""")
                await page.wait_for_timeout(1500)
                await engine.scan_all_frames(page)
                await engine.capture_visual_state(page)

                await engine.extract_active_introspection(page)
        finally:
            inv.stop_forensic_layer(engine)

        engine.export()
        return inv, engine


def capture_forensic(output_dir: Path, **kwargs):
    return asyncio.run(run_forensic_investigation(output_dir, **kwargs))
