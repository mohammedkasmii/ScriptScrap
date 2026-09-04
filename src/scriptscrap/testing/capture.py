"""Drive the real investigator through a deterministic workflow.

This runs the **post-M0 investigator**, unmodified, against the fixture app. It
does not reimplement any of it: it imports `camoufox_investigator`, builds the
same `WebHarvester`, and calls `attach_engine_to_page` -- the same wiring the
interactive entry point uses -- so the baseline describes what the tool actually
does rather than what a test harness does.

Two deliberate differences from an interactive session, both documented in the
golden master's README section:

* No `input()` prompts. Scope is constructed directly.
* The 2-second `background_dom_scanner` is NOT started. Its cadence is
  wall-clock dependent, so including it would make the baseline flaky and train
  people to re-bless it without reading the diff. Snapshots are instead taken at
  fixed points in the workflow, exercising the same `capture_visual_state` and
  `scan_all_frames` code paths. The scanner is covered by its own separate,
  non-golden test.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[3]
INVESTIGATOR_PATH = REPO_ROOT / "camoufox" / "camoufox_investigator.py"

# Fixed so the baseline never contains a clock reading from the run that made it.
FIXED_SESSION_ID = "sess-20260101-000000"


def load_investigator(output_dir: Path) -> ModuleType:
    """Import the investigator and point its output at `output_dir`.

    OUTPUT_DIR is a module-level constant read by `WebHarvester.__init__`, so it
    must be rebound before an engine is constructed.
    """
    spec = importlib.util.spec_from_file_location("camoufox_investigator", INVESTIGATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import investigator from {INVESTIGATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["camoufox_investigator"] = module
    spec.loader.exec_module(module)
    module.OUTPUT_DIR = output_dir
    return module


async def run_scripted_investigation(
    output_dir: Path,
    *,
    headless: bool = True,
    stop_after_step: int | None = None,
) -> ModuleType:
    """Investigate the fixture through a fixed workflow.

    `stop_after_step` raises deliberately after N workflow steps WITHOUT calling
    `export()`, simulating a crash. Used by the crash-resilience test to prove
    that events already emitted survive an interrupted session.
    """
    from camoufox.addons import DefaultAddons
    from camoufox.async_api import AsyncCamoufox

    from scriptscrap.fixture import FixtureServer

    inv = load_investigator(output_dir)

    with FixtureServer() as fixture:
        base = fixture.base_url
        scope = inv.InvestigationScope(base)
        engine = inv.WebHarvester(base, scope, session_id=FIXED_SESSION_ID)

        launch_options = {
            "headless": headless,
            "humanize": False,      # cursor-only; pure timing noise in a scripted run
            "os": "windows",
            "geoip": False,
            "enable_cache": False,  # a cached response produces no network evidence
            "exclude_addons": [DefaultAddons.UBO],
        }
        engine.record_launch_options(launch_options)

        step = 0

        def checkpoint() -> None:
            nonlocal step
            step += 1
            if stop_after_step is not None and step >= stop_after_step:
                raise _SimulatedCrash(f"simulated crash after workflow step {step}")

        async with AsyncCamoufox(**launch_options) as browser:
            page = await browser.new_page(locale="fr-FR", timezone_id="Europe/Paris")
            await inv.attach_engine_to_page(page, engine)

            # -- 1. initial load ------------------------------------------
            await page.goto(base + "/", wait_until="load")
            # state="attached": an <option> inside a closed <select> is never
            # "visible", which is Playwright's default wait condition.
            await page.wait_for_selector("#garage option", state="attached")
            await engine.scan_all_frames(page)
            await engine.capture_visual_state(page)
            checkpoint()

            # -- 2. operator fills the form -------------------------------
            await page.fill("#nom", "Alice Benali")
            await page.fill("#notes", "Dossier 44718 - vitre laterale")
            await page.check("#accord")
            await page.check("#type-choc")
            await page.select_option("#ville", "mar")
            await page.select_option("#garage", "GAR-0011")
            # Unmistakably synthetic: these values exist so redaction and
            # credential-classification have something to trip on, and so a
            # reader of the committed golden data cannot mistake them for real.
            await page.fill("#courriel", "fixture@example.test")
            await page.fill("#pw", "FIXTURE_PASSWORD_DO_NOT_USE")
            checkpoint()

            # -- 3. load dossier: the correlation SOURCE ------------------
            await page.click("#btn-charger")
            await page.wait_for_function(
                "document.querySelector('#mission') && "
                "document.querySelector('#mission').value.length > 0"
            )
            await engine.scan_all_frames(page)
            checkpoint()

            # -- 4. validate: the correlation CONSUMER --------------------
            #     missionId observed in the /api/dossier response is re-sent here.
            await page.click("#btn-valider")
            await page.wait_for_function(
                "document.querySelector('#resultat').textContent.includes('REF-FIXTURE-9001')"
            )
            checkpoint()

            # -- 5. urlencoded POST ---------------------------------------
            await page.click("#btn-form")
            await page.wait_for_timeout(250)
            checkpoint()

            # -- 6. redirect and error paths ------------------------------
            await page.click("#btn-redirect")
            await page.wait_for_timeout(250)
            await page.click("#btn-erreur")
            await page.wait_for_timeout(250)
            checkpoint()

            # -- 7. dynamic DOM change + calculation ----------------------
            await page.click("#btn-ajouter")
            await page.wait_for_selector("#champ-dynamique", state="attached")
            await page.click("#btn-calculer")
            await page.wait_for_timeout(150)
            await engine.scan_all_frames(page)
            await engine.capture_visual_state(page)
            checkpoint()

            # -- 7b. M3 inference cases -----------------------------------
            #     Sibling item paths (templating), a unique reference that
            #     propagates into /api/apply (dependency), common values that
            #     must NOT correlate, three SPA states, and a control whose id
            #     regenerates on every render (selector instability).
            # A named GraphQL mutation, so operation identity and technology
            # detection have real evidence in the baseline log.
            await page.click("#btn-graphql")
            await page.wait_for_function(
                "document.querySelector('#resultat').textContent.startsWith('graphql:')")

            # Twice: three items over two statuses is below the enum threshold,
            # and the right answer is to give the inference more evidence rather
            # than to lower the bar it has to clear.
            for _ in range(2):
                await page.click("#btn-items")
                await page.wait_for_function(
                    "document.querySelector('#items-log').textContent"
                    ".split('ITEMREF-CC0103').length > 1")
                await page.wait_for_timeout(150)
            await page.click("#btn-appliquer")
            await page.wait_for_function(
                "document.querySelector('#resultat').textContent.startsWith('applique:')")

            for state_button in ("#btn-etat-liste", "#btn-etat-detail", "#btn-etat-resume"):
                await page.click(state_button)
                await page.wait_for_timeout(120)

            for _ in range(3):
                await page.click("#zone-instable button")
                await page.wait_for_timeout(80)
            checkpoint()

            # -- 8. full navigation ---------------------------------------
            #     Wipes the in-page hook/mutation buffers. That data loss is a
            #     known limitation; the baseline records its consequence.
            await page.click("#btn-submit")
            await page.wait_for_load_state("load")
            await engine.scan_all_frames(page)
            await engine.capture_visual_state(page)
            checkpoint()

            # -- 9. final in-page introspection ---------------------------
            await engine.extract_active_introspection(page)

        engine.export()
        return inv


class _SimulatedCrash(RuntimeError):
    """Raised by `stop_after_step` to interrupt a run without exporting."""


SimulatedCrash = _SimulatedCrash


def capture(output_dir: Path, **kwargs) -> ModuleType:
    """Synchronous entry point."""
    return asyncio.run(run_scripted_investigation(output_dir, **kwargs))
