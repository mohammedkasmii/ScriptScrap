#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["camoufox"]
# ///

"""Regression probe: does Camoufox silently filter the investigator's evidence?

WHAT THIS PROTECTS
------------------
Camoufox adds uBlock Origin to `addons` unconditionally in
`camoufox/utils.py:launch_options` unless `exclude_addons` is passed. An
investigator running with defaults therefore captures an ad-blocked view of the
target application and has no way to know it.

This probe compares a default launch against `exclude_addons=[DefaultAddons.UBO]`
and asserts that:

  1. the default launch demonstrably blocks at least one request, and
  2. excluding UBO unblocks it, and
  3. camoufox_investigator.py actually passes exclude_addons.

Assertion 1 failing is not a problem in itself -- it may mean filter lists
changed -- but assertion 3 failing means the containment fix has regressed.

Requires network access. Exits 2 if the network is unavailable.

Run:  uv run diagnostics/probes/addon_filter_probe.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from camoufox.addons import DefaultAddons
from camoufox.async_api import AsyncCamoufox

# Hosts commonly present on EasyList/uBO filter lists. We only need ONE of
# these to differ between the two launches to demonstrate filtering.
TARGETS = [
    "https://www.google-analytics.com/analytics.js",
    "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js",
    "https://www.googletagmanager.com/gtm.js?id=GTM-TEST",
]

BLANK_PAGE = "data:text/html,<html><body>probe</body></html>"

INVESTIGATOR = Path(__file__).resolve().parents[2] / "camoufox" / "camoufox_investigator.py"


async def run_launch(label: str, **launch_kwargs) -> dict:
    """Fetch each target from a page and report which ones completed."""
    observed: list[str] = []
    failed: list[str] = []
    results: dict[str, str] = {}

    async with AsyncCamoufox(
        headless=True, humanize=False, os="windows", geoip=False, **launch_kwargs
    ) as browser:
        page = await browser.new_page()
        page.on("request", lambda r: observed.append(r.url))
        page.on("requestfailed", lambda r: failed.append(r.url))
        await page.goto(BLANK_PAGE)

        for target in TARGETS:
            results[target] = await page.evaluate(
                """async (u) => {
                    try {
                        const r = await fetch(u, {mode: 'no-cors'});
                        return 'OK status=' + r.status + ' type=' + r.type;
                    } catch (e) {
                        return 'BLOCKED: ' + e.message;
                    }
                }""",
                target,
            )
        await asyncio.sleep(0.5)

    return {
        "label": label,
        "fetch_results": results,
        "blocked_count": sum(1 for v in results.values() if v.startswith("BLOCKED")),
        "requests_observed_by_playwright": len([u for u in observed if "google" in u]),
        "requestfailed_count": len(failed),
    }


def check_investigator_source() -> tuple[bool, str]:
    """Static check: the investigator must exclude the default addons."""
    if not INVESTIGATOR.exists():
        return False, f"not found: {INVESTIGATOR}"
    source = INVESTIGATOR.read_text(encoding="utf-8")
    if "exclude_addons" not in source:
        return False, "camoufox_investigator.py does not pass exclude_addons"
    if "DefaultAddons.UBO" not in source:
        return False, "camoufox_investigator.py does not exclude DefaultAddons.UBO"
    return True, "exclude_addons=[DefaultAddons.UBO] present"


async def main() -> int:
    print("=" * 72)
    print("ADDON FILTER PROBE  --  is uBlock Origin editing the evidence?")
    print("=" * 72)

    ok_src, msg_src = check_investigator_source()
    print(f"\n[static] camoufox_investigator.py : {'PASS' if ok_src else 'FAIL'}  ({msg_src})")

    try:
        default_run = await run_launch("DEFAULT (no exclude_addons)")
        excluded_run = await run_launch(
            "exclude_addons=[UBO]", exclude_addons=[DefaultAddons.UBO]
        )
    except Exception as exc:
        print(f"\n[runtime] COULD NOT RUN: {exc}")
        print("[runtime] This probe needs network access and a fetched Camoufox browser.")
        return 2

    print("\n" + json.dumps([default_run, excluded_run], indent=2))

    default_blocked = default_run["blocked_count"]
    excluded_blocked = excluded_run["blocked_count"]
    filtering_demonstrated = default_blocked > excluded_blocked

    print("\n" + "-" * 72)
    print(f"default launch blocked   : {default_blocked}/{len(TARGETS)}")
    print(f"exclude_addons blocked   : {excluded_blocked}/{len(TARGETS)}")

    if filtering_demonstrated:
        print("VERDICT: default Camoufox DOES filter requests. exclude_addons is required.")
    else:
        print("VERDICT: no filtering difference observed in this run.")
        print("         Filter lists change; this does NOT prove uBO is absent.")
        print("         The static check above is the binding assertion.")

    print("-" * 72)
    return 0 if ok_src else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
