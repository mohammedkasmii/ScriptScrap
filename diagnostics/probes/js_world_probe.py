#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["camoufox"]
# ///

"""Probe: JS world semantics on a `file://` origin.

WHAT THIS PROTECTS
------------------
The same world assumptions as `hook_timing_probe.py`, but on a file:// origin
rather than http://. Isolated-world behaviour can in principle differ by origin
type, so both are kept: if these two ever disagree, the difference is itself the
finding.

Checks that `page.add_init_script` and `page.evaluate` both reach the page's
real `window`, and that a `window.fetch` patch installed from an init script is
visible to page scripts.

Exit 0 = assumptions hold.  Exit 1 = world semantics changed.

Run:  uv run diagnostics/probes/js_world_probe.py
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import sys

from camoufox.async_api import AsyncCamoufox

HERE = pathlib.Path(__file__).parent
PAGE_URL = (HERE / "probe_page.html").resolve().as_uri()

INIT = """
(() => {
    window.__initWorld = "INIT_MARKER";
    const of = window.fetch;
    const pf = function (...a) { return of.apply(this, a); };
    pf.__patchedByInit = true;
    window.fetch = pf;

    // Mirrors the MCMA hook loop in camoufox_investigator.py.
    window.__hookLog = [];
    const t = setInterval(() => {
        if (typeof window.pageFn === "function" && !window.pageFn.__hooked) {
            const orig = window.pageFn;
            const w = function (...a) {
                const r = orig.apply(this, a);
                window.__hookLog.push({ args: a, returned: r });
                return r;
            };
            w.__hooked = true;
            window.pageFn = w;
        }
    }, 50);
    setTimeout(() => clearInterval(t), 5000);
})();
"""


async def main() -> int:
    if not (HERE / "probe_page.html").exists():
        print(f"FAIL: probe_page.html missing next to {__file__}")
        return 2

    results: dict = {}
    async with AsyncCamoufox(headless=True, humanize=False, os="windows", geoip=False) as browser:
        page = await browser.new_page()
        await page.add_init_script(INIT)
        await page.goto(PAGE_URL, wait_until="load")
        await asyncio.sleep(1.0)

        # Written into the DOM by the page itself, so it is world-neutral.
        results["page_main_world_report"] = json.loads(await page.title())
        results["evaluate_sees_init_marker"] = await page.evaluate(
            "typeof window.__initWorld !== 'undefined' ? window.__initWorld : 'ABSENT'")
        results["evaluate_sees_page_marker"] = await page.evaluate(
            "typeof window.__pageWorld !== 'undefined' ? window.__pageWorld : 'ABSENT'")
        results["evaluate_hooklog_len"] = await page.evaluate("(window.__hookLog || []).length")
        results["evaluate_pageFn_result"] = await page.evaluate(
            "typeof window.__pageFnResult !== 'undefined' ? window.__pageFnResult : 'ABSENT'")

    print("=" * 72)
    print("JS WORLD PROBE  (file:// origin)")
    print("=" * 72)
    print(json.dumps(results, indent=2))

    report = results["page_main_world_report"]
    checks = {
        "add_init_script reaches page main world":
            report["initMarkerVisibleToPage"] == "INIT_MARKER",
        "page sees patched window.fetch":
            report["fetchIsPatchedFromPageView"] == "PATCHED",
        "page.evaluate sees init-script globals":
            results["evaluate_sees_init_marker"] == "INIT_MARKER",
        "page.evaluate sees page globals":
            results["evaluate_sees_page_marker"] == "PAGE_MARKER",
    }

    print("\n" + "-" * 72)
    for label, ok in checks.items():
        print(f"{'PASS' if ok else 'FAIL'}  {label}")

    if not all(checks.values()):
        print("\nVERDICT: FAIL -- JS world semantics changed on a file:// origin.")
        print("-" * 72)
        return 1

    print("\nVERDICT: PASS -- world semantics unchanged on file:// origin.")
    print("-" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
