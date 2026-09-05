#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["camoufox"]
# ///

"""Probe: the split-world runtime architecture, on a `file://` origin.

WHAT THIS PROTECTS
------------------
Firefox runs injected scripts in an ISOLATED JavaScript world: the document is
shared with the page, `window` is not. ScriptScrap's runtime probe is built
around that fact -- listeners and the reporting binding in the isolated world,
monkey-patched instruments in the page's own world, joined by a CustomEvent on
the shared document.

This probe verifies the five contracts that architecture depends on. It mirrors
the mechanism rather than importing it, so it keeps working in a bare venv that
has camoufox but not scriptscrap, and so it measures the BROWSER's behaviour
rather than re-testing our code against itself. The bridge event name is shared
with the real probe and asserted equal by `tests/test_diagnostics.py`.

  A  Worlds are isolated.
     The driver's globals are invisible to the page and the page's globals are
     invisible to the driver. This used to be recorded as a FAILURE, because
     the architecture assumed a shared world. It is now the premise.

  B  Page-world execution works.
     `evaluate("mw:" + script)` reaches the page's real window, so patch logic
     can be installed where the application will actually hit it.

  C  The application sees the patch.
     A patch installed that way replaces the global that page-authored code
     calls -- not a copy of it.

  D  Observations cross back.
     A record dispatched from the page world over the DOM CustomEvent bridge is
     received by an isolated-world listener AND reaches Python through the
     exposed binding. This is the whole transport chain, end to end.

  E  Exactly once.
     One application call produces one observation. The two roles install
     disjoint instruments and each install is idempotent, so a re-install on
     every navigation must not double-count.

Exit 0 = the split-world architecture holds.  Exit 1 = it does not, and the
runtime probe's network evidence cannot be trusted on this browser.

Run:  uv run diagnostics/probes/js_world_probe.py
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import pathlib
import sys

from camoufox.async_api import AsyncCamoufox

HERE = pathlib.Path(__file__).parent
PAGE_URL = (HERE / "probe_page.html").resolve().as_uri()

# Shared with src/scriptscrap/probe/probe.js. If these drift, the probe stops
# testing the thing that ships.
BRIDGE_EVENT = "__scriptscrapBridge"
BINDING_NAME = "__scriptscrapEmit"

# --- isolated world: listeners + transport, via add_init_script -------------
ISOLATED = """
(() => {
    if (window.__probeIsolatedInstalled) return;
    window.__probeIsolatedInstalled = true;
    window.__initWorld = "INIT_MARKER";

    // A patch installed HERE is the mistake this architecture exists to avoid:
    // it replaces a global no application ever calls. Installed anyway, marked
    // distinctly, so contract C can prove which of the two the page sees.
    const nativeFetch = window.fetch;
    const wrapped = function (...args) { return nativeFetch.apply(this, args); };
    wrapped.__patchedByInit = true;
    window.fetch = wrapped;

    window.__bridgeReceived = [];
    document.addEventListener("__scriptscrapBridge", (ev) => {
        let record;
        try { record = JSON.parse(ev.detail); }
        catch (err) { record = { parseError: String(err) }; }
        window.__bridgeReceived.push(record);
        // Straight on to Python, exactly as the real transport does.
        const binding = window.__scriptscrapEmit;
        if (typeof binding === "function") {
            try { binding(JSON.stringify([record])); } catch (e) { /* ignore */ }
        }
    }, true);
})();
"""

# --- page world: the patched instrument, via evaluate("mw:" + ...) ----------
PAGE_WORLD = """
(() => {
    if (window.__probeMainInstalled) return "ALREADY";
    window.__probeMainInstalled = true;

    const send = (record) => {
        document.dispatchEvent(new CustomEvent("__scriptscrapBridge", {
            detail: JSON.stringify(record),
        }));
    };

    const nativeFetch = window.fetch;
    const wrapped = function (...args) {
        send({ type: "runtime_fetch", world: "main", url: String(args[0]) });
        return nativeFetch.apply(this, args);
    };
    wrapped.__probePatched = true;
    window.fetch = wrapped;
    return "INSTALLED";
})()
"""


async def main() -> int:
    if not (HERE / "probe_page.html").exists():
        print(f"FAIL: probe_page.html missing next to {__file__}")
        return 2

    delivered_to_python: list[dict] = []
    results: dict = {}

    def on_batch(_source, raw: str) -> bool:
        # A malformed batch is a finding for the checks below, not a crash in
        # the binding -- which would surface inside the page.
        with contextlib.suppress(TypeError, ValueError):
            delivered_to_python.extend(json.loads(raw))
        return True

    async with AsyncCamoufox(
        headless=True, humanize=False, os="windows", geoip=False,
        # Load-bearing: without it the "mw:" prefix is refused and the patched
        # half of the runtime probe has nowhere to live.
        main_world_eval=True,
    ) as browser:
        page = await browser.new_page()
        await page.context.expose_binding(BINDING_NAME, on_batch)
        await page.context.add_init_script(ISOLATED)
        await page.goto(PAGE_URL, wait_until="load")

        # --- A: isolation ---------------------------------------------------
        # Written into the DOM by the page itself, so it is world-neutral.
        results["page_report"] = json.loads(await page.title())
        results["isolated_sees_page_global"] = await page.evaluate(
            "typeof window.__pageWorld !== 'undefined' ? window.__pageWorld : 'ABSENT'")
        results["page_world_sees_page_global"] = await page.evaluate(
            "mw:typeof window.__pageWorld !== 'undefined' ? window.__pageWorld : 'ABSENT'")

        # --- B: page-world execution ---------------------------------------
        results["install"] = await page.evaluate("mw:" + PAGE_WORLD)
        # Re-installed on every navigation in the real thing, so idempotency is
        # part of the contract, not an implementation detail.
        results["reinstall"] = await page.evaluate("mw:" + PAGE_WORLD)

        # --- C + D + E: the application calls, once -------------------------
        results["application_view_of_fetch"] = await page.evaluate(
            "mw:window.callApplicationFetch()")
        await asyncio.sleep(0.5)

        results["isolated_received"] = await page.evaluate(
            "(window.__bridgeReceived || []).length")
        results["isolated_received_records"] = await page.evaluate(
            "window.__bridgeReceived || []")

    results["delivered_to_python"] = delivered_to_python

    print("=" * 72)
    print("JS WORLD / SPLIT-WORLD RUNTIME PROBE  (file:// origin)")
    print("=" * 72)
    print(json.dumps(results, indent=2))

    report = results["page_report"]
    fetch_records = [r for r in delivered_to_python if r.get("type") == "runtime_fetch"]

    checks = {
        "JS worlds are isolated as expected": (
            report["initMarkerVisibleToPage"] == "ABSENT"
            and report["fetchIsPatchedFromPageView"] == "NATIVE"
            and results["isolated_sees_page_global"] == "ABSENT"
        ),
        "page-world execution can patch application fetch": (
            results["install"] == "INSTALLED"
            and results["reinstall"] == "ALREADY"
            and results["page_world_sees_page_global"] == "PAGE_MARKER"
        ),
        "application observes patched fetch": (
            results["application_view_of_fetch"] == "PATCHED"
        ),
        "page->isolated bridge delivered event": (
            results["isolated_received"] >= 1 and len(fetch_records) >= 1
        ),
        "event observed exactly once": (
            len(fetch_records) == 1
            and results["isolated_received"] == 1
        ),
    }

    print("\n" + "-" * 72)
    for label, ok in checks.items():
        print(f"{'PASS' if ok else 'FAIL'}  {label}")

    if not all(checks.values()):
        print("\nVERDICT: FAIL -- the split-world runtime architecture does not hold")
        print("         on this browser. Runtime network evidence (fetch, XHR,")
        print("         beacons, pushState) would be missing or double-counted.")
        print("         Re-read src/scriptscrap/probe/probe.js before capturing.")
        print("-" * 72)
        return 1

    print("\nVERDICT: PASS -- split-world runtime architecture verified.")
    print("-" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
