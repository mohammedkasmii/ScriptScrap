#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["camoufox"]
# ///

"""Probe: JS world semantics and runtime-hook timing, over a real HTTP origin.

WHAT THIS PROTECTS
------------------
Three assumptions the investigator's runtime instrumentation depends on. A
Camoufox or Playwright upgrade could silently invalidate any of them.

  Q1  Does `page.add_init_script` reach the page's REAL window?
      Camoufox documents isolating all Playwright JS from the page, which would
      mean monkey-patches never take effect. Measured behaviour on the pinned
      stack contradicts the documentation -- so this must be measured, not read.
      If this ever fails, every in-page hook silently stops working.

  Q2  Does `page.evaluate` read the page's REAL window?
      If not, reading back `window.functionHookLogs` returns an isolated-world
      copy and always looks empty.

  Q3  Does the setInterval-based hook pattern catch a function that a classic
      script declares AND calls during initial parse?
      Known answer: NO. Recorded here so the limitation stays visible, and so a
      future stack change that fixes it is noticed.

Q3 also demonstrates that an `Object.defineProperty` accessor trap does not fix
it either: a function declaration binds via [[DefineOwnProperty]], which
REPLACES the accessor rather than invoking its setter.

Exit 0 = Q1/Q2 hold.  Exit 1 = world semantics changed, hooks are broken.

Run:  uv run diagnostics/probes/hook_timing_probe.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from camoufox.async_api import AsyncCamoufox

PAGE = """<!doctype html><html><head><title>pending</title></head><body>
<script>
window.__pageWorld = "PAGE_MARKER";
// Legacy-portal shape: declared AND called during initial parse.
function DevisCalculerMontantCharge(a, b) { return a * b; }
window.DevisCalculerMontantCharge = DevisCalculerMontantCharge;
window.__loadTimeCall = window.DevisCalculerMontantCharge(6, 7);

document.title = JSON.stringify({
  initMarkerVisibleToPage: (typeof window.__initWorld !== "undefined")
      ? window.__initWorld : "ABSENT",
  fetchPatchedFromPageView: (window.fetch && window.fetch.__patched === true)
      ? "PATCHED" : "NATIVE"
});
</script></body></html>"""

INIT = """
(() => {
    window.__initWorld = "INIT_MARKER";
    const of = window.fetch;
    const pf = function (...a) { return of.apply(this, a); };
    pf.__patched = true;
    window.fetch = pf;

    // Technique A -- what camoufox_investigator.py does today.
    window.__intervalHookLog = [];
    const t = setInterval(() => {
        const f = window.DevisCalculerMontantCharge;
        if (typeof f === "function" && !f.__hookedA) {
            const w = function (...a) {
                const r = f.apply(this, a);
                window.__intervalHookLog.push({ args: a, returned: r });
                return r;
            };
            w.__hookedA = true;
            window.DevisCalculerMontantCharge = w;
        }
    }, 2000);
    setTimeout(() => clearInterval(t), 20000);

    // Technique B -- accessor trap installed before any page script runs.
    window.__trapHookLog = [];
    let _v;
    Object.defineProperty(window, "DevisCalculerMontantCharge", {
        configurable: true,
        get() { return _v; },
        set(fn) {
            if (typeof fn === "function" && !fn.__hookedB) {
                const w = function (...a) {
                    const r = fn.apply(this, a);
                    window.__trapHookLog.push({ args: a, returned: r });
                    return r;
                };
                w.__hookedB = true;
                _v = w;
            } else {
                _v = fn;
            }
        }
    });
})();
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802  (http.server API)
        body = PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args, **kwargs):
        pass


async def main() -> int:
    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}/"

    out: dict = {}
    try:
        async with AsyncCamoufox(headless=True, humanize=False, os="windows", geoip=False) as browser:
            page = await browser.new_page()
            await page.add_init_script(INIT)
            await page.goto(url, wait_until="load")
            await asyncio.sleep(3.0)  # let the 2s interval fire at least once

            out["page_main_world_report"] = json.loads(await page.title())
            out["evaluate_sees_page_marker"] = await page.evaluate(
                "typeof window.__pageWorld!=='undefined'?window.__pageWorld:'ABSENT'")
            out["load_time_call_result"] = await page.evaluate(
                "typeof window.__loadTimeCall!=='undefined'?window.__loadTimeCall:'ABSENT'")
            out["A_interval_hook_captured_at_load"] = await page.evaluate(
                "(window.__intervalHookLog||[]).length")
            out["B_trap_hook_captured_at_load"] = await page.evaluate(
                "(window.__trapHookLog||[]).length")

            await page.evaluate("window.DevisCalculerMontantCharge(3,4)")
            out["A_interval_hook_after_late_call"] = await page.evaluate(
                "(window.__intervalHookLog||[]).length")
            out["B_trap_hook_after_late_call"] = await page.evaluate(
                "(window.__trapHookLog||[]).length")
    finally:
        server.shutdown()

    print("=" * 72)
    print("HOOK TIMING / JS WORLD PROBE  (http origin)")
    print("=" * 72)
    print(json.dumps(out, indent=2))

    report = out["page_main_world_report"]
    q1 = report["initMarkerVisibleToPage"] == "INIT_MARKER"
    q1b = report["fetchPatchedFromPageView"] == "PATCHED"
    q2 = out["evaluate_sees_page_marker"] == "PAGE_MARKER"

    print("\n" + "-" * 72)
    print(f"Q1  add_init_script reaches page main world .... {'PASS' if q1 else 'FAIL'}")
    print(f"Q1b page sees patched window.fetch ............ {'PASS' if q1b else 'FAIL'}")
    print(f"Q2  page.evaluate reads page main world ....... {'PASS' if q2 else 'FAIL'}")

    interval_missed = out["A_interval_hook_captured_at_load"] == 0
    interval_late_ok = out["A_interval_hook_after_late_call"] > 0
    trap_missed = out["B_trap_hook_captured_at_load"] == 0

    print(f"\nQ3  setInterval hook misses parse-time call ... "
          f"{'as expected (still broken)' if interval_missed else 'CHANGED -- now captured!'}")
    print(f"Q3  setInterval hook catches later call ....... "
          f"{'yes' if interval_late_ok else 'no'}")
    print(f"Q3  defineProperty trap misses parse-time call  "
          f"{'as expected' if trap_missed else 'CHANGED -- now captured!'}")

    if not (q1 and q1b and q2):
        print("\nVERDICT: FAIL -- JS world semantics changed on this stack.")
        print("         In-page hooks and DOM-mutation capture are now UNRELIABLE.")
        print("         Investigate camoufox main_world_eval / 'mw:' before trusting output.")
        print("-" * 72)
        return 1

    print("\nVERDICT: PASS -- world semantics unchanged; in-page patching works.")
    if not interval_missed:
        print("         NOTE: parse-time hook capture now works. Re-read the blueprint's")
        print("         section 16 -- a stated limitation no longer holds.")
    print("-" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
