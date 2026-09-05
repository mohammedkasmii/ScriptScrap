#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["camoufox"]
# ///

"""Probe: runtime hook TIMING, over a real HTTP origin.

WHAT THIS PROTECTS
------------------
`js_world_probe.py` establishes that ScriptScrap can patch the page's own
globals. This probe measures the separate question of WHEN it can do so, and
therefore what it can and cannot see.

A page-world patch is installed after a navigation commits. Anything a classic
script declares and calls during its own initial parse has already run by then.
That is a permanent property of the mechanism, not a bug to be fixed, and it is
asserted here so that it stays visible -- and so that a stack change which ever
removes it is noticed rather than assumed.

  Q1  LATE functions: a function called after load is observed.
      This is the ordinary case and must work.

  Q2  PARSE-TIME functions: a function declared and called in the same parse is
      NOT observed by a runtime wrapper.
      Known answer: NOT OBSERVED. Two independent techniques are measured, so
      the finding is about the timing rather than about one implementation:
        A  interval polling  -- installs a wrapper once the global appears
        B  accessor trap     -- `Object.defineProperty` set() installed first
      B fails twice over, and both reasons are worth recording:
        * in the isolated world it installs fine and never fires, because the
          page's declaration writes to a different `window`;
        * in the PAGE world it cannot be installed at all after the fact -- a
          top-level function declaration creates a NON-CONFIGURABLE property
          on the global object, so `defineProperty` is refused outright. And it
          cannot be installed before the fact, because page-world execution is
          only available once a navigation has committed.
      Together those close the technique: there is no placement of an accessor
      trap that both reaches the page's window and precedes the declaration.

  Q3  SOURCE observation (M4, optional forensic layer): the early function can
      still be identified by reading the script's SOURCE before Firefox parses
      it. That establishes the function exists and is called during its own
      parse. It does NOT mean the call was dynamically hooked, and this probe
      is careful not to claim it was. ScriptScrap deliberately does not
      implement source rewriting.

Every page global here is read through the `mw:` prefix, because the driver
runs in the isolated world and a plain `evaluate` would report ABSENT for
everything and crash on any call. An earlier version of this probe did exactly
that: it invoked a page function through an ordinary `page.evaluate` and died
with a TypeError, which looked like a browser regression and was really the
probe asking the wrong world.

Exit 0 = timing properties are as documented.  Exit 1 = they changed.

Run:  uv run diagnostics/probes/hook_timing_probe.py
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from camoufox.async_api import AsyncCamoufox

# Deliberately synthetic and domain-neutral. An earlier version named a real
# customer's function here, which made a generic compatibility probe read like
# it only applied to one portal.
EARLY_FUNCTION = "fixtureEarlyFunction"
LATE_FUNCTION = "fixtureLateFunction"

APP_SCRIPT = """
// Declared AND called during this script's own parse. Nothing injected can
// wrap it in time, whatever technique is used.
function fixtureEarlyFunction(a, b) { return a * b; }
window.fixtureEarlyFunction = fixtureEarlyFunction;
window.__earlyCallResult = window.fixtureEarlyFunction(6, 7);

// Declared during parse, called later by the driver. The ordinary case.
function fixtureLateFunction(a, b) { return a + b; }
window.fixtureLateFunction = fixtureLateFunction;
"""

PAGE = """<!doctype html><html><head><title>pending</title></head><body>
<div id="out">pending</div>
<script src="/app.js"></script>
<script>
document.title = JSON.stringify({
  earlyCallResult: (typeof window.__earlyCallResult !== "undefined")
      ? window.__earlyCallResult : "ABSENT"
});
</script>
</body></html>"""

# Installed into the PAGE world, which is where ScriptScrap installs its
# patched instruments after de07d1b.
PAGE_WORLD_HOOKS = """
(() => {
    if (window.__hookProbeInstalled) return "ALREADY";
    window.__hookProbeInstalled = true;

    // Technique A: poll until the global exists, then wrap it.
    window.__intervalHookLog = [];
    const timer = setInterval(() => {
        const fn = window.fixtureEarlyFunction;
        if (typeof fn === "function" && !fn.__hookedA) {
            const wrapper = function (...args) {
                const result = fn.apply(this, args);
                window.__intervalHookLog.push({ args: args, returned: result });
                return result;
            };
            wrapper.__hookedA = true;
            window.fixtureEarlyFunction = wrapper;
        }
        const late = window.fixtureLateFunction;
        if (typeof late === "function" && !late.__hookedA) {
            const wrapper = function (...args) {
                const result = late.apply(this, args);
                window.__lateHookLog.push({ args: args, returned: result });
                return result;
            };
            wrapper.__hookedA = true;
            window.fixtureLateFunction = wrapper;
        }
    }, 200);
    setTimeout(() => clearInterval(timer), 15000);
    window.__lateHookLog = [];

    return "INSTALLED";
})()
"""

# Technique B has to be in place before the application script parses, so it
# cannot wait for a navigation. It is installed as an isolated-world init
# script AND re-attempted in the page world; the point of the probe is that
# neither placement helps, for a reason intrinsic to how declarations bind.
ACCESSOR_TRAP = """
(() => {
    if (window.__trapInstalled) return "ALREADY";
    window.__trapInstalled = true;
    window.__trapHookLog = [];
    let backing;
    Object.defineProperty(window, "fixtureEarlyFunction", {
        configurable: true,
        get() { return backing; },
        set(fn) {
            if (typeof fn === "function" && !fn.__hookedB) {
                const wrapper = function (...args) {
                    const result = fn.apply(this, args);
                    window.__trapHookLog.push({ args: args, returned: result });
                    return result;
                };
                wrapper.__hookedB = true;
                backing = wrapper;
            } else {
                backing = fn;
            }
        },
    });
    return "INSTALLED";
})()
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802  (http.server API)
        if self.path == "/app.js":
            body, content_type = APP_SCRIPT.encode(), "application/javascript"
        else:
            body, content_type = PAGE.encode(), "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8"
                         if "charset" not in content_type else content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args, **kwargs):
        pass


def load_source_analysis():
    """The REAL M4 source-analysis function, not a copy of it.

    Q3 checks a ScriptScrap capability rather than a browser behaviour, so it
    must exercise the shipped implementation -- a mirror would drift and could
    pass while the real thing was broken. The probe otherwise runs in uv's
    isolated script environment, so `src/` is put on the path explicitly, and a
    checkout where that fails reports Q3 as SKIPPED rather than failing.
    """
    src = pathlib.Path(__file__).resolve().parents[2] / "src"
    if src.is_dir() and str(src) not in sys.path:
        sys.path.insert(0, str(src))
    try:
        from scriptscrap.analysis.scriptinfo import find_parse_time_calls
    except ImportError:
        return None
    return find_parse_time_calls


async def evaluate_page_world(page, expression, default=None):
    """Read a PAGE global. Never raises -- an unreadable value is a finding."""
    try:
        return await page.evaluate("mw:" + expression)
    except Exception as exc:
        return {"__probe_error__": f"{type(exc).__name__}: {exc}", "default": default}


async def main() -> int:
    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}/"

    out: dict = {}
    try:
        async with AsyncCamoufox(
            headless=True, humanize=False, os="windows", geoip=False,
            main_world_eval=True,
        ) as browser:
            page = await browser.new_page()
            # Technique B, as early as anything can be placed.
            await page.context.add_init_script(ACCESSOR_TRAP)
            await page.goto(url, wait_until="load")

            # Technique A, in the world the application actually uses.
            out["page_world_hooks"] = await page.evaluate("mw:" + PAGE_WORLD_HOOKS)
            # Expected to be REFUSED: a top-level function declaration makes a
            # non-configurable global, so the trap cannot be retrofitted. The
            # refusal is the evidence, so it is captured rather than raised.
            out["accessor_trap_in_page_world"] = await evaluate_page_world(
                page, ACCESSOR_TRAP.strip())
            await asyncio.sleep(0.6)  # let the 200ms poll fire

            out["page_report"] = json.loads(await page.title())
            out["isolated_world_view_of_early_fn"] = await page.evaluate(
                "typeof window.fixtureEarlyFunction")
            out["page_world_view_of_early_fn"] = await evaluate_page_world(
                page, "typeof window.fixtureEarlyFunction")

            # Q2: was the parse-time call captured by either technique?
            out["A_interval_log_after_parse"] = await evaluate_page_world(
                page, "(window.__intervalHookLog || []).length", 0)
            out["B_trap_log_after_parse"] = await evaluate_page_world(
                page, "(window.__trapHookLog || []).length", 0)

            # Q1: a LATE call, made the way an application would make it.
            await page.evaluate("mw:window.fixtureLateFunction(3, 4)")
            out["late_hook_log"] = await evaluate_page_world(
                page, "(window.__lateHookLog || []).length", 0)

            # A late call to the EARLY function is observed too -- proof that
            # the wrapper is installed and it is only the timing that lost the
            # first call.
            await page.evaluate("mw:window.fixtureEarlyFunction(2, 5)")
            out["A_interval_log_after_late_call"] = await evaluate_page_world(
                page, "(window.__intervalHookLog || []).length", 0)
    finally:
        server.shutdown()

    # Q3: source observation, the M4 capability. No browser needed -- this is
    # what reading the response body before Firefox parses it makes possible.
    find_parse_time_calls = load_source_analysis()
    if find_parse_time_calls is None:
        parse_time = None
        out["source_identified_parse_time_calls"] = "SKIPPED: scriptscrap not importable"
    else:
        parse_time = find_parse_time_calls(APP_SCRIPT, [EARLY_FUNCTION, LATE_FUNCTION])
        out["source_identified_parse_time_calls"] = parse_time

    print("=" * 72)
    print("HOOK TIMING PROBE  (http origin)")
    print("=" * 72)
    print(json.dumps(out, indent=2))

    early_ran = out["page_report"]["earlyCallResult"] == 42
    late_observed = out["late_hook_log"] == 1
    early_observed_late = out["A_interval_log_after_late_call"] == 1
    parse_missed_a = out["A_interval_log_after_parse"] == 0
    parse_missed_b = out["B_trap_log_after_parse"] == 0
    trap_result = out["accessor_trap_in_page_world"]
    trap_refused = isinstance(trap_result, dict) and "__probe_error__" in trap_result
    source_skipped = parse_time is None
    source_found_early = parse_time == [EARLY_FUNCTION]
    isolated_blind = out["isolated_world_view_of_early_fn"] == "undefined"
    page_world_sees = out["page_world_view_of_early_fn"] == "function"

    print("\n" + "-" * 72)
    print("RUNTIME -- late-function visibility")
    print(f"{'PASS' if page_world_sees else 'FAIL'}  page world sees the application's function")
    print(f"{'PASS' if isolated_blind else 'FAIL'}  isolated world does not (worlds are separate)")
    print(f"{'PASS' if late_observed else 'FAIL'}  a function called after load is observed")
    print(f"{'PASS' if early_observed_late else 'FAIL'}  the early function is observed once "
          f"called later")

    print("\nRUNTIME -- parse-time limitation (expected, not a defect)")
    print(f"{'CONFIRMED' if early_ran else 'CHANGED  '}  the early function ran during its own parse")
    print(f"{'CONFIRMED' if parse_missed_a else 'CHANGED  '}  interval polling did NOT capture that call")
    print(f"{'CONFIRMED' if parse_missed_b else 'CHANGED  '}  accessor trap did NOT capture it either")
    print(f"{'CONFIRMED' if trap_refused else 'CHANGED  '}  the trap cannot even be installed "
          f"in the page world afterwards")
    if trap_refused:
        print(f"           browser said: {trap_result['__probe_error__'].splitlines()[0][:80]}")
    print("           A top-level function declaration creates a NON-CONFIGURABLE")
    print("           global, and page-world code can only run after a navigation")
    print("           commits -- so no accessor trap can both reach the page's")
    print("           window and precede the declaration.")

    print("\nFORENSIC -- source visibility (M4, optional)")
    if source_skipped:
        print("SKIP  scriptscrap is not importable from here; source analysis "
              "not exercised")
    else:
        print(f"{'PASS' if source_found_early else 'FAIL'}  reading the SOURCE identifies "
              f"{EARLY_FUNCTION} as parse-time called")
        print(f"      and correctly does NOT flag {LATE_FUNCTION}")
    print("           Source analysis establishes that the function EXISTS and is")
    print("           called during its own parse. It does NOT hook the call.")
    print("           ScriptScrap does not rewrite source to make it hookable:")
    print("           M4 deliberately left rewriting unimplemented.")

    runtime_ok = page_world_sees and isolated_blind and late_observed and early_observed_late
    limitation_holds = (early_ran and parse_missed_a and parse_missed_b
                        and trap_refused)

    if not runtime_ok:
        print("\nVERDICT: FAIL -- runtime hook timing changed; late calls are no")
        print("         longer reliably observed on this browser.")
        print("-" * 72)
        return 1
    if not source_skipped and not source_found_early:
        print("\nVERDICT: FAIL -- source analysis no longer identifies the")
        print("         parse-time call, so the M4 blind-spot mitigation is gone.")
        print("-" * 72)
        return 1

    print("\nVERDICT: PASS -- late-call observation works; the parse-time gap is")
    if limitation_holds:
        print("         present as documented and covered only by source reading.")
    else:
        print("         NO LONGER PRESENT. A stated limitation has changed --")
        print("         re-read the blueprint's parse-time section before relying on it.")
    print("-" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
