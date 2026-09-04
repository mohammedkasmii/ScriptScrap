#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["camoufox"]
# ///

"""Regression probe for F-03: visual capture must not modify the live page.

WHAT THIS PROTECTS
------------------
`capture_visual_state()` originally built its offline HTML snapshot by editing
the page it was investigating:

  * `fetch(link.href)` for every stylesheet -- page-originated network traffic
    that the investigator's own request handler then recorded as if it were
    application traffic;
  * `link.replaceWith(style)` -- permanently removed <link> elements from the
    live document;
  * `setAttribute('value', ...)` / `removeAttribute('checked')` -- permanently
    rewrote the operator's form state.

All of that ran from the 2-second background scanner, against a page a human was
actively using.

This probe measures the live DOM before and after a capture and asserts that
nothing changed. It runs BOTH implementations against identical pages so the
difference is evidence, not assertion.

Exit 0 = current implementation is non-destructive.
Exit 1 = contamination detected.

Run:  uv run diagnostics/probes/snapshot_integrity_probe.py
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from camoufox.async_api import AsyncCamoufox

REPO = Path(__file__).resolve().parents[2]
INVESTIGATOR = REPO / "camoufox" / "camoufox_investigator.py"

SAME_ORIGIN_CSS = "body { background: #eef; font-family: sans-serif; }\n" \
                  ".panel { background-image: url(../img/bg.png); }\n"
CROSS_ORIGIN_CSS = ".x-origin { color: rebeccapurple; }\n"

PAGE_TEMPLATE = """<!doctype html>
<html><head>
<title>snapshot fixture</title>
<link rel="stylesheet" href="/style.css">
<link rel="stylesheet" href="http://127.0.0.1:{other_port}/x.css">
<style>.inline {{ margin: 0; }}</style>
</head>
<body>
<form id="frm">
  <input type="text" id="nom" name="nom" value="">
  <input type="checkbox" id="accord" name="accord">
  <input type="radio" name="type" id="t1" value="a">
  <input type="radio" name="type" id="t2" value="b">
  <input type="password" id="pw" name="pw" value="">
  <textarea id="notes" name="notes"></textarea>
  <select id="ville" name="ville">
    <option value="cas">Casablanca</option>
    <option value="rab">Rabat</option>
    <option value="mar">Marrakech</option>
  </select>
</form>
</body></html>"""


def make_server(routes: dict[str, tuple[str, str]]) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            path = self.path.split("?")[0]
            if path not in routes:
                self.send_response(404)
                self.end_headers()
                return
            ctype, body_text = routes[path]
            body = body_text.encode()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args, **kwargs):
            pass

    return HTTPServer(("127.0.0.1", 0), Handler)


FINGERPRINT_JS = """
() => ({
    outerHTML: document.documentElement.outerHTML,
    stylesheetLinks: document.querySelectorAll('link[rel="stylesheet"]').length,
    styleTags: document.querySelectorAll('style').length,
    loadedSheets: document.styleSheets.length,
    controls: Array.from(document.querySelectorAll('input,textarea,select')).map(el => ({
        id: el.id,
        value: el.value,
        checked: (el.type === 'checkbox' || el.type === 'radio') ? el.checked : null
    }))
})
"""

# Historical implementation, copied verbatim from git commit a185277.
# Present ONLY so this probe can demonstrate the contamination it removed.
LEGACY_SNAPSHOT_JS = r"""async () => {
    const links = Array.from(document.querySelectorAll('link[rel="stylesheet"]'));
    for (let link of links) {
        try {
            const res = await fetch(link.href);
            let css = await res.text();
            const baseUrl = new URL(link.href);
            css = css.replace(/url\((?!['"]?(?:data:|https:|http:))['"]?([^'"\)]*)['"]?\)/gi,
                (match, urlPath) => `url('${new URL(urlPath, baseUrl).href}')`);
            const style = document.createElement('style');
            style.textContent = css;
            link.replaceWith(style);
        } catch (e) {}
    }
    document.querySelectorAll('input, textarea').forEach(el => {
        if (el.tagName === 'INPUT' && (el.type === 'checkbox' || el.type === 'radio')) {
            if (el.checked) el.setAttribute('checked', 'checked');
            else el.removeAttribute('checked');
        } else {
            el.setAttribute('value', el.value);
        }
    });
    return document.documentElement.outerHTML;
}"""


def load_investigator():
    spec = importlib.util.spec_from_file_location("investigator", INVESTIGATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {INVESTIGATOR}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def fill_in_operator_state(page):
    """Put the page into the state a human working the portal would have left."""
    await page.fill("#nom", "Alice Benali")
    await page.check("#accord")
    await page.check("#t2")
    await page.fill("#pw", "hunter2-live-secret")
    await page.fill("#notes", "Dossier 44718 - vitre laterale")
    await page.select_option("#ville", "mar")


async def measure(page, url, do_capture) -> dict:
    await page.goto(url, wait_until="load")
    await fill_in_operator_state(page)
    await asyncio.sleep(0.3)

    before = await page.evaluate(FINGERPRINT_JS)

    watching = {"on": True}
    during: list[str] = []
    page.on("request", lambda r: during.append(r.url) if watching["on"] else None)

    await do_capture(page)

    watching["on"] = False
    after = await page.evaluate(FINGERPRINT_JS)

    return {
        "before": before,
        "after": after,
        "requests_during_capture": during,
        "css_requests_during_capture": [u for u in during if u.endswith(".css")],
    }


def first_difference(a: str, b: str, context: int = 90) -> str:
    """Locate and show the first divergence, so a failure names its own cause."""
    limit = min(len(a), len(b))
    i = 0
    while i < limit and a[i] == b[i]:
        i += 1
    if i == limit and len(a) == len(b):
        return "(identical)"
    start = max(0, i - context // 2)
    return (
        f"      at offset {i} (len {len(a)} -> {len(b)})\n"
        f"      before: ...{a[start:i + context]!r}\n"
        f"      after : ...{b[start:i + context]!r}"
    )


def compare(label: str, m: dict) -> tuple[bool, list[str]]:
    before, after = m["before"], m["after"]
    problems = []

    if before["outerHTML"] != after["outerHTML"]:
        problems.append("live DOM outerHTML CHANGED")
        print(f"\n  [outerHTML diff for {label}]")
        print(first_difference(before["outerHTML"], after["outerHTML"]))
    if before["stylesheetLinks"] != after["stylesheetLinks"]:
        problems.append(
            f"stylesheet <link> count {before['stylesheetLinks']} -> {after['stylesheetLinks']}")
    if before["styleTags"] != after["styleTags"]:
        problems.append(f"<style> count {before['styleTags']} -> {after['styleTags']}")
    if before["controls"] != after["controls"]:
        changed = [
            f"#{b['id']}"
            for b, a in zip(before["controls"], after["controls"], strict=False)
            if b != a
        ]
        problems.append(f"live control state changed: {', '.join(changed) or 'unknown'}")
    if m["css_requests_during_capture"]:
        problems.append(
            f"{len(m['css_requests_during_capture'])} page-side CSS fetch(es) during capture")

    print(f"\n--- {label} ---")
    print(f"  stylesheet <link> elements : {before['stylesheetLinks']} -> {after['stylesheetLinks']}")
    print(f"  <style> elements           : {before['styleTags']} -> {after['styleTags']}")
    print(f"  live DOM identical         : {before['outerHTML'] == after['outerHTML']}")
    print(f"  control state identical    : {before['controls'] == after['controls']}")
    print(f"  CSS requests during capture: {len(m['css_requests_during_capture'])} "
          f"{m['css_requests_during_capture']}")
    if problems:
        for p in problems:
            print(f"  !! {p}")
    return (not problems), problems


async def main() -> int:
    other = make_server({"/x.css": ("text/css", CROSS_ORIGIN_CSS)})
    other_port = other.server_address[1]
    threading.Thread(target=other.serve_forever, daemon=True).start()

    main_srv = make_server({
        "/": ("text/html; charset=utf-8", PAGE_TEMPLATE.format(other_port=other_port)),
        "/style.css": ("text/css", SAME_ORIGIN_CSS),
    })
    port = main_srv.server_address[1]
    threading.Thread(target=main_srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}/"

    inv = load_investigator()
    tmpdir = Path(tempfile.mkdtemp(prefix="scriptscrap_snapshot_probe_"))
    inv.OUTPUT_DIR = tmpdir
    scope = inv.InvestigationScope(url)
    engine = inv.WebHarvester(url, scope)

    print("=" * 74)
    print("SNAPSHOT INTEGRITY PROBE (F-03)")
    print("=" * 74)
    print(f"fixture   : {url}")
    print(f"artifacts : {tmpdir}")

    try:
        async with AsyncCamoufox(headless=True, humanize=False, os="windows",
                                 geoip=False, exclude_addons=[inv.DefaultAddons.UBO]) as browser:

            # --- historical implementation, for contrast -----------------
            legacy_page = await browser.new_page()
            legacy = await measure(
                legacy_page, url,
                lambda p: p.evaluate(LEGACY_SNAPSHOT_JS),
            )
            legacy_ok, _ = compare("BEFORE the fix (commit a185277 logic)", legacy)
            await legacy_page.close()

            # --- current implementation ----------------------------------
            page = await browser.new_page()
            current = await measure(page, url, engine.capture_visual_state)
            current_ok, current_problems = compare("AFTER the fix (current)", current)
            await page.close()
    finally:
        main_srv.shutdown()
        other.shutdown()

    # --- artifact checks --------------------------------------------------
    pngs = sorted(tmpdir.glob("visual_traces/*.png"))
    htmls = sorted(tmpdir.glob("visual_traces/*.html"))
    print("\n--- artifacts produced by the current implementation ---")
    print(f"  screenshots : {[p.name for p in pngs]}")
    print(f"  html        : {[p.name for p in htmls]}")

    artifact_problems = []
    if not pngs:
        artifact_problems.append("no screenshot written")
    if not htmls:
        artifact_problems.append("no HTML snapshot written")
    else:
        snap = htmls[0].read_text(encoding="utf-8")
        checks = {
            "text input value serialized": 'value="Alice Benali"' in snap,
            "checkbox state serialized": 'id="accord"' in snap and "checked" in snap,
            "radio state serialized": snap.count('checked="checked"') >= 2,
            "textarea value serialized": "Dossier 44718" in snap,
            "select option serialized": 'selected="selected"' in snap,
            # cssRules serialisation normalises values (#eef -> rgb(...)), so
            # assert on the marker and a stable declaration, not the literal.
            "same-origin CSS inlined": "data-scriptscrap-inlined-from" in snap
                                       and "font-family" in snap,
            "relative url() rewritten absolute": "http://127.0.0.1" in snap
                                                 and "img/bg.png" in snap,
            "cross-origin <link> retained": "/x.css" in snap,
            "base tag injected": "<base" in snap,
            "password value NOT serialized": "hunter2-live-secret" not in snap,
        }
        print("\n--- offline snapshot content ---")
        for label, ok in checks.items():
            print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
            if not ok:
                artifact_problems.append(label)

    print("\n--- snapshot fidelity accounting ---")
    print(json.dumps(engine.snapshot_stats, indent=2))

    print("\n" + "=" * 74)
    if legacy_ok:
        print("NOTE: the historical implementation did NOT show contamination in this")
        print("      run. The fixture may no longer reproduce it -- investigate.")
    else:
        print("Historical implementation: CONTAMINATED the live page (as expected).")

    if current_ok and not artifact_problems:
        print("Current implementation:    live page UNCHANGED, artifacts complete.")
        print("VERDICT: PASS -- F-03 fixed.")
        print("=" * 74)
        return 0

    print("Current implementation:    PROBLEMS FOUND")
    for p in current_problems + artifact_problems:
        print(f"  - {p}")
    print("VERDICT: FAIL")
    print("=" * 74)
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
