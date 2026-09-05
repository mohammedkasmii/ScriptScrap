"""The behavioural baseline, as an assertion rather than as prose.

`uv.lock` pins the Python packages. It does NOT pin the browser: Camoufox
fetches its Firefox build separately, and `python -m camoufox fetch` will
happily replace it with a newer one. Every empirical finding this design rests
on -- JS world semantics, runtime hook timing, uBlock default-addon filtering,
snapshot non-destructiveness -- was verified against ONE browser build.

That distinction stopped being academic. A drift from beta.28 to beta.29
re-enabled JS world isolation, which silently killed every monkey-patched
instrument in the runtime probe while leaving the listener-based ones working.
The capture looked fine. The doctor printed the new build without comment,
because it had nothing to compare it to.

Bumping this value is therefore a claim, not a formality: it asserts that every
probe in `diagnostics/probes/` has been run on the named build and passed. A
bump made to silence a warning would remove the only signal that says the
evidence underneath a capture is untested.

So the baseline lives here, in one place, machine-readable, imported by both
the environment doctor and the investigator. A mismatch is not fatal -- the
tool still runs -- but it is stated loudly at launch and written into the
session manifest, so a capture can never again be read without knowing whether
the browser underneath it was the one the assumptions were tested against.
"""

from __future__ import annotations

from typing import Any

# The build every diagnostics/probes/ result in this repo was verified against.
# Bump this ONLY after re-running those probes and re-reviewing the golden
# master; the version string alone is worth nothing without that.
#
# 152.0.4-beta.29, verified by all four probes passing on it:
#   js_world_probe            split-world runtime architecture (5 contracts)
#   hook_timing_probe         late-call observation + the parse-time limitation
#   snapshot_integrity_probe  capture does not modify the live page
#   addon_filter_probe        uBlock default-addon filtering
# The previous baseline, 152.0.4-beta.28, shared a JS world between injected
# scripts and the page. beta.29 isolates them. The runtime probe was migrated
# to a split-world design in de07d1b, and the probes above now assert THAT
# architecture rather than the shared-world assumption it replaced.
BROWSER_BUILD = "152.0.4-beta.29"

# Python packages, mirrored from uv.lock so the doctor has one source.
PACKAGE_PINS = {
    "camoufox": "0.5.5",
    "playwright": "1.60.0",
}

MISMATCH_NOTE = (
    "The verified assumptions (JS world semantics, runtime hook timing, addon "
    "filtering, snapshot non-destructiveness) were NOT tested on this build. "
    "Re-run diagnostics/probes/ before trusting the runtime probe's evidence."
)


def installed_browser_build() -> str | None:
    """The Camoufox browser build actually on this machine, or None."""
    try:
        from camoufox.pkgman import installed_verstr
    except Exception:
        return None
    try:
        return str(installed_verstr())
    except Exception:
        return None


def compare_browser_build(found: str | None = None) -> dict[str, Any]:
    """Compare the installed browser build to the baseline.

    Returned verbatim in the session manifest, so a reader of an old capture
    can see which browser produced it and whether that was the tested one.
    """
    if found is None:
        found = installed_browser_build()
    if found is None:
        return {"baseline": BROWSER_BUILD, "found": None, "status": "unknown",
                "note": "browser build could not be read; run: python -m camoufox fetch"}
    if found == BROWSER_BUILD:
        return {"baseline": BROWSER_BUILD, "found": found, "status": "match",
                "note": "browser matches the build the assumptions were verified on"}
    return {"baseline": BROWSER_BUILD, "found": found, "status": "mismatch",
            "note": MISMATCH_NOTE}
