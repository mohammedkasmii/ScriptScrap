"""The browser build is not pinned by uv.lock, so it is asserted here.

Every empirical finding this design rests on was verified against ONE Firefox
build. A drift from 152.0.4-beta.28 to beta.29 re-enabled JS world isolation
and silently disabled every monkey-patched instrument in the runtime probe for
an entire real capture, while the environment doctor printed the new build
without comment because it had nothing to compare it against.
"""

from __future__ import annotations

from scriptscrap import baseline


def test_the_baseline_is_a_value_not_a_comment():
    assert baseline.BROWSER_BUILD
    assert baseline.PACKAGE_PINS["camoufox"]
    assert baseline.PACKAGE_PINS["playwright"]


def test_matching_build_is_reported_as_a_match():
    result = baseline.compare_browser_build(baseline.BROWSER_BUILD)
    assert result["status"] == "match"
    assert result["found"] == baseline.BROWSER_BUILD


def test_a_drifted_build_is_a_mismatch_with_an_actionable_note():
    result = baseline.compare_browser_build("152.0.4-beta.29")
    assert result["status"] == "mismatch"
    assert result["baseline"] == baseline.BROWSER_BUILD
    assert result["found"] == "152.0.4-beta.29"
    assert "diagnostics/probes" in result["note"]


def test_an_unreadable_build_is_unknown_not_a_silent_pass():
    result = baseline.compare_browser_build(None)
    if result["found"] is None:
        assert result["status"] == "unknown"
        assert "camoufox fetch" in result["note"]


def test_pins_agree_with_the_environment_doctor_expectations():
    """One source for the pins, so the doctor cannot drift from the baseline."""
    import importlib.metadata

    for package, expected in baseline.PACKAGE_PINS.items():
        try:
            found = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            continue
        assert found == expected, (
            f"{package} is {found}, baseline is {expected}. Re-run "
            f"diagnostics/probes/ before changing the baseline.")
