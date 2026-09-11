#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["camoufox"]
# ///

"""Compatibility check for the assumptions camoufox_investigator.py relies on.

This is a fast, offline, no-browser check. It reports conditions that would
silently degrade the evidence a session produces. It does NOT launch a browser;
for that, run the probes in ./probes/ (see ./README.md).

Interim M0 diagnostic. It will be replaced by `scriptscrap doctor` when the
package architecture lands in M1.

Exit 0 = no blocking problems.  Exit 1 = at least one FAIL.

Run:  uv run diagnostics/check_environment.py
"""

from __future__ import annotations

import importlib.metadata
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INVESTIGATOR = REPO / "camoufox" / "camoufox_investigator.py"

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
results: list[tuple[str, str, str]] = []


def record(status: str, name: str, detail: str) -> None:
    results.append((status, name, detail))


def _baseline():
    """The pinned baseline, if the scriptscrap package is importable."""
    try:
        from scriptscrap import baseline
    except ImportError:
        return None
    return baseline


def check_versions() -> None:
    record(PASS, "python", sys.version.split()[0])
    base = _baseline()
    pins = base.PACKAGE_PINS if base else {"camoufox": "0.5.5", "playwright": "1.60.0"}
    for pkg, expected in pins.items():
        try:
            found = importlib.metadata.version(pkg)
        except importlib.metadata.PackageNotFoundError:
            record(FAIL, pkg, "not installed")
            continue
        if found == expected:
            record(PASS, pkg, found)
        else:
            record(
                WARN, pkg,
                f"{found} (blueprint findings were verified against {expected}; "
                f"re-run diagnostics/probes/ to confirm assumptions still hold)",
            )


def check_browser() -> None:
    """The browser build is NOT pinned by uv.lock, so it is checked here.

    Printing the build was not enough: a drift from beta.28 to beta.29
    re-enabled JS world isolation and disabled every monkey-patched instrument
    in the runtime probe, and nothing in this doctor noticed. Compare it.
    """
    base = _baseline()
    if base is None:
        try:
            from camoufox.pkgman import installed_verstr
            record(WARN, "camoufox browser build",
                   f"{installed_verstr()} (scriptscrap not importable; "
                   f"cannot compare to the recorded baseline)")
        except Exception as exc:
            record(FAIL, "camoufox browser build",
                   f"not fetched or unreadable ({exc}). Run: python -m camoufox fetch")
        return

    comparison = base.compare_browser_build()
    if comparison["status"] == "match":
        record(PASS, "camoufox browser build", f"{comparison['found']} (baseline)")
    elif comparison["status"] == "unknown":
        record(FAIL, "camoufox browser build",
               "not fetched or unreadable. Run: python -m camoufox fetch")
    else:
        record(FAIL, "camoufox browser build",
               f"{comparison['found']}, baseline is {comparison['baseline']}. "
               f"{comparison['note']}")


def check_default_addons() -> None:
    """The F-01 containment check: is the investigator excluding uBlock Origin?"""
    try:
        from camoufox.addons import DefaultAddons

        defaults = [addon.name for addon in DefaultAddons]
    except Exception as exc:
        record(FAIL, "camoufox default addons", f"could not introspect ({exc})")
        return

    record(
        WARN if defaults else PASS,
        "camoufox default addons",
        f"{', '.join(defaults) or 'none'} -- installed unless exclude_addons is passed",
    )

    if not INVESTIGATOR.exists():
        record(FAIL, "investigator addon policy", f"missing: {INVESTIGATOR}")
        return

    source = INVESTIGATOR.read_text(encoding="utf-8")
    missing = [name for name in defaults if f"DefaultAddons.{name}" not in source]
    if "exclude_addons" not in source:
        record(FAIL, "investigator addon policy",
               "does NOT pass exclude_addons -- captures are being filtered by an ad blocker")
    elif missing:
        record(FAIL, "investigator addon policy",
               f"exclude_addons present but does not exclude: {', '.join(missing)}")
    else:
        record(PASS, "investigator addon policy",
               f"excludes all default addons ({', '.join(defaults)})")


def check_addon_cache() -> None:
    try:
        from camoufox.pkgman import INSTALL_DIR

        addons_dir = Path(INSTALL_DIR) / "addons"
        present = sorted(p.name for p in addons_dir.iterdir()) if addons_dir.is_dir() else []
        record(
            PASS, "downloaded addon cache",
            f"{', '.join(present) or 'empty'} "
            f"(presence is harmless once exclude_addons is set)",
        )
    except Exception as exc:
        record(WARN, "downloaded addon cache", f"unreadable ({exc})")


def check_gitignore() -> None:
    """Sensitive output must be un-committable, by pattern rather than by name."""
    samples = [
        "v13_investigation_output/network_traffic.json",
        "camoufox/v13_investigation_output/generated_client.py",
        "v99_future_rename_output/x.json",
        "sessions/abc/events.jsonl",
    ]
    leaks = []
    for sample in samples:
        # Fixed argument list; `sample` comes from the literal list above, never
        # from user input. `git` is resolved from PATH by design.
        proc = subprocess.run(  # noqa: S603
            ["git", "check-ignore", "-q", "--", sample],  # noqa: S607
            cwd=REPO, capture_output=True, check=False,
        )
        if proc.returncode != 0:
            leaks.append(sample)

    if leaks:
        record(FAIL, "gitignore covers output",
               "NOT ignored: " + ", ".join(leaks))
    else:
        record(PASS, "gitignore covers output",
               f"{len(samples)}/{len(samples)} sample output paths ignored")


def check_credential_classification() -> None:
    """The capture must record credential headers by NAME, never by value."""
    if not INVESTIGATOR.exists():
        record(FAIL, "credential classification", f"missing: {INVESTIGATOR}")
        return
    source = INVESTIGATOR.read_text(encoding="utf-8")
    if "is_sensitive_header" in source and "credential_header_names" in source:
        record(PASS, "credential classification",
               "credential-bearing headers recorded by name only")
    else:
        record(FAIL, "credential classification",
               "no credential-header filtering at capture time")


def check_generated_client_policy() -> None:
    """No captured credentials, and no disabled TLS verification.

    This used to audit the investigator, which emitted `generated_client.py`
    directly. That writer was retired; the generator now lives in its own
    module, so the check follows it there rather than looking for its remains
    in a file that no longer has the job.
    """
    generator = REPO / "src" / "scriptscrap" / "generate" / "client.py"
    if not generator.exists():
        record(PASS, "generated client policy",
               "no client generator present; nothing generates credentials to leak")
        return
    source = generator.read_text(encoding="utf-8")

    problems = []
    if "verify=False" in source:
        problems.append("emits verify=False (TLS verification disabled)")
    if "SCRIPTSCRAP_AUTH_HEADERS" not in source:
        problems.append("does not source credentials from the environment")

    if problems:
        record(FAIL, "generated client policy", "; ".join(problems))
    else:
        record(PASS, "generated client policy",
               "credentials excluded from generated source, TLS verification enforced")


def check_scope_policy() -> None:
    if not INVESTIGATOR.exists():
        return
    source = INVESTIGATOR.read_text(encoding="utf-8")
    if "InvestigationScope" in source and "_record_out_of_scope" in source:
        record(PASS, "investigation scope", "boundary enforced at capture time")
    else:
        record(FAIL, "investigation scope", "no scope boundary -- unrelated browsing "
                                            "would be captured in full")


def check_known_blind_spots() -> None:
    """Not failures -- limitations that must stay visible until later milestones.

    Kept honest in both directions. Two entries here described the tool as it
    was before M2, and a stale warning is its own kind of lie: it trains a
    reader to skim the list, which is where the real blind spots are.
    """
    for note in (
        # Still true: Firefox does not expose service-worker traffic to
        # Playwright at all, so nothing in the capture can see it.
        "service-worker traffic is invisible to Playwright on Firefox",

        # Narrowed. The runtime probe flushes on pagehide, beforeunload and
        # visibilitychange, and its page-world half dispatches synchronously
        # rather than buffering, so probe evidence survives navigation. What
        # is still read once at exit are the LEGACY page-side catalogs.
        "legacy exit-read catalogs (window.functionHookLogs, window.domMutations, "
        "the jQuery event map and dropdown catalogs) are read once at session end, "
        "so they describe only the final document; runtime probe events are "
        "flushed before each navigation and are NOT affected",

        # Still true, and now measured from two directions by
        # diagnostics/probes/hook_timing_probe.py.
        "a function declared AND called during its own initial parse cannot be "
        "wrapped by the runtime probe; forensic source reading identifies it but "
        "does not hook it",

        # The part of WebSocket observation that is genuinely still missing.
        # Frames themselves ARE captured -- see check_websocket_subscription.
        "WebSocket handshake headers are not exposed by Playwright, so the "
        "authentication used to open a socket is not recoverable",
    ):
        record(WARN, "known blind spot", note)


def check_websocket_subscription() -> None:
    """Prove the frame subscription exists instead of describing it.

    This was a standing WARN saying frames were "available on Firefox but not
    subscribed to" long after M2 subscribed to them -- a real capture recorded
    29 sockets, 72 frames sent and 134 received while the doctor still called
    it a blind spot. Checking the source keeps the claim true by construction.
    """
    sensor = REPO / "src" / "scriptscrap" / "sensors" / "websocket.py"
    if not sensor.exists():
        record(WARN, "websocket frames", "sensor module not found")
        return
    source = sensor.read_text(encoding="utf-8")
    subscribed = [name for name in ("framesent", "framereceived")
                  if f'"{name}"' in source]
    if len(subscribed) == 2:
        record(PASS, "websocket frames", "sent and received frames are subscribed")
    else:
        record(WARN, "websocket frames",
               f"only {subscribed or 'no'} frame event(s) subscribed; "
               f"payloads will be missing from the capture")


def main() -> int:
    check_versions()
    check_browser()
    check_default_addons()
    check_addon_cache()
    check_gitignore()
    check_credential_classification()
    check_generated_client_policy()
    check_scope_policy()
    check_websocket_subscription()
    check_known_blind_spots()

    width = max(len(name) for _, name, _ in results)
    print("=" * 78)
    print("SCRIPTSCRAP ENVIRONMENT CHECK  (M0)")
    print("=" * 78)
    for status, name, detail in results:
        print(f"[{status:4}] {name:<{width}}  {detail}")

    failures = [r for r in results if r[0] == FAIL]
    warnings = [r for r in results if r[0] == WARN]
    print("-" * 78)
    print(f"{len(results) - len(failures) - len(warnings)} pass, "
          f"{len(warnings)} warn, {len(failures)} fail")
    if failures:
        print("\nBLOCKING PROBLEMS:")
        for _, name, detail in failures:
            print(f"  - {name}: {detail}")
        print("\nDo not trust investigation output until these are resolved.")
    else:
        print("\nNo blocking problems. Browser-level assumptions are verified separately:")
        # All four. These are the evidence behind the browser baseline above,
        # so the list must not be a subset of them.
        print("  uv run diagnostics/probes/js_world_probe.py")
        print("  uv run diagnostics/probes/hook_timing_probe.py")
        print("  uv run diagnostics/probes/snapshot_integrity_probe.py")
        print("  uv run diagnostics/probes/addon_filter_probe.py   (needs network)")
    print("=" * 78)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
