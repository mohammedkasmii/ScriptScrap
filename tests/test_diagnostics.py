"""The compatibility probes must keep testing the architecture that ships.

The probes are standalone PEP 723 scripts so they run in a bare venv with only
camoufox installed, which means they MIRROR the runtime mechanism rather than
importing it. A mirror can drift, and a drifted probe is worse than no probe:
it passes while the real thing is broken. These tests pin the couple of details
where the mirror and the implementation have to agree.

No browser is launched here. The probes themselves do that.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scriptscrap import baseline
from scriptscrap.probe import BINDING_NAME

REPO = Path(__file__).resolve().parents[1]
PROBES = REPO / "diagnostics" / "probes"
PROBE_JS = (REPO / "src" / "scriptscrap" / "probe" / "probe.js").read_text(encoding="utf-8")
JS_WORLD_PROBE = (PROBES / "js_world_probe.py").read_text(encoding="utf-8")
HOOK_TIMING_PROBE = (PROBES / "hook_timing_probe.py").read_text(encoding="utf-8")
DOCTOR = (REPO / "diagnostics" / "check_environment.py").read_text(encoding="utf-8")


def test_probe_and_js_world_probe_share_the_bridge_event_name():
    """The name is the contract between the two JS worlds.

    If probe.js renamed its CustomEvent and the diagnostic did not, the probe
    would go on passing against an event nothing dispatches any more.
    """
    assert 'BRIDGE_EVENT = "__scriptscrapBridge"' in JS_WORLD_PROBE
    assert 'BRIDGE_EVENT = "__scriptscrapBridge"' in PROBE_JS


def test_probe_and_js_world_probe_share_the_binding_name():
    assert f'BINDING_NAME = "{BINDING_NAME}"' in JS_WORLD_PROBE
    assert f'const BINDING = "{BINDING_NAME}"' in PROBE_JS


def test_both_browser_probes_enable_main_world_eval():
    """Without it the `mw:` prefix is refused and the probes test nothing."""
    for name, source in (("js_world_probe", JS_WORLD_PROBE),
                         ("hook_timing_probe", HOOK_TIMING_PROBE)):
        assert "main_world_eval=True" in source, name


def test_hook_timing_probe_carries_no_customer_specific_names():
    """It is a generic compatibility probe, not a portal-specific one."""
    assert "DevisCalculerMontantCharge" not in HOOK_TIMING_PROBE
    assert "fixtureEarlyFunction" in HOOK_TIMING_PROBE
    assert "fixtureLateFunction" in HOOK_TIMING_PROBE


def test_hook_timing_probe_uses_the_real_source_analysis():
    """Q3 checks OUR capability, so it must not test a copy of it."""
    assert "from scriptscrap.analysis.scriptinfo import find_parse_time_calls" \
        in HOOK_TIMING_PROBE


def test_hook_timing_probe_makes_no_source_rewriting_claim():
    """M4 deliberately did not implement rewriting; the probe must not imply it."""
    assert "does not rewrite source" in HOOK_TIMING_PROBE


def test_js_world_probe_treats_isolation_as_the_premise_not_a_failure():
    """The superseded contract asserted a SHARED world. It must be gone."""
    assert "JS worlds are isolated as expected" in JS_WORLD_PROBE
    assert "add_init_script reaches page main world" not in JS_WORLD_PROBE


# --- the doctor's warnings must describe the code that exists ---------------

def test_doctor_does_not_claim_websocket_frames_are_unsubscribed():
    """A real capture recorded 29 sockets and 206 frames under this warning."""
    assert "not subscribed to" not in DOCTOR


def test_websocket_sensor_really_does_subscribe_to_frames():
    """What the removed warning was wrong about, asserted directly."""
    sensor = (REPO / "src" / "scriptscrap" / "sensors" / "websocket.py").read_text(
        encoding="utf-8")
    assert '"framesent"' in sensor
    assert '"framereceived"' in sensor


def test_navigation_wipe_warning_names_only_what_still_suffers_it():
    """M2 made the runtime probe navigation-safe; the warning must say so."""
    assert "in-page hook buffers are wiped by every full page navigation" not in DOCTOR
    assert "legacy exit-read catalogs" in DOCTOR
    assert "are NOT affected" in DOCTOR


def test_runtime_probe_flushes_before_teardown():
    """The basis for narrowing that warning, asserted rather than assumed."""
    for event in ("pagehide", "beforeunload", "visibilitychange"):
        assert f'"{event}"' in PROBE_JS


def test_main_world_role_does_not_buffer_across_navigation():
    """It dispatches synchronously, which is why it needs no flush of its own."""
    assert "if (IS_MAIN) { bridgeSend(mk(type, payload)); return; }" in PROBE_JS


def test_parse_time_blind_spot_is_still_declared():
    """Narrowing stale warnings must not quietly drop a real one."""
    assert "during its own initial parse" in DOCTOR


def test_service_worker_blind_spot_is_still_declared():
    assert "service-worker traffic is invisible" in DOCTOR


def test_websocket_handshake_blind_spot_is_declared():
    """Frames are captured; the handshake headers genuinely are not."""
    assert "handshake headers are not exposed" in DOCTOR


# --- the baseline claim ------------------------------------------------------

def test_baseline_matches_the_installed_browser():
    """The bump is only legitimate if this machine's probes ran on this build."""
    found = baseline.installed_browser_build()
    if found is None:
        pytest.skip("camoufox browser not fetched")
    assert found == baseline.BROWSER_BUILD, (
        f"installed browser is {found}, baseline claims {baseline.BROWSER_BUILD}. "
        "Run all four diagnostics/probes/ before changing the baseline.")
