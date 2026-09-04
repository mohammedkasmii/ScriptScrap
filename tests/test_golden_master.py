"""Golden master: the post-M0 investigator's behaviour, pinned.

A failure here is a DECISION POINT, not automatically a bug. Read the diff.
If the change is intended, re-bless the baseline in the same commit that causes
it, and say why in the commit message:

    SCRIPTSCRAP_UPDATE_GOLDEN=1 uv run pytest tests/test_golden_master.py

Alongside the whole-snapshot comparison there are targeted assertions on the
properties that must never regress silently. They exist so that a failure names
its own cause instead of leaving you to read a large diff -- and so that
re-blessing the baseline cannot quietly discard a security guarantee.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import pytest
from golden_support import GOLDEN_FILE, SAMPLE_EVENT_LOG, updating_golden

from scriptscrap.testing.snapshot import diff_lines, dump

pytestmark = pytest.mark.browser

EXPECTED_OUTPUT_FILES = {
    "api_dependencies.json",
    "dom_structure.json",
    "dropdown_catalogs.json",
    "events.jsonl",
    "generated_client.py",
    "jquery_events.json",
    "js_hooks_and_mutations.json",
    "mcma_openapi_spec.json",
    "network_traffic.json",
    "out_of_scope_metadata.json",
    "session_manifest.json",
    "SECURITY.md",
}


def test_all_expected_outputs_are_produced(investigation_snapshot):
    present = set(investigation_snapshot["files_present"])
    missing = EXPECTED_OUTPUT_FILES - present
    assert not missing, f"investigator stopped producing: {sorted(missing)}"


def test_matches_golden_master(investigation_snapshot, investigation_output: Path):
    if updating_golden():
        GOLDEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN_FILE.write_text(dump(investigation_snapshot), encoding="utf-8")
        # The offline replay tests read a real recorded log, so it is re-blessed
        # from the same run that produced the baseline. It contains only fixture
        # data -- no real portal, no real credentials.
        SAMPLE_EVENT_LOG.write_text(
            (investigation_output / "events.jsonl").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        pytest.skip(f"golden master re-blessed: {GOLDEN_FILE}")

    assert GOLDEN_FILE.exists(), (
        f"no baseline at {GOLDEN_FILE}. Create it with "
        f"SCRIPTSCRAP_UPDATE_GOLDEN=1 uv run pytest tests/test_golden_master.py"
    )
    expected = json.loads(GOLDEN_FILE.read_text(encoding="utf-8"))
    if expected != investigation_snapshot:
        diff = "\n".join(diff_lines(expected, investigation_snapshot))
        pytest.fail(
            "Investigator behaviour changed against the golden master.\n"
            "Read this diff before re-blessing it.\n\n" + diff,
            pytrace=False,
        )


# --- targeted invariants ------------------------------------------------
# Each of these is something the whole-snapshot diff would also catch, but
# would report as an unexplained line change. Named assertions fail loudly.

def test_network_capture_covers_the_scripted_workflow(investigation_snapshot):
    # network_log entries carry `url`, not `path` -- V11 recorded `path`, the
    # Camoufox rewrite dropped it. Derive it rather than assume it is there.
    paths = {
        urlparse(e["url"]).path for e in investigation_snapshot["network_traffic.json"]
    }
    assert {
        "/", "/page2", "/frame/outer", "/frame/inner",
        "/api/dossier", "/api/valider", "/api/form",
        "/api/referentiel", "/api/redirect", "/api/redirected", "/api/error",
    } <= paths


def test_dependency_correlation_finds_the_seeded_edge(investigation_snapshot):
    """The fixture re-sends /api/dossier's missionId in /api/valider's body."""
    edges = investigation_snapshot["api_dependencies.json"]
    assert any(
        e["source"]["origin_endpoint"] == "GET /api/dossier"
        and e["source"]["field"] == "missionId"
        and e["consumer"]["endpoint"] == "POST /api/valider"
        and e["consumer"]["field"] == "missionId"
        for e in edges
    ), f"seeded correlation edge missing; got {edges}"


def test_dropdown_catalogs_reflect_only_the_final_document(investigation_snapshot):
    """Pins a KNOWN LIMITATION, not a desirable behaviour.

    `extract_active_introspection` runs once, at exit, on the top frame only, so
    a full navigation destroys every catalog collected before it. The scripted
    workflow ends on /page2, so the index page's `ville` and `garage` catalogs
    are gone and only page2's `p2-etat` survives.

    This assertion exists so that when M2 fixes the limitation, this test fails
    and forces the change to be noticed and explained rather than absorbed into
    a re-blessed baseline.
    """
    catalogs = investigation_snapshot["dropdown_catalogs.json"]
    assert "p2-etat" in catalogs, "final document's dropdown catalog missing"
    assert "ville" not in catalogs, (
        "an index-page catalog survived a full navigation -- the read-once-at-exit "
        "limitation appears to be fixed. Update this test and known_blind_spots."
    )
    manifest = investigation_snapshot["session_manifest.json"]
    assert any(
        "destroyed by every full page navigation" in note
        for note in manifest["known_blind_spots"]
    ), "the limitation must stay documented in the manifest"


def test_dom_structure_captures_forms_across_frames(investigation_snapshot):
    snapshots = investigation_snapshot["dom_structure.json"]
    assert snapshots, "no DOM snapshots captured"
    frame_urls = {f["frame_url"] for s in snapshots for f in s["frames"]}
    assert any("/frame/outer" in u for u in frame_urls)
    assert any("/frame/inner" in u for u in frame_urls)


def test_openapi_records_every_observed_status(investigation_snapshot):
    spec = investigation_snapshot["mcma_openapi_spec.json"]
    assert "500" in spec["paths"]["/api/error"]["get"]["responses"]
    assert "200" in spec["paths"]["/api/dossier"]["get"]["responses"]


def test_generated_client_leaks_no_credentials(investigation_snapshot):
    """The security guarantee. Re-blessing the baseline must not weaken this."""
    client = investigation_snapshot["generated_client.py"]
    assert client["embeds_no_password"]
    assert client["embeds_no_csrf_value"]
    assert client["embeds_no_session_cookie"]
    assert client["embeds_no_operator_pii"]
    assert client["embeds_no_captured_query_values"]
    assert client["reads_credentials_from_env"]
    assert client["enforces_tls_verification"]


def test_visual_snapshots_are_faithful_and_safe(investigation_snapshot):
    traces = investigation_snapshot["visual_traces"]
    assert traces["screenshots"], "no screenshots captured"
    assert traces["html_snapshots"], "no HTML snapshots captured"
    for props in traces["html_properties"]:
        assert props["has_base_tag"]
        assert props["excludes_password_value"]
    # At least one snapshot was taken after the operator filled the form.
    assert any(p["serialises_text_value"] for p in traces["html_properties"])
    assert any(p["serialises_selected_option"] for p in traces["html_properties"])
    assert any(p["has_inlined_stylesheet"] for p in traces["html_properties"])


def test_session_manifest_records_the_conditions_of_capture(investigation_snapshot):
    manifest = investigation_snapshot["session_manifest.json"]
    assert manifest["browser"]["default_addons_excluded"] == ["UBO"]
    assert manifest["browser"]["addon_request_filtering_active"] is False
    assert manifest["scope"]["out_of_scope_policy"] == "metadata_only"
    assert manifest["known_blind_spots"], "blind spots must stay visible"
    assert manifest["event_spine"]["mode"] == "dual_write"


def test_event_spine_is_dual_written_and_intact(investigation_snapshot):
    events = investigation_snapshot["events.jsonl"]
    assert events["problems"] == []
    assert events["seq_is_dense"]
    assert events["first_type"] == "session_start"
    assert events["last_type"] == "session_end"
    assert events["by_type"]["http_request"] >= 11
    assert events["by_type"]["http_response"] >= 11
    assert events["by_type"]["capture_gap"] >= 1


def test_events_do_not_replace_existing_outputs(investigation_output: Path):
    """Dual-write means BOTH exist. The old outputs are still the authority."""
    assert (investigation_output / "events.jsonl").exists()
    assert (investigation_output / "network_traffic.json").exists()
    network = json.loads((investigation_output / "network_traffic.json").read_text("utf-8"))
    assert network, "existing network capture must not have been emptied"
