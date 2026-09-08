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
    "events.jsonl",
    "session_manifest.json",
    "SECURITY.md",
}

# Nine legacy files were retired here. Every assertion they carried moved onto
# the event log or the knowledge derived from it, which is why the tests below
# read `derived` rather than a JSON dump. Nothing was dropped for being
# inconvenient; anything the spine could not answer was added to the spine
# first (out-of-scope response statuses, DOM-snapshot frame URLs).
RETIRED_OUTPUT_FILES = {
    "api_dependencies.json",
    "dom_structure.json",
    "dropdown_catalogs.json",
    "generated_client.py",
    "jquery_events.json",
    "js_hooks_and_mutations.json",
    "mcma_openapi_spec.json",
    "network_traffic.json",
    "out_of_scope_metadata.json",
}


@pytest.fixture(scope="session")
def derived(investigation_output: Path):
    """The knowledge `scriptscrap analyze` derives from the captured log.

    This is what replaced the retired files, so it is what the invariants below
    are pinned against.
    """
    from scriptscrap.analysis import analyze_log

    return analyze_log(investigation_output / "events.jsonl")


def test_all_expected_outputs_are_produced(investigation_snapshot):
    present = set(investigation_snapshot["files_present"])
    missing = EXPECTED_OUTPUT_FILES - present
    assert not missing, f"investigator stopped producing: {sorted(missing)}"


def test_retired_outputs_stay_retired(investigation_snapshot):
    """One output contract, not two.

    A file reappearing here means a legacy writer came back, and the workspace
    would then have to choose which of two descriptions of the same session to
    believe.
    """
    present = set(investigation_snapshot["files_present"])
    returned = RETIRED_OUTPUT_FILES & present
    assert not returned, f"retired legacy output is being written again: {sorted(returned)}"


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

def test_network_capture_covers_the_scripted_workflow(derived):
    """Was read from network_traffic.json; now from the derived endpoints."""
    paths = {urlparse(e.template).path or e.template for e in derived.endpoints}
    assert {
        "/", "/page2", "/frame/outer", "/frame/inner",
        "/api/dossier", "/api/valider", "/api/form",
        "/api/referentiel", "/api/redirect", "/api/redirected", "/api/error",
    } <= paths


def test_dependency_correlation_finds_the_seeded_edge(derived):
    """The fixture re-sends /api/dossier's missionId in /api/valider's body.

    The derived edge carries a confidence and its own evidence ids, which the
    retired api_dependencies.json did not -- so this now also asserts that the
    conclusion can be walked back to the events behind it.
    """
    edges = [
        e for e in derived.dependencies
        if e.source_endpoint.endswith("/api/dossier")
        and e.source_field.endswith("missionId")
        and e.target_endpoint.endswith("/api/valider")
        and e.target_field.endswith("missionId")
    ]
    assert edges, (
        "seeded correlation edge missing; got "
        f"{[(e.source_endpoint, e.source_field, e.target_endpoint) for e in derived.dependencies]}"
    )
    assert edges[0].evidence.event_ids, "a dependency must cite the events behind it"


def test_dropdown_catalogs_reflect_only_the_final_document(investigation_output: Path):
    """Pins a KNOWN LIMITATION, not a desirable behaviour.

    `extract_active_introspection` runs once, at exit, on the top frame only, so
    a full navigation destroys every catalog collected before it. The scripted
    workflow ends on /page2, so the index page's `ville` and `garage` catalogs
    are gone and only page2's `p2-etat` survives.

    Read from the runtime_hooks event since dropdown_catalogs.json was retired;
    the catalog NAMES were always carried on that event too.

    This assertion exists so that when the limitation is fixed, this test fails
    and forces the change to be noticed and explained rather than absorbed into
    a re-blessed baseline.
    """
    from scriptscrap.events import EventLogReader, EventType

    hooks = EventLogReader(investigation_output / "events.jsonl").of_type(
        EventType.RUNTIME_HOOKS)
    assert hooks, "no runtime_hooks event was emitted"
    catalogs = set()
    for event in hooks:
        catalogs.update(event.payload.get("dropdown_catalogs") or [])

    assert "p2-etat" in catalogs, "final document's dropdown catalog missing"
    assert "ville" not in catalogs, (
        "an index-page catalog survived a full navigation -- the read-once-at-exit "
        "limitation appears to be fixed. Update this test and known_blind_spots."
    )
    manifest = json.loads(
        (investigation_output / "session_manifest.json").read_text("utf-8"))
    assert any(
        "destroyed by every full page navigation" in note
        for note in manifest["known_blind_spots"]
    ), "the limitation must stay documented in the manifest"


def test_dom_structure_captures_forms_across_frames(investigation_output: Path):
    """Was read from dom_structure.json.

    The dom_snapshot event counted frames but did not name them, so the frame
    URLs were added to it as part of retiring that file -- a scan that reaches
    the outer frame but not the nested one is exactly how a cross-frame form
    gets lost, and a count cannot show that.
    """
    from scriptscrap.events import EventLogReader, EventType

    snapshots = EventLogReader(investigation_output / "events.jsonl").of_type(
        EventType.DOM_SNAPSHOT)
    assert snapshots, "no DOM snapshots captured"
    frame_urls = {u for s in snapshots for u in (s.payload.get("frame_urls") or [])}
    assert any("/frame/outer" in u for u in frame_urls), frame_urls
    assert any("/frame/inner" in u for u in frame_urls), frame_urls


def test_every_observed_status_is_recorded(derived):
    """Was read from mcma_openapi_spec.json; now from the derived endpoints.

    `statuses` is a status -> count map keyed by string, so a status that was
    observed once and one observed forty times are both visible.
    """
    by_path = {urlparse(e.template).path or e.template: e for e in derived.endpoints}
    assert "500" in by_path["/api/error"].statuses, by_path["/api/error"].statuses
    assert "200" in by_path["/api/dossier"].statuses, by_path["/api/dossier"].statuses


# The out-of-scope response status that out_of_scope_metadata.json was the only
# record of is pinned in tests/test_out_of_scope_spine.py, driven directly. The
# fixture app is entirely in scope by construction, so a capture against it has
# no out-of-scope traffic and could only assert this by reaching the internet.


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
    assert manifest["event_spine"]["mode"] == "authoritative"


def test_event_spine_is_dual_written_and_intact(investigation_snapshot):
    events = investigation_snapshot["events.jsonl"]
    assert events["problems"] == []
    assert events["seq_is_dense"]
    assert events["first_type"] == "session_start"
    assert events["last_type"] == "session_end"
    assert events["by_type"]["http_request"] >= 11
    assert events["by_type"]["http_response"] >= 11
    assert events["by_type"]["capture_gap"] >= 1


def test_the_event_log_is_now_the_only_record(investigation_output: Path):
    """Dual-write is over.

    The nine legacy files were the behavioural authority while the spine was
    being proven. They are gone, so the log has to carry everything they did --
    which means it must not be empty, and analysis of it must produce the
    knowledge those files used to state directly.
    """
    from scriptscrap.analysis import analyze_log

    log = investigation_output / "events.jsonl"
    assert log.exists()
    result = analyze_log(log)
    assert result.event_count > 0, "the log is now the only record and it is empty"
    assert result.endpoints, "no endpoints derived; network_traffic.json had no successor"
    assert result.ui_elements, "no UI elements derived"
    assert result.states, "no states derived"


def test_every_conclusion_can_be_walked_back_to_evidence(derived):
    """The property that justified retiring the legacy files.

    Those files asserted facts. The derived model cites the events behind each
    one, which is strictly more than they offered -- but only if every record
    actually carries its evidence.
    """
    for endpoint in derived.endpoints:
        assert endpoint.evidence.event_ids, f"endpoint {endpoint.key} cites no evidence"
    for schema in derived.schemas:
        assert schema.evidence.event_ids, f"schema {schema.endpoint_key} cites no evidence"
    for state in derived.states:
        assert state.evidence.event_ids, f"state {state.label} cites no evidence"


def test_the_evidence_index_covers_the_whole_log(investigation_output: Path):
    """Every event is addressable, and every offset points at its own line."""
    import json as _json

    from scriptscrap.analysis import analyze_log

    log = investigation_output / "events.jsonl"
    result = analyze_log(log)
    raw = log.read_bytes()

    assert len(result.event_index) == result.event_count
    assert result.log_size == log.stat().st_size
    for row in result.event_index:
        line = raw[row.byte_offset:row.byte_offset + row.byte_length]
        assert _json.loads(line)["event_id"] == row.event_id


@pytest.mark.browser
def test_the_investigator_retains_no_unwritten_network_log(investigation_output):
    """`self.network_log` accumulated every request's headers and body in
    memory for the whole session and was written nowhere after the legacy
    outputs were retired -- re-creating the memory profile the event log was
    introduced to eliminate."""
    from scriptscrap.testing.capture import load_investigator

    module = load_investigator(investigation_output)
    scope = module.InvestigationScope("http://127.0.0.1:1")
    engine = module.WebHarvester("http://127.0.0.1:1", scope, session_id="s")
    dead = [name for name in
            ("network_log", "dom_snapshots", "value_dependencies",
             "openapi_paths", "out_of_scope", "value_origins")
            if hasattr(engine, name)]
    assert dead == [], f"unwritten in-memory buffers still exist: {dead}"


@pytest.mark.browser
def test_the_manifest_still_counts_out_of_scope_endpoints(investigation_snapshot):
    counters = investigation_snapshot["session_manifest.json"]["counters"]
    assert "out_of_scope_endpoints" in counters
    assert isinstance(counters["out_of_scope_endpoints"], int)
