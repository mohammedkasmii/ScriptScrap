"""M3 inference against the real fixture-captured log.

Offline: the log is committed, so this runs with no browser. The synthetic tests
in `test_analysis.py` prove each rule in isolation; these prove the whole
pipeline derives the seeded cases from evidence a real browser actually produced.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
from golden_support import SAMPLE_EVENT_LOG

from scriptscrap.analysis import analyze_log
from scriptscrap.analysis.report import render


@pytest.fixture(scope="module")
def result():
    return analyze_log(SAMPLE_EVENT_LOG)


# --- endpoints -----------------------------------------------------------

def test_sibling_item_paths_are_templated(result):
    templated = [e for e in result.endpoints if e.templated]
    assert templated, "no endpoint was templated from the seeded sibling paths"
    items = next(e for e in templated if "/api/items/" in e.template)
    assert items.template == "/api/items/{itemId}"
    # The three items are fetched twice, so six requests collapse to one route
    # while every concrete path is retained.
    assert items.observation_count == 6
    assert sorted(items.concrete_paths) == [
        "/api/items/101", "/api/items/102", "/api/items/103"]


def test_graphql_operation_is_its_own_endpoint(result):
    graphql = [e for e in result.endpoints if e.kind == "graphql"]
    assert graphql, "the GraphQL mutation was not given its own endpoint"
    assert graphql[0].graphql_operation == "ValiderItem"
    assert graphql[0].graphql_operation_type == "mutation"


def test_query_parameters_are_retained(result):
    page2 = next(e for e in result.endpoints if e.template == "/page2")
    names = {p.name for p in page2.params}
    assert {"nom", "ville", "missionId"} <= names


# --- schemas -------------------------------------------------------------

def test_optional_field_detected_from_the_seeded_item(result):
    """`note` is present on item 102 only."""
    schema = next(s for s in result.schemas
                  if "/api/items/{itemId}" in s.endpoint_key and s.direction == "response")
    fields = {f.path: f for f in schema.fields}
    assert schema.sample_count == 6, "three items fetched twice"
    assert fields["$.note"].observed_optional is True
    assert fields["$.note"].present_count == 2, "present on item 102 only, seen twice"
    assert fields["$.reference"].observed_optional is False
    assert fields["$.reference"].present_count == 6


def test_enum_candidate_detected_from_the_seeded_status(result):
    schema = next(s for s in result.schemas
                  if "/api/items/{itemId}" in s.endpoint_key and s.direction == "response")
    statut = {f.path: f for f in schema.fields}["$.statut"]
    assert statut.enum_candidate == ["ARCHIVE", "OK"]


# --- dependencies --------------------------------------------------------

def test_seeded_unique_dependency_is_found(result):
    """reference -> itemReference, across differently-named fields."""
    edge = next(
        (d for d in result.dependencies
         if d.source_field == "$.reference" and d.target_field == "$.itemReference"),
        None,
    )
    assert edge is not None, [d.label for d in result.dependencies]
    assert edge.mechanism == "response_to_request"
    assert edge.confidence >= 0.7
    assert edge.evidence.signals["unique_value_match"] is True
    assert 0 < edge.evidence.signals["field_name_similarity"] < 1.0
    assert len(edge.evidence.event_ids) >= 2


def test_seeded_common_values_are_rejected(result):
    """`statut: "OK"` and `actif: 1` travel the same path and must NOT correlate."""
    noise = [d for d in result.dependencies
             if d.source_field.endswith((".statut", ".actif"))
             or d.target_field.endswith((".statut", ".actif"))]
    assert noise == [], f"common values produced edges: {[d.label for d in noise]}"


def test_every_dependency_carries_its_evidence(result):
    for edge in result.dependencies:
        assert edge.evidence.event_ids
        assert "ordering_method" in edge.evidence.signals
        assert edge.mechanism != ""


def test_no_dependency_relies_on_cross_sensor_ingest_order(result):
    """M2 proved seq is ingest order; nothing may claim causality from it."""
    for edge in result.dependencies:
        method = edge.evidence.signals.get("ordering_method")
        assert method in {"probe_ordinal", "same_source_seq", "wall_clock"}, method


# --- selectors -----------------------------------------------------------

def test_regenerating_id_scores_badly_and_is_not_recommended(result):
    element = next(
        (u for u in result.ui_elements
         if (u.label or u.text or "") == "Action instable"), None)
    assert element is not None, "the unstable control was not observed"
    by_strategy = {loc.strategy: loc for loc in element.locators}
    assert by_strategy["id"].stability < 1.0
    assert by_strategy["id"].warning
    assert element.recommended.strategy != "id"
    assert element.recommended.stability == 1.0


def test_stable_controls_get_a_confident_locator(result):
    stable = [u for u in result.ui_elements
              if u.recommended and u.recommended.stability == 1.0]
    assert len(stable) >= 5


# --- states --------------------------------------------------------------

def test_three_spa_states_are_reconstructed(result):
    patterns = {s.url_pattern for s in result.states}
    assert {"/#/liste", "/#/detail/{id}", "/#/resume"} <= patterns
    assert result.transitions
    for transition in result.transitions:
        assert transition.evidence.event_ids
        assert "attribution" in transition.evidence.signals


# --- technology ----------------------------------------------------------

def test_graphql_technology_detected(result):
    names = {t.name for t in result.technologies}
    assert "GraphQL" in names


# --- report --------------------------------------------------------------

def test_report_states_its_caveats(result):
    report = render(result)
    assert "# ScriptScrap investigation report" in report
    assert "not observed" in report
    assert "makes no completeness claim" in report
    assert "proof of requiredness" in report
    assert "/api/items/{itemId}" in report


def test_report_contains_no_fixture_secret(result):
    """The report is a shareable artifact."""
    report = render(result)
    for secret in ("FIXTURE_PASSWORD_DO_NOT_USE", "FIXTURE_CSRF_TOKEN_0001"):
        assert secret not in report, f"{secret} leaked into the report"


# --- CLI -----------------------------------------------------------------

def test_cli_analyze_and_export_run_offline(tmp_path):
    session = tmp_path / "session"
    session.mkdir()
    (session / "events.jsonl").write_text(
        SAMPLE_EVENT_LOG.read_text(encoding="utf-8"), encoding="utf-8")

    for command in ("analyze", "export"):
        proc = subprocess.run(
            [sys.executable, "-m", "scriptscrap.cli", command, str(session)],
            capture_output=True, text=True, check=False,
        )
        assert proc.returncode == 0, proc.stderr

    assert (session / "session.sqlite").exists()
    assert (session / "analysis" / "report.md").exists()
    dataset = session / "export" / "shared" / "dataset.json"
    assert dataset.exists()

    payload = json.loads(dataset.read_text(encoding="utf-8"))
    assert payload["endpoints"]
    blob = dataset.read_text(encoding="utf-8")
    for secret in ("FIXTURE_PASSWORD_DO_NOT_USE", "FIXTURE_CSRF_TOKEN_0001",
                   "fixture@example.test"):
        assert secret not in blob, f"{secret} leaked into the shared dataset"
