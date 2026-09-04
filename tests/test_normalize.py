"""Normalisation must remove nondeterminism and nothing else."""

from __future__ import annotations

from scriptscrap.testing import normalize, normalize_text, sort_network_log


def test_removes_timestamps():
    assert normalize_text("at 2026-09-04T11:02:33.418+00:00 ok") == "at <TS> ok"
    assert normalize_text("2026-09-04T11:02:33Z") == "<TS>"


def test_removes_session_ids():
    assert normalize_text("sess-20260904-110233") == "<SESSION>"


def test_removes_ephemeral_ports_but_keeps_the_path():
    assert (
        normalize_text("http://127.0.0.1:51763/api/dossier?id=44718")
        == "http://127.0.0.1:<PORT>/api/dossier?id=44718"
    )


def test_removes_ephemeral_port_from_a_bare_host_header():
    """A `Host:` header has no scheme; it still varies per run."""
    assert normalize_text("127.0.0.1:63203") == "127.0.0.1:<PORT>"
    assert normalize_text("localhost:8931") == "localhost:<PORT>"


def test_removes_clock_from_artifact_names_but_keeps_step_number():
    assert normalize_text("step_003_142317.png") == "step_003_<TS>.png"


def test_pinned_environment_values_are_replaced_by_key():
    env = {"python": "3.14.0", "camoufox_lib": "0.5.5", "camoufox_browser_build": "152.0.4-beta.28"}
    assert normalize(env) == {
        "python": "<PINNED>",
        "camoufox_lib": "<PINNED>",
        "camoufox_browser_build": "<PINNED>",
    }


def test_monotonic_clock_is_replaced_by_key():
    assert normalize({"t_mono": 88231.442}) == {"t_mono": "<MONO>"}


def test_transport_metrics_are_normalised_but_event_counts_are_not():
    """How many IPC batches carried the events is not behaviour; how many events is."""
    assert normalize({"batches": 9, "events": 34}) == {
        "batches": "<TRANSPORT>",
        "events": 34,
    }


def test_behaviour_is_never_normalised_away():
    """The whole point: things that describe what happened must survive."""
    payload = {
        "method": "POST",
        "path": "/api/valider",
        "status": 200,
        "missionId": "M-FIXTURE-0001",
        "fields": [{"name": "nom", "required": True}],
        "statuses": [200, 500],
        "endpoints_in_scope": 7,
    }
    assert normalize(payload) == payload


def test_normalisation_is_recursive():
    nested = {"a": [{"b": {"t": "2026-01-01T00:00:00Z"}}]}
    assert normalize(nested) == {"a": [{"b": {"t": "<TS>"}}]}


def test_network_log_ordering_is_stable_but_lossless():
    entries = [
        {"method": "POST", "url": "http://h/b", "body": {"x": 1}},
        {"method": "GET", "url": "http://h/a", "body": None},
        {"method": "GET", "url": "http://h/c", "body": None},
    ]
    ordered = sort_network_log(entries)
    assert [e["url"] for e in ordered] == ["http://h/a", "http://h/c", "http://h/b"]
    assert len(ordered) == len(entries)
    assert sort_network_log(list(reversed(entries))) == ordered


def test_two_runs_of_identical_behaviour_normalise_equal():
    run_a = {
        "time": "2026-09-04T11:02:33.418+00:00",
        "session_id": "sess-20260904-110233",
        "url": "http://127.0.0.1:51763/api/dossier",
        "artifact": "step_001_110233.png",
        "status": 200,
    }
    run_b = {
        "time": "2026-09-05T18:44:01.002+00:00",
        "session_id": "sess-20260905-184401",
        "url": "http://127.0.0.1:60112/api/dossier",
        "artifact": "step_001_184401.png",
        "status": 200,
    }
    assert normalize(run_a) == normalize(run_b)


def test_differing_behaviour_still_differs_after_normalisation():
    run_a = {"url": "http://127.0.0.1:51763/api/dossier", "status": 200}
    run_b = {"url": "http://127.0.0.1:60112/api/dossier", "status": 500}
    assert normalize(run_a) != normalize(run_b)
