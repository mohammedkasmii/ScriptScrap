"""What each generator does and does not carry out of the session."""

from __future__ import annotations

from pathlib import Path

import pytest
from hostile import MARKER

from scriptscrap.generate import render_client, render_playwright

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"


def _marked():
    from test_export_policy import _marked_result
    return _marked_result()


def _value_marked():
    """A result carrying MARKER only where a captured VALUE would sit.

    Routes, parameter names, header names and the session id carry benign text
    instead. Those four ARE captured, and the client cannot function without
    them -- it exists to call the real routes with the real parameter names.
    The claim it must keep is narrower and is the one that matters: no observed
    VALUE reaches the file.
    """
    from scriptscrap.analysis.models import (
        AnalysisResult,
        Endpoint,
        Evidence,
        ParamObservation,
        Schema,
        SchemaField,
    )

    evidence = Evidence(event_ids=["evt-00000001"])
    return AnalysisResult(
        session_id="run-1", event_count=1,
        endpoints=[Endpoint(
            method="GET", template="/orders/{id}", kind="rest",
            observation_count=1, concrete_paths=["/orders/" + MARKER],
            statuses={"200": 1},
            params=[ParamObservation(
                name="status", location="query", inferred_type="string",
                sample_count=1, distinct_values=1, examples=[MARKER],
                enum_candidate=[MARKER])],
            evidence=evidence)],
        schemas=[Schema(
            endpoint_key="GET /orders/{id}", direction="response",
            sample_count=1, root_type="object", status="200",
            fields=[SchemaField(
                path="customer", types={"string": 1}, present_count=1,
                sample_count=1, examples=[MARKER], enum_candidate=[MARKER])],
            evidence=evidence)],
        auth_headers={"cookie": 1},
    )


def test_the_client_carries_no_captured_value():
    """This claim IS true for the client, and must stay true.

    An enum candidate used to reach the file as `one of: <values>`. It is a
    captured parameter value -- the same class of thing as `examples`, which
    this module has always refused to emit -- and a small distinct set is
    exactly the shape an API key takes in a short session.
    """
    source = render_client(_value_marked(), session_name="s")
    assert MARKER not in source
    assert "concrete_paths" not in source


def test_the_client_does_carry_routes_and_names_and_that_is_the_trade():
    """Stated, not hidden: the exception is exactly routes and names.

    A generated client that called sanitised routes would call nothing. The
    documented boundary is values, and this pins where the line sits so a later
    change cannot quietly move it.
    """
    source = render_client(_value_marked(), session_name="s")
    assert "/orders/{id}" in source
    assert "status" in source
    assert "cookie" in source


def test_the_default_playwright_script_carries_locators_and_says_so():
    source = render_playwright(_marked(), session_name="s")
    assert MARKER in source, "a usable locator is a captured value"
    assert "UNREDACTED" in source
    assert "--sanitised" in source


def test_the_cli_says_unredacted_before_and_after_writing(tmp_path, capsys):
    """The same warning cmd_workspace prints at the point of exposure."""
    import shutil

    from scriptscrap.cli import build_parser

    session = tmp_path / "session"
    session.mkdir()
    shutil.copy(SAMPLE, session / "events.jsonl")
    args = build_parser().parse_args(["generate", "playwright", str(session)])
    assert args.func(args) == 0
    printed = capsys.readouterr().out
    assert "UNREDACTED" in printed
    assert "--sanitised" in printed


def test_the_help_text_says_unredacted():
    from scriptscrap.cli import build_parser

    generate = [a for a in build_parser()._subparsers._group_actions
                if hasattr(a, "choices")][0].choices["generate"].format_help()
    assert "UNREDACTED" in generate
    assert "--sanitised" in generate


def test_the_sanitised_playwright_script_carries_no_captured_value():
    source = render_playwright(_marked(), session_name="s", sanitised=True)
    assert MARKER not in source
    compile(source, "observed_workflow.py", "exec")


def test_the_sanitised_script_names_every_locator_it_removed():
    """Not a silent substitution: the reader must be able to see which steps
    lost their locator and how many."""
    source = render_playwright(_marked(), session_name="s", sanitised=True)
    assert "LOCATOR REMOVED" in source
    assert "NOT RUNNABLE" in source


def test_the_sanitised_script_refuses_to_run_when_a_locator_was_removed():
    """It compiles -- that is a hostile-input requirement -- but it must not
    drive a browser at selectors that cannot match."""
    source = render_playwright(_marked(), session_name="s", sanitised=True)
    namespace: dict = {}
    exec(compile(source, "observed_workflow.py", "exec"), namespace)  # noqa: S102
    with pytest.raises(SystemExit) as excinfo:
        namespace["main"]()
    assert "locator" in str(excinfo.value).lower()


def test_a_sanitised_script_with_no_removed_locators_still_runs():
    """The refusal is conditional on something actually having been removed."""
    from scriptscrap.analysis.models import (
        AnalysisResult,
        Evidence,
        LocatorCandidate,
        UIElement,
        WorkflowStep,
    )

    result = AnalysisResult(session_id="s", event_count=1, ui_elements=[
        UIElement(key="k", tag="input", role="textbox", label=None, text=None,
                  form=None, observation_count=1, actions={"user_click": 1},
                  locators=[LocatorCandidate(strategy="css", value="#login",
                                             resolved_count=1, sample_count=1)],
                  evidence=Evidence(event_ids=["e"]))],
        workflow=[WorkflowStep(ordinal=0, seq=1, kind="click", element_key="k",
                               evidence=Evidence(event_ids=["e"]))])
    source = render_playwright(result, session_name="s", sanitised=True)
    assert "LOCATOR REMOVED" not in source
    assert "#login" in source


def test_the_client_generator_rejects_sanitised(tmp_path):
    """--sanitised is a property of the Playwright script. Accepting it for the
    client would imply the client had something to sanitise."""
    import shutil

    from scriptscrap.cli import build_parser

    session = tmp_path / "session"
    session.mkdir()
    shutil.copy(SAMPLE, session / "events.jsonl")
    args = build_parser().parse_args(
        ["generate", "client", str(session), "--sanitised"])
    with pytest.raises(SystemExit) as excinfo:
        args.func(args)
    assert "playwright" in str(excinfo.value)
