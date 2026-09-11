"""Every generator interpolation site, against the whole hostile corpus.

The audit ran 123 probes across six sites and 33 failed. This is that matrix,
made permanent. It asserts a behaviour -- the module compiles -- not the
presence of an escape sequence.
"""

from __future__ import annotations

import ast

import pytest
from hostile import HOSTILE

from scriptscrap.analysis.models import (
    AnalysisResult,
    AppState,
    Endpoint,
    Evidence,
    LocatorCandidate,
    ParamObservation,
    StateTransition,
    UIElement,
)
from scriptscrap.generate import render_client, render_playwright

CORPUS = sorted(HOSTILE)


def _endpoint(*, template="/x", param_name=None, evidence_id="evt-1", enum=None):
    params = []
    if param_name is not None:
        params = [ParamObservation(
            name=param_name, location="query", inferred_type="string",
            sample_count=1, distinct_values=1, examples=[param_name],
            enum_candidate=enum)]
    return Endpoint(
        method="GET", template=template, kind="rest", observation_count=1,
        concrete_paths=[template], statuses={"200": 1}, params=params,
        evidence=Evidence(event_ids=[evidence_id]))


def _client_result(endpoint):
    return AnalysisResult(session_id="s", event_count=1, endpoints=[endpoint])


# --- client -------------------------------------------------------------

@pytest.mark.parametrize("name", CORPUS)
def test_client_compiles_with_a_hostile_template(name):
    source = render_client(_client_result(_endpoint(template="/x/" + HOSTILE[name])),
                           session_name="s")
    compile(source, "generated_client.py", "exec")


@pytest.mark.parametrize("name", CORPUS)
def test_client_compiles_with_a_hostile_param_name(name):
    source = render_client(
        _client_result(_endpoint(param_name=HOSTILE[name], enum=[HOSTILE[name]])),
        session_name="s")
    compile(source, "generated_client.py", "exec")


@pytest.mark.parametrize("name", CORPUS)
def test_client_compiles_with_a_hostile_evidence_id(name):
    source = render_client(_client_result(_endpoint(evidence_id=HOSTILE[name])),
                           session_name="s")
    compile(source, "generated_client.py", "exec")


@pytest.mark.parametrize("name", CORPUS)
def test_client_compiles_with_a_hostile_session_name(name):
    source = render_client(_client_result(_endpoint()), session_name=HOSTILE[name])
    compile(source, "generated_client.py", "exec")


@pytest.mark.parametrize("name", CORPUS)
def test_client_compiles_with_a_hostile_session_id(name):
    result = _client_result(_endpoint())
    result.session_id = HOSTILE[name]
    compile(render_client(result, session_name="s"), "generated_client.py", "exec")


def test_two_holes_that_normalise_alike_get_distinct_arguments():
    """`/a/{x-1}/{x_1}` produced `duplicate argument 'x_1'`."""
    source = render_client(_client_result(_endpoint(template="/a/{x-1}/{x_1}")),
                           session_name="s")
    compile(source, "generated_client.py", "exec")


def test_holes_that_clean_to_nothing_get_distinct_arguments():
    """`/a/{--}/{__}` produced `duplicate argument 'value'`."""
    source = render_client(_client_result(_endpoint(template="/a/{--}/{__}")),
                           session_name="s")
    compile(source, "generated_client.py", "exec")


def test_a_captured_brace_is_not_evaluated_as_an_expression():
    """`f"{path_expr}"` made the template executable.

    Asserted on the syntax tree, not on the text: the captured template still
    APPEARS in the file, as a `# route:` comment and as the source of a
    sanitised argument name, and both of those are data. What must not exist
    is a call node for it.
    """
    template = "/x/{__import__('os').getcwd()}"
    source = render_client(_client_result(_endpoint(template=template)),
                           session_name="s")
    tree = ast.parse(source)
    called = {node.func.id for node in ast.walk(tree)
              if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert "__import__" not in called, "the template became executable code"
    assert not any(isinstance(node, ast.JoinedStr) for node in ast.walk(tree)), \
        "no f-string may carry a captured value"


def test_two_routes_that_normalise_to_one_name_both_survive():
    result = AnalysisResult(session_id="s", event_count=1, endpoints=[
        _endpoint(template="/a-b"), _endpoint(template="/a_b")])
    source = render_client(result, session_name="s")
    compile(source, "generated_client.py", "exec")
    # `HEADER` defines four: __aenter__, __aexit__, aclose, _call.
    assert source.count("async def ") == 2 + 4
    tree = ast.parse(source)
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef))
    names = {n.name for n in cls.body if isinstance(n, ast.AsyncFunctionDef)}
    assert len(names - {"__aenter__", "__aexit__", "aclose", "_call"}) == 2, \
        "a route was dropped rather than suffixed"


# --- playwright ---------------------------------------------------------

def _ui(value: str) -> UIElement:
    return UIElement(
        key=value, tag="input", role="textbox", label=value, text=value,
        form=value, observation_count=1, actions={"user_click": 1},
        locators=[LocatorCandidate(strategy="css", value=value,
                                   resolved_count=1, sample_count=1)],
        evidence=Evidence(event_ids=["evt-1"]))


@pytest.mark.parametrize("name", CORPUS)
def test_playwright_compiles_with_a_hostile_locator(name):
    result = AnalysisResult(session_id="s", event_count=1,
                            ui_elements=[_ui(HOSTILE[name])])
    compile(render_playwright(result, session_name="s"),
            "observed_workflow.py", "exec")


@pytest.mark.parametrize("name", CORPUS)
def test_playwright_compiles_with_a_hostile_url_pattern(name):
    result = AnalysisResult(session_id="s", event_count=1, states=[
        AppState(fingerprint="f", label="ok", url_pattern="/" + HOSTILE[name],
                 observation_count=1)])
    compile(render_playwright(result, session_name="s"),
            "observed_workflow.py", "exec")


@pytest.mark.parametrize("name", CORPUS)
def test_playwright_compiles_with_a_hostile_state_label(name):
    result = AnalysisResult(session_id="s", event_count=1, states=[
        AppState(fingerprint="f", label=HOSTILE[name], url_pattern="/a",
                 observation_count=1)])
    compile(render_playwright(result, session_name="s"),
            "observed_workflow.py", "exec")


@pytest.mark.parametrize("name", CORPUS)
def test_playwright_compiles_with_a_hostile_transition_trigger(name):
    result = AnalysisResult(session_id="s", event_count=1, transitions=[
        StateTransition(from_state="a", to_state="b", trigger=HOSTILE[name],
                        observation_count=1)])
    compile(render_playwright(result, session_name="s"),
            "observed_workflow.py", "exec")


@pytest.mark.parametrize("name", CORPUS)
def test_playwright_compiles_with_a_hostile_session_name(name):
    result = AnalysisResult(session_id="s", event_count=1, ui_elements=[_ui("ok")])
    compile(render_playwright(result, session_name=HOSTILE[name]),
            "observed_workflow.py", "exec")


def test_a_captured_url_pattern_cannot_execute_a_statement(tmp_path):
    """The audit wrote a file to disk through AppState.url_pattern."""
    sentinel = tmp_path / "PWNED.txt"
    payload = ('/a")\nimport pathlib; pathlib.Path(r"' + str(sentinel)
               + '").write_text("owned")\nif 0: page.goto("')
    result = AnalysisResult(session_id="s", event_count=1, states=[
        AppState(fingerprint="f", label="ok", url_pattern=payload,
                 observation_count=1)])
    source = render_playwright(result, session_name="s")
    namespace: dict = {}
    exec(compile(source, "observed_workflow.py", "exec"), namespace)  # noqa: S102
    assert not sentinel.exists(), "a captured URL pattern executed a statement"
