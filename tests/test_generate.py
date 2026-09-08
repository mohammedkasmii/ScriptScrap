"""Phase 3 generators: derived model in, usable starting point out.

The retired `generated_client.py` promised in a docstring that it carried no
captured credentials, and nothing enforced that. Its only check was a
golden-master summary of the file's text, which disappeared with it. Those
promises are tests here, and they are the reason this module is allowed to
exist at all: a generator that writes an operator's live session into a file
on disk is worse than no generator.

The generated output is a **suggestion**. It is derived from what was observed
in one session, and the header of every file says so, because a developer who
believes a generated client describes the whole API will be wrong in a way that
is hard to discover.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scriptscrap.analysis import analyze_log
from scriptscrap.generate import render_client, render_playwright

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"

# Values the fixture plants specifically so a leak has something to trip on.
# "Alice Benali" is operator PII and IS present in the sample log, so a
# generator that echoed captured values would fail on it.
PLANTED = [
    "fixture-password-not-a-real-secret",
    "FIXTURE-CSRF-TOKEN-0001",
    "FIXTURE-SESSION-0001",
    "Alice Benali",
]


@pytest.fixture(scope="module")
def result():
    return analyze_log(SAMPLE)


@pytest.fixture(scope="module")
def client(result):
    return render_client(result, session_name="fixture")


@pytest.fixture(scope="module")
def script(result):
    return render_playwright(result, session_name="fixture")


@pytest.fixture(scope="module")
def script_of_empty():
    from scriptscrap.analysis.models import AnalysisResult
    return render_playwright(AnalysisResult(session_id="s", event_count=0),
                             session_name="empty")


# --- the analysis this rests on -------------------------------------------

def test_auth_headers_are_derived_by_name(result):
    """Names only. The capture never held the values."""
    assert result.auth_headers
    assert "cookie" in result.auth_headers
    assert result.auth_headers["cookie"] > 0


# --- both outputs ---------------------------------------------------------

@pytest.mark.parametrize("fixture_name", ["client", "script"])
def test_output_is_valid_python(request, fixture_name):
    source = request.getfixturevalue(fixture_name)
    compile(source, f"{fixture_name}.py", "exec")


@pytest.mark.parametrize("fixture_name", ["client", "script"])
def test_no_planted_secret_appears(request, fixture_name):
    source = request.getfixturevalue(fixture_name)
    for secret in PLANTED:
        assert secret not in source, f"{fixture_name} leaked {secret!r}"


@pytest.mark.parametrize("fixture_name", ["client", "script"])
def test_the_header_names_the_session_and_says_it_is_derived(request, fixture_name):
    source = request.getfixturevalue(fixture_name)
    assert "fixture" in source
    assert "observed" in source.lower()
    assert "generated" in source.lower()


# --- the client -----------------------------------------------------------

def test_client_reads_credentials_from_the_environment(client):
    assert "SCRIPTSCRAP_AUTH_HEADERS" in client


def test_client_never_disables_tls_verification(client):
    """A generated client that turns off verification to 'just work' against a
    self-signed staging cert teaches the reader to ship that."""
    assert "verify=False" not in client
    assert "verify=" in client


def test_client_documents_the_credential_headers_by_name(client):
    """The reader has to know WHAT to supply, having been given no values."""
    assert "cookie" in client.lower()
    assert "credential" in client.lower()


def test_every_endpoint_becomes_a_method(client, result):
    rest = [e for e in result.endpoints if e.kind == "rest"]
    assert rest
    for endpoint in rest:
        assert endpoint.template in client, f"{endpoint.key} has no method"


def test_a_templated_path_becomes_a_parameter(client, result):
    templated = [e for e in result.endpoints if e.templated]
    if not templated:
        pytest.skip("this session derived no templated route")
    # `/api/items/{id}` must become an f-string hole, not a literal path.
    assert "{" in client


def test_methods_carry_their_observation_count(client):
    """Reading "observed 40x" beside "observed once" is the difference between
    a described API and a guess."""
    assert "observed" in client.lower()


def test_the_client_is_importable_as_a_module(client, tmp_path):
    """Compiles is not enough -- it has to import without a live session."""
    module = tmp_path / "generated_client.py"
    module.write_text(client, encoding="utf-8")
    import subprocess
    import sys
    proc = subprocess.run(
        [sys.executable, "-c",
         f"import importlib.util,sys;"
         f"spec=importlib.util.spec_from_file_location('gen', r'{module}');"
         f"m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);"
         f"print('OK')"],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout


def test_no_query_values_are_embedded(client, result):
    """A GET form submission puts every field in the query string, so a
    captured URL routinely carries passwords and personal data."""
    for endpoint in result.endpoints:
        for path in endpoint.concrete_paths:
            if "?" in path:
                assert path not in client, f"a captured query string was embedded: {path}"


# --- the playwright script ------------------------------------------------

def test_the_script_fills_an_element_that_was_typed_into(result, script):
    """0 fills for 19 user_input elements on the real capture, because
    _action_for tested 'input' against an actions dict keyed 'user_input'."""
    typed = [s for s in result.workflow if s.kind == "fill"]
    assert typed, "the sample log records no typing"
    assert script.count(".fill(") >= 1


def test_every_workflow_kind_reaches_a_playwright_call(result, script):
    calls = {
        "click": ".click()",
        "fill": ".fill(",
        "select": ".select_option(",
        "check": ".check()",
        "submit": ".click()",
        "navigate": "page.goto(",
    }
    for kind in {s.kind for s in result.workflow}:
        if kind == "press":
            continue          # covered by the two press tests below
        assert calls[kind] in script, f"{kind} produced no call"


def test_every_step_is_visible_in_the_script(result, script):
    """One marker per workflow step, so the script IS the workflow. A press
    with no recorded key still appears -- as a TODO, not as a call."""
    body = script.split("def run(page)", 1)[1]
    for step in result.workflow:
        assert f"# step {step.ordinal}:" in body, f"step {step.ordinal} missing"
    assert body.count("# step ") == len(result.workflow)


def _one_step_result(**step_fields):
    """A result holding one element and one step against it."""
    from scriptscrap.analysis.models import (
        AnalysisResult,
        Evidence,
        LocatorCandidate,
        UIElement,
        WorkflowStep,
    )

    element = UIElement(key="k", tag="input", role="textbox", label="Nom",
                        text=None, form=None, observation_count=1,
                        actions={"user_key": 1},
                        locators=[LocatorCandidate(strategy="css", value="#nom",
                                                   resolved_count=1, sample_count=1)],
                        evidence=Evidence(event_ids=["e"]))
    return AnalysisResult(
        session_id="s", event_count=1, ui_elements=[element],
        workflow=[WorkflowStep(ordinal=0, seq=1, element_key="k",
                               evidence=Evidence(event_ids=["e"]), **step_fields)])


def test_a_press_with_an_allowlisted_key_becomes_a_press_call():
    source = render_playwright(_one_step_result(kind="press", key="Tab"),
                               session_name="s")
    assert ".press(" + repr("Tab") + ")" in source
    compile(source, "observed_workflow.py", "exec")


def test_a_press_with_no_recorded_key_emits_a_todo_and_no_call():
    """press("Enter") for an unknown key is a keystroke the application never
    received -- and Enter is the key most likely to submit a form."""
    source = render_playwright(_one_step_result(kind="press", key=None),
                               session_name="s")
    # The TODO shows the operator the call to write; no line CALLS press.
    assert not [line for line in source.splitlines()
                if ".press(" in line and not line.lstrip().startswith("#")]
    assert "TODO" in source
    assert "# step 0: press" in source
    compile(source, "observed_workflow.py", "exec")


def test_the_script_starts_where_the_session_started(result, script):
    """The entry state was chosen from a list sorted by observation count."""
    first_navigate = next(s for s in result.workflow if s.kind == "navigate")
    goto = next(line for line in script.splitlines() if "page.goto(" in line)
    assert first_navigate.url_pattern in goto


def test_steps_appear_in_observed_order(result, script):
    """Not frequency order: the emitted order must match `ordinal`."""
    body = script.split("def run(page)", 1)[1]
    positions = []
    for step in result.workflow:
        marker = f"# step {step.ordinal}:"
        assert marker in body, f"step {step.ordinal} was not emitted"
        positions.append(body.index(marker))
    assert positions == sorted(positions)


def test_no_transition_claims_an_element_was_not_recorded_when_it_was(result, script):
    """47 of 47 said so on the real capture, several naming a real element."""
    keys = {e.key for e in result.ui_elements}
    unjoined = [t for t in result.transitions
                if t.trigger_element_key and t.trigger_element_key not in keys]
    assert unjoined == []
    for transition in result.transitions:
        if transition.trigger_element_key in keys:
            assert f"no element was recorded for {transition.trigger}" not in script


def test_a_repeated_step_says_how_many_times(result, script):
    repeated = [s for s in result.workflow if s.repeat_count > 1]
    if not repeated:
        pytest.skip("the sample log has no repeated step")
    assert f"x{repeated[0].repeat_count}" in script


def test_a_session_with_no_workflow_says_so(script_of_empty):
    assert "no workflow to replay" in script_of_empty.lower()


def test_script_flags_the_locator_it_actually_chose_if_unstable():
    """A locator below 100% matched zero or several nodes on some observation.

    Only the CHOSEN locator matters: an element with a stable candidate and an
    unstable one is generated from the stable one, and warning about the road
    not taken would be noise. So this drives the chooser directly rather than
    waiting for a session that happens to contain a shaky best candidate.
    """
    from scriptscrap.generate.playwright import _locator_call

    class _Locator:
        strategy, value = "css", "#btn"
        stability, resolved_count, sample_count = 0.5, 2, 4
        warning = "matched 2 nodes"

    class _Element:
        locators = [_Locator()]

    call, warning = _locator_call(_Element())
    # The locator value is emitted through `repr()` now, which quotes with
    # apostrophes. What matters is that it is one inert literal, so the
    # assertion is on the evaluated call rather than on the quote character.
    assert call == "page.locator(" + repr("#btn") + ")"
    assert "UNSTABLE" in warning
    assert "50%" in warning
    assert "matched 2 nodes" in warning


def test_a_stable_locator_carries_no_warning():
    from scriptscrap.generate.playwright import _locator_call

    class _Locator:
        strategy, value = "css", "#btn"
        stability, resolved_count, sample_count = 1.0, 4, 4
        warning = None

    class _Element:
        locators = [_Locator()]

    assert _locator_call(_Element())[1] is None


@pytest.mark.parametrize("value,flagged", [
    ('[data-id="1665b2ba-e3b3-4aa6-8a37-032b059e4d53"]', True),   # uuid
    ("#row-1788636921876", True),                                  # timestamp
    ("#a3f9c1d2e4b5a6f70819", True),                               # long hex
    ("#ITEM-0001", True),                                          # code
    ("#search-input", False),                                      # a real name
    (".btn-primary", False),
    ("#h2", False),                                                # short digit
    # Framework utility classes. Real runs flagged `g-3`, then `row-md-6`,
    # `col-sm-12` and `flex-shrink-0` once a length threshold was tried. A
    # warning that fires on Bootstrap is a warning nobody reads.
    (".row.g-3", False),
    (".col-2.mb-3.w-50", False),
    ("#nav-2", False),
    (".row-md-6.col-sm-12", False),
    (".flex-shrink-0", False),
    (".grid-cols-12", False),
])
def test_a_locator_carrying_a_volatile_id_is_flagged(value, flagged):
    """Found by generating from a real capture.

    Two UUIDs reached the generated script. They were perfectly STABLE -- they
    resolved to one node on every observation of that session -- so stability
    said nothing was wrong. They are also worthless in any other session, which
    is the failure a developer would hit on the first run and struggle to
    explain.
    """
    from scriptscrap.generate.playwright import _locator_call

    class _Locator:
        strategy = "css"
        stability, resolved_count, sample_count = 1.0, 4, 4
        warning = None

    class _Element:
        locators = [_Locator()]

    _Locator.value = value
    _, note = _locator_call(_Element())
    if flagged:
        assert note and "VOLATILE" in note, f"{value} should be flagged"
    else:
        assert note is None, f"{value} should not be flagged, got {note}"


def test_an_element_with_no_locator_says_so_rather_than_guessing():
    from scriptscrap.generate.playwright import _locator_call

    class _Element:
        locators = []

    _, warning = _locator_call(_Element())
    assert "NO LOCATOR" in warning


def test_captured_labels_cannot_break_out_of_a_comment():
    """A form's accessible name can be every option inside it, newlines and
    all. Interpolated raw, the comment ends at the first newline and the rest
    of the label becomes code."""
    from scriptscrap.analysis.models import AnalysisResult, UIElement
    from scriptscrap.generate.emit import py_comment

    assert "\n" not in py_comment("Nom\nNotes\n Accord\n Bris")

    hostile = AnalysisResult(session_id="s", event_count=1)
    # Hostile label text, never executed: it exists to prove that a captured
    # string cannot end the comment it is written into and become code.
    hostile.ui_elements = [UIElement(
        key="form:evil", tag="form", role=None,
        label='Nom\nNotes\n"""\nimport os; os.system("id")',
        text=None, form=None, observation_count=1,
    )]
    compile(render_playwright(hostile, session_name="s"), "evil.py", "exec")


def test_script_invents_no_state_that_was_not_reached(script, result):
    """It may only walk transitions that were actually observed."""
    labels = {s.label for s in result.states}
    for line in script.splitlines():
        if line.strip().startswith("# state:"):
            assert line.split("# state:", 1)[1].strip() in labels


def test_script_says_it_is_a_starting_point_not_a_test(script):
    assert "starting point" in script.lower()


def test_script_has_no_assertions_it_cannot_justify(script):
    """It observed a workflow; it did not observe what SHOULD happen. Emitting
    assertions would dress an observation up as a specification."""
    assert "assert " not in script


# --- empty sessions -------------------------------------------------------

def test_generators_survive_a_session_with_nothing_in_it():
    from scriptscrap.analysis.models import AnalysisResult

    empty = AnalysisResult(session_id="empty", event_count=0)
    for source in (render_client(empty, session_name="empty"),
                   render_playwright(empty, session_name="empty")):
        compile(source, "empty.py", "exec")
        assert "no " in source.lower()
