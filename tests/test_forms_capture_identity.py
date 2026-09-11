"""Form identity and control representation, proven through a real capture.

Driven by the PRODUCTION runner (`run_capture`), so the document-instance and
route identity, the anonymous-form attribution and the radio/checkbox
representation are exercised exactly as the CLI produces them -- not by
synthetic events. One capture visits a page of id-less radio/checkbox groups and
an anonymous form, then navigates the SAME tab between two documents that share a
form id.
"""

from __future__ import annotations

import asyncio

import pytest

from scriptscrap.analysis import analyze_events
from scriptscrap.events import EventLogReader, EventType

pytestmark = pytest.mark.browser


async def _workflow(page, engine):
    base = engine.target_url.rstrip("/")

    # -- /choices: id-less radio group, id-less checkboxes, anonymous form ----
    await page.wait_for_selector("html[data-fixture-choices-ready='true']",
                                 state="attached")
    await page.check("input[name='plan'][value='max']")     # switch off default
    await page.check("input[name='topping'][value='cheese']")
    await page.check("input[name='topping'][value='ham']")
    await page.fill("form:not([id]) input[name='note']", "an anonymous note")
    await page.click("#anon-submit")
    await page.wait_for_timeout(2300)     # let the scan loop inventory /choices

    # -- same-tab navigation between two documents sharing id="entity-form" ---
    await page.goto(base + "/claims/new", wait_until="load")
    await page.wait_for_selector("html[data-fixture-entity-ready='true']",
                                 state="attached")
    await page.fill("#entity-field", "CLAIM-1")
    await page.wait_for_timeout(2300)     # scan /claims/new

    await page.goto(base + "/customers/new", wait_until="load")
    await page.wait_for_selector("html[data-fixture-entity-ready='true']",
                                 state="attached")
    await page.fill("#entity-field", "Acme Corp")
    await page.wait_for_timeout(2300)     # scan /customers/new


async def _run(out):
    from scriptscrap.fixture import FixtureServer
    from scriptscrap.testing.capture import load_investigator

    inv = load_investigator()
    with FixtureServer() as fx:
        scope = inv.InvestigationScope(fx.base_url)
        engine = inv.WebHarvester(fx.base_url, scope,
                                  session_id="sess-20260101-000000", output_dir=out)
        await inv.run_capture(
            engine, target_url=fx.base_url + "/choices", forensic_config=None,
            headless=True, interact=_workflow)
    return EventLogReader(out / "events.jsonl")


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    out = tmp_path_factory.mktemp("forms_identity") / "out"
    log = asyncio.run(_run(out))
    assert log.validate() == []
    return analyze_events(list(log), "s")


def _entity_forms(result):
    return [f for f in result.forms if f.form_id == "entity-form"]


def _choices_form(result):
    """The prefs form on /choices, by its controls (id-less groups)."""
    return next(f for f in result.forms
                if any(c.type in ("radio", "checkbox") for c in f.controls))


def test_two_same_id_forms_across_a_same_tab_navigation_do_not_merge(result):
    """id="entity-form" appears in two different documents (a full navigation
    between /claims/new and /customers/new). They must be two entries."""
    entity = _entity_forms(result)
    assert len(entity) == 2, [f.form_key for f in entity]
    # Each is a distinct document instance, and their routes differ.
    assert len({f.document_instance for f in entity}) == 2, entity
    routes = {f.route for f in entity}
    assert routes == {"/claims/new", "/customers/new"}, routes


def test_an_idless_radio_group_is_one_control_with_all_options(result):
    form = _choices_form(result)
    radios = [c for c in form.controls if c.type == "radio"]
    assert len(radios) == 1, "the radio group must be one logical control"
    grp = radios[0]
    assert grp.kind == "radio_group"
    assert {o["value"] for o in grp.options} == {"basic", "pro", "max"}
    # The operator switched to "max"; that is the selected option now.
    assert grp.final_value == "max"
    assert [o["value"] for o in grp.options if o.get("checked")] == ["max"]


def test_idless_checkboxes_sharing_a_name_stay_distinct_choices(result):
    form = _choices_form(result)
    boxes = [c for c in form.controls if c.type == "checkbox"]
    assert len(boxes) == 3, [c.option_value for c in boxes]
    checked = {c.option_value for c in boxes if c.checked}
    assert checked == {"cheese", "ham"}


def test_an_anonymous_forms_input_and_submit_attribute_to_one_entry(result):
    """DOM inventory + input + submit for the anonymous form resolve to ONE
    entry, and the typed value is attributed to it."""
    anon = [f for f in result.forms
            if f.form_id is None
            and any(c.name == "note" for c in f.controls)]
    assert len(anon) == 1, [f.form_key for f in anon]
    entry = anon[0]
    note = next(c for c in entry.controls if c.name == "note")
    assert note.final_value == "an anonymous note"
    assert entry.submitted is True


# --- a programmatically submitted anonymous form (its own capture) ---------

async def _prog_workflow(page, engine):
    await page.wait_for_selector("html[data-fixture-prog-ready='true']",
                                 state="attached")
    await page.fill("form:not([id]) input[name='memo']", "typed then submitted")
    await page.click("#prog-go")     # calls form.submit() -- no native event
    await page.wait_for_load_state("load")
    await page.wait_for_timeout(400)


async def _run_prog(out):
    from scriptscrap.fixture import FixtureServer
    from scriptscrap.testing.capture import load_investigator

    inv = load_investigator()
    with FixtureServer() as fx:
        scope = inv.InvestigationScope(fx.base_url)
        engine = inv.WebHarvester(fx.base_url, scope,
                                  session_id="sess-20260101-000001", output_dir=out)
        await inv.run_capture(
            engine, target_url=fx.base_url + "/prog-anon", forensic_config=None,
            headless=True, interact=_prog_workflow)
    return EventLogReader(out / "events.jsonl")


def test_an_anonymous_form_submitted_programmatically_is_captured(tmp_path):
    log = asyncio.run(_run_prog(tmp_path / "out"))
    assert log.validate() == []
    # The wrapper observed the programmatic submit and recorded the form's path.
    rfs = list(log.of_type(EventType.RUNTIME_FORM_SUBMIT))
    assert any(e.payload.get("form_path") for e in rfs), \
        "runtime_form_submit carried no form_path for the anonymous form"
    # The submit merged with the anonymous form's inventory and input.
    result = analyze_events(list(log), "s")
    submitted = [f for f in result.forms
                 if f.form_id is None
                 and f.submitted
                 and any(c.name == "memo" for c in f.controls)]
    assert submitted, "the programmatic anonymous submit was dropped, not merged"
    memo = next(c for c in submitted[0].controls if c.name == "memo")
    assert memo.final_value == "typed then submitted"
