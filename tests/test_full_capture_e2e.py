"""A full agency-style capture, end to end, exercising every upgraded path.

One session opens multiple tabs, fills and submits a form in a popup, uses a
native select, a custom ARIA combobox, radio and checkbox, a hover menu, a
JavaScript dialog, drag/drop, and a virtualized table -- then the recorded log
is analysed, health-checked and exported through the real CLI, and the workspace
serves it. This is the NEW end-to-end validation the mission asks for; it does
not touch the old committed capture.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scriptscrap.events import EventLogReader, EventType

pytestmark = pytest.mark.browser


async def _workflow(page, engine):
    """The scripted agency workflow, run as run_capture's `interact`.

    run_capture has already launched, attached sensors, started coverage BEFORE
    the first navigation, and navigated to the main page -- exactly as the CLI
    does. `page` is that main page.
    """
    await page.wait_for_selector("html[data-fixture-ready='true']", state="attached")
    await page.fill("#nom", "Alice Benali")
    await page.check("#accord")
    await page.check("#type-choc")
    await page.select_option("#ville", "mar")
    await page.click("#agent-combo")
    await page.click("#opt-agent-2")
    await page.dblclick("#btn-icon")

    # -- a popup with a form -------------------------------------
    async with page.context.expect_page() as popup_info:
        await page.click("#btn-popup")
    popup = await popup_info.value
    await popup.wait_for_load_state("load")
    await popup.wait_for_function("() => (window.__scriptscrapRearmCount||0) >= 1")
    await popup.fill("#p2-reference", "REF-E2E-1")
    await popup.select_option("#p2-etat", "clos")
    await popup.click("#btn-page2-submit")
    await popup.wait_for_load_state("load")

    # -- a second tab: a table with sort/filter/paginate ---------
    async with page.context.expect_page() as tab_info:
        await page.evaluate("() => window.open('/table-demo', '_blank')")
    tab = await tab_info.value
    await tab.wait_for_load_state("load")
    await tab.wait_for_function("() => (window.__scriptscrapRearmCount||0) >= 1")
    await tab.click("#col-client")
    await tab.fill("#table-filter", "alpha")
    await tab.click(".row-edit[data-id='D-1001']")
    await tab.click("#next-page")
    await tab.wait_for_timeout(200)

    # -- a third tab: hover, dialog, drag/drop, virtualized table -
    async with page.context.expect_page() as rich_info:
        await page.evaluate("() => window.open('/interactions', '_blank')")
    rich = await rich_info.value
    await rich.wait_for_load_state("load")
    await rich.wait_for_function("() => (window.__scriptscrapRearmCount||0) >= 1")
    await rich.hover("#menu-trigger")
    await rich.wait_for_timeout(120)
    await rich.click("#btn-confirm")
    await rich.wait_for_timeout(120)
    await rich.click("#sim-drag")
    await rich.wait_for_timeout(120)
    for top in (300, 700, 1100):
        await rich.eval_on_selector("#virt-wrap", f"el => el.scrollTo(0, {top})")
        await rich.wait_for_timeout(400)


async def _capture(work_root: Path) -> Path:
    """Run a capture through the PRODUCTION runner, into the DEFAULT timestamped
    output directory, and return that directory."""
    from scriptscrap.fixture import FixtureServer
    from scriptscrap.testing.capture import load_investigator

    inv = load_investigator()
    prev_cwd = Path.cwd()
    os.chdir(work_root)          # so the default scriptscrap_output/ lands here
    try:
        with FixtureServer() as fx:
            scope = inv.InvestigationScope(fx.base_url)
            # No output_dir: exercise the default timestamped directory.
            engine = inv.WebHarvester(fx.base_url, scope)
            await inv.run_capture(
                engine, target_url=fx.base_url + "/", forensic_config=None,
                headless=True, interact=_workflow)
            # Resolve while still chdir'd: the default output dir is relative.
            return (work_root / engine.output_dir).resolve()
    finally:
        os.chdir(prev_cwd)


@pytest.fixture(scope="module")
def capture_dir(tmp_path_factory) -> Path:
    work = tmp_path_factory.mktemp("e2e")
    return asyncio.run(_capture(work))


def test_the_capture_used_the_default_timestamped_output(capture_dir):
    assert capture_dir.parent.name == "scriptscrap_output"
    assert capture_dir.name.startswith("session-")
    assert (capture_dir / "session_manifest.json").is_file()


def test_the_manifest_records_a_clean_session_and_session_end(capture_dir):
    manifest = json.loads((capture_dir / "session_manifest.json").read_text("utf-8"))
    assert manifest["outcome"] == "clean"
    assert manifest["completion"]["clean"] is True
    log = EventLogReader(capture_dir / "events.jsonl")
    assert str(log.events[-1].type) == "session_end", "SESSION_END was not last"


def test_every_open_page_was_drained_at_session_end(capture_dir):
    """Drain-all: each in-scope page open at session end is drained (a per-page
    runtime_hooks dump) BEFORE the context teardown closes it.

    The old runner drained only the initial page; here all tabs/popups are.
    """
    log = EventLogReader(capture_dir / "events.jsonl")
    hooks_pages = {e.page_id for e in log.of_type(EventType.RUNTIME_HOOKS) if e.page_id}
    open_pages = {e.page_id for e in log.of_type(EventType.PAGE_OPENED) if e.page_id}
    # Several pages were opened (main + popup + two tabs), and every one was
    # drained -- not just the first.
    assert len(open_pages) >= 3, f"expected several pages, saw {open_pages}"
    assert open_pages <= hooks_pages, (
        f"pages opened but not drained: {open_pages - hooks_pages}")


def test_the_capture_is_a_valid_multipage_log(capture_dir):
    log = EventLogReader(capture_dir / "events.jsonl")
    assert log.validate() == []
    pages = {e.page_id for e in log.of_type(EventType.PAGE_OPENED) if e.page_id}
    assert len(pages) >= 3, f"expected several tabs/pages, saw {pages}"


def test_every_interaction_type_was_captured(capture_dir):
    log = EventLogReader(capture_dir / "events.jsonl")
    present = {str(e.type) for e in log}
    for required in ("user_click", "user_dblclick", "user_input", "user_change",
                     "user_submit", "user_hover", "user_drag", "user_scroll",
                     "dialog", "popup_opened"):
        assert required in present, f"{required} was not captured"


def test_the_full_pipeline_runs_over_the_new_capture(capture_dir):
    """analyze, then export, both clean, over the fresh capture."""
    for command in ("analyze", "export", "health"):
        proc = subprocess.run(
            [sys.executable, "-m", "scriptscrap.cli", command, str(capture_dir)],
            capture_output=True, text=True, check=False)
        assert proc.returncode == 0, f"{command} failed: {proc.stderr}"
    assert (capture_dir / "session.sqlite").exists()
    assert (capture_dir / "export" / "shared" / "dataset.json").exists()


def test_the_analysis_reflects_the_agency_workflow(capture_dir):
    from scriptscrap.analysis import analyze_log

    result = analyze_log(capture_dir / "events.jsonl")
    # Forms: the popup form and the main form, with a native select and an ARIA
    # combobox somewhere.
    assert result.forms, "no forms catalogued"
    all_controls = [c for f in result.forms for c in f.controls]
    assert any(c.tag == "select" and c.options_complete for c in all_controls), \
        "no native select with a complete option set"
    combo = next((c for c in all_controls if c.kind == "combobox"), None)
    assert combo is not None, "no ARIA combobox"
    # The option the operator clicked carries its owning listbox id, so the
    # trigger's aria-controls matches it EXACTLY -- not a same-frame proximity
    # guess. (Regression: the probe once dropped the option's listbox id, which
    # forced every combobox onto the proximity fallback.)
    assert combo.listbox == "agent-list", combo.listbox
    assert combo.connection == "aria-controls", combo.connection
    # Tables: the static table and the virtualized one, the latter with more
    # rows than one window.
    assert result.tables, "no tables catalogued"
    virt = next((t for t in result.tables if t.table_id == "virt-table"), None)
    assert virt is not None and len(virt.rows) > 12, "virtualized rows not harvested"
    # Activities: the long session split into more than one.
    assert len(result.segments) >= 2, "the session was not segmented"


def test_the_export_leaks_no_captured_secret(capture_dir):
    dataset = (capture_dir / "export" / "shared" / "dataset.json").read_text(encoding="utf-8")
    for secret in ("FIXTURE_PASSWORD_DO_NOT_USE", "FIXTURE_CSRF_TOKEN_0001"):
        assert secret not in dataset, f"{secret} leaked into the shared export"
    # Valid JSON.
    json.loads(dataset)


def test_the_workspace_serves_the_new_capture(capture_dir):
    from scriptscrap.workspace import api
    from scriptscrap.workspace.server import Workspace, WorkspaceConfig

    # analyze must have run (previous test writes the store); ensure it here too.
    subprocess.run([sys.executable, "-m", "scriptscrap.cli", "analyze", str(capture_dir)],
                   capture_output=True, check=False)
    ws = Workspace(WorkspaceConfig(root=capture_dir))
    q: dict = {}
    assert api.segments(ws, q)["segments"], "workspace served no activities"
    assert api.forms(ws, q)["forms"], "workspace served no forms"
    assert api.tables(ws, q)["tables"], "workspace served no tables"
    overview = api.session_overview(ws, q)
    assert overview["counts"]["events"] > 0
