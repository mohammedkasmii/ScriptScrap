"""What a real browser does with the workspace.

The status code and the Set-Cookie header are the server's half. Whether the
token leaves the address bar, whether the cookie is HttpOnly in the jar, and
whether a second launch works in a browser that still holds the first launch's
cookie are the browser's half -- and the audit found the second launch broken
while every server-side test passed.
"""

from __future__ import annotations

import asyncio
import shutil
import threading
from pathlib import Path

import pytest

from scriptscrap.analysis import DerivedStore, analyze_log
from scriptscrap.workspace import Workspace, WorkspaceConfig

pytestmark = pytest.mark.browser

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"


@pytest.fixture
def session_root(tmp_path):
    root = tmp_path / "session"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")
    with DerivedStore(root / "session.sqlite") as store:
        store.write(analyze_log(root / "events.jsonl"))
    return root


class _Running:
    """A workspace serving on a thread, for the duration of a with-block."""

    def __init__(self, root: Path) -> None:
        self.workspace = Workspace(WorkspaceConfig(root=root))
        self._thread = threading.Thread(
            target=self.workspace.serve_forever, daemon=True)

    def __enter__(self) -> Workspace:
        self._thread.start()
        return self.workspace

    def __exit__(self, *exc) -> None:
        self.workspace.shutdown()
        self._thread.join(timeout=5)


async def _browser():
    from camoufox.addons import DefaultAddons
    from camoufox.async_api import AsyncCamoufox

    return AsyncCamoufox(headless=True, humanize=False, os="windows",
                         geoip=False, exclude_addons=[DefaultAddons.UBO])


def test_the_token_leaves_the_address_bar(session_root):
    async def run():
        with _Running(session_root) as workspace:
            async with await _browser() as browser:
                page = await browser.new_page()
                await page.goto(workspace.url, wait_until="load")
                await page.wait_for_selector("#app:not([hidden])")
                assert "t=" not in page.url, page.url
                assert page.url.rstrip("/").endswith(
                    f"{workspace.address[0]}:{workspace.address[1]}"), page.url

    asyncio.run(run())


def test_the_cookie_is_httponly_in_the_jar(session_root):
    async def run():
        with _Running(session_root) as workspace:
            async with await _browser() as browser:
                page = await browser.new_page()
                await page.goto(workspace.url, wait_until="load")
                await page.wait_for_selector("#app:not([hidden])")
                cookies = await page.context.cookies()
                token = next(c for c in cookies
                             if c["name"] == "scriptscrap_token")
                assert token["value"] == workspace.token
                assert token["httpOnly"] is True
                assert token["sameSite"] in ("Strict", "strict")
                assert await page.evaluate("document.cookie") == ""

    asyncio.run(run())


def test_the_shell_loads_and_renders_a_view_under_the_csp(session_root):
    """`script-src 'self'` must not break the module the shell loads."""
    async def run():
        errors = []
        with _Running(session_root) as workspace:
            async with await _browser() as browser:
                page = await browser.new_page()
                page.on("console", lambda m: errors.append(m.text)
                        if m.type == "error" else None)
                page.on("pageerror", lambda e: errors.append(str(e)))
                await page.goto(workspace.url, wait_until="load")
                await page.wait_for_selector("#rail .rail-link")
                await page.click("a.rail-link[data-view='endpoints']")
                await page.wait_for_selector(".view-endpoints")
                assert errors == [], errors

    asyncio.run(run())


def test_a_second_launch_works_in_a_browser_holding_the_first_cookie(session_root):
    """The operator-visible failure: launch, close, launch again. Cookies are
    not scoped by port, so the first launch's token was sent to the second and
    the query token was ignored."""
    async def run():
        async with await _browser() as browser:
            context = await browser.new_context()
            page = await context.new_page()

            with _Running(session_root) as first:
                await page.goto(first.url, wait_until="load")
                await page.wait_for_selector("#app:not([hidden])")

            with _Running(session_root) as second:
                assert second.token != first.token
                await page.goto(second.url, wait_until="load")
                await page.wait_for_selector("#rail .rail-link")
                body = await page.text_content("#content")
                assert "missing or invalid token" not in (body or "")
                cookies = await context.cookies()
                token = next(c for c in cookies
                             if c["name"] == "scriptscrap_token")
                assert token["value"] == second.token, \
                    "the stale cookie was not replaced"

    asyncio.run(run())


def test_the_redaction_badge_reads_unredacted_for_a_raw_session(session_root):
    """test_workspace_assets asserts the STRING 'UNREDACTED' exists in app.js.
    This asserts a browser renders it over the right session."""
    async def run():
        with _Running(session_root) as workspace:
            async with await _browser() as browser:
                page = await browser.new_page()
                await page.goto(workspace.url, wait_until="load")
                await page.wait_for_selector("#redaction")
                assert (await page.text_content("#redaction")) == "UNREDACTED"
                classes = await page.get_attribute("#redaction", "class")
                assert "badge-danger" in classes

    asyncio.run(run())


def test_the_badge_reads_sanitised_over_an_export(tmp_path):
    from scriptscrap.cli import build_parser

    root = tmp_path / "capture"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")
    for command in (["analyze", str(root)], ["export", str(root)]):
        args = build_parser().parse_args(command)
        args.func(args)

    async def run():
        with _Running(tmp_path) as workspace:
            shared = next(h.name for h in workspace.sessions
                          if h.redaction == "sanitised")
            async with await _browser() as browser:
                page = await browser.new_page()
                await page.goto(workspace.url, wait_until="load")
                await page.wait_for_selector("#session-picker")
                await page.select_option("#session-picker", shared)
                await page.wait_for_function(
                    "document.getElementById('redaction').textContent === 'SANITISED'")
                classes = await page.get_attribute("#redaction", "class")
                assert "badge-safe" in classes

    asyncio.run(run())
