"""Properties of the frontend that are checkable without a browser.

Two of these are security properties rather than tidiness:

* **No `innerHTML`.** Every string this UI renders -- URLs, element labels,
  console output, response bodies -- was captured from somebody else's web
  application. Assigning any of it as markup would let a captured page script
  itself into the viewer, and the viewer is the window holding an
  authenticated session's evidence.
* **No off-origin references.** The tool has to work on a disconnected
  machine, and a workspace that fetched a font or a script from a CDN while
  displaying a capture would be announcing that capture's existence to a third
  party. The server's CSP enforces this at runtime; this catches it at commit
  time, where the error is readable.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ASSETS = Path(__file__).resolve().parents[1] / "src" / "scriptscrap" / "workspace" / "assets"

EXPECTED_VIEWS = {
    "overview.js", "timeline.js", "endpoints.js", "states.js",
    "elements.js", "schemas.js", "dependencies.js", "technology.js",
}
EXPECTED_LIB = {"dom.js", "api.js", "evidence.js", "graph.js"}


def _sources() -> list[Path]:
    return sorted(p for p in ASSETS.rglob("*") if p.suffix in {".js", ".css", ".html"})


def test_the_asset_tree_is_complete():
    assert (ASSETS / "index.html").is_file()
    assert (ASSETS / "app.js").is_file()
    assert (ASSETS / "app.css").is_file()
    assert {p.name for p in (ASSETS / "views").glob("*.js")} == EXPECTED_VIEWS
    assert {p.name for p in (ASSETS / "lib").glob("*.js")} == EXPECTED_LIB


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith(("//", "*", "/*"))


def test_nothing_assigns_innerhtml():
    """Captured content is rendered as text, never as markup.

    Comments are skipped: the rule is documented in `lib/dom.js`, and a check
    that fired on its own explanation would teach people to delete the
    explanation.
    """
    offenders = [
        f"{p.relative_to(ASSETS)}:{n}: {line.strip()}"
        for p in _sources()
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if re.search(r"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b", line)
        and not _is_comment(line)
    ]
    assert not offenders, (
        "captured application content must never be rendered as markup:\n"
        + "\n".join(offenders))


def test_no_asset_references_an_external_origin():
    """The workspace must work with no network, and must not phone anywhere."""
    offenders = []
    for path in _sources():
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in re.finditer(r"https?://[^\s\"'`)]+", line):
                url = match.group(0)
                # The SVG namespace is an identifier, not a fetch.
                if url.startswith("http://www.w3.org/"):
                    continue
                # Prose in a comment naming a captured host is not a reference.
                if _is_comment(line):
                    continue
                offenders.append(f"{path.relative_to(ASSETS)}:{n} {url}")
    assert not offenders, "assets must not reference an external origin:\n" + "\n".join(offenders)


def test_index_references_only_local_files():
    html = (ASSETS / "index.html").read_text(encoding="utf-8")
    for attr in re.findall(r'(?:src|href)="([^"]+)"', html):
        assert attr.startswith("/"), f"{attr} is not a local absolute path"


def test_every_view_module_exports_a_title_and_render():
    for path in sorted((ASSETS / "views").glob("*.js")):
        source = path.read_text(encoding="utf-8")
        assert "export const title" in source, f"{path.name} exports no title"
        assert "export async function render" in source, f"{path.name} exports no render"


def test_app_registers_every_view():
    app = (ASSETS / "app.js").read_text(encoding="utf-8")
    for name in EXPECTED_VIEWS:
        stem = name[:-3]
        assert f"./views/{name}" in app, f"{name} is not imported by app.js"
        assert f"'{stem}'" in app, f"{stem} is not routed in app.js"


def test_the_redaction_badge_is_wired_to_the_api():
    """The header must state UNREDACTED from data, never from a guess."""
    app = (ASSETS / "app.js").read_text(encoding="utf-8")
    assert "session.redaction" in app
    assert "UNREDACTED" in app
    assert "SANITISED" in app


@pytest.mark.parametrize("view,route", [
    ("overview.js", "session"),
    ("timeline.js", "timeline"),
    ("endpoints.js", "endpoints"),
    ("states.js", "states"),
    ("elements.js", "ui_elements"),
    ("schemas.js", "schemas"),
    ("dependencies.js", "dependencies"),
    ("technology.js", "technologies"),
])
def test_each_view_calls_its_route(view, route):
    source = (ASSETS / "views" / view).read_text(encoding="utf-8")
    assert f"get('{route}'" in source, f"{view} does not call /api/{route}"


def test_every_route_a_view_calls_actually_exists():
    """A typo'd route would render an empty panel that looks like empty data."""
    from scriptscrap.workspace import api

    known = set(api.ROUTES)
    called = set()
    for path in sorted(ASSETS.rglob("*.js")):
        called.update(re.findall(r"get\('([a-z_]+)'", path.read_text(encoding="utf-8")))
    assert called <= known, f"views call routes that do not exist: {sorted(called - known)}"


def test_views_render_evidence_rather_than_only_stating_facts():
    """The property that separates this from the retired JSON files."""
    exempt = {"technology.js"}   # uses evidenceList inside a table cell
    for path in sorted((ASSETS / "views").glob("*.js")):
        source = path.read_text(encoding="utf-8")
        if path.name in exempt:
            assert "evidenceList" in source
            continue
        assert "evidence" in source.lower(), f"{path.name} never surfaces evidence"
