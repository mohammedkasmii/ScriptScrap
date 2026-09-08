"""Nothing captured leaves in any artifact of the sanitised export.

This is the precondition for making SANITISED workspace mode reachable. Until
it passes, `export/shared` must stay unopenable: a badge that says SANITISED
over data that is not is worse than no badge.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

import pytest
from hostile import MARKER

from scriptscrap.analysis import DerivedStore, analyze_log  # noqa: F401
from scriptscrap.analysis.report import render
from scriptscrap.cli import build_parser
from scriptscrap.events import EventLogReader
from scriptscrap.export import DatasetExporter, Redactor, sanitise

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"
REAL = Path(__file__).parent.parent / "v13_investigation_output_run3_interrupted"


def _artifacts(shared: Path) -> dict[str, str]:
    """Every byte the sanitised export writes, as text."""
    out = {
        "dataset.json": (shared / "dataset.json").read_text(encoding="utf-8"),
        "report.md": (shared / "report.md").read_text(encoding="utf-8"),
    }
    conn = sqlite3.connect(shared / "session.sqlite")
    try:
        rows = []
        for (table,) in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"):
            for row in conn.execute(f"SELECT * FROM {table}"):  # noqa: S608
                rows.append(" ".join("" if v is None else str(v) for v in row))
        out["session.sqlite"] = "\n".join(rows)
    finally:
        conn.close()
    return out


def _export(tmp_path: Path, log: Path) -> Path:
    root = tmp_path / "session"
    root.mkdir()
    shutil.copy(log, root / "events.jsonl")
    args = build_parser().parse_args(["export", str(root)])
    assert args.func(args) == 0
    return root / "export" / "shared"


def _captured_strings(log: Path) -> set[str]:
    found: set[str] = set()

    def walk(value):
        if isinstance(value, str):
            found.add(value)
        elif isinstance(value, dict):
            for key, item in value.items():
                found.add(str(key))
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    for event in EventLogReader(log):
        walk(event.payload)
    return found


def test_the_synthetic_marker_survives_in_no_artifact(tmp_path):
    from test_export_policy import _marked_result

    safe = sanitise(_marked_result(), Redactor())
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "dataset.json").write_text(
        json.dumps(DatasetExporter().build_from_sanitised(safe)), encoding="utf-8")
    (shared / "report.md").write_text(render(safe), encoding="utf-8")
    with DerivedStore(shared / "session.sqlite") as store:
        store.write(safe)

    for name, blob in _artifacts(shared).items():
        assert MARKER not in blob, f"{name} carries the marker"


def _deliberately_kept(log: Path) -> set[str]:
    """The strings a documented disposition CHOSE to keep, derived not listed.

    Three dispositions keep application-authored text, each for a stated
    reason, and each pinned by its own test in `test_export_policy.py`:

      ROUTE    a route shape, or the export describes an API nobody can find
      NAME     a parameter, header, field or technology name -- the vocabulary
               the application's own developers chose
      LOCATOR  a structural selector, or a reader cannot find the element again

    Computing this from the sanitised model rather than hard-coding a list is
    the point: it grants an exemption to exactly what policy already decided,
    and anything NEW that survives is still a failure.
    """
    safe = sanitise(analyze_log(log), Redactor())
    kept: set[str] = set()
    for element in safe.ui_elements:
        kept.update(str(locator.value) for locator in element.locators)
    for endpoint in safe.endpoints:
        kept.add(str(endpoint.template))
        kept.update(str(p.name) for p in endpoint.params)
    for schema in safe.schemas:
        kept.update(str(f.path) for f in schema.fields)
    kept.update(str(t.name) for t in safe.technologies)
    kept.update(str(state.url_pattern) for state in safe.states)
    kept.update(str(step.url_pattern) for step in safe.workflow)
    kept.update(str(name) for name in safe.auth_headers)
    return kept


def test_no_string_from_the_fixture_log_survives(tmp_path):
    shared = _export(tmp_path, SAMPLE)
    artifacts = _artifacts(shared)

    # ScriptScrap's own words, which a captured page may also happen to use.
    # The dataset's notice explains what sanitisation did; a phrase inside it
    # is the tool talking, not the capture leaking.
    tool_vocabulary = {"HTML snapshots"}
    kept = _deliberately_kept(SAMPLE) | tool_vocabulary

    interesting = {
        s for s in _captured_strings(SAMPLE)
        if len(s) >= 8
        and s not in kept
        and not any(s in allowed for allowed in kept)
        and any(ch.isspace() or ch.isdigit() for ch in s)
    }
    survivors = {name: sorted(s for s in interesting if s in blob)[:5]
                 for name, blob in artifacts.items()}
    survivors = {k: v for k, v in survivors.items() if v}
    assert survivors == {}, survivors


@pytest.mark.skipif(not REAL.exists(), reason="the real capture is not present")
def test_no_string_from_the_real_capture_survives(tmp_path):
    """The capture the audit found the leak in: a password shown on a login
    page and a rendered table of student names, genders, states and majors."""
    shared = _export(tmp_path, REAL / "events.jsonl")
    artifacts = _artifacts(shared)
    for needle in ("SuperSecretPassword", "Alice Johnson", "Sophomore",
                   "Extracurricular", "Mathematics", "practice"):
        for name, blob in artifacts.items():
            assert needle not in blob, f"{name} carries {needle!r}"


@pytest.mark.skipif(not REAL.exists(), reason="the real capture is not present")
def test_forty_strings_drawn_from_the_real_capture_do_not_survive(tmp_path):
    shared = _export(tmp_path, REAL / "events.jsonl")
    artifacts = _artifacts(shared)
    corpus = sorted(
        (s for s in _captured_strings(REAL / "events.jsonl")
         if 12 <= len(s) <= 200 and any(ch.isspace() for ch in s)),
        key=len, reverse=True)[:40]
    assert len(corpus) == 40, "the real capture yielded too few probe strings"
    survivors = [(name, s) for name, blob in artifacts.items()
                 for s in corpus if s in blob]
    assert survivors == [], survivors[:5]


def test_the_sanitised_store_holds_no_evidence_index(tmp_path):
    """Byte offsets into a log the recipient does not have are meaningless,
    and the offsets themselves say how big each event was."""
    shared = _export(tmp_path, SAMPLE)
    conn = sqlite3.connect(shared / "session.sqlite")
    try:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
        row = conn.execute(
            "SELECT log_size, log_sha256 FROM analysis_runs").fetchone()
        assert row[0] is None and row[1] is None
    finally:
        conn.close()


def test_the_sanitised_export_writes_no_event_log(tmp_path):
    shared = _export(tmp_path, SAMPLE)
    assert not (shared / "events.jsonl").exists()
    assert sorted(p.name for p in shared.iterdir()) == [
        "dataset.json", "report.md", "session.sqlite"]
