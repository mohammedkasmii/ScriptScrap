"""The shared report is a view of the sanitised model, not of the raw one.

`cmd_export` rendered report.md straight from AnalysisResult. The audit's run3
export happened not to show the planted strings only because the element table
truncates at 40 rows -- truncation, not a safety property.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from hostile import MARKER

from scriptscrap.analysis.report import render
from scriptscrap.cli import build_parser
from scriptscrap.export import Redactor, sanitise

SAMPLE = Path(__file__).parent / "golden" / "sample_events.jsonl"


def test_the_shared_report_is_rendered_from_the_sanitised_model(tmp_path):
    from test_export_policy import _marked_result

    root = tmp_path / "session"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")

    args = build_parser().parse_args(["export", str(root)])
    assert args.func(args) == 0

    report = (root / "export" / "shared" / "report.md").read_text(encoding="utf-8")
    unsafe = render(_marked_result())
    assert MARKER in unsafe, "the fixture builder must actually carry the marker"
    assert MARKER not in report


def test_a_marker_anywhere_in_the_model_never_reaches_the_shared_report():
    from test_export_policy import _marked_result

    safe = sanitise(_marked_result(), Redactor())
    assert MARKER not in render(safe)


def test_the_export_writes_every_artifact(tmp_path):
    """Three now, not two: `session.sqlite` is what makes the export openable
    in the workspace, so SANITISED mode can be entered at all."""
    root = tmp_path / "session"
    root.mkdir()
    shutil.copy(SAMPLE, root / "events.jsonl")
    build_parser().parse_args(["export", str(root)]).func(
        build_parser().parse_args(["export", str(root)]))

    shared = root / "export" / "shared"
    assert sorted(p.name for p in shared.iterdir()) == [
        "dataset.json", "report.md", "session.sqlite"]


def test_the_report_says_when_it_truncated_a_table():
    """40 rows is a readability limit, and must not read as completeness."""
    from scriptscrap.analysis.models import (
        AnalysisResult,
        Evidence,
        LocatorCandidate,
        UIElement,
    )

    elements = [UIElement(key=f"k{i}", tag="a", role=None, label=f"L{i}",
                          text=None, form=None, observation_count=1,
                          actions={"user_click": 1},
                          locators=[LocatorCandidate(strategy="css", value=f".c{i}",
                                                     resolved_count=1, sample_count=1)],
                          evidence=Evidence(event_ids=["e"]))
                for i in range(60)]
    text = render(AnalysisResult(session_id="s", event_count=1,
                                 ui_elements=elements))
    assert "20 more" in text
    assert "not shown" in text.lower()
