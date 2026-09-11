"""A session says how it ended.

The manifest records started_at and finished_at but not whether the session
ended cleanly. The repository's own interrupted capture is distinguishable only
by its directory name, which is not evidence.
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.browser


def test_a_completed_session_records_a_clean_outcome(investigation_output):
    manifest = json.loads(
        (investigation_output / "session_manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] == "clean"


def test_the_outcome_is_one_of_a_closed_vocabulary(investigation_output):
    manifest = json.loads(
        (investigation_output / "session_manifest.json").read_text(encoding="utf-8"))
    assert manifest["outcome"] in ("clean", "interrupted", "failed")


def test_the_snapshot_pins_the_outcome(investigation_snapshot):
    assert investigation_snapshot["session_manifest.json"]["outcome"] == "clean"
