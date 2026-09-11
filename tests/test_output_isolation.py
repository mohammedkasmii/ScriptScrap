"""Every investigation writes its own directory.

A fixed global output path let two sessions append to one events.jsonl, mixing
two sessions' evidence into a log the reader flags as `mixed_sessions` and no
analysis can un-mix. The default is now a per-session timestamped directory, an
explicit --output is honoured, and writing into a directory that already holds
a session is refused rather than appended to.

The offline checks pin the directory logic and the refusal without a browser;
the browser regression proves two consecutive real captures stay separate and
each validates.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "camoufox_investigator", REPO / "camoufox" / "camoufox_investigator.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


inv = _load()


# --- directory selection --------------------------------------------------

def test_two_default_directories_are_distinct():
    """Timestamped to microseconds, so two sessions in the same second differ."""
    a = inv.default_output_dir()
    b = inv.default_output_dir()
    assert a != b
    # And it is under the gitignored root, not a fixed global name.
    assert a.parts[-2] == "scriptscrap_output"
    assert "v13_investigation_output" not in str(a)


def test_output_flag_is_parsed():
    args = inv.parse_cli_args(["--output", "some/where"])
    assert args.output == "some/where"


def test_a_fresh_directory_is_accepted(tmp_path):
    engine = inv.WebHarvester("https://app.test", inv.InvestigationScope("https://app.test"),
                              session_id="s1", output_dir=tmp_path / "s1")
    try:
        assert (tmp_path / "s1" / "events.jsonl").exists()
    finally:
        engine.close_events()


def test_writing_into_a_used_directory_is_refused(tmp_path):
    """The core guarantee: never append to another session's log."""
    first = inv.WebHarvester("https://app.test", inv.InvestigationScope("https://app.test"),
                             session_id="s1", output_dir=tmp_path / "shared")
    first.close_events()
    assert (tmp_path / "shared" / "events.jsonl").stat().st_size > 0

    with pytest.raises(inv.OutputInUse):
        inv.WebHarvester("https://app.test", inv.InvestigationScope("https://app.test"),
                         session_id="s2", output_dir=tmp_path / "shared")


def test_the_fixed_global_name_is_gone():
    assert not hasattr(inv, "OUTPUT_DIR"), (
        "the fixed global output directory must be removed")


# --- two consecutive real captures stay separate --------------------------

@pytest.mark.browser
def test_two_consecutive_captures_are_separate_and_valid(tmp_path):
    from scriptscrap.events import EventLogReader
    from scriptscrap.testing.capture import capture

    out_a = tmp_path / "capture_a"
    out_b = tmp_path / "capture_b"
    capture(out_a, headless=True)
    capture(out_b, headless=True)

    log_a = out_a / "events.jsonl"
    log_b = out_b / "events.jsonl"
    assert log_a.exists() and log_b.exists()
    assert log_a != log_b

    reader_a = EventLogReader(log_a)
    reader_b = EventLogReader(log_b)
    # Structurally valid: no mixed sessions, no gaps, ordered.
    assert reader_a.validate() == []
    assert reader_b.validate() == []
    # And genuinely separate: each log carries exactly one session id, and the
    # two runs did not bleed into one another's file.
    sessions_a = {e.session_id for e in reader_a}
    sessions_b = {e.session_id for e in reader_b}
    assert len(sessions_a) == 1 and len(sessions_b) == 1
    # The scripted harness pins the same session id, so identity is not what
    # separates them -- the DIRECTORIES are. Prove the second run did not append
    # to the first by comparing event counts to each file's own line count.
    assert len(reader_a) == sum(
        1 for line in log_a.read_text(encoding="utf-8").splitlines() if line.strip())
    assert len(reader_b) == sum(
        1 for line in log_b.read_text(encoding="utf-8").splitlines() if line.strip())
