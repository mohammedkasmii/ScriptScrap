"""The investigator's command line, and its forensic opt-in.

Forensic mode was reachable only from the test helpers. An operator running a
real agency session needs it from the normal entry point, through a clear flag
-- and the most invasive part of it, source rewriting, must stay a separate
opt-in, because rewriting a response before the browser parses it is
intervention, not observation.

Offline: only the argument parsing and the config it produces are under test
here; the forensic capture path itself is covered by the browser suite.
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


def test_normal_capture_is_the_default():
    args = inv.parse_cli_args([])
    assert args.forensic is False
    assert inv.forensic_config_from_args(args) is None


def test_forensic_flag_enables_the_layer():
    args = inv.parse_cli_args(["--forensic"])
    config = inv.forensic_config_from_args(args)
    assert config is not None
    assert config.enabled is True
    # Enabling forensic mode must NOT enable source rewriting on its own.
    assert config.source_rewrite is False
    assert config.rewriting_active is False


def test_max_body_bytes_is_configurable():
    args = inv.parse_cli_args(["--forensic", "--forensic-max-body-bytes", "1024"])
    config = inv.forensic_config_from_args(args)
    assert config.max_body_bytes == 1024


def test_source_rewriting_requires_forensic_mode():
    """The gate is real: --rewrite-source without --forensic is refused."""
    args = inv.parse_cli_args(["--rewrite-source", "app.js:doThing"])
    with pytest.raises(SystemExit):
        inv.forensic_config_from_args(args)


def test_source_rewriting_is_a_separate_opt_in():
    args = inv.parse_cli_args(
        ["--forensic", "--rewrite-source", "app.js:calc,validate"])
    config = inv.forensic_config_from_args(args)
    assert config.source_rewrite is True
    assert config.rewriting_active is True
    target = config.rewrite_targets[0]
    assert target.script == "app.js"
    assert target.functions == ["calc", "validate"]


def test_headless_is_off_by_default_and_can_be_set():
    assert inv.parse_cli_args([]).headless is False
    assert inv.parse_cli_args(["--headless"]).headless is True
