"""Shared fixtures.

The scripted investigation launches a browser and takes ~30s, so it runs ONCE
per test session and every browser-marked test reads the same output.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def investigation_output(tmp_path_factory) -> Path:
    """Run the post-M0 investigator against the fixture app, once."""
    from scriptscrap.testing.capture import capture

    out = tmp_path_factory.mktemp("investigation") / "output"
    capture(out, headless=True)
    return out


@pytest.fixture(scope="session")
def investigation_snapshot(investigation_output: Path) -> dict:
    from scriptscrap.testing.snapshot import build_snapshot

    return build_snapshot(investigation_output)
