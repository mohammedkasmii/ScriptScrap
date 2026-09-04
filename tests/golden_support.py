"""Golden-master locations and the re-bless switch.

A plain module rather than conftest, so test modules can import it directly.
pytest puts the tests directory on sys.path, so `import golden_support` works
without making tests a package.
"""

from __future__ import annotations

import os
from pathlib import Path

GOLDEN_DIR = Path(__file__).parent / "golden"
GOLDEN_FILE = GOLDEN_DIR / "investigation.json"
SAMPLE_EVENT_LOG = GOLDEN_DIR / "sample_events.jsonl"

UPDATE_ENV = "SCRIPTSCRAP_UPDATE_GOLDEN"


def updating_golden() -> bool:
    """True when the run is allowed to overwrite the baseline."""
    return os.environ.get(UPDATE_ENV) == "1"
