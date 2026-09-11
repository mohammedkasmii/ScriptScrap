"""The export's health-overall vocabulary must match what health can produce.

A fully-healthy session (every sensor green) failed the shared export because
`_OVERALL_CODES` never contained the code for "COMPLETE / ALL SENSORS HEALTHY"
-- the vocabulary was a guess that happened to include the one phrase every
reference capture hit. This pins the vocabulary to the producer, so the two
cannot drift apart again.
"""

from __future__ import annotations

import re

from scriptscrap.analysis.health import HealthAnalyzer, SensorHealth
from scriptscrap.export.policy import _OVERALL_CODES


def _code(phrase: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", phrase.lower()).strip("_")


def _overall(*statuses_and_blind_spots) -> str:
    sensors = []
    for i, (status, blind) in enumerate(statuses_and_blind_spots):
        sensors.append(SensorHealth(f"s{i}", status, blind_spots=blind))
    return HealthAnalyzer._overall(sensors)


def test_every_overall_phrase_has_a_vocabulary_entry():
    from scriptscrap.analysis.health import (
        DEGRADED,
        HEALTHY,
        NOT_APPLICABLE,
        UNAVAILABLE,
    )

    phrases = {
        _overall((HEALTHY, [])),                              # complete
        _overall((DEGRADED, [])),                             # high coverage
        _overall((UNAVAILABLE, [])),                          # unavailable
        _overall((HEALTHY, ["lost a family"])),               # blind spot
        _overall((UNAVAILABLE, ["lost a family"])),           # blind spot + unavailable
        _overall((NOT_APPLICABLE, ())),                       # unknown (all n/a)
    }
    for phrase in phrases:
        assert _code(phrase) in _OVERALL_CODES, (
            f"health can emit {phrase!r} -> {_code(phrase)!r}, which the export "
            f"vocabulary does not contain")
