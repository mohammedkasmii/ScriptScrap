"""Offline reader for an event log.

This module establishes the boundary the whole future architecture rests on:

    capture  ->  event log  ->  offline reader

Nothing here imports Playwright, Camoufox, or anything that touches a browser.
An event log can therefore be read, validated and analysed long after the
session ended, on a machine that has no browser at all -- which is what makes
analysis testable without launching one.

It is deliberately NOT an analysis engine. It loads, validates, and answers
structural questions. Correlation, schema inference and state reconstruction are
later milestones that will consume this, not live here.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .model import Event, EventType, Source


@dataclass(frozen=True)
class LogProblem:
    """A defect found while reading. Line numbers are 1-based."""

    line: int
    kind: str
    detail: str

    def __str__(self) -> str:
        return f"line {self.line}: {self.kind}: {self.detail}"


class EventLogReader:
    """Loads and validates a newline-delimited event log.

    Tolerates a truncated final line, because that is exactly what a killed
    process leaves behind and recovering everything before it is the point.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.events: list[Event] = []
        self.problems: list[LogProblem] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            raise FileNotFoundError(self.path)

        with self.path.open("r", encoding="utf-8") as handle:
            lines = handle.readlines()

        for number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            is_last = number == len(lines)
            if not line.endswith("\n") and is_last:
                # A process killed mid-write leaves a partial final line.
                # Everything before it is still valid evidence.
                self.problems.append(
                    LogProblem(number, "truncated_final_line",
                               "log ends mid-write; earlier events are intact")
                )
                continue
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError as exc:
                self.problems.append(LogProblem(number, "invalid_json", str(exc)))
                continue
            try:
                self.events.append(Event.from_dict(raw))
            except ValueError as exc:
                self.problems.append(LogProblem(number, "invalid_envelope", str(exc)))

    # -- access ------------------------------------------------------------
    def __len__(self) -> int:
        return len(self.events)

    def __iter__(self) -> Iterator[Event]:
        return iter(self.events)

    def of_type(self, *types: EventType) -> list[Event]:
        wanted = set(types)
        return [e for e in self.events if e.type in wanted]

    def from_source(self, *sources: Source) -> list[Event]:
        wanted = set(sources)
        return [e for e in self.events if e.source in wanted]

    # -- validation --------------------------------------------------------
    def sequence_gaps(self) -> list[tuple[int, int]]:
        """Ranges missing from the sequence.

        A gap means an event was allocated a number but never reached disk, so
        the log is knowably incomplete rather than silently short.
        """
        seqs = sorted(e.seq for e in self.events)
        gaps: list[tuple[int, int]] = []
        for previous, current in zip(seqs, seqs[1:], strict=False):
            if current > previous + 1:
                gaps.append((previous + 1, current - 1))
        return gaps

    def validate(self) -> list[LogProblem]:
        """Structural checks over the whole log."""
        problems = list(self.problems)

        if not self.events:
            problems.append(LogProblem(0, "empty_log", "no readable events"))
            return problems

        sessions = {e.session_id for e in self.events}
        if len(sessions) > 1:
            problems.append(
                LogProblem(0, "mixed_sessions", f"{len(sessions)} session ids in one log")
            )

        seqs = [e.seq for e in self.events]
        if seqs != sorted(seqs):
            problems.append(LogProblem(0, "unordered", "seq is not monotonically increasing"))

        duplicates = [s for s, n in Counter(seqs).items() if n > 1]
        if duplicates:
            problems.append(
                LogProblem(0, "duplicate_seq", f"repeated: {sorted(duplicates)[:10]}")
            )

        ids = [e.event_id for e in self.events]
        dup_ids = [i for i, n in Counter(ids).items() if n > 1]
        if dup_ids:
            problems.append(LogProblem(0, "duplicate_event_id", f"repeated: {sorted(dup_ids)[:10]}"))

        for start, end in self.sequence_gaps():
            problems.append(
                LogProblem(0, "sequence_gap", f"seq {start}..{end} never reached disk")
            )

        monos = [e.t_mono for e in self.events]
        if monos != sorted(monos):
            problems.append(
                LogProblem(0, "non_monotonic_clock", "t_mono decreases; clock source is wrong")
            )

        return problems

    # -- reporting ---------------------------------------------------------
    def summary(self) -> dict[str, object]:
        by_type = Counter(str(e.type) for e in self.events)
        by_source = Counter(str(e.source) for e in self.events)
        return {
            "path": str(self.path),
            "events": len(self.events),
            "sessions": sorted({e.session_id for e in self.events}),
            "seq_range": [min(e.seq for e in self.events), max(e.seq for e in self.events)]
            if self.events
            else [],
            "by_type": dict(sorted(by_type.items())),
            "by_source": dict(sorted(by_source.items())),
            "problems": [str(p) for p in self.validate()],
        }
