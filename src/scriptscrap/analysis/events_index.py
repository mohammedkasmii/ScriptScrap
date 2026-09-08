"""Reading the evidence index.

This is the only module that knows byte offsets exist. Everything above it asks
for events by id, by filter, or by window; nothing above it ever sees a
position. Replacing the backing store later means rewriting this file and
nothing else.

The split it maintains:

    session.sqlite   the envelope -- filterable, countable, cheap
    events.jsonl     the payload  -- the source of truth, read by seek

Metadata questions ("how many clicks?", "the next 200 events") are answered
without opening the log at all. Only a payload costs a read.

**Staleness is an error, not a best effort.** `events.jsonl` is append-only, so
a session that kept recording after `analyze` ran leaves an index that points
into the right file at the wrong places. Serving whatever now sits at that
offset would hand back evidence belonging to some other event, and a reader
would have no way to tell. So the log's size and sha256 are checked before the
first payload read and `StaleIndexError` names the remedy.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ..events import Event
from .dbpath import read_only_uri
from .models import EventIndexRow

# Filtering and counting are answered from sqlite; only these need the log.
_PAYLOAD_REQUIRED = "reading an event payload"


class StaleIndexError(RuntimeError):
    """The log no longer matches the bytes the index was built from."""


@dataclass(frozen=True)
class EventPage:
    """One page of a filtered walk, with payloads.

    `next_seq` is the cursor to pass back as `after_seq`; None means the walk
    is finished. `total` is the size of the whole filtered set, not the page.
    """

    events: list[Event]
    next_seq: int | None
    total: int


@dataclass(frozen=True)
class IndexPage:
    """One page of a filtered walk, envelopes only.

    What a timeline actually renders: type, source, time, page. Reading 200
    payloads to draw a list of 200 rows would be 200 seeks for text nobody is
    looking at yet, so the list is served from sqlite alone and a payload is
    fetched by `get` when a row is opened.
    """

    rows: list[EventIndexRow]
    next_seq: int | None
    total: int


class EventStore:
    """Random access to a session's events, backed by the derived index."""

    def __init__(self, db_path: str | Path, log_path: str | Path,
                 run_id: int | None = None) -> None:
        self.db_path = Path(db_path)
        self.log_path = Path(log_path)
        self.conn = sqlite3.connect(read_only_uri(self.db_path), uri=True)
        self.conn.row_factory = sqlite3.Row
        self.run_id = run_id if run_id is not None else self._latest_run()
        self._verified = False

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> EventStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- run selection -----------------------------------------------------
    def _latest_run(self) -> int:
        row = self.conn.execute(
            "SELECT id FROM analysis_runs ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            raise StaleIndexError(
                f"{self.db_path} holds no analysis run; run `scriptscrap analyze`")
        return int(row["id"])

    # -- staleness ---------------------------------------------------------
    def _verify_log(self) -> None:
        """Check the log against the fingerprint the index was built from.

        Runs once per instance, on the first payload read. Metadata queries
        never reach here, so a timeline still lists correctly on a machine
        where the log has been moved away.
        """
        if self._verified:
            return
        row = self.conn.execute(
            "SELECT log_size, log_sha256 FROM analysis_runs WHERE id=?",
            (self.run_id,)).fetchone()
        expected_size = row["log_size"] if row else None
        expected_hash = row["log_sha256"] if row else None

        if expected_size is None or expected_hash is None:
            raise StaleIndexError(
                f"run {self.run_id} predates the evidence index; "
                "re-run `scriptscrap analyze` to build it")
        if not self.log_path.exists():
            raise StaleIndexError(f"{self.log_path} is missing; {_PAYLOAD_REQUIRED} needs it")

        actual_size = self.log_path.stat().st_size
        if actual_size != expected_size:
            raise StaleIndexError(
                f"{self.log_path} is {actual_size} bytes, index was built from "
                f"{expected_size}; the session kept recording after analysis. "
                "Re-run `scriptscrap analyze` before trusting this evidence.")

        digest = hashlib.sha256()
        with self.log_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected_hash:
            raise StaleIndexError(
                f"{self.log_path} has the expected size but different contents; "
                "the index does not describe this log. Re-run `scriptscrap analyze`.")
        self._verified = True

    # -- reading -----------------------------------------------------------
    def _read(self, offset: int, length: int) -> Event | None:
        self._verify_log()
        with self.log_path.open("rb") as handle:
            handle.seek(offset)
            raw = handle.read(length)
        try:
            return Event.from_dict(json.loads(raw.decode("utf-8")))
        except (ValueError, UnicodeDecodeError):
            # The fingerprint matched, so this is a defect in the index rather
            # than a changed log. Surfacing it as a miss would hide that.
            raise StaleIndexError(
                f"offset {offset}+{length} in {self.log_path} is not a valid event; "
                "the index is corrupt. Re-run `scriptscrap analyze --rebuild`.") from None

    def get(self, event_id: str) -> Event | None:
        row = self.conn.execute(
            "SELECT byte_offset, byte_length FROM events WHERE run_id=? AND event_id=?",
            (self.run_id, event_id)).fetchone()
        if row is None:
            # Still verify: a caller asking for an id that is not in the index
            # deserves to know the index is stale rather than be told "no such
            # event" about one the log now contains.
            self._verify_log()
            return None
        return self._read(row["byte_offset"], row["byte_length"])

    def get_many(self, event_ids: Sequence[str]) -> list[Event]:
        """Fetch several events, in the order asked for.

        Unknown ids are skipped rather than raising: an evidence list is
        frequently longer than what a truncated log actually holds, and losing
        the ones that survived would be the wrong trade.
        """
        if not event_ids:
            return []
        placeholders = ",".join("?" * len(event_ids))
        rows = self.conn.execute(
            f"SELECT event_id, byte_offset, byte_length FROM events "  # noqa: S608
            f"WHERE run_id=? AND event_id IN ({placeholders})",
            (self.run_id, *event_ids)).fetchall()
        located = {r["event_id"]: (r["byte_offset"], r["byte_length"]) for r in rows}

        events: list[Event] = []
        for event_id in event_ids:
            position = located.get(event_id)
            if position is None:
                continue
            event = self._read(*position)
            if event is not None:
                events.append(event)
        return events

    def _select(self, *, types: Sequence[str] | None,
                sources: Sequence[str] | None,
                page_id: str | None,
                after_seq: int | None,
                limit: int) -> tuple[list[sqlite3.Row], int | None, int]:
        """The shared filtered walk, in `seq` order.

        Ordered by `seq` and never by timestamp: wall clocks from different
        sensors disagree, and `seq` is the only total order the spine
        guarantees (`events/model.py`).

        One row past `limit` is fetched to decide whether a cursor is needed,
        so "is there more?" costs no second query.
        """
        where = ["run_id = ?"]
        params: list[object] = [self.run_id]
        if types:
            where.append(f"type IN ({','.join('?' * len(types))})")
            params.extend(types)
        if sources:
            where.append(f"source IN ({','.join('?' * len(sources))})")
            params.extend(sources)
        if page_id is not None:
            where.append("page_id = ?")
            params.append(page_id)
        clause = " AND ".join(where)

        total = int(self.conn.execute(
            f"SELECT COUNT(*) FROM events WHERE {clause}", params).fetchone()[0])  # noqa: S608

        paged = list(params)
        if after_seq is not None:
            clause += " AND seq > ?"
            paged.append(after_seq)
        rows = self.conn.execute(
            f"SELECT * FROM events WHERE {clause} ORDER BY seq LIMIT ?",  # noqa: S608
            (*paged, limit + 1)).fetchall()

        has_more = len(rows) > limit
        rows = rows[:limit]
        next_seq = int(rows[-1]["seq"]) if has_more and rows else None
        return rows, next_seq, total

    def page(self, *, types: Sequence[str] | None = None,
             sources: Sequence[str] | None = None,
             page_id: str | None = None,
             after_seq: int | None = None,
             limit: int = 200) -> EventPage:
        """One page of a filtered walk, with payloads read from the log."""
        rows, next_seq, total = self._select(
            types=types, sources=sources, page_id=page_id,
            after_seq=after_seq, limit=limit)
        events = [e for r in rows if (e := self._read(r["byte_offset"], r["byte_length"]))]
        return EventPage(events=events, next_seq=next_seq, total=total)

    def page_index(self, *, types: Sequence[str] | None = None,
                   sources: Sequence[str] | None = None,
                   page_id: str | None = None,
                   after_seq: int | None = None,
                   limit: int = 200) -> IndexPage:
        """One page of envelopes. Never opens the log.

        This is what a timeline list is built from. Reading 200 payloads to
        render 200 collapsed rows would be 200 seeks for text nobody has asked
        to see; the payload arrives via `get` when a row is opened.
        """
        rows, next_seq, total = self._select(
            types=types, sources=sources, page_id=page_id,
            after_seq=after_seq, limit=limit)
        return IndexPage(
            rows=[EventIndexRow(
                event_id=r["event_id"], seq=r["seq"], type=r["type"],
                source=r["source"], t_wall=r["t_wall"], t_mono=r["t_mono"],
                page_id=r["page_id"], frame_id=r["frame_id"],
                byte_offset=r["byte_offset"], byte_length=r["byte_length"],
            ) for r in rows],
            next_seq=next_seq,
            total=total,
        )

    def window(self, start_seq: int, end_seq: int) -> list[Event]:
        """Every event in an inclusive `seq` range."""
        rows = self.conn.execute(
            "SELECT byte_offset, byte_length FROM events "
            "WHERE run_id=? AND seq BETWEEN ? AND ? ORDER BY seq",
            (self.run_id, start_seq, end_seq)).fetchall()
        return [e for r in rows if (e := self._read(r["byte_offset"], r["byte_length"]))]

    # -- metadata (never touches the log) ----------------------------------
    def counts_by_type(self) -> dict[str, int]:
        return {r["type"]: int(r["n"]) for r in self.conn.execute(
            "SELECT type, COUNT(*) AS n FROM events WHERE run_id=? "
            "GROUP BY type ORDER BY n DESC", (self.run_id,))}

    def counts_by_source(self) -> dict[str, int]:
        return {r["source"]: int(r["n"]) for r in self.conn.execute(
            "SELECT source, COUNT(*) AS n FROM events WHERE run_id=? "
            "GROUP BY source ORDER BY n DESC", (self.run_id,))}

    def seq_range(self) -> tuple[int, int] | None:
        row = self.conn.execute(
            "SELECT MIN(seq) AS lo, MAX(seq) AS hi FROM events WHERE run_id=?",
            (self.run_id,)).fetchone()
        if row is None or row["lo"] is None:
            return None
        return int(row["lo"]), int(row["hi"])
