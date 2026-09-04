"""Append-only event log.

The single most important property for M1: **events reach disk as they happen.**
The pre-existing investigator held its entire network log in memory and wrote it
once at exit, so a crash or a kill destroyed the whole investigation. Here each
event is written and flushed immediately, so an interrupted session still leaves
a readable log of everything observed up to the interruption.

Sequence numbers are allocated here, by one writer, so they are the authoritative
total order across every sensor.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from types import TracebackType
from typing import Any

from .model import (
    Event,
    EventType,
    Source,
    make_payload,
    now_mono,
    now_wall,
)


def new_id(prefix: str, counter: int) -> str:
    """Deterministic, sortable, dependency-free identifier.

    Not a ULID: a random component would make golden-master runs
    non-reproducible for no benefit, since a session directory is already unique.
    """
    return f"{prefix}-{counter:08d}"


class EventLog:
    """Writes newline-delimited JSON events to a file, one line per event.

    Thread-safe. `fsync_every` controls durability: 1 fsyncs every event
    (slowest, strongest), 0 never fsyncs and relies on flush alone. The default
    flushes every event and fsyncs periodically, which survives a process kill --
    the case that matters -- without paying a disk sync per request.
    """

    def __init__(
        self,
        path: str | Path,
        session_id: str,
        *,
        fsync_every: int = 25,
    ) -> None:
        self.path = Path(path)
        self.session_id = session_id
        self.fsync_every = fsync_every
        self.path.parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self._seq = 0
        self._event_counter = 0
        self._since_sync = 0
        self._closed = False
        # Line-buffered append. Opened once and held for the session.
        self._fh = self.path.open("a", encoding="utf-8", buffering=1)

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> EventLog:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
            except (OSError, ValueError):
                pass
            self._fh.close()

    @property
    def count(self) -> int:
        return self._seq

    # -- emission ----------------------------------------------------------
    def emit(
        self,
        source: Source,
        event_type: EventType,
        *,
        page_id: str | None = None,
        frame_id: str | None = None,
        **payload: Any,
    ) -> Event | None:
        """Append one event. Never raises into the caller's capture path.

        A logging failure must not take down an investigation, so this returns
        None on failure rather than propagating. The failure is still visible:
        the resulting gap in `seq` is detectable by the offline reader.
        """
        with self._lock:
            if self._closed:
                return None
            self._seq += 1
            self._event_counter += 1
            event = Event(
                session_id=self.session_id,
                event_id=new_id("evt", self._event_counter),
                seq=self._seq,
                t_wall=now_wall(),
                t_mono=now_mono(),
                source=source,
                type=event_type,
                payload=make_payload(**payload),
                page_id=page_id,
                frame_id=frame_id,
            )
            try:
                self._fh.write(event.to_json() + "\n")
                self._since_sync += 1
                if self.fsync_every and self._since_sync >= self.fsync_every:
                    self._fh.flush()
                    os.fsync(self._fh.fileno())
                    self._since_sync = 0
            except (OSError, ValueError, TypeError):
                return None
            return event

    # -- convenience -------------------------------------------------------
    def sensor_error(
        self,
        source: Source,
        where: str,
        exc: BaseException,
        **extra: Any,
    ) -> Event | None:
        """ScriptScrap failed to observe something. Not the same as nothing happening."""
        return self.emit(
            source,
            EventType.SENSOR_ERROR,
            where=where,
            error_type=type(exc).__name__,
            error=str(exc),
            **extra,
        )

    def capture_gap(
        self,
        source: Source,
        reason: str,
        **extra: Any,
    ) -> Event | None:
        """Something happened that was deliberately or unavoidably not captured.

        Recording the hole is the point: it makes 'we did not look' distinguishable
        from 'there was nothing there'.
        """
        return self.emit(source, EventType.CAPTURE_GAP, reason=reason, **extra)
