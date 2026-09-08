"""Finding and opening the sessions a workspace serves.

A session is a directory, not a database: `events.jsonl` is the evidence and
`session.sqlite` is derived from it. Both are needed, and this is where that is
checked once rather than in every handler.

**Redaction posture is a first-class property here**, not a detail. A session
directory is an unredacted capture of an authenticated session; `export/shared`
is the sanitised twin of the same session, and the two look alike in a
screenshot. Whichever one is open, the workspace says so in its header, so the
question "is this safe to screen-share?" has an answer on screen rather than in
the operator's memory.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

UNREDACTED = "unredacted"
SANITISED = "sanitised"


class SessionError(RuntimeError):
    """A directory that cannot be served, and why."""


@dataclass(frozen=True)
class SessionHandle:
    """One openable session."""

    name: str
    root: Path
    log_path: Path
    db_path: Path
    redaction: str

    @property
    def manifest_path(self) -> Path:
        return self.root / "session_manifest.json"

    def manifest(self) -> dict | None:
        """The session manifest, or None.

        Absent is a legitimate state -- an interrupted session never wrote one
        -- so this returns None rather than raising. The overview reports the
        absence, because a manifest is how a reader judges everything else.
        """
        try:
            return json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def connect(self) -> sqlite3.Connection:
        """A read-only connection to the derived store.

        Read-only at the driver level, not by convention: the workspace has no
        write path, and opening the file writable would make that a promise
        rather than a property.

        The path goes through `read_only_uri` because a URI is not a path: a
        session directory named `acme-#2` is legal everywhere, and pasting it
        into `file:{path}?mode=ro` starts a URI fragment.
        """
        from ..analysis.dbpath import read_only_uri

        conn = sqlite3.connect(read_only_uri(self.db_path), uri=True)
        conn.row_factory = sqlite3.Row
        return conn


def _redaction_of(root: Path) -> str:
    """A sanitised export lives at `export/shared` and has no raw log."""
    if root.name == "shared" and root.parent.name == "export":
        return SANITISED
    return UNREDACTED


def is_session(path: Path) -> bool:
    return (path / "events.jsonl").is_file()


def open_session(path: str | Path) -> SessionHandle:
    """Open one session directory.

    Raises rather than degrades: a workspace that opens a session with no
    derived store would render empty views and look like an application with
    nothing in it, when the actual problem is that nobody ran `analyze`.
    """
    root = Path(path).resolve()
    if not root.is_dir():
        raise SessionError(f"{root} is not a directory")

    log = root / "events.jsonl"
    if not log.is_file():
        raise SessionError(
            f"{root} holds no events.jsonl; it is not an investigation session")

    db = root / "session.sqlite"
    if not db.is_file():
        raise SessionError(
            f"{root} has no session.sqlite. Run `scriptscrap analyze {root}` first.")

    return SessionHandle(
        name=root.name,
        root=root,
        log_path=log,
        db_path=db,
        redaction=_redaction_of(root),
    )


def discover_sessions(path: str | Path) -> list[SessionHandle]:
    """Every session at `path`, whether it is one session or a parent of many.

    A session that has not been analysed is skipped rather than failing the
    whole listing: one un-analysed directory beside five good ones should cost
    that one directory, not the workspace.
    """
    root = Path(path).resolve()
    if not root.is_dir():
        raise SessionError(f"{root} is not a directory")

    if is_session(root):
        return [open_session(root)]

    sessions: list[SessionHandle] = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        for candidate in (child, child / "export" / "shared"):
            if is_session(candidate):
                try:
                    sessions.append(open_session(candidate))
                except SessionError:
                    continue
    if not sessions:
        raise SessionError(
            f"no analysed session found at {root}. A session directory holds "
            "events.jsonl and session.sqlite; run `scriptscrap analyze` to "
            "produce the latter.")
    return sessions
