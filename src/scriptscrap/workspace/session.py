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
    """One openable session.

    `log_path` is None for a sanitised export: it has no raw log, by design.
    Every route that needs a payload checks, and says so, rather than failing
    on a path that does not exist.
    """

    name: str
    root: Path
    db_path: Path
    redaction: str
    log_path: Path | None = None

    @property
    def has_evidence(self) -> bool:
        return self.log_path is not None

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


def _name_for(root: Path, base: Path | None) -> str:
    """A name that identifies the session, not just its last path segment.

    `export/shared` is a session's sanitised twin, and two of them are both
    called `shared`. The name is what the session picker addresses, so it has
    to be unique -- and it has to say WHICH session, or the picker offers two
    identical entries.
    """
    if base is None or root == base:
        return root.name
    try:
        relative = root.relative_to(base)
    except ValueError:
        return root.name
    parts = relative.parts
    if parts[-2:] == ("export", "shared"):
        return f"{'/'.join(parts[:-2]) or base.name} (shared)"
    return "/".join(parts)


def is_session(path: Path) -> bool:
    """A session is a derived store. The raw log is what makes it UNREDACTED."""
    return (path / "session.sqlite").is_file()


def open_session(path: str | Path, *, base: Path | None = None) -> SessionHandle:
    """Open one session directory.

    Raises rather than degrades: a workspace that opens a session with no
    derived store would render empty views and look like an application with
    nothing in it, when the actual problem is that nobody ran `analyze`.
    """
    root = Path(path).resolve()
    if not root.is_dir():
        raise SessionError(f"{root} is not a directory")

    db = root / "session.sqlite"
    log = root / "events.jsonl"
    redaction = _redaction_of(root)

    if not db.is_file():
        if log.is_file():
            raise SessionError(
                f"{root} has no session.sqlite. "
                f"Run `scriptscrap analyze {root}` first.")
        raise SessionError(
            f"{root} holds no session.sqlite; it is not an investigation session")
    if redaction == UNREDACTED and not log.is_file():
        # A raw session directory without its log is a session whose evidence
        # has been moved away, not a sanitised one. Say which.
        raise SessionError(
            f"{root} has a derived store but no events.jsonl; evidence "
            "drill-through would be impossible. If this is a sanitised export, "
            "it belongs at export/shared.")

    return SessionHandle(
        name=_name_for(root, base), root=root, db_path=db, redaction=redaction,
        log_path=log if log.is_file() else None,
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
                    sessions.append(open_session(candidate, base=root))
                except SessionError:
                    continue
    if not sessions:
        raise SessionError(
            f"no analysed session found at {root}. A session directory holds "
            "session.sqlite, derived from events.jsonl; run "
            "`scriptscrap analyze` to produce it.")
    return sessions
