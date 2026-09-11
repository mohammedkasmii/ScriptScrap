"""The investigation workspace: a read-only, local view of a captured session.

Imports no browser. `scriptscrap.workspace` sits on the same side of the line
as `scriptscrap.analysis` -- it reads a recorded session and never produces
one -- and `tests/test_analysis_boundary.py` enforces that.
"""

from .server import Workspace, WorkspaceConfig, serve
from .session import (
    SANITISED,
    UNREDACTED,
    SessionError,
    SessionHandle,
    discover_sessions,
    open_session,
)

__all__ = [
    "SANITISED",
    "UNREDACTED",
    "SessionError",
    "SessionHandle",
    "Workspace",
    "WorkspaceConfig",
    "discover_sessions",
    "open_session",
    "serve",
]
