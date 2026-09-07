"""Turning the derived model into a starting point a developer can run.

Both generators read `AnalysisResult` and nothing else. They never open the
event log, so they cannot embed a captured value even by accident: the derived
model holds shapes, parameter names and header names, and the generators do not
emit the one field that carries captured values (`examples`).

Everything produced here is a **suggestion**, derived from one observed
session. Every generated file says so in its header, because a developer who
believes a generated client describes the whole API will be wrong in a way that
is expensive to discover.
"""

from .client import render_client
from .playwright import render_playwright

__all__ = ["render_client", "render_playwright"]
