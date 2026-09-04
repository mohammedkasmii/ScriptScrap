"""Capture configuration, and the forensic opt-in.

Two modes, and the boundary between them is explicit by design:

    normal     Playwright sensors + in-page runtime probe. The default.
    forensic   the above, plus a Firefox extension that sees response bodies,
               script source before execution, and the real cookie jar.

Forensic mode is more invasive, so it never turns itself on, and it never
silently enables the most invasive part of itself: **source rewriting has its
own separate opt-in**, because rewriting a response before the browser parses it
means the application no longer runs the code its author shipped. Observation
and intervention must not share a switch.

Whatever is enabled is written into the session manifest verbatim, so a reader
of the evidence can always tell what produced it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .storage.blobs import DEFAULT_MAX_BLOB_BYTES

MODE_NORMAL = "normal"
MODE_FORENSIC = "forensic"


@dataclass(slots=True)
class RewriteTarget:
    """A function to instrument from its first execution.

    Generic by construction: the core accepts arbitrary names supplied by the
    operator. No application's function names live in ScriptScrap.
    """

    script: str            # substring matched against the script URL
    functions: list[str]   # function names to wrap on entry

    def to_dict(self) -> dict[str, Any]:
        return {"script": self.script, "functions": list(self.functions)}


@dataclass(slots=True)
class ForensicConfig:
    """What the forensic layer is permitted to do this session."""

    enabled: bool = False
    capture_bodies: bool = True
    capture_scripts: bool = True
    capture_cookies: bool = True
    max_body_bytes: int = 2 * 1024 * 1024
    max_blob_bytes: int = DEFAULT_MAX_BLOB_BYTES

    # Separate opt-in. Enabling forensic mode must NOT enable this.
    source_rewrite: bool = False
    rewrite_targets: list[RewriteTarget] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.source_rewrite and not self.enabled:
            raise ValueError("source rewriting requires forensic mode")

    @property
    def rewriting_active(self) -> bool:
        """True only when rewriting is enabled AND something is targeted."""
        return self.enabled and self.source_rewrite and bool(self.rewrite_targets)

    def to_manifest(self) -> dict[str, Any]:
        return {
            "mode": MODE_FORENSIC if self.enabled else MODE_NORMAL,
            "response_body_interception": self.enabled and self.capture_bodies,
            "script_source_capture": self.enabled and self.capture_scripts,
            "cookie_state_capture": self.enabled and self.capture_cookies,
            "max_body_bytes": self.max_body_bytes,
            "max_blob_bytes": self.max_blob_bytes,
            "source_rewriting": {
                "enabled": self.source_rewrite,
                "active": self.rewriting_active,
                "targets": [t.to_dict() for t in self.rewrite_targets],
                "note": (
                    "Source rewriting alters the code the browser executes. When "
                    "active, behaviour in this session is NOT pure observation, "
                    "and every rewritten script records both hashes."
                ),
            },
        }


@dataclass(slots=True)
class CaptureConfig:
    """Everything that shapes a capture session."""

    target_url: str
    extra_scope_domains: list[str] = field(default_factory=list)
    headless: bool = False
    forensic: ForensicConfig = field(default_factory=ForensicConfig)

    @property
    def mode(self) -> str:
        return MODE_FORENSIC if self.forensic.enabled else MODE_NORMAL

    def to_manifest(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "sensors": {
                "playwright": True,
                "runtime_probe": True,
                "extension": self.forensic.enabled,
            },
            "forensic": self.forensic.to_manifest(),
        }


def normal() -> CaptureConfig:
    """Placeholder used by tests; a real session supplies a target."""
    return CaptureConfig(target_url="")
