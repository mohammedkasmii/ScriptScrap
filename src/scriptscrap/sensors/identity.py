"""Stable page and frame identity for the lifetime of a session.

Playwright exposes no durable id for a Page or a Frame. M1 derived a frame label
from the frame tree, which was deterministic but not stable: two different frames
with the same name or path collided, and a frame that navigated changed label.

This registry assigns `p1`, `p2`, ... and `f1`, `f2`, ... on first sight and keeps
them for the object's lifetime, so an event stream can be grouped by frame even
across navigations. Ids are allocated in observation order, which is deterministic
for a scripted run.

Playwright's Page and Frame objects are hashable and identity-stable, so they are
used directly as keys. Entries are dropped when a page closes or a frame detaches,
which is also what bounds the registry in a long session.
"""

from __future__ import annotations

from typing import Any


class PageRegistry:
    """Assigns and resolves stable page/frame identifiers."""

    def __init__(self) -> None:
        self._pages: dict[Any, str] = {}
        self._frames: dict[Any, str] = {}
        self._frame_page: dict[str, str | None] = {}
        self._frame_parent: dict[str, str | None] = {}
        self._page_counter = 0
        self._frame_counter = 0

    # -- pages -------------------------------------------------------------
    def page_id(self, page: Any) -> str | None:
        """Id for a page, allocating one if this is the first sighting."""
        if page is None:
            return None
        existing = self._pages.get(page)
        if existing is not None:
            return existing
        self._page_counter += 1
        assigned = f"p{self._page_counter}"
        self._pages[page] = assigned
        return assigned

    def forget_page(self, page: Any) -> str | None:
        return self._pages.pop(page, None)

    # -- frames ------------------------------------------------------------
    def frame_id(self, frame: Any) -> str | None:
        """Id for a frame, recording its page and parent on first sighting."""
        if frame is None:
            return None
        existing = self._frames.get(frame)
        if existing is not None:
            return existing
        self._frame_counter += 1
        assigned = f"f{self._frame_counter}"
        self._frames[frame] = assigned

        try:
            self._frame_page[assigned] = self.page_id(frame.page)
        except Exception:
            self._frame_page[assigned] = None
        try:
            parent = frame.parent_frame
            self._frame_parent[assigned] = self.frame_id(parent) if parent else None
        except Exception:
            self._frame_parent[assigned] = None

        return assigned

    def forget_frame(self, frame: Any) -> str | None:
        assigned = self._frames.pop(frame, None)
        if assigned is not None:
            self._frame_page.pop(assigned, None)
            self._frame_parent.pop(assigned, None)
        return assigned

    def frame_page_id(self, frame_id: str | None) -> str | None:
        return self._frame_page.get(frame_id) if frame_id else None

    def parent_frame_id(self, frame_id: str | None) -> str | None:
        return self._frame_parent.get(frame_id) if frame_id else None

    def frame_of_request(self, request: Any) -> str | None:
        """Frame that issued a request.

        Playwright raises for service-worker-origin requests, which on Firefox
        are invisible anyway. Returning None keeps the caller simple; the
        service-worker blind spot is reported separately as a capture gap.
        """
        try:
            return self.frame_id(request.frame)
        except Exception:
            return None

    # -- reporting ---------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        return {
            "pages": len(self._pages),
            "frames": len(self._frames),
            "frame_tree": {
                fid: {"page_id": self._frame_page.get(fid),
                      "parent_frame_id": self._frame_parent.get(fid)}
                for fid in sorted(self._frame_parent)
            },
        }
