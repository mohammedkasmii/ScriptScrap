"""Lifecycle sensor: pages, frames, navigation, console, errors, downloads.

Listeners are attached at the CONTEXT level wherever Playwright allows it, so a
popup or a window opened by the application is observed on the same footing as
the page the operator started on. A page-only listener would miss them entirely.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from ..events import EventType, Source
from .identity import PageRegistry
from .scope import URL_PAYLOAD_KEYS, strip_query

# Console output above this is clipped. A page that logs a megabyte object
# should not be able to dominate the event log.
MAX_CONSOLE_TEXT = 4096


class LifecycleSensor:
    """Pages, frames, navigation, console messages, exceptions and downloads."""

    def __init__(self, engine: Any, registry: PageRegistry) -> None:
        self.engine = engine
        self.registry = registry
        self.pages_seen = 0
        self.popups_seen = 0
        self.console_messages = 0
        self.page_exceptions = 0
        self.downloads = 0
        self.dialogs = 0

    # -- engagement boundary ------------------------------------------------
    def _scoped(self, **payload: Any) -> dict[str, Any]:
        """Reduce any URL in this payload that lies outside the engagement.

        Only the URL half of the runtime probe's reduction applies here. That
        sensor rebuilds an out-of-scope payload from an allowlist because it
        carries bodies, header names and typed values; a lifecycle payload
        carries none of those, so its URLs are the only thing that can leak.

        The event is kept and marked rather than dropped: "a third-party iframe
        attached here" is the same forensic fact the network path preserves,
        and losing it would make an out-of-scope page look silent.
        """
        scope = getattr(self.engine, "scope", None)
        if scope is None:
            return payload
        reduced = False
        for key in URL_PAYLOAD_KEYS:
            value = payload.get(key)
            if isinstance(value, str) and value and not scope.contains(value):
                payload[key] = strip_query(value)
                reduced = True
        if reduced:
            payload["scope"] = "out_of_scope"
            payload["evidence_reduced"] = True
        return payload

    # -- attachment --------------------------------------------------------
    async def attach(self, context: Any) -> None:
        """Observe every page in the context, including ones opened later."""
        try:
            context.on("page", self._on_page)
        except Exception as exc:
            self.engine.emit_sensor_error("lifecycle_attach_context", exc)
            self.engine.emit_capture_gap(
                "context_page_events_unavailable",
                note="popups and new tabs may not be observed",
            )
        for page in getattr(context, "pages", []) or []:
            self.observe_page(page)

    def _on_page(self, page: Any) -> None:
        self.observe_page(page, from_context=True)

    def observe_page(self, page: Any, *, from_context: bool = False) -> str | None:
        """Attach page-level listeners once per page."""
        if getattr(page, "_scriptscrap_observed", False):
            return self.registry.page_id(page)
        with contextlib.suppress(AttributeError, TypeError):
            page._scriptscrap_observed = True

        page_id = self.registry.page_id(page)
        self.pages_seen += 1

        self.engine.emit_event(
            Source.PLAYWRIGHT,
            EventType.PAGE_OPENED,
            **self._scoped(
                page_id=page_id,
                url=getattr(page, "url", None),
                discovered_via="context" if from_context else "explicit",
            ),
        )

        page.on("close", lambda p=page: self._on_close(p))
        page.on("popup", lambda p: self._on_popup(p, page_id))
        page.on("frameattached", lambda f: self._on_frame_attached(f, page_id))
        page.on("framedetached", lambda f: self._on_frame_detached(f, page_id))
        page.on("framenavigated", lambda f: self._on_frame_navigated(f, page_id))
        page.on("console", lambda m: self._on_console(m, page_id))
        page.on("pageerror", lambda e: self._on_page_error(e, page_id))
        page.on("download", lambda d: self._on_download(d, page_id))
        page.on("dialog", lambda d: self._on_dialog(d, page_id))
        return page_id

    # -- handlers ----------------------------------------------------------
    def _on_close(self, page: Any) -> None:
        page_id = self.registry.forget_page(page)
        self.engine.emit_event(Source.PLAYWRIGHT, EventType.PAGE_CLOSED, page_id=page_id)

    def _on_popup(self, popup: Any, opener_page_id: str | None) -> None:
        self.popups_seen += 1
        popup_id = self.observe_page(popup, from_context=True)
        self.engine.emit_event(
            Source.PLAYWRIGHT,
            EventType.POPUP_OPENED,
            **self._scoped(
                page_id=popup_id,
                opener_page_id=opener_page_id,
                url=getattr(popup, "url", None),
            ),
        )

    def _on_frame_attached(self, frame: Any, page_id: str | None) -> None:
        frame_id = self.registry.frame_id(frame)
        self.engine.emit_event(
            Source.PLAYWRIGHT,
            EventType.FRAME_ATTACHED,
            **self._scoped(
                page_id=page_id,
                frame_id=frame_id,
                parent_frame_id=self.registry.parent_frame_id(frame_id),
                url=getattr(frame, "url", None),
                name=getattr(frame, "name", None) or None,
            ),
        )

    def _on_frame_detached(self, frame: Any, page_id: str | None) -> None:
        frame_id = self.registry.forget_frame(frame)
        self.engine.emit_event(
            Source.PLAYWRIGHT,
            EventType.FRAME_DETACHED,
            page_id=page_id,
            frame_id=frame_id,
        )

    def _on_frame_navigated(self, frame: Any, page_id: str | None) -> None:
        frame_id = self.registry.frame_id(frame)
        is_main = False
        try:
            is_main = frame.parent_frame is None
        except Exception as exc:
            # Whether this was the main frame decides whether a
            # navigation_committed is emitted, so failing to know is a real gap.
            self.engine.emit_sensor_error(
                "frame_navigated_is_main", exc, page_id=page_id, frame_id=frame_id
            )
        self.engine.emit_event(
            Source.PLAYWRIGHT,
            EventType.FRAME_NAVIGATED,
            **self._scoped(
                page_id=page_id,
                frame_id=frame_id,
                parent_frame_id=self.registry.parent_frame_id(frame_id),
                url=getattr(frame, "url", None),
                is_main_frame=is_main,
            ),
        )
        if is_main:
            self.engine.emit_event(
                Source.PLAYWRIGHT,
                EventType.NAVIGATION_COMMITTED,
                **self._scoped(
                    page_id=page_id,
                    frame_id=frame_id,
                    url=getattr(frame, "url", None),
                ),
            )

    def _on_console(self, message: Any, page_id: str | None) -> None:
        self.console_messages += 1
        try:
            text = message.text
        except Exception as exc:
            self.engine.emit_sensor_error("console_text", exc, page_id=page_id)
            return
        location = None
        # Source location is a bonus, not the message. Losing it must not lose
        # the console message itself.
        with contextlib.suppress(Exception):
            loc = message.location
            if loc:
                location = f"{loc.get('url', '')}:{loc.get('lineNumber', '')}"
        self.engine.emit_event(
            Source.PLAYWRIGHT,
            EventType.CONSOLE_MESSAGE,
            page_id=page_id,
            level=getattr(message, "type", None),
            text=text[:MAX_CONSOLE_TEXT] if isinstance(text, str) else str(text),
            truncated=isinstance(text, str) and len(text) > MAX_CONSOLE_TEXT,
            location=location,
        )

    def _on_page_error(self, error: Any, page_id: str | None) -> None:
        self.page_exceptions += 1
        # An uncaught exception is often the fastest route to understanding an
        # application's contract, so the stack is kept.
        self.engine.emit_event(
            Source.PLAYWRIGHT,
            EventType.PAGE_EXCEPTION,
            page_id=page_id,
            name=getattr(error, "name", None),
            message=getattr(error, "message", None) or str(error),
            stack=(getattr(error, "stack", None) or "")[:MAX_CONSOLE_TEXT] or None,
        )

    def _on_dialog(self, dialog: Any, page_id: str | None) -> None:
        """A JavaScript dialog: observe it, then dismiss it.

        The automation layer intercepts alert/confirm/prompt/beforeunload -- the
        native dialog never reaches the employee, whether or not a handler is
        registered (with none, Playwright auto-dismisses). So the honest record
        is the dialog's type, message and default, plus the recorder's OWN
        handling, and a capture gap stating the employee's real choice cannot be
        observed under automation. Dismiss matches the no-handler default, so
        registering this handler does not change behaviour.
        """
        self.dialogs += 1
        dtype = None
        message = None
        default_value = None
        with contextlib.suppress(Exception):
            dtype = dialog.type
        with contextlib.suppress(Exception):
            message = dialog.message
        with contextlib.suppress(Exception):
            default_value = dialog.default_value
        # Dismiss asynchronously: in the async API `dialog.dismiss()` is a
        # coroutine, and the triggering call (confirm/alert) blocks until the
        # dialog is handled. Scheduling the await lets the click proceed while
        # still dismissing -- matching the no-handler default.
        handled = "dismissed"
        try:
            asyncio.get_running_loop().create_task(self._dismiss_dialog(dialog))
        except RuntimeError:
            handled = "unhandled"
        self.engine.emit_event(
            Source.PLAYWRIGHT,
            EventType.DIALOG,
            page_id=page_id,
            dialog_type=dtype,
            message=message[:MAX_CONSOLE_TEXT] if isinstance(message, str) else message,
            default_value=default_value,
            handling=handled,
            handled_by="recorder",
        )
        # The one thing we cannot know: what the employee would have chosen.
        self.engine.emit_capture_gap(
            "dialog_choice_unobservable",
            dialog_type=dtype,
            note=("a JavaScript dialog was intercepted by the automation layer; "
                  "the recorder dismissed it (the no-handler default) and the "
                  "employee's real accept/dismiss choice is not observable"),
        )

    async def _dismiss_dialog(self, dialog: Any) -> None:
        with contextlib.suppress(Exception):
            await dialog.dismiss()

    def _on_download(self, download: Any, page_id: str | None) -> None:
        self.downloads += 1
        # Metadata only. File content never enters the event log.
        self.engine.emit_event(
            Source.PLAYWRIGHT,
            EventType.DOWNLOAD,
            **self._scoped(
                page_id=page_id,
                url=getattr(download, "url", None),
                suggested_filename=getattr(download, "suggested_filename", None),
            ),
        )

    def stats(self) -> dict[str, Any]:
        return {
            "pages": self.pages_seen,
            "popups": self.popups_seen,
            "console_messages": self.console_messages,
            "page_exceptions": self.page_exceptions,
            "downloads": self.downloads,
            "dialogs": self.dialogs,
        }
