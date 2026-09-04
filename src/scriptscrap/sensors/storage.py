"""Storage sensor: cookies, localStorage, sessionStorage snapshots.

Incremental storage WRITES come from the runtime probe (it wraps
`Storage.prototype`). This sensor captures periodic full snapshots, which the
probe cannot: it sees values written before the probe loaded, and cookies that
page JavaScript can never read at all.

Deliberately NOT here:
* httpOnly cookie truth and partition keys -- needs the extension sensor (M4).
  Playwright's `context.cookies()` does return httpOnly cookies, but without
  the change stream or partition detail, so this is a snapshot, not a feed.
* IndexedDB and Cache Storage -- excluded until they can be done reliably.
  Their absence is reported as a capture gap rather than left implicit.

Cookie and storage VALUES are captured: this is the raw local vault, which the
scope policy already bounds. Sanitised export is M3.
"""

from __future__ import annotations

from typing import Any

from ..events import EventType, Source
from .identity import PageRegistry

READ_STORAGE_JS = """
() => {
    const dump = (store) => {
        const out = {};
        try {
            for (let i = 0; i < store.length; i++) {
                const k = store.key(i);
                const v = store.getItem(k);
                out[k] = v === null ? null : (v.length > 4096 ? v.slice(0, 4096) + "…" : v);
            }
        } catch (e) {
            return { __error__: String(e && e.message || e) };
        }
        return out;
    };
    return {
        origin: location.origin,
        localStorage: dump(window.localStorage),
        sessionStorage: dump(window.sessionStorage),
        has_indexed_db: typeof indexedDB !== "undefined",
        has_service_worker: !!(navigator.serviceWorker &&
                               navigator.serviceWorker.controller),
        has_cache_storage: typeof caches !== "undefined",
    };
}
"""


class StorageSensor:
    """Snapshots browser storage at meaningful points in a session."""

    def __init__(self, engine: Any, registry: PageRegistry) -> None:
        self.engine = engine
        self.registry = registry
        self.snapshots = 0
        self._reported_gaps: set[str] = set()

    async def snapshot(self, page: Any, *, reason: str) -> None:
        page_id = self.registry.page_id(page)

        if not self.engine.scope.contains(getattr(page, "url", "") or ""):
            self.engine.emit_capture_gap(
                "storage_snapshot_out_of_scope", reason=reason, page_id=page_id
            )
            return

        web_storage: dict[str, Any] = {}
        try:
            web_storage = await page.evaluate(READ_STORAGE_JS)
        except Exception as exc:
            self.engine.emit_sensor_error("storage_snapshot", exc, page_id=page_id)

        cookies: list[dict] = []
        try:
            raw = await page.context.cookies()
            cookies = [
                {
                    "name": c.get("name"),
                    "domain": c.get("domain"),
                    "path": c.get("path"),
                    "http_only": c.get("httpOnly"),
                    "secure": c.get("secure"),
                    "same_site": c.get("sameSite"),
                    "value_length": len(c.get("value") or ""),
                    "value": c.get("value"),
                }
                for c in raw
                if self.engine.scope.contains_host((c.get("domain") or "").lstrip("."))
            ]
        except Exception as exc:
            self.engine.emit_sensor_error("cookie_snapshot", exc, page_id=page_id)

        self.snapshots += 1
        self.engine.emit_event(
            Source.PLAYWRIGHT,
            EventType.STORAGE_SNAPSHOT,
            page_id=page_id,
            reason=reason,
            origin=web_storage.get("origin"),
            local_storage=web_storage.get("localStorage"),
            session_storage=web_storage.get("sessionStorage"),
            cookies=cookies,
            cookie_count=len(cookies),
        )

        self._report_unobservable(web_storage)

    def _report_unobservable(self, info: dict[str, Any]) -> None:
        """Name what exists but cannot be observed, once per session.

        Silence here would be indistinguishable from an application that has no
        service worker and no IndexedDB.
        """
        if info.get("has_service_worker") and "service_worker" not in self._reported_gaps:
            self._reported_gaps.add("service_worker")
            self.engine.emit_capture_gap(
                "service_worker_visibility_unavailable",
                note=(
                    "a service worker controls this page. Playwright cannot observe "
                    "or route service-worker traffic on Firefox, so requests it "
                    "fulfils are absent from this session"
                ),
            )
        if info.get("has_indexed_db") and "indexed_db" not in self._reported_gaps:
            self._reported_gaps.add("indexed_db")
            self.engine.emit_capture_gap(
                "indexed_db_not_captured",
                note="IndexedDB contents are not captured in this build",
            )
        if info.get("has_cache_storage") and "cache_storage" not in self._reported_gaps:
            self._reported_gaps.add("cache_storage")
            self.engine.emit_capture_gap(
                "cache_storage_not_captured",
                note="Cache Storage contents are not captured in this build",
            )

    def stats(self) -> dict[str, Any]:
        return {"snapshots": self.snapshots, "gaps_reported": sorted(self._reported_gaps)}
