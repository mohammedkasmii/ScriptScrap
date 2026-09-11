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

# Async, because IndexedDB and Cache Storage are promise-based. Everything is
# read-only and bounded: databases are opened WITHOUT a version so an open can
# never trigger an upgrade, each open races a short timeout so a lock cannot
# hang the snapshot, and per-database / per-cache / per-store counts are capped.
# Values are deliberately not read -- names, store record counts and cached
# request URLs are the achievable inventory, and the sensor says so rather than
# pretending it captured contents it did not.
MAX_DATABASES = 25
MAX_STORES = 50
MAX_CACHES = 25
MAX_CACHE_REQUESTS = 100

_READ_STORAGE_TEMPLATE = """
async () => {
    const CFG = { maxDatabases: __MAX_DB__, maxStores: __MAX_STORES__,
                  maxCaches: __MAX_CACHES__, maxCacheRequests: __MAX_REQS__ };
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

    const withTimeout = (promise, ms) => Promise.race([
        promise,
        new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), ms)),
    ]);

    const openDb = (name) => withTimeout(new Promise((resolve, reject) => {
        // No version: opening cannot upgrade the database or block on one.
        let request;
        try { request = indexedDB.open(name); }
        catch (e) { reject(e); return; }
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error("open failed"));
        request.onblocked = () => reject(new Error("blocked"));
    }), 2000);

    const countStore = (db, storeName) => withTimeout(new Promise((resolve) => {
        try {
            const tx = db.transaction(storeName, "readonly");
            const req = tx.objectStore(storeName).count();
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => resolve(null);
        } catch (e) { resolve(null); }
    }), 1500).catch(() => null);

    const inventoryIndexedDb = async () => {
        if (typeof indexedDB === "undefined") return { available: false, databases: [] };
        if (typeof indexedDB.databases !== "function") {
            // Older engines cannot enumerate databases; presence is all we know.
            return { available: true, enumerable: false, databases: [] };
        }
        try {
            const list = (await indexedDB.databases()).slice(0, CFG.maxDatabases);
            const databases = [];
            for (const info of list) {
                const entry = { name: info.name, version: info.version, stores: [] };
                try {
                    const db = await openDb(info.name);
                    const names = Array.from(db.objectStoreNames).slice(0, CFG.maxStores);
                    for (const storeName of names) {
                        entry.stores.push({ name: storeName, count: await countStore(db, storeName) });
                    }
                    db.close();
                } catch (e) {
                    entry.error = String(e && e.message || e);
                }
                databases.push(entry);
            }
            return { available: true, enumerable: true, databases: databases };
        } catch (e) {
            return { error: String(e && e.message || e) };
        }
    };

    const inventoryCaches = async () => {
        if (typeof caches === "undefined") return { available: false, caches: [] };
        try {
            const names = (await caches.keys()).slice(0, CFG.maxCaches);
            const out = [];
            for (const name of names) {
                try {
                    const cache = await caches.open(name);
                    const requests = await cache.keys();
                    out.push({
                        name: name,
                        count: requests.length,
                        requests: requests.slice(0, CFG.maxCacheRequests).map((r) => r.url),
                    });
                } catch (e) {
                    out.push({ name: name, error: String(e && e.message || e) });
                }
            }
            return { available: true, caches: out };
        } catch (e) {
            return { error: String(e && e.message || e) };
        }
    };

    return {
        origin: location.origin,
        localStorage: dump(window.localStorage),
        sessionStorage: dump(window.sessionStorage),
        indexed_db: await inventoryIndexedDb(),
        cache_storage: await inventoryCaches(),
        has_indexed_db: typeof indexedDB !== "undefined",
        has_service_worker: !!(navigator.serviceWorker &&
                               navigator.serviceWorker.controller),
        has_cache_storage: typeof caches !== "undefined",
    };
}
"""

READ_STORAGE_JS = (
    _READ_STORAGE_TEMPLATE
    .replace("__MAX_DB__", str(MAX_DATABASES))
    .replace("__MAX_STORES__", str(MAX_STORES))
    .replace("__MAX_CACHES__", str(MAX_CACHES))
    .replace("__MAX_REQS__", str(MAX_CACHE_REQUESTS))
)


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
            # The inventories: database/store names with record counts, and the
            # request URLs a cache holds. Absent when the page has neither.
            indexed_db=web_storage.get("indexed_db"),
            cache_storage=web_storage.get("cache_storage"),
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
        idb = info.get("indexed_db") or {}
        # A gap only when the inventory could not be taken -- an error, or an
        # engine that cannot enumerate databases. When names and counts WERE
        # captured, the honest statement is the narrower one: record VALUES are
        # not read, which is emitted once so a reader knows the inventory is
        # structural rather than exhaustive.
        if info.get("has_indexed_db"):
            if idb.get("error") or idb.get("enumerable") is False:
                if "indexed_db" not in self._reported_gaps:
                    self._reported_gaps.add("indexed_db")
                    self.engine.emit_capture_gap(
                        "indexed_db_not_captured",
                        error=idb.get("error"),
                        note="IndexedDB could not be inventoried in this session",
                    )
            elif idb.get("databases") and "indexed_db_values" not in self._reported_gaps:
                self._reported_gaps.add("indexed_db_values")
                self.engine.emit_capture_gap(
                    "indexed_db_values_not_captured",
                    note="IndexedDB database/store names and record counts were "
                         "captured; individual record values were not read",
                )

        cache = info.get("cache_storage") or {}
        if info.get("has_cache_storage"):
            if cache.get("error"):
                if "cache_storage" not in self._reported_gaps:
                    self._reported_gaps.add("cache_storage")
                    self.engine.emit_capture_gap(
                        "cache_storage_not_captured",
                        error=cache.get("error"),
                        note="Cache Storage could not be inventoried in this session",
                    )
            elif cache.get("caches") and "cache_storage_bodies" not in self._reported_gaps:
                self._reported_gaps.add("cache_storage_bodies")
                self.engine.emit_capture_gap(
                    "cache_storage_bodies_not_captured",
                    note="Cache Storage cache names and cached request URLs were "
                         "captured; the cached response bodies were not read",
                )

    def stats(self) -> dict[str, Any]:
        return {"snapshots": self.snapshots, "gaps_reported": sorted(self._reported_gaps)}
