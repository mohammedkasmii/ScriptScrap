"""IndexedDB and Cache Storage inventory.

The storage sensor used to report only that these existed, as a capture gap.
That is honest but thin: what is technically achievable on Firefox is an
inventory -- database and object-store names with record counts, and the
request URLs a cache holds -- and where it can be captured, a blanket "not
captured" gap is a lie by omission.

The JS that reads the browser is exercised by the browser suite; here the
Python wiring is pinned with a stub page, so a test states exactly what the
evaluate returned and asserts what the sensor did with it.
"""

from __future__ import annotations

from scriptscrap.sensors.storage import StorageSensor


class _Registry:
    def page_id(self, page):
        return "p1"


class _Scope:
    def contains(self, url):
        return True

    def contains_host(self, host):
        return True


class _Engine:
    def __init__(self):
        self.scope = _Scope()
        self.events = []
        self.gaps = []

    def emit_event(self, source, event_type, **payload):
        self.events.append((event_type, payload))

    def emit_capture_gap(self, reason, **extra):
        self.gaps.append((reason, extra))

    def emit_sensor_error(self, where, exc, **extra):
        self.gaps.append(("sensor_error", {"where": where}))


class _Cookies:
    async def cookies(self):
        return []


class _Page:
    url = "http://app.example/"

    def __init__(self, evaluate_result):
        self._result = evaluate_result
        self.context = _Cookies()

    async def evaluate(self, _script):
        return self._result


def _snapshot(evaluate_result):
    import asyncio

    engine = _Engine()
    sensor = StorageSensor(engine, _Registry())
    asyncio.run(sensor.snapshot(_Page(evaluate_result), reason="test"))
    return engine


def test_indexed_db_inventory_is_recorded_on_the_snapshot():
    engine = _snapshot({
        "origin": "http://app.example",
        "localStorage": {}, "sessionStorage": {},
        "has_indexed_db": True, "has_cache_storage": False,
        "has_service_worker": False,
        "indexed_db": {"databases": [
            {"name": "app-db", "version": 3,
             "stores": [{"name": "orders", "count": 12}]}]},
        "cache_storage": {"caches": []},
    })
    snapshot = next(p for t, p in engine.events if str(t) == "storage_snapshot")
    idb = snapshot["indexed_db"]
    assert idb["databases"][0]["name"] == "app-db"
    assert idb["databases"][0]["stores"][0]["count"] == 12
    # It was captured, so the blanket "not captured" gap must NOT fire.
    assert not any(g[0] == "indexed_db_not_captured" for g in engine.gaps)


def test_cache_storage_inventory_is_recorded():
    engine = _snapshot({
        "origin": "http://app.example",
        "localStorage": {}, "sessionStorage": {},
        "has_indexed_db": False, "has_cache_storage": True,
        "has_service_worker": False,
        "indexed_db": {"databases": []},
        "cache_storage": {"caches": [
            {"name": "v1", "requests": ["http://app.example/a.js"], "count": 1}]},
    })
    snapshot = next(p for t, p in engine.events if str(t) == "storage_snapshot")
    cache = snapshot["cache_storage"]
    assert cache["caches"][0]["name"] == "v1"
    assert "http://app.example/a.js" in cache["caches"][0]["requests"]
    assert not any(g[0] == "cache_storage_not_captured" for g in engine.gaps)


def test_a_failed_indexed_db_inventory_still_reports_the_gap():
    """When the inventory itself failed, the old honest gap is the right answer."""
    engine = _snapshot({
        "origin": "http://app.example",
        "localStorage": {}, "sessionStorage": {},
        "has_indexed_db": True, "has_cache_storage": False,
        "has_service_worker": False,
        "indexed_db": {"error": "SecurityError"},
        "cache_storage": {"caches": []},
    })
    assert any(g[0] == "indexed_db_not_captured" for g in engine.gaps)
