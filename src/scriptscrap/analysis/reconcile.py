"""Reconcile observations of the same activity across sensors.

In forensic mode up to three sensors can see one HTTP request: the runtime
probe (in the page, before it was sent), Playwright (from the driver), and the
extension (from the network stack). Storing three copies and calling them three
events would triple-count the application's behaviour.

So raw events stay immutable and untouched, and this derives RELATIONSHIPS over
them:

    same_activity      these observations describe one request
    corroborates       two sensors agree on a fact
    conflicts_with     two sensors disagree, and both claims are preserved
    unmatched          one sensor saw something no other sensor did

`unmatched` is not a failure of this code -- it is often the most interesting
output. An extension request with no Playwright counterpart is a request
Playwright could not see, which is exactly what the forensic layer exists to
surface.

Matching NEVER uses `seq` across sensors: M2 proved that is ingest order. The
join is (method, url) with a body-hash tiebreak, and the time delta is recorded
as evidence rather than used as proof.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..events import Event, EventType, Source
from .models import Evidence

# Sensor-specific event types that describe one HTTP request/response.
REQUEST_TYPES = {
    EventType.HTTP_REQUEST: "playwright",
    EventType.EXTENSION_REQUEST: "extension",
    EventType.RUNTIME_FETCH: "runtime",
    EventType.RUNTIME_XHR: "runtime",
}
RESPONSE_TYPES = {
    EventType.HTTP_RESPONSE: "playwright",
    EventType.EXTENSION_RESPONSE: "extension",
}


@dataclass(slots=True)
class ActivityMatch:
    """One network activity as seen by one or more sensors."""

    key: str
    method: str
    url: str
    sensors: dict[str, list[str]] = field(default_factory=dict)   # sensor -> event ids
    relation: str = "unmatched"
    confidence: float = 0.0
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    corroborations: list[str] = field(default_factory=list)
    evidence: Evidence = field(default_factory=Evidence)

    @property
    def sensor_count(self) -> int:
        return len(self.sensors)


def _wall_ms(event: Event) -> float | None:
    try:
        return datetime.fromisoformat(event.t_wall).timestamp() * 1000.0
    except (TypeError, ValueError):
        return None


class Reconciler:
    """Relates multi-sensor observations of the same request."""

    def analyze(self, events: list[Event]) -> list[ActivityMatch]:
        buckets: dict[tuple[str, str], dict[str, list[Event]]] = defaultdict(
            lambda: defaultdict(list))
        statuses: dict[tuple[str, str], dict[str, set[int]]] = defaultdict(
            lambda: defaultdict(set))
        bodies: dict[tuple[str, str], dict[str, bool]] = defaultdict(dict)

        for event in events:
            sensor = REQUEST_TYPES.get(event.type)
            if sensor:
                key = self._key(event)
                if key:
                    buckets[key][sensor].append(event)
                continue

            sensor = RESPONSE_TYPES.get(event.type)
            if sensor:
                key = self._key(event)
                if key:
                    buckets[key][sensor].append(event)
                    status = event.payload.get("status")
                    if isinstance(status, int):
                        statuses[key][sensor].add(status)
                continue

            if event.type is EventType.RESPONSE_BODY_CAPTURED:
                key = self._key(event)
                if key:
                    buckets[key]["extension"].append(event)
                    bodies[key]["extension"] = True

        matches = [
            self._build(key, by_sensor, statuses.get(key, {}), bodies.get(key, {}))
            for key, by_sensor in buckets.items()
        ]
        matches.sort(key=lambda m: (-m.sensor_count, m.url))
        return matches

    @staticmethod
    def _key(event: Event) -> tuple[str, str] | None:
        payload = event.payload
        url = payload.get("url")
        if not isinstance(url, str) or not url:
            return None
        method = str(payload.get("method") or "GET").upper()
        # Responses and body captures inherit the request's method where the
        # sensor supplies one; a body capture carries only the URL.
        return (method, url)

    def _build(self, key, by_sensor, statuses, bodies) -> ActivityMatch:
        method, url = key
        sensors = {name: [e.event_id for e in evs] for name, evs in by_sensor.items()}
        evidence = Evidence()
        for events in by_sensor.values():
            evidence.cite(*[e.event_id for e in events])

        match = ActivityMatch(
            key=f"{method} {url}", method=method, url=url, sensors=sensors,
            evidence=evidence,
        )

        # Time spread across sensors, as evidence -- never as the join.
        times = [t for evs in by_sensor.values() for e in evs if (t := _wall_ms(e))]
        if len(times) > 1:
            evidence.add("time_spread_ms", round(max(times) - min(times), 1))
        evidence.add("join", "method+url; cross-sensor seq is ingest order and is not used")
        evidence.add("sensors", sorted(sensors))

        if match.sensor_count <= 1:
            match.relation = "unmatched"
            match.confidence = 0.4
            only = next(iter(sensors), "unknown")
            evidence.add(
                "interpretation",
                f"seen only by {only}. For the extension this usually means "
                f"traffic the other sensors cannot observe."
            )
            return match

        match.relation = "same_activity"
        # Agreement across independent channels is the strongest signal here.
        match.confidence = round(min(0.99, 0.6 + 0.15 * match.sensor_count), 3)

        # -- corroboration and conflict --------------------------------
        observed = {s: sorted(v) for s, v in statuses.items() if v}
        if len(observed) > 1:
            distinct = {tuple(v) for v in observed.values()}
            if len(distinct) == 1:
                match.corroborations.append("status")
                evidence.add("status_agreement", next(iter(distinct)))
            else:
                match.relation = "conflicts_with"
                match.conflicts.append({
                    "field": "status",
                    "by_sensor": observed,
                    "note": "sensors disagree; both claims are preserved",
                })
                evidence.add("status_conflict", observed)

        if bodies.get("extension") and "playwright" in sensors:
            match.corroborations.append("body_available_from_extension")
            evidence.add(
                "body_source", "extension captured a body; Playwright body may be absent")

        if match.corroborations:
            evidence.add("corroborations", match.corroborations)
        return match


def summarise(matches: list[ActivityMatch]) -> dict[str, Any]:
    """Counts for the capture-health report."""
    by_relation: dict[str, int] = defaultdict(int)
    by_sensor: dict[str, int] = defaultdict(int)
    unmatched_by_sensor: dict[str, int] = defaultdict(int)

    for match in matches:
        by_relation[match.relation] += 1
        for sensor in match.sensors:
            by_sensor[sensor] += 1
        if match.relation == "unmatched":
            for sensor in match.sensors:
                unmatched_by_sensor[sensor] += 1

    return {
        "activities": len(matches),
        "by_relation": dict(sorted(by_relation.items())),
        "observations_by_sensor": dict(sorted(by_sensor.items())),
        "unmatched_by_sensor": dict(sorted(unmatched_by_sensor.items())),
        "conflicts": sum(1 for m in matches if m.conflicts),
        "multi_sensor": sum(1 for m in matches if m.sensor_count > 1),
    }


__all__ = ["ActivityMatch", "Reconciler", "Source", "summarise"]
