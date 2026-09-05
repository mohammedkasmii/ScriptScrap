"""M2 observation sensors, end to end against the fixture.

One browser session drives every new sensor and the assertions read the
resulting event log. Grouped in one module because the session is the expensive
part; splitting it per sensor would multiply a 30-second cost by eight.
"""

from __future__ import annotations

import asyncio

import pytest

from scriptscrap.events import EventLogReader, EventType, Source

pytestmark = pytest.mark.browser


async def _run(tmp_path):
    from camoufox.addons import DefaultAddons
    from camoufox.async_api import AsyncCamoufox

    from scriptscrap.fixture import FixtureServer
    from scriptscrap.testing.capture import load_investigator

    out = tmp_path / "output"
    inv = load_investigator(out)

    with FixtureServer() as fx:
        scope = inv.InvestigationScope(fx.base_url)
        engine = inv.WebHarvester(fx.base_url, scope, session_id="sess-20260101-000000")
        engine.record_launch_options({"headless": True})

        async with AsyncCamoufox(
            headless=True, humanize=False, os="windows", geoip=False,
            exclude_addons=[DefaultAddons.UBO],
            main_world_eval=True,
        ) as browser:
            page = await browser.new_page()
            await inv.attach_engine_to_page(page, engine)
            await page.goto(fx.base_url + "/", wait_until="load")
            # DOM, not a page global: the driver may be in the isolated world,
            # which shares the document but not `window`.
            await page.wait_for_selector("html[data-fixture-ready='true']",
                                         state="attached")

            # -- user actions -----------------------------------------
            await page.fill("#nom", "Alice Benali")
            await page.check("#accord")
            await page.select_option("#ville", "mar")
            await page.fill("#pw", "fixture-password-not-a-real-secret")
            await page.click("#btn-charger")
            await page.wait_for_function(
                "document.querySelector('#mission').value.length > 0")

            # -- runtime causality ------------------------------------
            await page.click("#btn-valider")
            await page.wait_for_function(
                "document.querySelector('#resultat').textContent.includes('REF-FIXTURE-9001')")

            # -- GraphQL ----------------------------------------------
            await page.click("#btn-graphql")
            await page.wait_for_function(
                "document.querySelector('#resultat').textContent.startsWith('graphql:')")

            # -- WebSocket --------------------------------------------
            await page.click("#btn-ws")
            await page.wait_for_function(
                "document.querySelector('#ws-log').textContent.includes('fixture-done')",
                timeout=15000)

            # -- SSE ---------------------------------------------------
            await page.click("#btn-sse")
            await page.wait_for_function(
                "document.querySelector('#sse-log').textContent.includes('[fin]')",
                timeout=15000)

            # -- diagnostics + state ----------------------------------
            await page.click("#btn-console")
            await page.click("#btn-exception")
            await page.click("#btn-requete-morte")
            await page.click("#btn-stockage")
            await page.click("#btn-route")
            await page.wait_for_timeout(600)

            await engine.storage_sensor.snapshot(page, reason="mid_session")

            # -- navigation survival ----------------------------------
            # Everything above must already be on disk once we navigate away.
            await page.click("#btn-submit")
            await page.wait_for_load_state("load")

            await engine.extract_active_introspection(page)

        engine.close_events()
        return EventLogReader(out / "events.jsonl")


@pytest.fixture(scope="module")
def log(tmp_path_factory) -> EventLogReader:
    return asyncio.run(_run(tmp_path_factory.mktemp("observation")))


def _payloads(log, event_type):
    return [e.payload for e in log.of_type(event_type)]


# --- integrity ----------------------------------------------------------

def test_log_is_intact(log):
    assert log.validate() == []
    errors = log.of_type(EventType.SENSOR_ERROR)
    assert errors == [], f"sensors reported errors: {[e.payload for e in errors]}"


# --- M2.1 lifecycle and identity ---------------------------------------

def test_pages_and_frames_have_stable_ids(log):
    opened = _payloads(log, EventType.PAGE_OPENED)
    assert opened, "no page_opened event"
    assert all(e.page_id for e in log.of_type(EventType.PAGE_OPENED))

    attached = log.of_type(EventType.FRAME_ATTACHED)
    assert attached, "nested iframes should produce frame_attached events"
    # The fixture nests /frame/inner inside /frame/outer.
    assert any(e.payload.get("parent_frame_id") for e in attached), "no frame parent recorded"


def test_navigation_is_committed_and_observed(log):
    committed = _payloads(log, EventType.NAVIGATION_COMMITTED)
    assert any("/page2" in (p.get("url") or "") for p in committed)


# --- M2.2 user actions --------------------------------------------------

def test_user_actions_are_recorded_with_element_context(log):
    clicks = _payloads(log, EventType.USER_CLICK)
    assert clicks, "no user_click events"
    ids = {c["element"]["id"] for c in clicks if c.get("element")}
    assert {"btn-charger", "btn-valider", "btn-graphql"} <= ids

    charger = next(c for c in clicks if c["element"]["id"] == "btn-charger")
    assert charger["element"]["tag"] == "button"
    assert charger["element"]["dom_path"]
    assert charger["trusted"] is True


def test_input_and_change_capture_values_and_labels(log):
    changes = _payloads(log, EventType.USER_CHANGE) + _payloads(log, EventType.USER_INPUT)
    by_id = {c["element"]["id"]: c for c in changes if c.get("element")}
    assert "nom" in by_id
    assert by_id["nom"]["value"]["value"] == "Alice Benali"
    assert by_id["nom"]["element"]["label"] == "Nom"
    assert by_id["accord"]["value"]["checked"] is True
    assert by_id["ville"]["value"]["value"] == "mar"


def test_password_values_are_never_recorded(log):
    """Presence and length are observed; the value is not."""
    events = _payloads(log, EventType.USER_INPUT) + _payloads(log, EventType.USER_CHANGE)
    pw = [e for e in events if e.get("element", {}).get("id") == "pw"]
    assert pw, "the password field interaction should still be observed"
    for entry in pw:
        assert entry["value"]["redacted"] is True
        assert entry["value"]["reason"] == "secret_field"
        assert entry["value"]["length"] == len("fixture-password-not-a-real-secret")
        assert "fixture-password-not-a-real-secret" not in str(entry)


def test_no_password_value_anywhere_in_the_user_action_stream(log):
    for event in log:
        if str(event.type).startswith("user_"):
            assert "fixture-password-not-a-real-secret" not in str(event.payload)


def test_form_submission_is_observed_before_navigation(log):
    submits = _payloads(log, EventType.USER_SUBMIT)
    assert submits, "form submit not observed"
    fields = {f["name"] for f in submits[0]["fields"]}
    assert {"nom", "ville", "pw"} <= fields
    pw_field = next(f for f in submits[0]["fields"] if f["name"] == "pw")
    assert pw_field["value"]["redacted"] is True


# --- M2.3 runtime causality --------------------------------------------

def test_runtime_fetch_is_observed_with_a_stack(log):
    fetches = _payloads(log, EventType.RUNTIME_FETCH)
    assert fetches, "no runtime_fetch events"
    valider = [f for f in fetches if "/api/valider" in (f.get("url") or "")]
    assert valider, "the validate fetch was not observed"
    call = valider[0]
    assert call["method"] == "POST"
    assert call["stack"], "no JS stack captured for the fetch"
    assert any("valider" in frame.lower() for frame in call["stack"]), call["stack"]
    assert call["body"]["kind"] == "string"


def test_runtime_call_and_network_request_share_a_join_key(log):
    """What M3 will actually correlate on.

    `seq` is INGEST order, not occurrence order: the probe batches over a
    channel independent of Playwright's network events, so the same request can
    be ingested from the two sensors in either order. Asserting a strict seq
    ordering across sensors would be asserting a race.

    What IS reliable is that both sensors describe the same request, and that
    the probe carries its own in-page clock and ordinal for ordering within a
    frame. That pair is the join key.
    """
    runtime = next(e for e in log.of_type(EventType.RUNTIME_FETCH)
                   if "/api/valider" in (e.payload.get("url") or ""))
    request = next(e for e in log.of_type(EventType.HTTP_REQUEST)
                   if e.payload.get("path") == "/api/valider")

    assert runtime.payload["method"] == request.payload["method"]
    assert runtime.payload["url"] == request.payload["url"]
    assert runtime.payload["probe_ordinal"] > 0
    assert runtime.payload["probe_time_ms"] > 0
    assert runtime.frame_id == request.frame_id


def test_probe_ordinals_are_monotonic_within_a_frame_and_world(log):
    """In-page ordering is recoverable even though ingest order is not.

    The scope of that guarantee is one frame in one JS WORLD. The probe runs in
    two -- listeners in the isolated world, patched instruments in the page's
    own -- and each counts its own ordinals. Comparing them across worlds is
    the same mistake as comparing `seq` across sensors, so the join key
    includes `probe_world`.
    """
    by_frame_world: dict[tuple[str, str], list[int]] = {}
    worlds: set[str] = set()
    for event in log:
        if event.source is Source.RUNTIME and event.payload.get("probe_ordinal"):
            world = event.payload.get("probe_world") or "isolated"
            worlds.add(world)
            by_frame_world.setdefault(
                (event.frame_id or "?", world), []
            ).append(event.payload["probe_ordinal"])

    assert by_frame_world, "no probe events carried an ordinal"
    assert worlds == {"isolated", "main"}, (
        f"expected evidence from both probe roles, got {sorted(worlds)}. "
        "A missing 'main' means the patched instruments never reached the page.")
    for (frame_id, world), ordinals in by_frame_world.items():
        assert ordinals == sorted(ordinals), (
            f"probe ordinals out of order in {frame_id} / {world} world")


def test_history_api_is_observed(log):
    history = _payloads(log, EventType.RUNTIME_HISTORY)
    assert {h["via"] for h in history} >= {"pushState", "replaceState"}


def test_runtime_events_survive_navigation(log):
    """M1's biggest data-loss problem: buffers were destroyed on navigation."""
    submit = log.of_type(EventType.USER_SUBMIT)[0]
    # Everything observed before the submit must already be in the log, i.e.
    # have a lower sequence number than the navigation that followed it.
    committed = [e for e in log.of_type(EventType.NAVIGATION_COMMITTED)
                 if "/page2" in (e.payload.get("url") or "")]
    assert committed
    assert submit.seq < committed[0].seq
    earlier_clicks = [e for e in log.of_type(EventType.USER_CLICK) if e.seq < committed[0].seq]
    assert len(earlier_clicks) >= 5, "pre-navigation user actions were lost"


# --- M2.4 protocols -----------------------------------------------------

def test_websocket_lifecycle_and_frames(log):
    assert log.of_type(EventType.WS_OPEN), "no ws_open"
    sent = _payloads(log, EventType.WS_FRAME_SENT)
    received = _payloads(log, EventType.WS_FRAME_RECEIVED)
    assert sent and received

    assert any(f.get("payload_text") == "fixture-ping" for f in sent)
    assert any("echo:fixture-ping" in (f.get("payload_text") or "") for f in received)
    # Binary frames are classified and sized, never inlined.
    binary = [f for f in received if f["opcode"] == "binary"]
    assert binary, "binary frame not classified"
    # A binary payload is described by size, never inlined. Absent and None are
    # the same statement here: the envelope drops null fields.
    assert binary[0].get("payload_text") is None
    assert binary[0]["size"] > 0
    assert log.of_type(EventType.WS_CLOSE)


def test_websocket_handshake_gap_is_declared(log):
    reasons = {g.payload["reason"] for g in log.of_type(EventType.CAPTURE_GAP)}
    assert "websocket_handshake_headers_unavailable" in reasons


def test_sse_messages_are_captured_incrementally(log):
    messages = _payloads(log, EventType.SSE_MESSAGE)
    assert log.of_type(EventType.SSE_OPEN), "no sse_open"
    assert messages, "no sse_message events"
    names = {m["event"] for m in messages}
    assert {"message", "progression", "fin"} <= names
    data = {m["data"] for m in messages}
    assert "fixture-sse-1" in data
    assert any(m["last_event_id"] for m in messages), "lastEventId not captured"


def test_graphql_operation_identity_is_retained(log):
    requests = [e.payload for e in log.of_type(EventType.HTTP_REQUEST)
                if e.payload.get("graphql")]
    assert requests, "GraphQL request not recognised"
    gql = requests[0]["graphql"]
    op = gql["operations"][0]
    assert op["operation_name"] == "ValiderItem"
    assert op["operation_type"] == "mutation"
    assert op["variable_names"] == ["id", "note"]
    assert op["document_hash"]


# --- M2.5 application state --------------------------------------------

def test_console_messages_are_captured_with_severity(log):
    messages = _payloads(log, EventType.CONSOLE_MESSAGE)
    levels = {m["level"] for m in messages}
    assert {"warning", "error"} & levels, levels
    texts = " ".join(m["text"] for m in messages)
    assert "fixture warn message" in texts
    assert "fixture error message" in texts


def test_uncaught_page_exception_is_captured(log):
    errors = _payloads(log, EventType.PAGE_EXCEPTION)
    assert errors, "no page_exception event"
    assert any("fixture uncaught exception" in (e.get("message") or "") for e in errors)


def test_failed_request_is_explicit(log):
    failures = _payloads(log, EventType.HTTP_FAILED)
    assert failures, "a request that never completed produced no event"
    assert any("/jamais" in (f.get("url") or "") for f in failures)
    assert any(f.get("failure") for f in failures), "no failure reason recorded"


def test_storage_writes_are_observed_as_they_happen(log):
    changes = _payloads(log, EventType.STORAGE_CHANGE)
    assert changes
    sets = {(c["store"], c["key"]) for c in changes if c["op"] == "set"}
    assert ("localStorage", "fixtureToken") in sets
    assert ("sessionStorage", "fixtureSession") in sets
    assert any(c["op"] == "remove" and c["key"] == "fixtureCounter" for c in changes)


def test_storage_snapshot_includes_cookies_and_web_storage(log):
    snapshots = _payloads(log, EventType.STORAGE_SNAPSHOT)
    assert snapshots
    latest = snapshots[-1]
    assert latest["local_storage"].get("fixtureToken") == "LOCAL-FIXTURE-0001"
    assert any(c["name"] == "fixture_session" for c in latest["cookies"])


def test_dom_mutations_are_emitted_as_bounded_batches(log):
    batches = _payloads(log, EventType.DOM_MUTATION)
    assert batches, "no dom_mutation events"
    for batch in batches:
        assert batch["count"] <= 40, "mutation batch exceeded its bound"
        assert isinstance(batch["mutations"], list)


def test_failed_request_url_is_the_dead_port(log):
    """The failure must be in scope, or the sensor correctly refuses to record it."""
    failures = _payloads(log, EventType.HTTP_FAILED)
    assert all("127.0.0.1" in (f.get("url") or "") for f in failures)


# --- capture honesty -----------------------------------------------------

def test_sensor_stats_are_recorded(log):
    end = log.of_type(EventType.SESSION_END)
    assert end
    runtime_events = [e for e in log if e.source is Source.RUNTIME]
    assert len(runtime_events) > 20, "runtime probe produced almost nothing"
