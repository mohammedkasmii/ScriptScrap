# Phase 2 Investigation Workspace — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn a ScriptScrap session directory into a browsable investigation workspace where every derived conclusion drills through to the raw events that support it, and add tested generators that turn the derived model into a starting-point client and Playwright script.

**Architecture:** `analyze` gains an index of the event *envelope* plus a byte offset into `events.jsonl`, so evidence lookup is a seek rather than a re-parse, while payloads stay in the log and `session.sqlite` stays derived and rebuildable. A stdlib-only, loopback-bound, token-gated, read-only HTTP server reads that index and serves a no-build-step ES-module frontend.

**Tech Stack:** Python 3.13, stdlib `sqlite3` + `http.server` (no new runtime dependencies), plain ES modules + CSS, pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-09-07-phase-2-investigation-workspace-design.md`

## Global Constraints

- **No new runtime dependencies.** The pinned baseline in `README.md` is behavioural; a presentation layer does not get to add to it. Test/dev deps are equally unnecessary here.
- **`events.jsonl` is the only source of truth.** `session.sqlite` must stay fully rebuildable from it; deleting the database and re-running `analyze` reproduces it exactly.
- **The workspace computes no new knowledge.** It presents what `analyze` produced. A missing number is added to the analysis layer with a test, never calculated in a request handler.
- **`scriptscrap.analysis` and `scriptscrap.workspace` import no browser module.** Enforced by `tests/test_analysis_boundary.py`.
- **The server is read-only, binds `127.0.0.1` only, and gates `/api/` on a per-launch token.** The served directory is an unredacted capture of an authenticated session.
- **Every derived conclusion keeps its `evidence_ids`.** No view may present a fact without a path to its evidence.
- Run after every task: `uv run pytest -m "not browser"` and `uv run ruff check .`.

---

## File Structure

**Created**

| Path | Responsibility |
|---|---|
| `src/scriptscrap/sensors/scope.py` | URL scope reduction shared by every sensor |
| `src/scriptscrap/analysis/events_index.py` | `EventStore`: the only module that knows byte offsets exist |
| `src/scriptscrap/workspace/__init__.py` | package exports |
| `src/scriptscrap/workspace/server.py` | HTTP server, token gate, routing, static serving |
| `src/scriptscrap/workspace/api.py` | request handlers → JSON; pure functions over a session |
| `src/scriptscrap/workspace/session.py` | locating and opening sessions; redaction posture |
| `src/scriptscrap/workspace/assets/` | `index.html`, `app.css`, `app.js`, view modules |
| `src/scriptscrap/generate/__init__.py` | package exports |
| `src/scriptscrap/generate/client.py` | httpx client from endpoints + schemas |
| `src/scriptscrap/generate/playwright.py` | Playwright starting point from states + selectors |

**Modified**

| Path | Change |
|---|---|
| `src/scriptscrap/sensors/runtime.py` | import scope helpers instead of defining them |
| `src/scriptscrap/sensors/lifecycle.py` | apply scope reduction to every emitted URL |
| `src/scriptscrap/events/reader.py` | opt-in `with_offsets=True` |
| `src/scriptscrap/analysis/store.py` | `events` table; log fingerprint on `analysis_runs` |
| `src/scriptscrap/analysis/pipeline.py` | carry offsets into the result |
| `src/scriptscrap/cli.py` | `workspace` and `generate` commands |
| `camoufox/camoufox_investigator.py:1428-1451` | delete the nine legacy writers |
| `tests/golden/investigation.json` | deliberate re-baseline |
| `tests/test_analysis_boundary.py` | extend to `scriptscrap.workspace` |

---

# M4.5 — Foundation

### Task 1: Extract scope reduction into a shared module

**Files:**
- Create: `src/scriptscrap/sensors/scope.py`
- Modify: `src/scriptscrap/sensors/runtime.py:66-112` (remove definitions, import instead)
- Test: `tests/test_scope_reduction.py`

**Interfaces:**
- Produces: `strip_query(url: str) -> str`, `redact_stack_frame(scope, frame) -> Any`, `URL_PAYLOAD_KEYS: tuple[str, ...]`, `REDUCED_KEEP_KEYS: frozenset[str]`

Pure refactor. `tests/test_runtime_scope.py` must stay green with no edits — that is the proof the move changed no behaviour.

- [ ] **Step 1: Write the failing test**

```python
from scriptscrap.sensors.scope import strip_query, redact_stack_frame

def test_strip_query_keeps_origin_and_path():
    assert strip_query("https://h/p?a=secret#f") == "https://h/p"

def test_strip_query_leaves_bare_path():
    assert strip_query("/p?a=1") == "/p"

def test_redact_stack_frame_keeps_position():
    class Scope:
        def contains(self, url): return False
    assert redact_stack_frame(Scope(), "h@https://x/a.js?v=3:12:5") == "h@https://x/a.js:12:5"
```

- [ ] **Step 2: Run to verify it fails** — `uv run pytest tests/test_scope_reduction.py -v`, expected `ModuleNotFoundError`
- [ ] **Step 3: Move `_strip_query`, `_redact_stack_frame`, `_STACK_URL`, `URL_PAYLOAD_KEYS`, `REDUCED_KEEP_KEYS` verbatim from `runtime.py` into `scope.py`, dropping the leading underscore on the two functions.** Keep the explanatory comments — they record a real capture's leak and are the reason the module exists.
- [ ] **Step 4: In `runtime.py`, replace the definitions with `from .scope import REDUCED_KEEP_KEYS, URL_PAYLOAD_KEYS, redact_stack_frame, strip_query` and update the two call sites.**
- [ ] **Step 5: Run `uv run pytest tests/test_runtime_scope.py tests/test_scope_reduction.py -v`** — all pass, no edits to the existing file
- [ ] **Step 6: Commit** — `refactor(sensors): extract scope reduction to a shared module`

---

### Task 2: Apply scope reduction to LifecycleSensor

**Files:**
- Modify: `src/scriptscrap/sensors/lifecycle.py:60-190`
- Test: `tests/test_scope_reduction.py`

**Interfaces:**
- Consumes: `strip_query`, `URL_PAYLOAD_KEYS` from Task 1
- Produces: `LifecycleSensor._scoped(**payload) -> dict`

`LifecycleSensor` emits `page.url`, `frame.url`, `popup.url` and `download.url` verbatim. An out-of-scope iframe or an SSO redirect therefore lands in the log with its query string intact.

Lifecycle payloads carry no bodies or typed values, so only the URL half of the runtime reduction applies: strip query and fragment from any URL whose own host is out of scope, and mark the event `evidence_reduced` when its own subject is out of scope.

- [ ] **Step 1: Write the failing test**

```python
class _Scope:
    def __init__(self, host): self.host = host
    def contains(self, url): return isinstance(url, str) and self.host in url

class _Engine:
    def __init__(self, scope): self.scope, self.events = scope, []
    def emit_event(self, source, etype, **payload): self.events.append((etype, payload))
    def emit_sensor_error(self, *a, **k): pass
    def emit_capture_gap(self, *a, **k): pass

def _sensor():
    from scriptscrap.sensors.lifecycle import LifecycleSensor
    from scriptscrap.sensors.identity import PageRegistry
    return LifecycleSensor(_Engine(_Scope("app.test")), PageRegistry())

def test_out_of_scope_frame_url_loses_query():
    s = _sensor()
    s._on_frame_attached(_Frame("https://ads.example/i?token=SECRET"), "page-1")
    _, payload = s.engine.events[-1]
    assert payload["url"] == "https://ads.example/i"
    assert payload["evidence_reduced"] is True

def test_in_scope_frame_url_is_untouched():
    s = _sensor()
    s._on_frame_attached(_Frame("https://app.test/x?q=1"), "page-1")
    _, payload = s.engine.events[-1]
    assert payload["url"] == "https://app.test/x?q=1"
    assert "evidence_reduced" not in payload
```

Repeat for `_on_page` (via `observe_page`), `_on_popup` and `_on_download`.

- [ ] **Step 2: Run to verify it fails** — the URL comes back with `?token=SECRET`
- [ ] **Step 3: Add `_scoped` to `LifecycleSensor` and route every `emit_event` payload through it**

```python
def _scoped(self, **payload: Any) -> dict[str, Any]:
    """Reduce URLs that lie outside the engagement.

    Lifecycle payloads carry no bodies or typed values, so unlike the runtime
    probe there is nothing to rebuild from an allowlist -- the URLs are the
    only thing that can leak. The event is kept: "a third-party iframe
    attached here" is the same forensic fact the network path preserves.
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
```

- [ ] **Step 4: Run the tests** — pass
- [ ] **Step 5: Run the full offline suite** — `uv run pytest -m "not browser"`
- [ ] **Step 6: Commit** — `fix(lifecycle): reduce out-of-scope URLs to metadata`

---

### Task 3: Byte offsets in the event log reader

**Files:**
- Modify: `src/scriptscrap/events/reader.py`
- Test: `tests/test_events_offsets.py`

**Interfaces:**
- Produces: `EventLogReader(path, *, with_offsets: bool = False)`; `reader.offsets: dict[str, tuple[int, int]]` mapping `event_id -> (byte_offset, byte_length)`

One parser, not two. Offsets are opt-in so the existing hot path is unchanged.

- [ ] **Step 1: Write the failing test**

```python
def test_every_offset_round_trips(tmp_path):
    log = tmp_path / "events.jsonl"
    log.write_bytes(SAMPLE_LOG_BYTES)          # from tests/golden/sample_events.jsonl
    reader = EventLogReader(log, with_offsets=True)
    raw = log.read_bytes()
    assert len(reader.offsets) == len(reader.events)
    for event in reader.events:
        offset, length = reader.offsets[event.event_id]
        line = raw[offset:offset + length]
        assert json.loads(line)["event_id"] == event.event_id

def test_offsets_absent_unless_requested(tmp_path):
    ...
    assert EventLogReader(log).offsets == {}

def test_truncated_final_line_still_indexes_intact_events(tmp_path):
    log.write_bytes(SAMPLE_LOG_BYTES + b'{"session_id":"x","event_id":"trunc"')
    reader = EventLogReader(log, with_offsets=True)
    assert "trunc" not in reader.offsets
    assert len(reader.offsets) == len(reader.events)
```

- [ ] **Step 2: Run to verify it fails** — `TypeError: unexpected keyword argument 'with_offsets'`
- [ ] **Step 3: Rework `_load` to read binary and track cumulative offsets**

Read with `open("rb")`, iterate lines, decode each with `line.decode("utf-8")`, and keep a running `offset += len(raw_line)`. Record `(offset, len(raw_line_without_trailing_newline))` for each event that parses. Existing behaviour — blank-line skipping, truncated-final-line tolerance, problem records — must be preserved exactly.

- [ ] **Step 4: Run the tests** — pass
- [ ] **Step 5: Run `uv run pytest tests/test_events.py tests/test_replay.py -v`** — the existing reader contract is unchanged
- [ ] **Step 6: Commit** — `feat(events): optional byte offsets for random access`

---

### Task 4: `events` table and log fingerprint

**Files:**
- Modify: `src/scriptscrap/analysis/store.py`, `src/scriptscrap/analysis/models.py`, `src/scriptscrap/analysis/pipeline.py`
- Test: `tests/test_derived_store.py`

**Interfaces:**
- Consumes: `reader.offsets` from Task 3
- Produces: `AnalysisResult.event_index: list[EventIndexRow]`, `AnalysisResult.log_size: int`, `AnalysisResult.log_sha256: str`; `analysis_runs.log_size`, `analysis_runs.log_sha256`; the `events` table from the spec

- [ ] **Step 1: Write the failing test**

```python
def test_events_table_indexes_every_event(tmp_path):
    result = analyze_log(SAMPLE_LOG)
    with DerivedStore(tmp_path / "s.sqlite") as store:
        run_id = store.write(result)
    rows = sqlite3.connect(tmp_path / "s.sqlite").execute(
        "SELECT COUNT(*) FROM events WHERE run_id=?", (run_id,)).fetchone()[0]
    assert rows == result.event_count

def test_run_records_log_fingerprint(tmp_path):
    ...
    assert row["log_size"] == SAMPLE_LOG.stat().st_size
    assert len(row["log_sha256"]) == 64

def test_payload_is_not_copied_into_sqlite(tmp_path):
    """The store must not become a second source of truth."""
    ...
    cols = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
    assert "payload" not in cols
```

- [ ] **Step 2: Run to verify it fails** — `no such table: events`
- [ ] **Step 3: Add the `events` DDL and indexes from the spec to `SCHEMA`; add `log_size`/`log_sha256` to `analysis_runs`; add the fields to `AnalysisResult`; populate them in `analyze_log`; insert rows in `DerivedStore.write` with `executemany`**
- [ ] **Step 4: Run the tests** — pass
- [ ] **Step 5: Bump `ANALYSIS_VERSION` in `models.py`** — the derived schema changed
- [ ] **Step 6: Commit** — `feat(analysis): index the event envelope with byte offsets`

---

### Task 5: `EventStore` read API

**Files:**
- Create: `src/scriptscrap/analysis/events_index.py`
- Test: `tests/test_events_index.py`

**Interfaces:**
- Produces:

```python
class StaleIndexError(RuntimeError): ...

@dataclass(frozen=True)
class EventPage:
    events: list[Event]
    next_seq: int | None
    total: int

class EventStore:
    def __init__(self, db_path: Path, log_path: Path, run_id: int | None = None): ...
    def get(self, event_id: str) -> Event | None: ...
    def get_many(self, event_ids: Sequence[str]) -> list[Event]: ...
    def page(self, *, types=None, sources=None, page_id=None,
             after_seq=None, limit=200) -> EventPage: ...
    def counts_by_type(self) -> dict[str, int]: ...
    def window(self, start_seq: int, end_seq: int) -> list[Event]: ...
    def close(self) -> None: ...
```

`run_id=None` selects the most recent run. Consumers never see byte offsets.

- [ ] **Step 1: Write the failing tests**

```python
def test_get_returns_the_event_by_id(store):
    event = store.get(KNOWN_EVENT_ID)
    assert event.event_id == KNOWN_EVENT_ID
    assert event.payload            # payload came from the log, not sqlite

def test_get_unknown_id_returns_none(store): assert store.get("nope") is None

def test_page_filters_by_type(store):
    page = store.page(types=["http_request"], limit=10)
    assert all(e.type == "http_request" for e in page.events)
    assert len(page.events) <= 10

def test_page_walks_the_whole_log(store):
    seen, cursor = 0, None
    while True:
        page = store.page(after_seq=cursor, limit=100)
        seen += len(page.events)
        if page.next_seq is None: break
        cursor = page.next_seq
    assert seen == page.total

def test_stale_index_raises_when_log_grew(store, log_path):
    log_path.open("ab").write(b'{"...": "appended"}\n')
    with pytest.raises(StaleIndexError):
        store.get(KNOWN_EVENT_ID)
```

- [ ] **Step 2: Run to verify they fail** — `ModuleNotFoundError`
- [ ] **Step 3: Implement.** Verify `log_size` and `log_sha256` against the file once per instance, on first payload read, and raise `StaleIndexError` naming the remedy (`re-run scriptscrap analyze`). Reconstruct each `Event` via `Event.from_dict(json.loads(raw))` so there is one definition of a valid event.
- [ ] **Step 4: Run the tests** — pass
- [ ] **Step 5: Commit** — `feat(analysis): EventStore for evidence lookup`

---

### Task 6: Retire the legacy output and re-baseline the golden master

**Files:**
- Modify: `camoufox/camoufox_investigator.py:1428-1451`
- Modify: `tests/golden/investigation.json`, `src/scriptscrap/testing/snapshot.py`
- Modify: `README.md`

Deletes: `network_traffic.json`, `dom_structure.json`, `api_dependencies.json`, `generated_client.py`, `dropdown_catalogs.json`, `jquery_events.json`, `js_hooks_and_mutations.json`, `mcma_openapi_spec.json`, `out_of_scope_metadata.json`.

- [ ] **Step 1: Run the golden master first and save the output** — `uv run pytest tests/test_golden_master.py -v` (needs a browser). This is the before-picture.
- [ ] **Step 2: Delete the nine writers and any now-unused helper they were the sole caller of** (`generate_httpx_code` and the OpenAPI assembly). Leave the underlying observation — `self.network_log`, `self.catalogs` and friends still feed the event spine.
- [ ] **Step 3: Update `snapshot.py` if it enumerates output filenames**
- [ ] **Step 4: Re-run the golden master, inspect the diff, and confirm every removed key is one of the nine files** — a change anywhere else is a bug, not a re-baseline
- [ ] **Step 5: Commit the re-baseline on its own**, naming the removed keys in the message. `README.md` calls this "a decision point, not automatically a bug"; the commit is where that decision is recorded.
- [ ] **Step 6: Update the layout section of `README.md`** to stop promising the retired files, and note that a client generator returns in Phase 3

---

# M5 — Server and endpoint explorer

### Task 7: Workspace server skeleton and its security properties

**Files:**
- Create: `src/scriptscrap/workspace/__init__.py`, `server.py`, `session.py`, `assets/index.html`, `assets/app.css`
- Test: `tests/test_workspace_server.py`

**Interfaces:**
- Produces:

```python
@dataclass(frozen=True)
class WorkspaceConfig:
    root: Path
    host: str = "127.0.0.1"
    port: int = 0
    token: str = ""          # generated when empty

class Workspace:
    def __init__(self, config: WorkspaceConfig): ...
    @property
    def url(self) -> str: ...
    def serve_forever(self) -> None: ...
    def shutdown(self) -> None: ...

def open_session(path: Path) -> SessionHandle   # session.py
def discover_sessions(root: Path) -> list[SessionHandle]
```

`SessionHandle` carries `name`, `root`, `db_path`, `log_path`, `redaction` (`"unredacted" | "sanitised"`).

Security tests come first here because they are the requirement, not a follow-up.

- [ ] **Step 1: Write the failing security tests**

```python
def test_binds_loopback_only(workspace):
    assert workspace.server.server_address[0] == "127.0.0.1"

def test_api_without_token_is_rejected(workspace):
    assert urlopen_status(f"{workspace.url}/api/sessions") == 401

def test_api_with_token_is_allowed(workspace):
    assert urlopen_status(f"{workspace.url}/api/sessions", token=workspace.token) == 200

def test_write_methods_are_rejected(workspace):
    for method in ("POST", "PUT", "DELETE", "PATCH"):
        assert request_status(workspace, method, "/api/sessions") == 405

def test_path_traversal_cannot_escape_assets(workspace):
    assert urlopen_status(f"{workspace.url}/../../../../etc/passwd") in (400, 403, 404)
    assert urlopen_status(f"{workspace.url}/%2e%2e%2fsecret") in (400, 403, 404)
```

- [ ] **Step 2: Run to verify they fail** — `ModuleNotFoundError`
- [ ] **Step 3: Implement `server.py`.** `ThreadingHTTPServer` + a `BaseHTTPRequestHandler` subclass. `do_POST`/`do_PUT`/`do_DELETE`/`do_PATCH` all return 405 immediately. `do_GET` routes `/api/*` through a token check (cookie or `?t=`), everything else to a static handler that resolves the path under the assets directory with `Path.resolve()` and rejects anything not `is_relative_to` it. Token via `secrets.token_urlsafe(32)`, compared with `secrets.compare_digest`.
- [ ] **Step 4: Run the tests** — pass
- [ ] **Step 5: Extend `tests/test_analysis_boundary.py` to assert `scriptscrap.workspace` imports no browser module**
- [ ] **Step 6: Commit** — `feat(workspace): loopback, token-gated, read-only server`

---

### Task 8: Session and endpoint APIs

**Files:**
- Create: `src/scriptscrap/workspace/api.py`
- Test: `tests/test_workspace_api.py`

**Interfaces:**
- Consumes: `EventStore` (Task 5), `SessionHandle` (Task 7)
- Produces: handler functions, each `(SessionHandle, dict[str, str]) -> dict`, so they are testable without a socket:
  - `sessions(root) -> dict`
  - `session_overview(handle) -> dict`
  - `endpoints(handle) -> dict`
  - `endpoint_detail(handle, endpoint_key) -> dict`
  - `event(handle, event_id) -> dict`
  - `events_by_id(handle, ids) -> dict`

Routes: `/api/sessions`, `/api/session`, `/api/endpoints`, `/api/endpoints/<key>`, `/api/events/<id>`, `/api/events?ids=a,b,c`.

- [ ] **Step 1: Write the failing tests** against the fixture session built by `tests/golden_support.py`

```python
def test_endpoints_carry_evidence_ids(handle):
    body = api.endpoints(handle)
    assert body["endpoints"]
    assert all(e["evidence_ids"] for e in body["endpoints"])

def test_endpoint_detail_includes_params_and_schemas(handle):
    detail = api.endpoint_detail(handle, KNOWN_ENDPOINT_KEY)
    assert detail["params"] is not None and "schemas" in detail

def test_event_lookup_returns_the_payload(handle):
    evidence = api.endpoints(handle)["endpoints"][0]["evidence_ids"][0]
    assert api.event(handle, evidence)["payload"]

def test_unknown_event_returns_not_found(handle):
    assert api.event(handle, "nope")["error"] == "not_found"

def test_overview_reports_redaction_posture(handle):
    assert api.session_overview(handle)["redaction"] in ("unredacted", "sanitised")
```

- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement `api.py` as plain SQL reads plus `EventStore`.** No inference — every value is read from a column `analyze` wrote.
- [ ] **Step 4: Run the tests** — pass
- [ ] **Step 5: Wire the routes into `server.py` and add one live-server integration test that walks endpoint → evidence id → payload over HTTP**
- [ ] **Step 6: Commit** — `feat(workspace): session and endpoint APIs with evidence drill-through`

---

### Task 9: Frontend shell and endpoint explorer

**Files:**
- Create: `src/scriptscrap/workspace/assets/app.js`, `assets/views/endpoints.js`, `assets/views/evidence.js`
- Modify: `assets/index.html`, `assets/app.css`
- Test: `tests/test_workspace_assets.py`

The shell: a session picker, a nav rail, a content pane, and a persistent header stating **UNREDACTED** or **SANITISED**. Hash routing (`#/endpoints/<key>`), no framework, no build step.

The endpoint view lists method, template, observation count, statuses, corroborating sources and confidence; selecting one opens params, schemas, and an evidence list where each `event_id` expands to its raw payload fetched from `/api/events/<id>`.

- [ ] **Step 1: Write the failing test** — assets exist, `index.html` references only local files, and no asset contains an absolute `http://`/`https://` URL (the offline requirement, checkable without a browser)
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement the shell and the two views**
- [ ] **Step 4: Run the tests** — pass
- [ ] **Step 5: Manual check against `v13_investigation_output_run3_interrupted`** — record what the endpoint list shows
- [ ] **Step 6: Commit** — `feat(workspace): endpoint explorer with evidence drill-through`

---

### Task 10: `scriptscrap workspace` command

**Files:**
- Modify: `src/scriptscrap/cli.py`
- Test: `tests/test_workspace_cli.py`

- [ ] **Step 1: Write the failing test** — `build_parser().parse_args(["workspace", "x"])` yields `func is cmd_workspace`, `--port` and `--no-open` parse
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Add `cmd_workspace`.** Print the tokenised URL, the session name, the event count and the redaction posture before serving; open a browser unless `--no-open`; exit cleanly on `KeyboardInterrupt`.
- [ ] **Step 4: Run the tests** — pass
- [ ] **Step 5: Commit** — `feat(cli): scriptscrap workspace`

---

# M6 — Timeline

### Task 11: Timeline API

**Files:** Modify `src/scriptscrap/workspace/api.py`; Test `tests/test_workspace_timeline.py`

**Interfaces:** Produces `timeline(handle, params) -> dict` over `/api/timeline?types=&sources=&page=&after_seq=&limit=`

- [ ] **Step 1: Write the failing tests** — unfiltered paging covers the log; a type filter returns only those types; a source filter returns only that source; combined filters intersect; `counts_by_type` drives the filter chips; an out-of-range cursor returns an empty page rather than an error
- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement over `EventStore.page`** — no new SQL outside `events_index.py`
- [ ] **Step 4: Run the tests** — pass
- [ ] **Step 5: Commit** — `feat(workspace): timeline API`

### Task 12: Timeline view

**Files:** Create `assets/views/timeline.js`; Test `tests/test_workspace_assets.py`

Chronological rows ordered by `seq` — never by timestamp, per `events/model.py:7`. Filter chips for user / network / DOM / storage / WebSocket / errors mapped to event types. Each row expands to its payload. Infinite scroll on the `next_seq` cursor.

- [ ] **Step 1: Write the failing asset test** — [ ] **Step 2: Verify it fails** — [ ] **Step 3: Implement** — [ ] **Step 4: Tests pass** — [ ] **Step 5: Commit** `feat(workspace): timeline view`

---

# M7 — Overview

### Task 13: Overview, health and findings API

**Files:** Modify `api.py`; Test `tests/test_workspace_overview.py`

**Interfaces:** Produces `overview(handle) -> dict` — counts for every derived table, capture health per sensor, findings ordered by severity, session manifest facts (browser build, baseline comparison, scope policy, forensic flags).

- [ ] **Step 1: Write the failing tests** — counts match `analyze_log` exactly for the fixture session; sensors carry status and reasons; findings are severity-ordered with `critical` first; a session with no manifest degrades to `null` rather than raising
- [ ] **Step 2: Verify they fail** — [ ] **Step 3: Implement** — [ ] **Step 4: Tests pass** — [ ] **Step 5: Commit** `feat(workspace): overview and health API`

### Task 14: Overview view

**Files:** Create `assets/views/overview.js`; Test `tests/test_workspace_assets.py`

Counts, per-sensor health with its reasons, findings with severity, and the blind spots the manifest records. Critical findings are visible without scrolling — a conclusion resting on evidence nobody collected outranks the numbers beside it.

- [ ] **Step 1: Failing asset test** — [ ] **Step 2: Verify** — [ ] **Step 3: Implement** — [ ] **Step 4: Pass** — [ ] **Step 5: Commit** `feat(workspace): overview view`

---

# M8 — Remaining views and the graph

### Task 15: Remaining entity APIs

**Files:** Modify `api.py`; Test `tests/test_workspace_entities.py`

**Interfaces:** Produces `states(handle)`, `state_transitions(handle)`, `ui_elements(handle)`, `schemas(handle)`, `dependencies(handle)`, `technologies(handle)` — each returning rows with their `evidence_ids`.

- [ ] **Step 1: Write the failing tests** — one per entity: row count matches `analyze_log`, and every row carries at least one evidence id
- [ ] **Step 2: Verify they fail** — [ ] **Step 3: Implement** — [ ] **Step 4: Pass** — [ ] **Step 5: Commit** `feat(workspace): state, element, schema, dependency and technology APIs`

### Task 16: Entity views

**Files:** Create `assets/views/states.js`, `elements.js`, `schemas.js`, `dependencies.js`, `technology.js`

UI elements show every selector candidate with its measured stability and any warning — the unstable ones are the point, because they are what a generated script would break on.

- [ ] **Step 1: Failing asset test** — [ ] **Step 2: Verify** — [ ] **Step 3: Implement** — [ ] **Step 4: Pass** — [ ] **Step 5: Commit** `feat(workspace): entity views`

### Task 17: Graph view

**Files:** Create `assets/views/graph.js`; Test `tests/test_workspace_assets.py`

Two modes over the same renderer: state transitions (`states` → `state_transitions`), and value dependencies (`dependencies`, source endpoint → target endpoint labelled with the field and mechanism). Hand-rolled SVG, layered left-to-right by longest path, no library. Nodes carry their observation count; clicking one opens its evidence.

- [ ] **Step 1: Write the failing test** — the layout function assigns every node a layer, places no two nodes at the same coordinate, and terminates on a cyclic graph (state machines have cycles; a naive longest-path walk hangs)
- [ ] **Step 2: Verify it fails** — [ ] **Step 3: Implement** — [ ] **Step 4: Pass** — [ ] **Step 5: Commit** `feat(workspace): state and dependency graph`

---

# M9 / Phase 3 — Generators

### Task 18: httpx client generator

**Files:** Create `src/scriptscrap/generate/__init__.py`, `client.py`; Test `tests/test_generate_client.py`

**Interfaces:** Produces `render_client(result: AnalysisResult, *, session_name: str) -> str`

Reads the derived model only. Every function carries the endpoint it came from and the evidence count behind it. Credentials are read from the environment, never embedded — the retired `generated_client.py` had a docstring promising this and no test enforcing it.

- [ ] **Step 1: Write the failing tests**

```python
def test_output_is_valid_python():
    compile(render_client(RESULT, session_name="fixture"), "client.py", "exec")

def test_no_captured_credential_appears(): ...   # assert every known fixture secret is absent
def test_each_endpoint_becomes_a_method(): ...
def test_header_names_the_session_and_evidence(): ...
def test_templated_path_becomes_a_parameter(): ...
```

- [ ] **Step 2: Verify they fail** — [ ] **Step 3: Implement** — [ ] **Step 4: Pass** — [ ] **Step 5: Commit** `feat(generate): httpx client from the derived model`

### Task 19: Playwright script generator

**Files:** Create `src/scriptscrap/generate/playwright.py`; Test `tests/test_generate_playwright.py`

**Interfaces:** Produces `render_playwright(result, *, session_name: str) -> str`

Walks `transitions` from the entry state; each step uses the highest-stability selector for its element and **comments any selector whose stability is below 1.0 with its measured value**, so the reader sees which steps rest on a locator that already moved.

- [ ] **Step 1: Write the failing tests** — output compiles; a low-stability selector carries its warning; a state with no observed transition is not invented
- [ ] **Step 2: Verify they fail** — [ ] **Step 3: Implement** — [ ] **Step 4: Pass** — [ ] **Step 5: Commit** `feat(generate): playwright starting point`

### Task 20: `scriptscrap generate` and workspace download

**Files:** Modify `cli.py`, `api.py`, `assets/views/export.js`; Test `tests/test_generate_cli.py`

- [ ] **Step 1: Write the failing tests** — `generate client` and `generate playwright` parse and write to the session directory; `/api/generate/<kind>` returns the source as text
- [ ] **Step 2: Verify they fail** — [ ] **Step 3: Implement** — [ ] **Step 4: Pass** — [ ] **Step 5: Commit** `feat(cli): scriptscrap generate`

### Task 21: Documentation and final verification

- [ ] **Step 1: Update `README.md`** — the workspace and generate commands, the loopback/token posture, the retired files, the restored client generator
- [ ] **Step 2: Run `uv run pytest -m "not browser"`** — all green
- [ ] **Step 3: Run `uv run pytest`** — full suite including browser tests
- [ ] **Step 4: Run `uv run ruff check .`** — clean
- [ ] **Step 5: Run `uv run python diagnostics/check_environment.py`** — the doctor still passes
- [ ] **Step 6: Open the workspace against a real captured session and confirm every view renders with real data**
- [ ] **Step 7: Commit** — `docs: workspace and generator usage`

---

## Self-Review

**Spec coverage:** evidence index → Tasks 3-5. Staleness guard → Task 5. Scope reduction → Tasks 1-2. Server and its security properties → Task 7. Frontend → Tasks 9, 12, 14, 16, 17. Legacy retirement → Task 6. Phase 3 generators → Tasks 18-20. Every testing-table row maps to a task. Covered.

**Type consistency:** `EventStore.page` returns `EventPage` with `next_seq`, used as the cursor in Tasks 11-12. `SessionHandle.redaction` is the string used in Task 8's test and Task 9's header. Handler signature `(handle, params) -> dict` is uniform across Tasks 8, 11, 13, 15.

**Known risk:** Task 6 is the only irreversible step and the only one touching the behavioural baseline. It runs last in M4.5, after the foundation is green, so a re-baseline is never entangled with a failing new feature.
