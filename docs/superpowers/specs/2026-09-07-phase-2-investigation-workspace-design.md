# Phase 2 — Investigation Workspace

Status: approved 2026-09-07
Supersedes: nothing. Phase 1 (capture + offline analysis) is frozen as of `95e8fec`.

## Problem

Phase 1 derives real knowledge — endpoints, schemas, selectors, states,
transitions, dependencies, technologies, capture health — and every conclusion
cites the `event_id`s that support it. All of it is delivered as a directory of
files. Reading it means opening `analysis/report.md`, cross-referencing
`session.sqlite` by hand, and grepping a 7 MB `events.jsonl` for an event id.

The goal of Phase 2:

> A developer should be able to investigate an unfamiliar application without
> manually opening twelve files.

## What is actually missing

Not a dashboard. `analysis/report.md` already contains every number a session
overview would show. The missing piece is one level down:

**There is no way to get from a conclusion to its evidence.**

Every derived table in `session.sqlite` stores `evidence_ids` as TEXT. The
events those ids name live only in `events.jsonl`, and `EventLogReader`
(`src/scriptscrap/events/reader.py:53`) `readlines()` the whole file and parses
every line. There is no index. A single evidence lookup costs a full re-parse
of the log.

Everything else in Phase 2 — the timeline, the graph, the drill-through — is
downstream of fixing that.

## Non-goals

Explicitly out of scope, restating the Phase 1 boundary:

- Autonomous site navigation, automatic form execution, LLM-driven browsing
- Any write path back into the captured application
- Accounts, teams, billing, cloud deployment, plugin surfaces
- Re-deriving analysis in the presentation layer

The workspace **presents** what `analyze` produced. It computes no new
knowledge. If a view needs a number that does not exist, the number is added to
the analysis layer with a test, not calculated in a request handler.

## Architecture

```
events.jsonl ───────────────────────────────► source of truth, append-only
     │
     │  scriptscrap analyze
     ▼
session.sqlite ─────────────────────────────► derived, rebuildable
     │   derived knowledge (existing)
     │   + events index (new: envelope + byte offset)
     │
     │  scriptscrap workspace
     ▼
localhost HTTP server ──────────────────────► read-only, loopback, token-gated
     │
     ├── /api/*   JSON from sqlite; payloads by seek into events.jsonl
     └── /        static ES modules + CSS, no build step
```

### 1. The evidence index

`analyze` gains a second output into the same database: one row per event,
holding **the envelope only**.

```sql
CREATE TABLE events (
    run_id      INTEGER NOT NULL REFERENCES analysis_runs(id),
    event_id    TEXT    NOT NULL,
    seq         INTEGER NOT NULL,
    type        TEXT    NOT NULL,
    source      TEXT    NOT NULL,
    t_wall      TEXT    NOT NULL,
    t_mono      REAL    NOT NULL,
    page_id     TEXT,
    frame_id    TEXT,
    byte_offset INTEGER NOT NULL,
    byte_length INTEGER NOT NULL
);
CREATE INDEX events_by_event_id ON events(run_id, event_id);
CREATE INDEX events_by_seq      ON events(run_id, seq);
CREATE INDEX events_by_type     ON events(run_id, type, seq);
CREATE INDEX events_by_source   ON events(run_id, source, seq);
```

The payload is **not** copied. `byte_offset` and `byte_length` locate the line
in `events.jsonl`; a drill-through is one `seek` and one `read`.

Rationale for the split:

- ~100 bytes/row. 9,255 events ≈ 1 MB, against ~7 MB to copy payloads.
- `session.sqlite` stays derived and deletable. Copying payloads would make it
  a second source of truth, which the store's own docstring forbids
  (`src/scriptscrap/analysis/store.py:6`).
- Timeline filtering (by type, by source, by time window, by page) becomes an
  indexed SQL query rather than a linear scan.

**Offsets are only valid for the exact bytes they were built from.**
`analysis_runs` gains `log_size INTEGER` and `log_sha256 TEXT`. `EventStore`
verifies both before serving any payload and raises `StaleIndexError` on a
mismatch. `events.jsonl` is append-only and never rewritten, so the normal
cause of a mismatch is an index built from a shorter log — a session that kept
recording after `analyze` ran. The workspace surfaces this as "re-run
`scriptscrap analyze`", never as silently wrong evidence.

Events are stored per `run_id`, like every other derived table, and the
workspace reads the most recent run. Re-running `analyze` without `--rebuild`
therefore appends a second set — ~1 MB — rather than mutating the first, which
keeps the store append-only in the same way the log is.

Offsets are computed during a single byte-accurate pass over the log. This
requires reading it in binary and tracking cumulative offsets, which
`EventLogReader` does not currently do — it decodes text and discards
positions. The reader gains an opt-in `with_offsets=True` mode rather than a
second parser, so there remains exactly one place that decides what a valid
event line is.

### 2. `EventStore` — the read API

A new module, `src/scriptscrap/analysis/events_index.py`, is the only thing
that knows offsets exist:

```python
class EventStore:
    def get(event_id: str) -> Event | None
    def get_many(event_ids: Sequence[str]) -> list[Event]
    def page(*, types=None, sources=None, page_id=None,
             after_seq=None, limit=200) -> EventPage
    def counts_by_type() -> dict[str, int]
    def window(start_seq: int, end_seq: int) -> list[Event]
```

Consumers never see byte offsets. Swapping the backing store later changes this
file and nothing else.

### 3. Scope reduction, shared

`LifecycleSensor` emits `page.url`, `frame.url`, `popup.url` and
`download.url` verbatim (`src/scriptscrap/sensors/lifecycle.py:64,91,102,132,141,188`).
An out-of-scope frame — a third-party iframe, an SSO redirect carrying a token
in the query — therefore lands in the event log with its full query string.
This is the same defect already fixed for the runtime probe, where a real
capture recorded 213 out-of-scope observations carrying full query strings
(`src/scriptscrap/sensors/runtime.py:55-64`).

`_strip_query`, `_redact_stack_frame` and `URL_PAYLOAD_KEYS` move from
`runtime.py` to a new `src/scriptscrap/sensors/scope.py`. `runtime.py` imports
them; `lifecycle.py` gains the URL-stripping half.

Lifecycle needs only the first of the runtime module's two reductions. Its
payloads carry no bodies, header names or typed values — the things the
allowlist rebuild exists to remove — so a lifecycle event whose subject is out
of scope keeps its fields, loses every URL query and fragment, and is marked
`evidence_reduced: true`. "A third-party iframe attached here" stays a
recorded fact.

### 4. Workspace server

`scriptscrap workspace <path>` where `<path>` is a session directory or a
parent directory containing several.

- `http.server.ThreadingHTTPServer` from the stdlib. **No new runtime
  dependency.** The pinned-baseline discipline in `README.md` is a reason not
  to add one for a presentation layer.
- Binds `127.0.0.1` explicitly. Never `0.0.0.0`. Asserted by test.
- Ephemeral port unless `--port` is given.
- **Read-only.** No handler mutates anything. `POST`/`PUT`/`DELETE`/`PATCH`
  return 405 unconditionally.
- A random token is generated per launch, printed in the URL, and set as a
  cookie on first load. Every `/api/` route requires it. The served directory
  is an unredacted capture of an authenticated session (`README.md`,
  `SECURITY.md`); loopback alone does not isolate it from other local
  processes.
- Static assets are served from one fixed package directory, resolved and
  checked to remain inside it. Session file access is limited to a whitelist
  of known filenames.

### 5. Frontend

Plain ES modules and CSS served as static files. No build step, no npm, no CDN
— the tool must work on a disconnected machine, which also rules out loading a
graph library at runtime. The dependency and state graphs are hand-rolled SVG
with a layered layout; at 33 endpoints and 25 states this is a small amount of
code and avoids a dependency the rest of the project would not otherwise carry.

Views:

| View | Source |
|---|---|
| Overview | `analysis_runs`, counts, `health` |
| Timeline | `events` index, filtered |
| Endpoints | `endpoints`, `endpoint_params`, `schemas` |
| States | `states`, `state_transitions` |
| UI Elements | `ui_elements`, `selectors` |
| Dependencies | `dependencies` + graph |
| Technology | `technologies` |
| Findings | `findings` |

Every view drills through to raw events by `event_id`.

The header states whether the open session is **UNREDACTED** (the session
directory) or **SANITISED** (`export/shared/`), because the two look alike and
only one is safe to screen-share.

### 6. Legacy retirement

`camoufox/camoufox_investigator.py:1428-1451` writes nine files that predate
the event spine and duplicate what `analyze` now derives:

```
network_traffic.json        dom_structure.json       api_dependencies.json
generated_client.py         dropdown_catalogs.json   jquery_events.json
js_hooks_and_mutations.json mcma_openapi_spec.json   out_of_scope_metadata.json
```

All are removed. The workspace then has exactly one output contract instead of
choosing between two.

This changes the golden master (`tests/golden/investigation.json`), which
`README.md` calls "a decision point, not automatically a bug". It is therefore
its own reviewed commit, with the removed keys named in the message.

**Accepted capability loss:** `generated_client.py` disappears. Phase 3
replaces it with a generator that reads the derived model and is tested; until
that lands, nothing emits a client. `out_of_scope_metadata.json` is retained
in spirit — the same facts are in the event log as `evidence_reduced` events.

## Phase 3 — Developer export

In scope for this work, after Phase 2 lands:

- `scriptscrap generate client <session>` — an httpx client from `endpoints` +
  `schemas`, with no captured credentials in the output, reading them from the
  environment instead.
- `scriptscrap generate playwright <session>` — a starting-point script from
  `states`, `transitions` and the highest-stability `selectors`.
- Both are **derived suggestions**, generated from the derived model only, and
  both carry a header naming the session and the evidence they rest on.
- Generated output is offered in the workspace as a download.

## Testing

TDD. Tests precede implementation for every unit below.

| Area | Test |
|---|---|
| Offsets | every `event_id` in a real log round-trips to a byte-identical line |
| Staleness | appending to the log makes `EventStore` raise; re-analyse clears it |
| Truncated log | a killed-mid-write log still indexes every intact event |
| `EventStore` | filter/page/window against the fixture session |
| Scope | out-of-scope frame/page/popup/download URLs lose query and fragment |
| Scope | in-scope URLs are untouched |
| API | every route's JSON shape, against a fixture session |
| Auth | any `/api/` request without the token is rejected |
| Method | `POST`/`PUT`/`DELETE` are rejected on every route |
| Traversal | `../` in a static path cannot escape the asset directory |
| Bind | the listening socket is on `127.0.0.1` |
| Boundary | `scriptscrap.workspace` imports no browser module |
| Golden | re-baselined deliberately; all other assertions unchanged |
| Generators | output parses, imports, and contains no captured credential |

The existing suite must stay green throughout, except the one intentional
golden-master change.

## Milestones

| | Scope |
|---|---|
| M4.5 | events index, `EventStore`, `sensors/scope.py`, lifecycle fix, legacy retirement + golden re-baseline |
| M5 | server, shell, endpoint explorer with evidence drill-through |
| M6 | timeline with filters |
| M7 | overview + capture health + findings |
| M8 | states, UI elements, schemas, dependencies, technology, graph |
| M9 | Phase 3 generators + workspace download |

Each milestone ends green: full test suite plus `ruff check`.
