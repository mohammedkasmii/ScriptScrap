# ScriptScrap

A black-box web-application investigation engine built on
[Camoufox](https://camoufox.com). An operator drives a real authenticated session
by hand; ScriptScrap observes it and exports a dataset a developer can use to
understand and automate the platform.

Capture is observation-first: it must never become the reason the application
behaves differently. An optional forensic layer goes deeper, and says so.

## Setup

Requires [uv](https://docs.astral.sh/uv/) and a fetched Camoufox browser.

```bash
uv sync --all-groups
uv run python -m camoufox fetch     # one-off, downloads the browser
```

Dependencies are pinned and locked (`uv.lock`). **The pinned versions are part of
the behavioural baseline** — every empirical finding the design rests on (JS world
semantics, runtime hook timing, uBlock default-addon filtering, snapshot
non-destructiveness) was verified against camoufox 0.5.5 / playwright 1.60.0 /
browser 152.0.4-beta.29. Do not bump them without re-running the diagnostics and
re-reviewing the golden master.

**`uv.lock` does not pin the browser.** `python -m camoufox fetch` replaces the
Firefox build independently, and that is not cosmetic: the drift from
`152.0.4-beta.28` to `beta.29` isolated the JS worlds, which disabled every
monkey-patched instrument in the runtime probe for an entire real capture while
capture health still reported the probe healthy. The baseline is therefore an
assertion, not a comment: it lives in `src/scriptscrap/baseline.py`,
`check_environment.py` **fails** on a mismatch, and every session manifest
records the comparison.

Bumping the baseline means *all four probes were run on that build and passed* —
never that a warning was inconvenient.

## Verification

```bash
uv run python diagnostics/check_environment.py   # offline: config, versions, gitignore, policy
uv run pytest -m "not browser"                   # fast: event spine, normalisation, replay
uv run pytest                                    # full: also launches Camoufox
uv run ruff check .
```

Browser-level assumptions that a dependency upgrade could silently invalidate are
verified separately — see [`diagnostics/README.md`](diagnostics/README.md):

```bash
uv run diagnostics/probes/snapshot_integrity_probe.py   # capture does not modify the live page
uv run diagnostics/probes/hook_timing_probe.py          # JS world semantics, hook timing
uv run diagnostics/probes/js_world_probe.py             # JS world semantics (file:// origin)
uv run diagnostics/probes/addon_filter_probe.py         # uBlock filtering (needs network)
```

## Running an investigation

```bash
uv run python camoufox/camoufox_investigator.py
```

It asks for a target URL and the engagement scope, opens a browser, and records
what you do until you press ENTER. Output goes to `v13_investigation_output/`.

The probe runs in **two JavaScript worlds**, because Firefox isolates injected
scripts from the page. Listeners (clicks, input, DOM mutations) go in the
isolated world with the reporting channel; the monkey-patched instruments
(`fetch`, XHR, `sendBeacon`, form submit, `pushState`) must replace the globals
the *application* calls, so they are installed into the page's own world with
`main_world_eval` and hand records back over a DOM CustomEvent. The launch
option is load-bearing: without it the patches observe nothing, and the sensor
says so rather than reporting a quiet session.

**That directory is an unredacted capture of an authenticated session.** It is
gitignored by pattern and carries its own `SECURITY.md`. Read
`session_manifest.json` first: it records the browser build, the addon
configuration, the scope policy and the known blind spots that produced the
evidence.

## Forensic mode (optional)

Normal capture uses Playwright sensors plus an in-page runtime probe. **Forensic
mode adds a Firefox WebExtension** that sees what those cannot: full response
bodies (via Firefox's `filterResponseData`), script source *before* it is
parsed, and the real cookie jar including `httpOnly`.

It is entirely optional — nothing in normal capture or offline analysis requires
it — and whatever is enabled is written verbatim into the session manifest.

Response bodies go into a content-addressed blob store (`blobs/<sha256>`), so
identical payloads are stored once and the event log keeps only a hash and a
size. Oversized bodies are recorded as skipped **with a reason**, never dropped
silently.

Source *rewriting* has its own separate opt-in. Enabling forensic mode does not
enable it, because rewriting a response before the browser parses it means the
application no longer runs the code its author shipped — that is intervention,
not observation, and the two must not share a switch.

```bash
uv run scriptscrap health v13_investigation_output   # did we fail to see it?
```

## Analysing a session

Analysis is **offline**: it reads the recorded event log and never launches a
browser, so a session can be analysed and re-analysed from any machine.

```bash
uv run scriptscrap analyze v13_investigation_output   # -> session.sqlite + analysis/report.md
uv run scriptscrap export  v13_investigation_output   # -> export/shared/
```

`events.jsonl` is the source of truth; `session.sqlite` is derived and
rebuildable — deleting it and re-running `analyze` reproduces it exactly
(`--rebuild` does both).

`analyze` derives endpoints (with path templating and query parameters), schemas
with sample counts, scored dependency hypotheses, locator candidates with
measured stability, observed states, and technology fingerprints. Every
conclusion cites the raw `event_id`s that support it.

It also writes an **evidence index**: one row per event holding the envelope and
the byte offset of its line in `events.jsonl`. Payloads are never copied, so the
log stays the only source of truth — but a conclusion can be walked back to the
events behind it with a seek instead of a re-parse. The run records the log's
size and sha256, and a reader refuses to serve evidence against a log those no
longer match rather than returning whatever now sits at that offset.

`export` writes a **sanitised** dataset: credentials removed, identifiers and
emails replaced by deterministic pseudonyms so value propagation stays
analysable, and no raw bodies, screenshots or HTML. Sanitisation is deny by
default — a model field with no declared disposition is an error, not a value
that passes through — so adding a field to the analysis cannot silently add it
to a shareable export.

`export/shared/` holds `dataset.json`, `report.md` and a `session.sqlite`
derived from the same sanitised model, so `scriptscrap workspace` can open it
and the header reads **SANITISED**. It carries no event log: evidence
drill-through is unavailable there by construction, and the workspace says so
rather than showing an empty panel.

## Browsing a session

```bash
uv run scriptscrap workspace v13_investigation_output
```

Opens a local viewer over the analysed session: overview and capture health,
timeline, endpoints, states, UI elements, schemas, dependencies, technology.
Every record drills through to the raw events that support it.

The path may be one session directory or a parent holding several.

It is **read-only and loopback-only**. Because the directory it serves is an
unredacted capture of an authenticated session:

* it binds `127.0.0.1` and refuses any other host
* every `/api/` route requires a token minted for that launch — "only local
  processes can reach it" is not "only you can reach it"
* `POST`/`PUT`/`DELETE`/`PATCH` are rejected unconditionally; no route mutates
  anything
* the page header states **UNREDACTED** or **SANITISED**, because a session
  directory and its `export/shared` twin are indistinguishable in a screenshot

No runtime dependency was added for any of it, and nothing is loaded from a
CDN — the workspace works on a disconnected machine.

## Generating a starting point

```bash
uv run scriptscrap generate client     v13_investigation_output
uv run scriptscrap generate playwright v13_investigation_output
```

`client` writes an httpx client with a method per observed route. `playwright`
writes the observed workflow using the most stable locator for each element.

`client` reads only shapes, parameter names and header names, so it carries no
captured value — enforced by a test. `playwright` is **UNREDACTED**: a locator
that does not name the real element cannot find it, so the script embeds
locators, labels and element text read off the application. Its header, its
`--help` and the command's own output all say so.

`--sanitised` produces a shareable variant. Locators that carried application
text are removed and marked in place, and the script deliberately refuses to
run rather than pretending to work with selectors that cannot match.

Credentials are read from the environment at runtime:

```bash
export SCRIPTSCRAP_AUTH_HEADERS='{"Cookie": "..."}'
export SCRIPTSCRAP_BASE_URL=https://...
```

**These are derived suggestions, not specifications.** They describe one
observed session: a route nobody visited is not in them, and a parameter nobody
varied is inferred from a single value's shape. The generated Playwright script
contains no assertions — the capture recorded what the application did, never
what it should do — and it flags two different problems in place:

* `UNSTABLE` — the locator was already ambiguous when observed
* `VOLATILE` — the locator was unambiguous then and will be wrong later,
  because it carries a UUID, a timestamp or a row id

## Layout

```
camoufox/camoufox_investigator.py   the investigator (capture)
src/scriptscrap/
  baseline.py  the pinned browser build, asserted by the doctor and the manifest
  events/      append-only event spine + offline reader
  sensors/     observation sensors (lifecycle, runtime, websocket, storage)
               scope.py holds the boundary rule every sensor applies
  probe/       the injected in-page observer, in two JS-world roles
  analysis/    OFFLINE inference: endpoints, schemas, correlation, selectors,
               states, technology, reconciliation, capture health.
               events_index.py is the only module that knows byte offsets exist.
               Imports no browser -- enforced by test.
  workspace/   read-only local viewer: stdlib server + no-build-step frontend.
               Imports no browser -- same test.
  generate/    derived suggestions: an httpx client, a Playwright starting point
  extension/   optional Firefox forensic sensor (MV2) + loopback transport
  storage/     content-addressed blob store for raw evidence
  export/      sanitised shareable dataset
  cli.py       scriptscrap analyze / export / workspace / generate
  fixture/     deterministic local app used as the test laboratory
  testing/     scripted capture, normalisation, golden snapshots
diagnostics/   compatibility probes + environment doctor
tests/         unit, replay, golden master, crash resilience
tests/golden/  committed baselines (see its README)
```

## Testing model

`tests/` is split by what it needs:

* **offline** (`-m "not browser"`) — event spine, normalisation, and replay of a
  committed event log. Runs on a machine with no browser at all. This is the
  boundary the future analysis layer depends on.
* **browser** — drives the fixture app through a fixed workflow with the real
  investigator and compares every output to a golden master.

A golden-master failure is a decision point, not automatically a bug. See
[`tests/golden/README.md`](tests/golden/README.md).
