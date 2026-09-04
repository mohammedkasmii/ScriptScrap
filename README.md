# ScriptScrap

A black-box web-application investigation engine built on
[Camoufox](https://camoufox.com). An operator drives a real authenticated session
by hand; ScriptScrap observes it and exports a dataset a developer can use to
understand and automate the platform.

Current state: **M1** — the investigator is a single script with a safety system
around it. See `docs/` for the architecture blueprint this is being built toward.

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
browser 152.0.4-beta.28. Do not bump them without re-running the diagnostics and
re-reviewing the golden master.

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

**That directory is an unredacted capture of an authenticated session.** It is
gitignored by pattern and carries its own `SECURITY.md`. Read
`session_manifest.json` first: it records the browser build, the addon
configuration, the scope policy and the known blind spots that produced the
evidence.

## Analysing a session

Analysis is **offline**: it reads the recorded event log and never launches a
browser, so a session can be analysed and re-analysed from any machine.

```bash
uv run scriptscrap analyze v13_investigation_output   # -> session.sqlite + analysis/report.md
uv run scriptscrap export  v13_investigation_output   # -> export/shared/dataset.json
```

`events.jsonl` is the source of truth; `session.sqlite` is derived and
rebuildable — deleting it and re-running `analyze` reproduces it exactly
(`--rebuild` does both).

`analyze` derives endpoints (with path templating and query parameters), schemas
with sample counts, scored dependency hypotheses, locator candidates with
measured stability, observed states, and technology fingerprints. Every
conclusion cites the raw `event_id`s that support it.

`export` writes a **sanitised** dataset: credentials removed, identifiers and
emails replaced by deterministic pseudonyms so value propagation stays
analysable, and no raw bodies, screenshots or HTML.

## Layout

```
camoufox/camoufox_investigator.py   the investigator (behavioural authority)
src/scriptscrap/
  events/      append-only event spine + offline reader
  sensors/     observation sensors (lifecycle, runtime, websocket, storage)
  probe/       the injected in-page observer
  analysis/    OFFLINE inference: endpoints, schemas, correlation, selectors,
               states, technology. Imports no browser -- enforced by test.
  export/      sanitised shareable dataset
  cli.py       scriptscrap analyze / export
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
