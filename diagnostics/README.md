# Diagnostics

These scripts encode **empirically verified assumptions** that
`camoufox/camoufox_investigator.py` depends on. A Camoufox or Playwright upgrade
can invalidate any of them **silently** — the investigator would keep running and
keep producing output that is quietly incomplete.

Run them after any dependency upgrade, and before trusting a new investigation.

Each script is self-contained ([PEP 723](https://peps.python.org/pep-0723/)
inline metadata), so `uv run` resolves its own dependencies.

## Quick check — offline, no browser

```bash
uv run diagnostics/check_environment.py
```

Verifies versions, browser build, addon policy, `.gitignore` coverage, the
generated-client credential policy, and the scope boundary. Exits non-zero on a
blocking problem.

## Browser probes — launch Camoufox

| Probe | Verifies | Needs network |
|---|---|---|
| `probes/snapshot_integrity_probe.py` | Visual capture does not modify the live page (F-03) | no |
| `probes/js_world_probe.py` | The split-world runtime architecture, over `file://` | no |
| `probes/hook_timing_probe.py` | Runtime hook timing over `http://`; the parse-time limitation | no |
| `probes/addon_filter_probe.py` | uBlock Origin default-addon filtering | **yes** |

All four are the evidence behind `scriptscrap.baseline.BROWSER_BUILD`. Run them
on a new browser build before bumping it; `check_environment.py` fails until
they agree.

```bash
uv run diagnostics/probes/snapshot_integrity_probe.py
uv run diagnostics/probes/hook_timing_probe.py
uv run diagnostics/probes/js_world_probe.py
uv run diagnostics/probes/addon_filter_probe.py
```

`probes/probe_page.html` is a fixture for `js_world_probe.py`.

## What each probe protects, and why it exists

### `snapshot_integrity_probe.py` — the app must survive being observed

`capture_visual_state()` originally built its offline HTML by **editing the page
it was investigating**: `fetch()`-ing every stylesheet from inside the page,
replacing live `<link>` elements with `<style>`, and rewriting form attributes —
all from a 2-second background loop, against a page a human was actively using.
The fetches were then recorded by the investigator's own request handler as if
they were application traffic.

The current implementation deep-clones `document.documentElement` and transforms
only the detached copy, reading stylesheet text from already-loaded
`document.styleSheets` rather than re-fetching it.

This probe runs **both** implementations against identical fixture pages and
diffs the live DOM before and after, so the difference is measured rather than
asserted. It also caught a second, non-obvious contamination source: Playwright's
`screenshot()` defaults to `caret="hide"`, which sets and then clears an inline
style and leaves a residual `style=""` attribute on every input. The investigator
now passes `caret="initial"`.

Cross-origin stylesheets cannot be read (`cssRules` throws), so they keep their
`<link>` and are counted in `snapshot_fidelity.sheets_not_readable` in the
session manifest — a partial snapshot is reported as partial.

### `addon_filter_probe.py` — evidence integrity

Camoufox adds uBlock Origin to `addons` **unconditionally** unless
`exclude_addons` is passed (`camoufox/utils.py`, in `launch_options`). An
investigator running with defaults captures an ad-blocked view of the target and
has no way to know it.

Measured on camoufox 0.5.5 / browser `152.0.4-beta.29`: with defaults, a request
to `googletagmanager.com/gtm.js` raised `NetworkError` and fired `requestfailed`;
with `exclude_addons=[DefaultAddons.UBO]` the same request completed.

The **binding assertion** is the static one: `camoufox_investigator.py` must pass
`exclude_addons=[DefaultAddons.UBO]`. The live comparison is supporting evidence
and can legitimately vary as filter lists change.

### `js_world_probe.py` — the split-world runtime architecture

**Superseded assumption.** Until `de07d1b` these probes asserted that
`add_init_script` and `page.evaluate` reached the page's real `window`. On
browser `152.0.4-beta.28` that was measurably true and contradicted Camoufox's
own documentation. On `beta.29` it stopped being true, every monkey-patched
instrument in the runtime probe went silent, and a whole real capture came back
with no fetch, XHR, beacon or `pushState` evidence in it.

World isolation is therefore **no longer treated as a failure**. It is the
premise. The runtime probe splits by what each technique needs, and this probe
verifies the five contracts that split depends on:

| | Contract |
|---|---|
| A | Worlds are isolated — driver globals invisible to the page, and vice versa |
| B | `evaluate("mw:" + script)` reaches the page's own world, idempotently |
| C | A patch installed that way is what page-authored code actually calls |
| D | A record dispatched over the DOM `CustomEvent` bridge reaches the isolated world **and** Python through the exposed binding |
| E | One application call yields exactly one observation — the roles install disjoint instruments |

It mirrors the mechanism rather than importing it, so it measures the
*browser* and still runs in a bare venv. `tests/test_diagnostics.py` asserts the
bridge event name matches `src/scriptscrap/probe/probe.js`, so the mirror
cannot drift.

### `hook_timing_probe.py` — when instrumentation can be installed

`js_world_probe.py` establishes that the page's globals *can* be patched. This
one measures **when**, and therefore what is observable:

1. **Late calls are observed.** A function called after load is wrapped and
   recorded. The ordinary case, and it must work.
2. **Parse-time calls are not.** A function declared and called during its own
   initial parse has already run before a page-world patch can be installed —
   page-world execution is only available once a navigation has committed. Two
   independent techniques are measured so the finding is about *timing*, not
   about one implementation:
   * interval polling installs its wrapper too late;
   * an `Object.defineProperty` accessor trap fails twice over. In the isolated
     world it installs and never fires, because the page's declaration writes to
     a different `window`. In the page world it cannot be installed **at all**
     after the fact — a top-level `function` declaration creates a
     *non-configurable* global property, and the browser refuses to redefine it.
     There is no placement that both reaches the page's window and precedes the
     declaration.
3. **Source reading identifies what runtime hooking cannot.** The optional M4
   forensic layer reads a script's source before Firefox parses it, and
   `find_parse_time_calls` names the early function. That establishes the
   function exists and is called during its own parse. It does **not** hook the
   call, and ScriptScrap does not rewrite source to make it hookable — M4
   deliberately left rewriting unimplemented.

The probe reads every page global through the `mw:` prefix. An earlier version
called a page function through an ordinary `page.evaluate` and died with a
`TypeError` that looked like a browser regression and was really the probe
asking the wrong world. A limitation must be reported as a finding, never as a
traceback.

Both probes are kept because isolated-world behaviour can in principle differ
between `file://` (`js_world_probe`) and `http://` (`hook_timing_probe`)
origins. If they ever disagree, that disagreement is itself the finding.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Assumptions hold |
| `1` | An assumption was violated — investigate before trusting output |
| `2` | Could not run (no network, browser not fetched, fixture missing) |

## Status

Interim M0 diagnostics. `check_environment.py` will be replaced by
`scriptscrap doctor` when the package architecture lands in M1; the probes are
intended to become browser-level regression tests against the M1 fixture
application.
