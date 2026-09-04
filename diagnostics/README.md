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
| `probes/hook_timing_probe.py` | JS world semantics over `http://`; runtime hook timing | no |
| `probes/js_world_probe.py` | JS world semantics over `file://` | no |
| `probes/addon_filter_probe.py` | uBlock Origin default-addon filtering | **yes** |

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

Measured on camoufox 0.5.5 / browser `152.0.4-beta.28`: with defaults, a request
to `googletagmanager.com/gtm.js` raised `NetworkError` and fired `requestfailed`;
with `exclude_addons=[DefaultAddons.UBO]` the same request completed.

The **binding assertion** is the static one: `camoufox_investigator.py` must pass
`exclude_addons=[DefaultAddons.UBO]`. The live comparison is supporting evidence
and can legitimately vary as filter lists change.

### `hook_timing_probe.py` — instrumentation reachability

Three assumptions:

1. **`add_init_script` reaches the page's real `window`.** Camoufox's
   documentation states that all Playwright JS is isolated from the page, which
   would mean monkey-patches never take effect. On the pinned stack the measured
   behaviour **contradicts the documentation** — patches do reach the page. This
   must therefore be *measured*, never read off the docs. If it ever fails, every
   in-page hook silently stops working and `js_hooks_and_mutations.json` becomes
   a permanently empty file that looks like a finding.
2. **`page.evaluate` reads the page's real `window`.** If not, reading back
   `window.functionHookLogs` returns an isolated-world copy and always looks
   empty.
3. **The `setInterval` hook pattern misses parse-time calls.** Known answer:
   it does. The probe records this so the limitation stays visible, and so a
   stack change that fixes it gets noticed.

Assumption 3 also demonstrates that an `Object.defineProperty` accessor trap
does **not** fix it: a classic-script `function` declaration binds via
`[[DefineOwnProperty]]`, which *replaces* the accessor rather than invoking its
setter. There is currently no injected-JS technique that reliably hooks a named
global function called during initial page parse.

### `js_world_probe.py` — same assumptions, different origin

Isolated-world behaviour can in principle differ between `file://` and `http://`
origins. Both are kept: if the two probes ever disagree, that disagreement is
itself the finding.

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
