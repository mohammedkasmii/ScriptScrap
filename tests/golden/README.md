# Golden master

Committed baselines for the post-M0 investigator's behaviour.

| File | What it is |
|---|---|
| `investigation.json` | Normalised snapshot of every output a scripted fixture investigation produces |
| `sample_events.jsonl` | A real event log from that same run, so the replay tests can run offline with no browser |

Both are produced by one command:

```bash
SCRIPTSCRAP_UPDATE_GOLDEN=1 uv run pytest tests/test_golden_master.py
```

## These files contain credential-shaped values, and that is intended

`sample_events.jsonl` and `investigation.json` contain strings like
`fixture-password-not-a-real-secret` and `FIXTURE-CSRF-TOKEN-0001`.

**They are synthetic.** The fixture app plants them precisely so the
credential-classification and leak-detection paths have something to trip on. A
baseline with no credential-shaped data in it could not prove that the generated
client excludes credentials.

They are here for a second reason too: the event spine is **raw evidence**. It
records full URLs, and a GET form submission puts every field — including a
password — into the query string. Committing a fixture-derived log makes that
property visible rather than letting it be discovered later on a real portal.

`test_replay.py::test_committed_log_came_from_the_fixture_and_not_a_real_portal`
fails if either file is ever regenerated against a non-loopback host, so a live
session cannot be committed by accident.

## The browser build is part of this baseline

`camoufox_browser_build` is normalised to `<PINNED>` in the snapshot, so the
committed file does not say which browser produced it. It matters, because the
browser is fetched outside `uv.lock` and its behaviour is not stable:

| Re-blessed on | Notable behavioural difference |
|---|---|
| `152.0.4-beta.28` | original baseline |
| `152.0.4-beta.29` | JS worlds isolated; `user_click` 20 → 22 for the same script |

The `user_click` change is the browser's, not the tool's — the same count comes
out of the pre-fix code on the same build. The runtime-probe counts
(`runtime_fetch` 14, `runtime_history` 3) are unchanged across both builds
*because* the probe now installs its patched half in the page's own world;
before that fix, beta.29 produced zero of them.

`scriptscrap.baseline.BROWSER_BUILD` remains `152.0.4-beta.28`: that is the
build the *empirical assumptions* in `diagnostics/probes/` were verified on, and
`hook_timing_probe.py` still fails on beta.29. The doctor reports the mismatch
deliberately. Do not bump it to silence the warning — bump it only after every
probe passes.

## Reviewing a failure

A golden-master failure is a **decision point**, not automatically a bug.

1. Read the unified diff the failure prints. It names the file and field.
2. Decide whether the change is intended.
3. If it is, re-bless the baseline **in the same commit** that causes it, and say
   why in the commit message.
4. If it is not, you have found a regression.

Never re-bless to make a red test green without reading the diff. The targeted
assertions in `test_golden_master.py` exist so that the security guarantees and
the seeded correlation edge cannot be silently discarded by a re-bless.
