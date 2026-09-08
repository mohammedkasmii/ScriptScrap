# Known limitations

What ScriptScrap knows it does not do. Two kinds live in two places:

* **Per-session blind spots** are written into every
  `session_manifest.json` under `known_blind_spots`, because they depend on
  what that session's browser and addons actually did.
* **Standing limitations** are here, because they are true of every session.

If you are judging a capture, read the manifest first: it records the browser
build, the addon configuration, the scope policy and the blind spots that
produced the evidence.

## Standing limitations

### Console output is captured in full and is most of the log

A real capture of a public demo site produced **2,067 `console_message` events
out of 9,255** — 22 % of the log. There is no filter. This is deliberate for
now: a console line is sometimes the only record of an application's own
error handling, and a filter tuned on one application silently drops another's
evidence. It does mean log size is dominated by an application's chattiness
rather than by its behaviour.

*If this becomes a problem:* the filter belongs at capture time with a
`capture_gap` recording what it dropped, never at analysis time.

### Visual traces are large

One session of a public demo site produced **137 MB** of `visual_traces/` —
125 screenshots and 125 HTML snapshots. Screenshots are never exported and
HTML snapshots stay in the local session directory, so this is a disk-space
limitation rather than a safety one.

### The background DOM scanner runs against pages that may close

`sensor_error: background_dom_scanner` appears in capture health when a scan
is in flight as a page closes. This is reported, not hidden: it shows in
`capture_health.sensor_errors`, and analysis raises it as a `warning`-severity
finding. On the reference capture it occurred 12 times.

### Some evidence is read once, at exit

Dropdown catalogues, jQuery handler maps and the legacy named-function hook
buffers are page globals, read once during teardown from the top frame. Every
full page navigation before that point discarded them. The capture records this
as the `runtime_buffers_read_once_at_exit` capture gap rather than presenting
the tail as the whole session.

### Not every response is attributed to a request

On the reference capture: `response_body_unavailable` 55 times, and the
reconciler left 159 of 441 activities unmatched (28 seen only by Playwright,
131 only by the runtime probe). Both numbers are in
`capture_health`, and the difference between the two sensors is the point —
collapsing them would destroy the corroboration the reconciler looks for.

### A session's outcome

`session_manifest.json` records `outcome`: `clean`, `interrupted` (Ctrl-C) or
`failed` (teardown raised). A session killed hard writes no manifest at all,
and the workspace reports `manifest_present: false` rather than rendering an
empty panel.

### The generated Playwright script is unredacted by default

A locator that does not name the real element cannot find it, so
`scriptscrap generate playwright` embeds locators, labels and element text read
off the application. Its header, its `--help` and the command's own output all
say `UNREDACTED`. `--sanitised` produces a shareable variant that removes every
locator carrying application text, marks each removal in place, and refuses to
run rather than pretending to work with selectors that cannot match.

### A shareable export keeps route shapes, authored names and structural locators

Sanitisation is deny-by-default over the model's fields, and three dispositions
deliberately keep application-authored text:

| Disposition | Keeps | Why |
|---|---|---|
| `ROUTE` | route shapes, with identifier-looking segments templated | an export describing an API nobody can find is not an export |
| `NAME` | parameter, header, schema-field and technology names | the vocabulary the application's own developers chose |
| `LOCATOR` | structural selectors (`#id`, `.class`, `[attr="v"]`) | a reader who cannot find the element again cannot check the claim |

Everything else is dropped, bucketed, pseudonymised or checked against a closed
vocabulary. `tests/test_export_leakage_exhaustive.py` derives this exemption
list from the sanitised model rather than hard-coding it, so anything new that
survives is a failure rather than an accepted exception.

## Deferred maintenance

### `ruff format` has not been adopted

`ruff check` is the gate and passes. `ruff format --check` reports **106 files
would be reformatted, 33 already formatted** (measured at the end of the
Phase 2/3 remediation). Adopting it is worth doing and was deliberately kept out of the
Phase 2/3 remediation: a diff that size in the middle of behavioural work makes
the behavioural work unreviewable, and it would rewrite the blame history of
comments that carry the reasoning behind specific decisions.

When it is adopted: one commit, nothing else in flight, `ruff format .` with no
manual edits, the full suite reporting identical counts before and after, and
`ruff format --check .` added to the verification block in `README.md`.

### Capture-health reasons have no machine-readable codes

`HealthAnalyzer` builds `reasons`, `notes` and `blind_spots` as prose
(`health.py:180,237,251,324`). The shared export therefore drops them and keeps
only a count: the export emits a string only when it belongs to a closed
vocabulary declared for that field, and a string built with an f-string has no
such vocabulary to belong to. Giving each one a code alongside the prose -- as
`LocatorCandidate.warning_code` does -- would let a shared dataset say *why* a
sensor was degraded rather than only *that* it was.
