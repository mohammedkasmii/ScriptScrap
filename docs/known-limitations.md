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

### The semantic catalogs record what was USED, not the whole application

The form catalog, the table catalog and the activity segmentation are built
from what the operator actually did. A form control never touched, a table row
never scrolled into an interaction, an activity performed entirely outside the
browser — none of those appear, because none was observed. This is the same
posture as the rest of the tool: absence means *not observed*, never *not
present*. In particular a table's rows are those the operator interacted with
plus the header row, not every row a virtualised grid ever held.

### Activity segmentation is a heuristic interpretation

The split into activities is inferred from idle gaps, form submissions, returns
to a home route and route-section changes. It is an interpretation laid over the
timeline, carries a confidence derived from the boundary evidence, and never
rewrites the ordered log — the workflow and the event log remain the source of
truth. Two unrelated tasks with no idle gap and no route change between them can
land in one segment; a single task interrupted by a long pause can split in two.

### The semantic catalogs are dropped from a shared export

`AnalysisResult.forms`, `.tables` and `.segments` carry application content —
control labels and values, table cell data, route shapes and form ids. The
shared export drops them (deny-by-default, `export/policy.py`), so they are read
from the local session directory. A sanitised projection of each is future work;
until every field is classified, DROP is the safe default.

### IndexedDB values and cached response bodies are inventoried, not read

IndexedDB is inventoried down to database/store names and record counts, and
Cache Storage down to cache names and cached request URLs. The record *values*
and the cached response *bodies* are not read; the capture records
`indexed_db_values_not_captured` / `cache_storage_bodies_not_captured` rather
than implying it saw them. `indexedDB.databases()` also requires an engine that
supports enumeration; where it is unavailable the older `indexed_db_not_captured`
gap is emitted instead.

### JavaScript dialogs cannot capture the employee's real choice

The automation layer intercepts `alert`/`confirm`/`prompt`/`beforeunload`: the
native dialog never reaches the employee, whether or not a handler is registered
(with none, Playwright auto-dismisses). So the capture records the dialog's
type, message and default, plus the recorder's own handling (dismiss, the
no-handler default), and emits a `dialog_choice_unobservable` capture gap. It
never claims the employee accepted or dismissed anything, because that choice is
not observable under automation.

### Drag-and-drop capture is verified only by dispatched events

The probe listens for `dragstart`/`drop`/`dragend` and records source,
destination and file metadata. A real employee's native drag fires trusted
events content-script listeners receive, so it is captured in a live session.
It is NOT possible to verify this through the automated harness: Playwright
cannot drive native HTML5 drag-and-drop on Firefox (its `drag_and_drop` uses
synthetic mouse events that do not start a native drag), and a synthetic
`DragEvent` dispatched from the driver's own world does not reliably reach the
probe. The browser test therefore fires the DragEvent sequence from the page's
own world, which exercises the same listener path; a trusted drag by a human is
believed to work but is not proven in CI.

### An anonymous form's typed values are attributed only coarsely

Form identity is (page, frame/document, form). A form with an id/name is exact;
an anonymous form is separated by its document index and structural path, which
the DOM scan and a submit both carry. An `input`/`change` event on a field of an
anonymous form, however, reports only `form: "(unnamed)"`, so its typed value
cannot be attributed to a *specific* anonymous form and lands in a per-frame
`anon` control group. Anonymous forms stay SEPARATE (the correctness guarantee);
merging their live field values is the part that is coarse.

### A scroll's isTrusted does not distinguish a programmatic scroll

`isTrusted` is recorded on hover, drag and scroll. For drag it is decisive -- a
scripted `DragEvent` is `isTrusted === false`. For scroll it is not: the browser
dispatches the scroll event with `isTrusted === true` even when the scroll
position was set programmatically, so the flag cannot tell a programmatic scroll
from a human one. The value is recorded as-is; the table catalog never claims
"the employee scrolled", only that rows were observed via a scroll.

### A popup closed faster than its first snapshot loses its final state

Coverage snapshots a new page eagerly rather than waiting for the 2-second poll,
so a popup used and closed in a second or two still yields its DOM/form
inventory. A page closed before even that eager snapshot completes emits a
`page_closed_before_capture` gap. Live user actions on it may still have been
captured -- the probe flushes on pagehide -- but that flush races the teardown,
so a value typed and the page closed within a few hundred milliseconds can be
lost; the gap makes the incompleteness explicit rather than silent.

### Popup isolated-world listeners are re-armed, not native

A Camoufox quirk: the context-level init script defines the probe's globals in a
popup or new tab's isolated world, but its DOM listeners do not fire there. The
recorder re-arms the isolated probe in each non-initial page's live document
(at load and on each navigation); the initial page uses the context script,
which works. This is verified against a popup and multiple tabs, but it is a
workaround for a browser behaviour, not a guarantee across every future build.

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
