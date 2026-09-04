# Forensic extension sensor

An optional Firefox WebExtension, loaded into Camoufox only when forensic mode
is enabled. Normal capture never touches it.

## Why an extension at all

Each of these is something neither Playwright nor injected page JavaScript can
do, which is the only reason this exists:

| Observation | Why the other sensors cannot |
|---|---|
| Response **bodies** | `webRequest.filterResponseData` is Firefox-only. Playwright's `response.body()` throws on redirects, evicted bodies, and responses navigated away from. |
| **Script source before parsing** | A function declared and called in the same parse cannot be hooked from injected JS — proven in `diagnostics/probes/hook_timing_probe.py`. Reading the source is the only way to see it. |
| **httpOnly cookies** | Page JavaScript can never read them, by definition. `browser.cookies` can, and gives a change stream rather than snapshots. |
| Repeated **Set-Cookie** headers | `responseHeaders` is a list, so N headers stay N headers instead of collapsing. |
| Requests with **no page-JS surface** | `beacon`, `ping`, prefetch, worker and speculative loads. |

## Design constraints

**MV2, deliberately.** Firefox still supports it, and it keeps a persistent
background page plus blocking `webRequest` — which `filterResponseData`
requires — without MV3's service-worker lifecycle.

**Loaded as an unpacked temporary addon.** Camoufox accepts `addons=[dir]` and
installs through Firefox's temporary-addon path, so no signature is needed and
nothing persists in a profile. The directory is generated per session by
`loader.py` because the extension must be built with the transport port already
baked into `config.js` — a background script takes no arguments.

**Loopback WebSocket transport.** A background page cannot call Python. It can
open a socket to `127.0.0.1`, which is exempt from mixed-content blocking and
unaffected by any page's CSP. Native messaging was rejected: it needs a host
manifest and a Windows registry key written before launch, which is invasive for
a tool whose point is leaving no trace.

## The rules this code must not break

1. **`filterResponseData` always writes the original bytes through, and always
   disconnects.** A filter that throws or forgets to close hangs the request
   *forever* — on a live application someone is using. `ondata` therefore calls
   `filter.write()` before doing anything else, and `onstop` disconnects before
   attempting to report.
2. **Observation only.** Listeners return `{}`; nothing is blocked or modified
   unless source rewriting was separately opted into.
3. **Scope is enforced in the browser.** Out-of-scope traffic is reduced to
   origin plus path *before* it leaves the extension. Third-party query strings
   and bodies never cross the socket.
4. **The sensor does not observe itself.** Its own loopback channel shares a
   host with the target, so every listener skips it. Without that guard the
   extension reports its own evidence stream as application traffic.
5. **Failure is fail-open for the site, fail-loud for the investigation.** A
   sensor problem emits `sensor_error` or `capture_gap` and lets the page carry
   on; it never breaks the application to protect a measurement.

## Files

| File | Role |
|---|---|
| `manifest.json` | MV2 manifest, `<all_urls>` + `webRequestBlocking` + `cookies` |
| `background.js` | all observation; batches evidence over the socket |
| `loader.py` | builds the per-session unpacked directory and `config.js` |
| `transport.py` | loopback WebSocket server that receives batches |

`config.js` is generated, never committed.
