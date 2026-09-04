import asyncio
import contextlib
import hashlib
import json
import platform
import re
import sys
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from camoufox.addons import DefaultAddons
from camoufox.async_api import AsyncCamoufox

# ---------------------------------------------------------------------------
# Event spine (dual-write).
#
# The structures in WebHarvester remain the behavioural authority. Events are
# emitted ALONGSIDE them so the model can be proven against real sessions before
# anything depends on it. The import is defensive: this script must keep working
# when run directly from a bare venv that has camoufox but not the scriptscrap
# package installed. The supported path is `uv run`.
# ---------------------------------------------------------------------------
EV: Any
SENSORS: Any
try:
    from scriptscrap import events as EV
    from scriptscrap import sensors as SENSORS

    EVENTS_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only in a bare venv
    EV = None
    SENSORS = None
    EVENTS_AVAILABLE = False

OUTPUT_DIR = Path("v13_investigation_output")

NOISY_ENDPOINTS = {
    "iadvize.com", "usejimo.com", "iconify.design", "privacy-center.org",
    "error-js", "utilisation-log", "events/log", "dynatrace", "google-analytics"
}

STATIC_MEDIA_EXTENSIONS = {
    ".mp3", ".mp4", ".wav", ".avi", ".mov"
}

CAPTURED_RESOURCE_TYPES = ("xhr", "fetch", "document")

SECURITY_NOTICE = """# Investigation output — handle as sensitive

This directory is an **unredacted capture of an authenticated session**.

It can contain:

- `Authorization` / `Cookie` / CSRF headers for a live session
- full request and response bodies, including personal and business data
- full-page HTML snapshots and screenshots of authenticated pages
- an auto-generated API client

## Rules

1. **Do not commit it.** The repository `.gitignore` covers `*_output/` by
   pattern. Verify with `git check-ignore -v <path>` before any commit.
2. **Do not share it** outside the authorized engagement. A redaction pipeline
   that produces a shareable dataset is planned but does not exist yet.
3. `generated_client.py` contains **no** captured credentials. It reads them
   from `SCRIPTSCRAP_AUTH_HEADERS` / `SCRIPTSCRAP_COOKIE` at runtime.
4. Read `session_manifest.json` first. It records the browser build, the addon
   configuration, the scope policy and the known blind spots that produced this
   evidence.

Deletion is a deliberate operator decision. Nothing here is auto-deleted.
"""

# ============================================================
# CREDENTIAL CLASSIFICATION
# ============================================================
# Header names whose VALUES authenticate the operator's live session. These are
# never written into generated source. The generated client asks for them from
# the environment at runtime instead.
SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "www-authenticate", "authentication",
    "cookie", "set-cookie", "cookie2",
    "x-csrf-token", "csrf-token", "x-csrftoken", "x-xsrf-token", "xsrf-token",
    "x-requestverificationtoken", "__requestverificationtoken",
    "x-api-key", "api-key", "apikey", "x-apikey",
    "x-auth-token", "auth-token", "x-access-token", "access-token",
    "x-session-id", "x-session-token", "session-id",
    "x-amz-security-token", "x-goog-authuser", "x-ms-token",
    # Short field names that the substring rules below cannot safely catch.
    # Exact matches only, so they cannot produce false positives.
    "pw", "pwd", "passwd", "pass",
}

# Substrings that mark a header as credential-bearing even when the exact name
# is portal-specific. Over-blocking here is the safe direction.
SENSITIVE_HEADER_SUBSTRINGS = (
    "auth", "token", "secret", "credential", "session", "cookie",
    "apikey", "api-key", "password", "signature", "assertion",
)


def is_sensitive_header(name: str) -> bool:
    """True if this header's value may authenticate the captured session."""
    lowered = name.lower().lstrip(":")
    if lowered in SENSITIVE_HEADERS:
        return True
    return any(marker in lowered for marker in SENSITIVE_HEADER_SUBSTRINGS)


# ============================================================
# INVESTIGATION SCOPE
# ============================================================
class InvestigationScope:
    """The engagement boundary, enforced at capture time.

    In scope  -> full capture (headers, bodies, DOM, screenshots).
    Out of scope -> METADATA ONLY: method, host, path, status. No headers, no
    bodies, no query strings, no screenshots. Unrelated browsing in the same
    browser therefore cannot produce a sensitive capture.
    """

    def __init__(self, target_url: str, extra_domains=()):
        self.roots: set[str] = set()
        host = (urlparse(target_url).hostname or "").lower().strip(".")
        if host:
            self.roots.add(host)
        for domain in extra_domains:
            cleaned = domain.strip().lower().lstrip("*").strip(".")
            if cleaned:
                self.roots.add(cleaned)

    def contains_host(self, host: str | None) -> bool:
        if not host:
            return False
        host = host.lower().strip(".")
        return any(host == root or host.endswith("." + root) for root in self.roots)

    def contains(self, url: str) -> bool:
        return self.contains_host(urlparse(url).hostname)

    def as_dict(self) -> dict:
        return {
            "in_scope_roots": sorted(self.roots),
            "match_rule": "exact host or any subdomain of a root",
            "out_of_scope_policy": "metadata_only",
            "out_of_scope_retained": ["method", "host", "path", "status", "count"],
            "out_of_scope_discarded": [
                "request headers", "request bodies", "response bodies",
                "query strings", "screenshots", "HTML snapshots", "DOM structure",
            ],
        }


def _split_captured_url(url: str) -> tuple[str, list[str], list[str]]:
    """Split a captured URL into an endpoint and its parameter NAMES.

    Query-string values are discarded, never emitted into generated source. A
    GET form submission puts every field in the query string, so a captured URL
    routinely carries passwords, CSRF tokens and personal data.

    Returns (endpoint_url_without_query, all_param_names, credential_param_names).
    """
    parsed = urlparse(url)
    endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    names: list[str] = []
    for pair in parsed.query.split("&"):
        if not pair:
            continue
        name = pair.split("=", 1)[0]
        if name and name not in names:
            names.append(name)
    sensitive = [n for n in names if is_sensitive_header(n)]
    return endpoint, names, sensitive


def _frame_id_of(frame) -> str | None:
    """A stable, human-meaningful frame label.

    Playwright exposes no durable frame id, and an identity-based registry would
    make golden-master runs depend on object lifetimes. Deriving the label from
    the frame tree keeps it deterministic. Full frame identity is a later
    milestone; this is enough to attribute events during M1.
    """
    if frame is None:
        return None
    try:
        if frame.parent_frame is None:
            return "main"
        return frame.name or (urlparse(frame.url).path or "frame")
    except Exception:
        return None


def _frame_id(request) -> str | None:
    """Frame of a request. Playwright raises for service-worker-origin requests."""
    try:
        return _frame_id_of(request.frame)
    except Exception:
        return None


def prompt_for_scope(target_url: str) -> InvestigationScope:
    host = urlparse(target_url).hostname or "?"
    print(f"\n[SCOPE] Target host ....... {host}")
    print("[SCOPE] In scope by default: this host and its subdomains.")
    print("[SCOPE] Anything else is recorded as METADATA ONLY — no headers,")
    print("[SCOPE] no bodies, no query strings, no screenshots.")
    raw = input("[SCOPE] Additional in-scope domains (comma-separated, ENTER for none): ")
    extras = [part for part in (chunk.strip() for chunk in raw.split(",")) if part]
    scope = InvestigationScope(target_url, extras)
    print(f"[SCOPE] Active scope ...... {', '.join(sorted(scope.roots)) or '(none)'}\n")
    return scope

# ============================================================
# ACTIVE INTROSPECTION INJECTIONS
# ============================================================
HOOK_AND_OBSERVER_JS = """
(() => {
    window.functionHookLogs = [];
    window.domMutations = [];

    // 1. Time-Travel DOM Mutation Observer
    window.addEventListener('DOMContentLoaded', () => {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((m) => {
                if (m.target && (m.target.id || m.target.className)) {
                    window.domMutations.push({
                        time: Date.now(),
                        type: m.type,
                        targetId: m.target.id || m.target.className || m.target.tagName,
                        addedNodes: m.addedNodes ? m.addedNodes.length : 0
                    });
                }
            });
        });
        observer.observe(document.body, { childList: true, subtree: true, attributes: true });
    });

    // 2. Monkey Patching MCMA Legacy Math Formulas
    function hookMCMAFunction(funcName) {
        if (typeof window[funcName] === 'function' && !window[funcName].isHooked) {
            const original = window[funcName];
            window[funcName] = function(...args) {
                const result = original.apply(this, args);
                window.functionHookLogs.push({
                    function: funcName,
                    arguments: args,
                    returned: result,
                    timestamp: Date.now()
                });
                return result;
            };
            window[funcName].isHooked = true;
        }
    }

    // Interval to hook functions even if loaded later via AJAX
    setInterval(() => {
        ['DevisCalculerMontantCharge', 'CalculerMntArrete', 'CalculerMontantVetuste', 'ValiderDevis', 'CalculerMontantDommage'].forEach(hookMCMAFunction);
    }, 2000);
})();
"""

# ============================================================
# NON-DESTRUCTIVE VISUAL SNAPSHOT
# ============================================================
# Builds an offline HTML snapshot without touching the live page.
#
#   observe live page -> deep-clone -> transform the CLONE -> return string
#
# Two rules this must never break:
#   1. No mutation of the live document. An investigator that edits the page an
#      employee is working in can break a real business workflow.
#   2. No page-originated network requests. The previous implementation called
#      fetch() on every stylesheet, and those requests were then captured as if
#      they were application traffic -- the observer polluting its own evidence.
#
# Stylesheets are therefore read from document.styleSheets, which the browser
# has ALREADY loaded, instead of being re-fetched. Cross-origin sheets throw on
# .cssRules access; those keep their <link> in the snapshot and are counted as
# not inlined, so a partial snapshot is reported honestly rather than faked.
#
# The whole function is synchronous, so the page cannot change mid-capture.
NON_DESTRUCTIVE_SNAPSHOT_JS = """
() => {
    const report = {
        elements: 0, controls_serialized: 0,
        sheets_inlined: 0, sheets_not_readable: 0,
        index_mismatch: false
    };

    // 1. Deep copy. Everything after this point mutates only the detached clone.
    const clone = document.documentElement.cloneNode(true);

    // cloneNode(true) is a faithful copy, so a document-order walk of each tree
    // yields the same elements at the same indices.
    const liveEls = [document.documentElement].concat(
        Array.from(document.documentElement.querySelectorAll('*')));
    const cloneEls = [clone].concat(Array.from(clone.querySelectorAll('*')));
    report.elements = liveEls.length;

    if (cloneEls.length !== liveEls.length) {
        // Should not happen; bail out with a plain clone rather than corrupt it.
        report.index_mismatch = true;
        return { html: clone.outerHTML, report: report };
    }

    // 2. Serialize live control state into the clone.
    //    Live properties (el.value, el.checked, option.selected) are not
    //    reflected as attributes, so cloneNode alone loses what the operator
    //    typed. We copy them onto the COPY.
    for (let i = 0; i < liveEls.length; i++) {
        const live = liveEls[i];
        const copy = cloneEls[i];
        const tag = live.tagName;

        if (tag === 'INPUT') {
            const type = (live.type || '').toLowerCase();
            if (type === 'checkbox' || type === 'radio') {
                if (live.checked) copy.setAttribute('checked', 'checked');
                else copy.removeAttribute('checked');
            } else if (type !== 'password') {
                copy.setAttribute('value', live.value);
            } else {
                copy.setAttribute('value', '');
            }
            report.controls_serialized++;
        } else if (tag === 'TEXTAREA') {
            copy.textContent = live.value;
            report.controls_serialized++;
        } else if (tag === 'OPTION') {
            if (live.selected) copy.setAttribute('selected', 'selected');
            else copy.removeAttribute('selected');
            report.controls_serialized++;
        }
    }

    // 3. Inline stylesheets the browser already holds. No network traffic.
    const sheetByOwner = new Map();
    for (const sheet of Array.from(document.styleSheets)) {
        if (sheet.ownerNode) sheetByOwner.set(sheet.ownerNode, sheet);
    }

    for (let i = 0; i < liveEls.length; i++) {
        const live = liveEls[i];
        if (live.tagName !== 'LINK') continue;
        if (!(live.getAttribute('rel') || '').toLowerCase().includes('stylesheet')) continue;

        const sheet = sheetByOwner.get(live);
        let rules = null;
        try {
            rules = sheet ? sheet.cssRules : null;   // throws for cross-origin
        } catch (e) {
            rules = null;
        }
        if (!rules) {
            report.sheets_not_readable++;           // keep the <link>: honest partial
            continue;
        }

        let css = Array.from(rules).map(r => r.cssText).join('\\n');
        try {
            const base = new URL(sheet.href || document.baseURI, document.baseURI);
            css = css.replace(
                /url\\((?!['"]?(?:data:|https:|http:|#))['"]?([^'"\\)]*)['"]?\\)/gi,
                (m, p) => {
                    try { return "url('" + new URL(p, base).href + "')"; }
                    catch (e) { return m; }
                });
        } catch (e) { /* keep css as-is */ }

        const style = document.createElement('style');
        style.setAttribute('data-scriptscrap-inlined-from', sheet.href || '');
        style.textContent = css;
        cloneEls[i].replaceWith(style);             // detached clone only
        report.sheets_inlined++;
    }

    // 4. <base> so relative URLs still resolve when the file is opened offline.
    //    The query string is stripped: relative-URL resolution ignores it, but a
    //    GET form submission puts every field there, so keeping it would write
    //    passwords and CSRF tokens into the snapshot.
    const head = clone.querySelector('head');
    if (head && !head.querySelector('base')) {
        let baseHref = document.baseURI;
        try {
            const u = new URL(document.baseURI);
            u.search = '';
            u.hash = '';
            baseHref = u.href;
        } catch (e) { /* keep baseURI as-is */ }
        const base = document.createElement('base');
        base.setAttribute('href', baseHref);
        head.insertBefore(base, head.firstChild);
    }

    return { html: clone.outerHTML, report: report };
}
"""

DOM_PROBE_JS = """
(() => {
    function querySelectorAllDeep(selector, root = document) {
        let results = Array.from(root.querySelectorAll(selector));
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT, null, false);
        while (walker.nextNode()) {
            const node = walker.currentNode;
            if (node.shadowRoot) {
                results = results.concat(querySelectorAllDeep(selector, node.shadowRoot));
            }
        }
        return results;
    }

    const parseElement = (el) => {
        const tag = el.tagName.toLowerCase();
        const type = (el.type || "").toLowerCase();
        const base = {
            tag, type,
            name: el.name || el.getAttribute("name") || null,
            id: el.id || null,
            placeholder: el.placeholder || el.getAttribute("placeholder") || null,
        };

        if (tag === "select") {
            base.options = Array.from(el.options).map(o => ({
                value: o.value, text: (o.text || "").trim()
            }));
        } else if (["checkbox", "radio"].includes(type)) {
            base.value = el.value;
            base.checked = el.checked;
        } else if (el.value !== undefined) {
            base.value = el.value;
        }
        return base;
    };

    const forms = querySelectorAllDeep("form").map((form, idx) => ({
        index: idx,
        id: form.id || null,
        action: form.action || window.location.href,
        method: (form.method || "GET").toUpperCase(),
        fields: querySelectorAllDeep("input, select, textarea, button", form).map(parseElement)
    }));

    return { forms };
})();
"""

class WebHarvester:
    def __init__(self, target_url: str, scope: InvestigationScope, session_id: str | None = None):
        self.target_url = target_url
        self.scope = scope
        self.endpoints = {}
        self.network_log = []
        self.dom_snapshots = []
        self.value_origins = {}
        self.value_dependencies = []
        self.openapi_paths = {}

        # Metadata-only record of everything outside the engagement boundary.
        self.out_of_scope = {}
        self.skipped_visual_captures = 0

        # Snapshot fidelity accounting: a partial offline snapshot must be
        # visible as partial, not silently pass for complete.
        self.snapshot_stats = {
            "snapshots": 0,
            "sheets_inlined": 0,
            "sheets_not_readable": 0,
            "controls_serialized": 0,
            "index_mismatches": 0,
            "failures": 0,
            "last_error": None,
        }

        # --- observation sensors (M2) --------------------------------------
        # Stable page/frame identity plus the sensors that cover what the
        # network+DOM capture above cannot see.
        self.registry = SENSORS.PageRegistry() if EVENTS_AVAILABLE else None
        self.lifecycle_sensor = None
        self.runtime_sensor = None
        self.websocket_sensor = None
        self.storage_sensor = None
        self.graphql_operations = {}
        self.launch_options_record = {}
        self.started_at = datetime.now(UTC)

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        self.visual_dir = OUTPUT_DIR / "visual_traces"
        self.visual_dir.mkdir(parents=True, exist_ok=True)
        self.step_counter = 1

        # --- event spine, dual-write ---------------------------------------
        # Written incrementally so a crash cannot destroy the session history.
        self.session_id = session_id or datetime.now(UTC).strftime("sess-%Y%m%d-%H%M%S")
        self.event_log = None
        if EVENTS_AVAILABLE:
            try:
                self.event_log = EV.EventLog(OUTPUT_DIR / "events.jsonl", self.session_id)
                self.event_log.emit(
                    EV.Source.ENGINE,
                    EV.EventType.SESSION_START,
                    target_url=target_url,
                    scope=scope.as_dict(),
                )
            except OSError as exc:
                print(f"[events] disabled: {exc}")
                self.event_log = None

    # ==========================================
    # EVENT SPINE (dual-write)
    # ==========================================
    def emit_event(self, source, event_type, **payload):
        """Emit one event. A no-op when the spine is unavailable."""
        if self.event_log is None:
            return None
        return self.event_log.emit(source, event_type, **payload)

    def emit_sensor_error(self, where: str, exc: BaseException, **extra):
        """ScriptScrap failed to observe something -- not the same as nothing happening."""
        if self.event_log is None:
            return None
        return self.event_log.sensor_error(EV.Source.PLAYWRIGHT, where, exc, **extra)

    def emit_capture_gap(self, reason: str, **extra):
        if self.event_log is None:
            return None
        return self.event_log.capture_gap(EV.Source.ENGINE, reason, **extra)

    def close_events(self):
        if self.event_log is None:
            return
        self.event_log.emit(
            EV.Source.ENGINE,
            EV.EventType.SESSION_END,
            counters={
                "endpoints_in_scope": len(self.endpoints),
                "network_events": len(self.network_log),
                "out_of_scope_endpoints": len(self.out_of_scope),
            },
        )
        self.event_log.close()

    # ==========================================
    # SCOPE ENFORCEMENT
    # ==========================================
    def _frame_of(self, request):
        """Stable frame id for a request, via the registry when available."""
        if self.registry is not None:
            return self.registry.frame_of_request(request)
        return _frame_id(request)

    def _record_out_of_scope(self, method: str, url: str, status: int | None = None):
        """Retain that a request happened, and nothing that could be sensitive.

        Deliberately drops the query string: it routinely carries identifiers
        and PII on legacy portals.
        """
        parsed = urlparse(url)
        key = f"{method} {parsed.hostname or '?'}{parsed.path or '/'}"
        entry = self.out_of_scope.setdefault(key, {
            "method": method,
            "host": parsed.hostname,
            "path": parsed.path or "/",
            "count": 0,
            "statuses": set(),
            "first_seen": datetime.now(UTC).isoformat(),
        })
        if status is None:
            entry["count"] += 1
        else:
            entry["statuses"].add(status)

    async def route_filter(self, route):
        """Media-blocking route handler. NOT installed by default any more.

        Retained so the behaviour can be re-enabled deliberately, but blanket
        `page.route("**/*")` is no longer used: routing every request through
        Python disables the HTTP cache for routed requests and adds a round trip
        to each one, which changes both timing and cache behaviour. That is a
        large distortion to pay for aborting five media extensions.

        Prefer observing everything. Noise classification belongs to analysis.
        """
        url = route.request.url.lower()
        parsed = urlparse(url)
        if any(parsed.path.endswith(ext) for ext in STATIC_MEDIA_EXTENSIONS):
            await route.abort()
            return
        await route.continue_()

    async def capture_visual_state(self, page):
        """Captures full-page screenshots and fully-styled offline HTML."""
        # Never screenshot or snapshot a page outside the engagement boundary.
        if not self.scope.contains(page.url):
            self.skipped_visual_captures += 1
            self.emit_capture_gap(
                "visual_capture_out_of_scope",
                host=urlparse(page.url).hostname,
                withheld=["screenshot", "html_snapshot"],
            )
            return

        timestamp = datetime.now().strftime("%H%M%S")
        file_prefix = self.visual_dir / f"step_{self.step_counter:03d}_{timestamp}"
        
        try:
            # 1. Screenshot.
            #    caret="initial" is required for non-destructiveness: Playwright's
            #    default caret="hide" sets and then clears an inline caret-color on
            #    input elements, leaving a residual style="" attribute on the live
            #    page. It is cosmetic, but it is still the investigator editing the
            #    application. A visible text caret in the image costs us nothing.
            await page.screenshot(path=f"{file_prefix}.png", full_page=True, caret="initial")

            # 2. Build the offline HTML from a detached clone. The live page is
            #    never modified and no page-side network request is issued.
            result = await page.evaluate(NON_DESTRUCTIVE_SNAPSHOT_JS)

            Path(f"{file_prefix}.html").write_text(result["html"], encoding="utf-8")

            # 3. Account for what could not be inlined, so a partial snapshot is
            #    visible in the manifest instead of silently looking complete.
            report = result.get("report", {})
            self.snapshot_stats["snapshots"] += 1
            self.snapshot_stats["sheets_inlined"] += report.get("sheets_inlined", 0)
            self.snapshot_stats["sheets_not_readable"] += report.get("sheets_not_readable", 0)
            self.snapshot_stats["controls_serialized"] += report.get("controls_serialized", 0)
            if report.get("index_mismatch"):
                self.snapshot_stats["index_mismatches"] += 1

            self.emit_event(
                EV.Source.ENGINE,
                EV.EventType.SCREENSHOT,
                url=page.url,
                step=self.step_counter,
                artifact=Path(f"{file_prefix}.png").name,
            )
            self.emit_event(
                EV.Source.ENGINE,
                EV.EventType.HTML_SNAPSHOT,
                url=page.url,
                step=self.step_counter,
                artifact=Path(f"{file_prefix}.html").name,
                bytes=len(result["html"]),
                **report,
            )
            if report.get("sheets_not_readable"):
                self.emit_capture_gap(
                    "stylesheet_not_readable",
                    url=page.url,
                    count=report["sheets_not_readable"],
                    note="cross-origin sheet; <link> retained, snapshot is partial",
                )

            self.step_counter += 1

        except Exception as exc:
            # Transient failures are expected when the page navigates mid-capture,
            # but they must be counted rather than silently swallowed.
            self.snapshot_stats["failures"] += 1
            self.snapshot_stats["last_error"] = f"{type(exc).__name__}: {exc}"
            self.emit_sensor_error("capture_visual_state", exc, url=page.url)

    async def handle_request(self, request):
        if request.resource_type in CAPTURED_RESOURCE_TYPES and request.method != "OPTIONS":
            url = request.url
            method = request.method.upper()

            if not self.scope.contains(url):
                self._record_out_of_scope(method, url)
                parsed = urlparse(url)
                self.emit_capture_gap(
                    "out_of_scope",
                    method=method,
                    host=parsed.hostname,
                    path=parsed.path or "/",
                    withheld=["headers", "body", "query"],
                )
                return

            if any(noise in url for noise in NOISY_ENDPOINTS):
                self.emit_capture_gap(
                    "noisy_endpoint_dropped_at_capture",
                    method=method,
                    url=url,
                    note="matched NOISY_ENDPOINTS; not recoverable from this session",
                )
                return

            headers = await request.all_headers()
            post_data = request.post_data
            parsed_json = None
            
            if post_data:
                # A non-JSON body is normal (forms, multipart), not a failure.
                with contextlib.suppress(ValueError):
                    parsed_json = json.loads(post_data)

            url_path = urlparse(url).path or "/"
            key = (method, url_path)
            
            if key not in self.endpoints:
                self.endpoints[key] = {
                    "method": method, 
                    "url": url,
                    "headers": headers, 
                    "sample_payloads": [], 
                    "statuses": set(),
                    "response_samples": []
                }

            if parsed_json and len(self.endpoints[key]["sample_payloads"]) < 2:
                self.endpoints[key]["sample_payloads"].append(parsed_json)
            elif post_data and not parsed_json and len(self.endpoints[key]["sample_payloads"]) < 2:
                self.endpoints[key]["sample_payloads"].append(post_data) # Capture raw forms/multipart

            self.network_log.append({
                "time": datetime.now().isoformat(), 
                "method": method,
                "url": url, 
                "headers": headers,
                "body": parsed_json or post_data
            })
            
            print(f"[API ->] {method:6} {url_path}")

            if isinstance(parsed_json, (dict, list)):
                self._correlate_dependencies(parsed_json, method, url_path)

            self._build_openapi_request(method, url_path, parsed_json or post_data)

            # GraphQL collapses an entire API onto one URL, so the operation --
            # not the path -- is the endpoint identity worth recording.
            graphql = None
            if EVENTS_AVAILABLE:
                graphql = SENSORS.describe_graphql(url, parsed_json)
                if graphql:
                    label = SENSORS.operation_label(graphql)
                    if label:
                        self.graphql_operations.setdefault(url_path, set()).add(label)
                        print(f"[GQL ->] {label}")

            self.emit_event(
                EV.Source.PLAYWRIGHT,
                EV.EventType.HTTP_REQUEST,
                frame_id=self._frame_of(request),
                method=method,
                url=url,
                path=url_path,
                resource_type=request.resource_type,
                is_navigation=request.is_navigation_request(),
                header_names=sorted(headers),
                credential_header_names=sorted(h for h in headers if is_sensitive_header(h)),
                body=parsed_json if parsed_json is not None else post_data,
                body_present=post_data is not None,
                graphql=graphql,
            )

    async def handle_response(self, response):
        req = response.request
        if req.resource_type in CAPTURED_RESOURCE_TYPES and req.method != "OPTIONS":
            # Out of scope: record the status code, never read the body.
            if not self.scope.contains(req.url):
                self._record_out_of_scope(req.method.upper(), req.url, status=response.status)
                return

            url_path = urlparse(req.url).path or "/"
            key = (req.method.upper(), url_path)

            if key in self.endpoints:
                self.endpoints[key]["statuses"].add(response.status)

            body_for_openapi = None
            body_kind = None
            try:
                resp_text = await response.text()
                try:
                    data = json.loads(resp_text)
                    body_kind = "json"
                    body_for_openapi = data
                    self._map_response_tokens(data, req.method.upper(), url_path)

                    if len(self.endpoints.get(key, {}).get("response_samples", [])) < 2:
                        self.endpoints[key]["response_samples"].append(data)
                except json.JSONDecodeError:
                    body_kind = "text"
                    body_for_openapi = resp_text[:500]
                    if len(self.endpoints.get(key, {}).get("response_samples", [])) < 1:
                        self.endpoints[key]["response_samples"].append(resp_text[:500] + "...")

                self._build_openapi_response(
                    req.method.upper(), url_path, response.status, body_for_openapi)
            except Exception as exc:
                # Playwright throws for redirects, evicted bodies, and bodies read
                # after navigation. That is a hole in the evidence, not a non-event.
                self.emit_capture_gap(
                    "response_body_unavailable",
                    method=req.method.upper(),
                    url=req.url,
                    status=response.status,
                    error_type=type(exc).__name__,
                    error=str(exc),
                )

            self.emit_event(
                EV.Source.PLAYWRIGHT,
                EV.EventType.HTTP_RESPONSE,
                frame_id=self._frame_of(req),
                method=req.method.upper(),
                url=req.url,
                path=url_path,
                status=response.status,
                body_kind=body_kind,
                body=body_for_openapi,
            )

    async def handle_request_failed(self, request):
        """A request the browser started but never completed.

        Previously invisible. A blocked or aborted request looks identical to
        'the application never made one' unless it is recorded.
        """
        if request.resource_type not in CAPTURED_RESOURCE_TYPES:
            return
        if not self.scope.contains(request.url):
            return
        self.emit_event(
            EV.Source.PLAYWRIGHT,
            EV.EventType.HTTP_FAILED,
            frame_id=self._frame_of(request),
            method=request.method.upper(),
            url=request.url,
            resource_type=request.resource_type,
            failure=request.failure,
        )

    async def handle_frame_navigated(self, frame):
        if not self.scope.contains(frame.url):
            return
        self.emit_event(
            EV.Source.PLAYWRIGHT,
            EV.EventType.FRAME_NAVIGATED,
            frame_id=_frame_id_of(frame),
            url=frame.url,
            is_main_frame=frame.parent_frame is None,
        )

    # ==========================================
    # DATA CORRELATION & OPENAPI
    # ==========================================
    def _map_response_tokens(self, data, method, path, prefix=""):
        if isinstance(data, dict):
            for k, v in data.items(): 
                self._map_response_tokens(v, method, path, f"{prefix}.{k}" if prefix else str(k))
        elif isinstance(data, list):
            for i, v in enumerate(data[:10]): 
                self._map_response_tokens(v, method, path, f"{prefix}[{i}]")
        elif isinstance(data, (str, int)) and not isinstance(data, bool):
            val = str(data)
            if 3 <= len(val) <= 120:
                # Index key for value-propagation lookup, not a security primitive.
                h = hashlib.sha1(  # noqa: S324
                    val.encode("utf-8", errors="ignore"), usedforsecurity=False
                ).hexdigest()
                self.value_origins[h] = {"origin_endpoint": f"{method} {path}", "field": prefix}

    def _correlate_dependencies(self, data, method, path, prefix=""):
        if isinstance(data, dict):
            for k, v in data.items(): 
                self._correlate_dependencies(v, method, path, f"{prefix}.{k}" if prefix else str(k))
        elif isinstance(data, list):
            for i, v in enumerate(data[:10]): 
                self._correlate_dependencies(v, method, path, f"{prefix}[{i}]")
        elif isinstance(data, (str, int)) and not isinstance(data, bool):
            # Must match the digest used by _map_response_tokens.
            h = hashlib.sha1(  # noqa: S324
                str(data).encode("utf-8", errors="ignore"), usedforsecurity=False
            ).hexdigest()
            origin = self.value_origins.get(h)
            if origin:
                link = {"source": origin, "consumer": {"endpoint": f"{method} {path}", "field": prefix}}
                if link not in self.value_dependencies:
                    self.value_dependencies.append(link)

    def _build_openapi_request(self, method, path, payload):
        if path not in self.openapi_paths:
            self.openapi_paths[path] = {}
        
        m_lower = method.lower()
        if m_lower not in self.openapi_paths[path]:
            self.openapi_paths[path][m_lower] = {
                "summary": f"Auto-captured {path}",
                "responses": {}
            }
            
        if payload:
            content_type = "application/json" if isinstance(payload, (dict, list)) else "application/x-www-form-urlencoded"
            self.openapi_paths[path][m_lower]["requestBody"] = {
                "content": {
                    content_type: {
                        "schema": {"type": "object"},
                        "example": payload
                    }
                }
            }

    def _build_openapi_response(self, method, path, status, payload):
        m_lower = method.lower()
        if path in self.openapi_paths and m_lower in self.openapi_paths[path]:
            content_type = "application/json" if isinstance(payload, (dict, list)) else "text/html"
            self.openapi_paths[path][m_lower]["responses"][str(status)] = {
                "description": "Auto-captured response",
                "content": {
                    content_type: {
                        "example": payload
                    }
                }
            }

    # ==========================================
    # FINAL EXPORT ENGINES
    # ==========================================
    async def scan_all_frames(self, page):
        if not self.scope.contains(page.url):
            return

        results = []
        for frame in page.frames:
            # A frame may be third-party even when the top document is in scope.
            if not self.scope.contains(frame.url):
                self.emit_capture_gap(
                    "frame_out_of_scope",
                    host=urlparse(frame.url).hostname,
                    frame_id=_frame_id_of(frame),
                )
                continue
            try:
                dom = await frame.evaluate(DOM_PROBE_JS)
                results.append({"frame_url": frame.url, "data": dom})
            except Exception as exc:
                # A frame we could not read is a hole, not an empty frame.
                self.emit_sensor_error(
                    "scan_all_frames", exc, frame_id=_frame_id_of(frame), url=frame.url)

        self.dom_snapshots.append({"time": datetime.now().isoformat(), "frames": results})
        self.emit_event(
            EV.Source.ENGINE,
            EV.EventType.DOM_SNAPSHOT,
            url=page.url,
            frames_captured=len(results),
            frames_total=len(page.frames),
            forms=sum(len(r["data"].get("forms", [])) for r in results),
        )

    async def extract_active_introspection(self, page):
        """Pulls Hooks, Dropdowns, and jQuery events before closing."""
        # Drain anything the probe still holds, and take a final state snapshot,
        # before the page is torn down.
        if self.runtime_sensor is not None:
            await self.runtime_sensor.drain(page)
        if self.storage_sensor is not None:
            await self.storage_sensor.snapshot(page, reason="session_end")

        print("\n[*] Dumping Dropdown Catalogs & jQuery Events...")
        
        self.catalogs = await page.evaluate("""() => {
            let dict = {};
            document.querySelectorAll('select').forEach(sel => {
                let options = [];
                sel.querySelectorAll('option').forEach(opt => {
                    options.push({id: opt.value, label: opt.innerText.trim()});
                });
                if(sel.id || sel.name) dict[sel.id || sel.name] = options;
            });
            return dict;
        }""")

        self.jquery_events = await page.evaluate("""() => {
            let eventsMap = {};
            if (window.jQuery) {
                window.jQuery('*').each(function() {
                    let ev_data = window.jQuery._data(this, 'events');
                    if (ev_data) {
                        let id = this.id ? '#' + this.id : (this.className ? '.' + this.className : this.tagName);
                        eventsMap[id] = Object.keys(ev_data);
                    }
                });
            }
            return eventsMap;
        }""")

        self.js_hooks = await page.evaluate("window.functionHookLogs || []")
        self.mutations = await page.evaluate("window.domMutations || []")

        self.emit_event(
            EV.Source.RUNTIME,
            EV.EventType.RUNTIME_HOOKS,
            url=page.url,
            hook_calls=len(self.js_hooks),
            functions=sorted({h.get("function") for h in self.js_hooks if h.get("function")}),
            dropdown_catalogs=sorted(self.catalogs),
            jquery_bound_selectors=sorted(self.jquery_events),
            # The legacy MutationObserver's tail, summarised. Incremental
            # mutations now come from the runtime probe as dom_mutation events;
            # this stays folded in here so the two are never confused.
            legacy_mutation_count=len(self.mutations),
            legacy_mutation_types=sorted(
                {m.get("type") for m in self.mutations if m.get("type")}
            ),
        )
        # These buffers live in page memory and are read only here, so every full
        # navigation before this point discarded them. Record that limitation in
        # the evidence rather than presenting the tail as the whole session.
        self.emit_capture_gap(
            "runtime_buffers_read_once_at_exit",
            note=(
                "window.functionHookLogs / window.domMutations are wiped by every "
                "full page navigation; only the final document's buffers are here"
            ),
        )

    def generate_httpx_code(self) -> str:
        """Generate an API client that contains NO captured credentials.

        Session-authenticating headers are recorded by NAME ONLY so the caller
        knows what to supply, and are read from the environment at runtime.
        TLS verification is never disabled.
        """
        observed_credential_headers: set[str] = set()
        for meta in self.endpoints.values():
            for name in meta["headers"]:
                if is_sensitive_header(name):
                    observed_credential_headers.add(name.lower().lstrip(":"))

        cred_list = "\n".join(f"    - {name}" for name in sorted(observed_credential_headers)) \
            or "    (none observed)"

        preamble = f'''"""Auto-generated API client for {self.target_url}

GENERATED FROM A CAPTURED SESSION — DO NOT COMMIT.

This client deliberately contains NO captured credentials. The investigator
observed these credential-bearing headers, by name only:
{cred_list}

Supply them at runtime:

    SCRIPTSCRAP_AUTH_HEADERS   JSON object of header name -> value
                               e.g. {{"authorization": "Bearer ..."}}
    SCRIPTSCRAP_COOKIE         raw Cookie header value
    SCRIPTSCRAP_CA_BUNDLE      path to a CA bundle, if the portal uses a
                               private/corporate CA

Captured example request bodies are NOT embedded here either. Look them up in
mcma_openapi_spec.json in this directory, and pass one as `payload`.
"""
import asyncio  # noqa: F401  (for callers driving these coroutines)
import json
import os

import httpx


def _verify():
    """TLS verification is always on. A private CA is supplied by path."""
    return os.environ.get("SCRIPTSCRAP_CA_BUNDLE") or True


def _auth_headers() -> dict:
    """Session credentials, from the environment — never from capture."""
    headers = {{}}
    raw = os.environ.get("SCRIPTSCRAP_AUTH_HEADERS")
    if raw:
        headers.update(json.loads(raw))
    cookie = os.environ.get("SCRIPTSCRAP_COOKIE")
    if cookie:
        headers["cookie"] = cookie
    if not headers:
        raise RuntimeError(
            "No credentials supplied. Set SCRIPTSCRAP_AUTH_HEADERS and/or "
            "SCRIPTSCRAP_COOKIE. This client intentionally does not embed the "
            "session credentials that were captured during the investigation."
        )
    return headers
'''

        code_blocks = [preamble]
        used_names: dict[str, int] = {}

        for idx, ((method, path), meta) in enumerate(self.endpoints.items()):
            base_name = re.sub(r"[^a-zA-Z0-9_]+", "_", f"{method.lower()}_{path.strip('/')}") or f"req_{idx}"
            # Distinct endpoints must not silently shadow one another.
            count = used_names.get(base_name, 0)
            used_names[base_name] = count + 1
            fn_name = base_name if count == 0 else f"{base_name}__{count + 1}"

            safe_headers = {
                k: v for k, v in meta["headers"].items()
                if not k.startswith(":")
                and k.lower() not in ("content-length", "host")
                and not is_sensitive_header(k)
            }

            # A GET form submission puts every field in the query string, so the
            # captured URL can carry passwords, CSRF tokens and personal data.
            # Emit the endpoint, never the captured values: keep scheme/host/path
            # and document the parameter NAMES so the caller knows what to pass.
            endpoint_url, param_names, sensitive_params = _split_captured_url(meta["url"])
            observed_credential_headers.update(sensitive_params)

            param_doc = ""
            if param_names:
                param_doc = (
                    f"\n\n    Observed query parameters (names only, values not retained):"
                    f"\n        {', '.join(param_names)}"
                )
                if sensitive_params:
                    param_doc += (
                        f"\n    Credential-shaped, must be supplied by the caller:"
                        f"\n        {', '.join(sensitive_params)}"
                    )

            fn = f'''
async def {fn_name}(payload: dict = None, params: dict = None, custom_headers: dict = None):
    """{method} {path}  ·  observed statuses: {sorted(meta["statuses"]) or "none"}{param_doc}
    """
    url = "{endpoint_url}"
    headers = {json.dumps(safe_headers, indent=4)}
    headers.update(_auth_headers())
    if custom_headers:
        headers.update(custom_headers)
    async with httpx.AsyncClient(verify=_verify()) as client:
        res = await client.{method.lower()}(url, headers=headers, params=params, json=payload)
        return res.json() if "application/json" in res.headers.get("content-type", "") else res.text
'''
            code_blocks.append(fn.strip() + "\n")
        return "\n".join(code_blocks)

    # ==========================================
    # SESSION MANIFEST
    # ==========================================
    def record_launch_options(self, options: dict):
        """Store a JSON-safe copy of exactly what the browser was launched with."""
        self.launch_options_record = {
            key: ([getattr(v, "name", str(v)) for v in value]
                  if isinstance(value, (list, tuple)) else value)
            for key, value in options.items()
        }

    def build_manifest(self) -> dict:
        def _v(name):
            try:
                return pkg_version(name)
            except PackageNotFoundError:
                return None

        try:
            from camoufox.pkgman import installed_verstr
            browser_build = installed_verstr()
        except Exception as exc:
            browser_build = f"unavailable: {exc}"

        return {
            "schema": "scriptscrap/session-manifest/1",
            "session_id": self.session_id,
            "target_url": self.target_url,
            "started_at": self.started_at.isoformat(),
            "finished_at": datetime.now(UTC).isoformat(),
            "scope": self.scope.as_dict(),
            "environment": {
                "python": sys.version.split()[0],
                "platform": platform.platform(),
                "camoufox_lib": _v("camoufox"),
                "playwright": _v("playwright"),
                "camoufox_browser_build": browser_build,
            },
            "browser": {
                "launch_options": self.launch_options_record,
                "default_addons_excluded": ["UBO"],
                "extra_addons": [],
                "addon_request_filtering_active": False,
                "note": (
                    "Camoufox installs uBlock Origin as a default addon unless "
                    "exclude_addons is passed. It is excluded here so the capture "
                    "reflects the application's real requests. If this says an "
                    "addon filter WAS active, the evidence in this session is "
                    "incomplete."
                ),
            },
            "capture_policy": {
                "resource_types_captured": list(CAPTURED_RESOURCE_TYPES),
                "methods_excluded": ["OPTIONS"],
                "request_routing_active": False,
                "media_extensions_aborted": [],
                "routing_note": (
                    "blanket page.route('**/*') is NOT installed: it disables the "
                    "HTTP cache for routed requests and taxes every request, which "
                    "distorts both timing and caching. No media is blocked."
                ),
                "url_substrings_dropped_at_capture": sorted(NOISY_ENDPOINTS),
                "response_samples_per_endpoint": 2,
                "request_samples_per_endpoint": 2,
                "listeners_attached_at": "browser_context",
            },
            "sensors": {
                "lifecycle": self.lifecycle_sensor.stats() if self.lifecycle_sensor else None,
                "runtime": self.runtime_sensor.stats() if self.runtime_sensor else None,
                "websocket": self.websocket_sensor.stats() if self.websocket_sensor else None,
                "storage": self.storage_sensor.stats() if self.storage_sensor else None,
                "identity": self.registry.snapshot() if self.registry else None,
            },
            "graphql_operations": {
                path: sorted(ops) for path, ops in sorted(self.graphql_operations.items())
            },
            "known_blind_spots": [
                "Service-worker traffic is invisible to Playwright on Firefox. When a "
                "service worker is detected a capture_gap is emitted.",
                "WebSocket handshake headers are not exposed by Playwright, so auth "
                "sent on the upgrade is unobserved. Frames themselves ARE captured.",
                "httpOnly cookie changes are only visible as periodic snapshots, not "
                "as a change stream. IndexedDB and Cache Storage are not captured.",
                "Legacy named-function hooks run on a 2s interval and miss calls made "
                "during initial page parse. Proven unsolvable from injected JS; "
                "source rewriting is a later, gated capability.",
                "Dropdown catalogs and jQuery events are still read once at exit, from "
                "the top frame only, and are destroyed by every full page navigation. "
                "User actions, runtime calls and DOM mutations are NOT: those are "
                "flushed before navigation by the runtime probe.",
                "NOISY_ENDPOINTS drops matching URLs at capture time; they are not "
                "recoverable from this session.",
                "Response bodies are truncated to 2 samples per endpoint.",
                "Endpoint identity ignores the query string and does not template "
                "path parameters.",
                "Runtime stacks are raw observation. No causal relationship between a "
                "runtime call and a network request is asserted at capture time.",
            ],
            "counters": {
                "endpoints_in_scope": len(self.endpoints),
                "network_events_logged": len(self.network_log),
                "dom_snapshots": len(self.dom_snapshots),
                "visual_traces": self.step_counter - 1,
                "out_of_scope_endpoints": len(self.out_of_scope),
                "visual_captures_skipped_out_of_scope": self.skipped_visual_captures,
                "dependency_edges": len(self.value_dependencies),
            },
            "event_spine": {
                "mode": "dual_write",
                "available": EVENTS_AVAILABLE,
                "log": "events.jsonl" if self.event_log is not None else None,
                "events_emitted": self.event_log.count if self.event_log is not None else 0,
                "note": (
                    "Events are written alongside the outputs above, incrementally, "
                    "so an interrupted session still leaves a readable history. The "
                    "structures in this manifest remain the behavioural authority; "
                    "nothing reads the event log to produce them yet."
                ),
            },
            "snapshot_fidelity": {
                **self.snapshot_stats,
                "note": (
                    "Snapshots are built from a detached clone: the live page is "
                    "never modified and no page-side fetch is issued to build them. "
                    "Stylesheets are read from already-loaded document.styleSheets. "
                    "Cross-origin sheets cannot be read and keep their <link>, so "
                    "sheets_not_readable > 0 means those snapshots are partial and "
                    "need the network to render fully."
                ),
            },
        }

    def export(self):
        # export() runs from a finally block and from non-interactive callers
        # (the golden-master harness), so the console-encoding guard has to be
        # here rather than only in main(). Idempotent.
        _configure_stdout()

        (OUTPUT_DIR / "network_traffic.json").write_text(json.dumps(self.network_log, indent=2, ensure_ascii=False), encoding="utf-8")
        (OUTPUT_DIR / "dom_structure.json").write_text(json.dumps(self.dom_snapshots, indent=2, ensure_ascii=False), encoding="utf-8")
        (OUTPUT_DIR / "api_dependencies.json").write_text(json.dumps(self.value_dependencies, indent=2, ensure_ascii=False), encoding="utf-8")
        (OUTPUT_DIR / "generated_client.py").write_text(self.generate_httpx_code(), encoding="utf-8")
        
        # New Introspection Dumps
        (OUTPUT_DIR / "dropdown_catalogs.json").write_text(json.dumps(getattr(self, 'catalogs', {}), indent=2, ensure_ascii=False), encoding="utf-8")
        (OUTPUT_DIR / "jquery_events.json").write_text(json.dumps(getattr(self, 'jquery_events', {}), indent=2, ensure_ascii=False), encoding="utf-8")
        (OUTPUT_DIR / "js_hooks_and_mutations.json").write_text(json.dumps({"function_calls": getattr(self, 'js_hooks', []), "dom_mutations": getattr(self, 'mutations', [])}, indent=2), encoding="utf-8")

        # OpenAPI Spec
        openapi_spec = {
            "openapi": "3.0.0",
            "info": {"title": "MCMA Auto-Synthesized API", "version": "1.0"},
            "paths": self.openapi_paths
        }
        (OUTPUT_DIR / "mcma_openapi_spec.json").write_text(json.dumps(openapi_spec, indent=2, ensure_ascii=False), encoding="utf-8")

        # Metadata-only record of traffic outside the engagement boundary.
        out_of_scope_serialisable = {
            key: {**entry, "statuses": sorted(entry["statuses"])}
            for key, entry in self.out_of_scope.items()
        }
        (OUTPUT_DIR / "out_of_scope_metadata.json").write_text(
            json.dumps(out_of_scope_serialisable, indent=2, ensure_ascii=False), encoding="utf-8")

        # Session manifest: makes the evidence self-describing.
        (OUTPUT_DIR / "session_manifest.json").write_text(
            json.dumps(self.build_manifest(), indent=2, ensure_ascii=False), encoding="utf-8")

        (OUTPUT_DIR / "SECURITY.md").write_text(SECURITY_NOTICE, encoding="utf-8")

        # Close the event spine last: it records the session end.
        self.close_events()

        written = sorted(p.name for p in OUTPUT_DIR.glob("*.*"))
        print(f"\n🏆 Exported {len(written)} files + visual traces to ./{OUTPUT_DIR.name}/")
        print(f"   In-scope endpoints: {len(self.endpoints)} | "
              f"out-of-scope (metadata only): {len(self.out_of_scope)}")
        print("   ⚠  This directory contains unredacted authenticated capture. "
              "It is gitignored. Do not share it.")

async def attach_engine_to_page(page, engine):
    """Wire an engine and all observation sensors to a page and its context.

    Extracted so the interactive entry point and the golden-master harness use
    exactly the same wiring. If these drift apart, the baseline stops describing
    what the tool actually does.

    Listeners go on the CONTEXT wherever Playwright allows, so a popup or a
    window the application opens is observed on the same footing as this page.
    """
    context = page.context

    # Legacy named-function hooks. Their parse-time blind spot is documented in
    # the session manifest and is deliberately NOT solved here; source rewriting
    # is a later, gated capability.
    await page.add_init_script(HOOK_AND_OBSERVER_JS)

    # Network capture stays on the engine: it also feeds the exporters that
    # remain the behavioural authority.
    context.on("request", engine.handle_request)
    context.on("response", engine.handle_response)
    context.on("requestfailed", engine.handle_request_failed)

    if EVENTS_AVAILABLE:
        engine.lifecycle_sensor = SENSORS.LifecycleSensor(engine, engine.registry)
        engine.runtime_sensor = SENSORS.RuntimeSensor(engine, engine.registry)
        engine.websocket_sensor = SENSORS.WebSocketSensor(engine, engine.registry)
        engine.storage_sensor = SENSORS.StorageSensor(engine, engine.registry)

        # The probe must be installed before anything navigates, so it is
        # present at document_start in every frame of every page.
        await engine.runtime_sensor.attach(context)
        await engine.lifecycle_sensor.attach(context)
        engine.lifecycle_sensor.observe_page(page)
        engine.websocket_sensor.attach_page(page)

        # A page opened later needs its own WebSocket listener.
        context.on("page", engine.websocket_sensor.attach_page)
    else:
        # Without the package the engine still works, but observes far less.
        page.on("framenavigated", engine.handle_frame_navigated)


async def background_dom_scanner(page, engine):
    """Hybrid snapshot trigger: semantic where possible, polled as a safety net.

    Full semantic triggering is a later step. What is added here is a URL check,
    so a navigation is snapshotted on the next tick even when the new document
    happens to hash close to the old one, and a storage snapshot alongside it so
    state is captured at the boundary that actually changes it.

    The 2s content poll remains because removing it would silently reduce
    coverage on pages that mutate without navigating.
    """
    last_hash = ""
    last_url = None
    await engine.capture_visual_state(page)
    while True:
        await asyncio.sleep(2.0)
        try:
            current_url = page.url
            content = await page.content()
            # Change-detection only. Not a security primitive.
            curr_hash = hashlib.md5(  # noqa: S324
                content.encode("utf-8"), usedforsecurity=False
            ).hexdigest()
            navigated = current_url != last_url
            if navigated or curr_hash != last_hash:
                last_hash = curr_hash
                last_url = current_url
                await engine.scan_all_frames(page)
                await engine.capture_visual_state(page)
                if navigated and engine.storage_sensor is not None:
                    await engine.storage_sensor.snapshot(page, reason="navigation")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # The scanner is the only thing driving periodic capture. If it keeps
            # failing, the session looks quiet when it is actually unobserved.
            engine.emit_sensor_error("background_dom_scanner", exc)

def _configure_stdout():
    """Keep the emoji status output from killing the run on a cp1252 console.

    Windows consoles and redirected stdout default to a legacy codepage, where
    printing a non-encodable character raises UnicodeEncodeError. export() runs
    from a finally block, so an unhandled error there lands at the worst moment.
    """
    for stream in (sys.stdout, sys.stderr):
        # reconfigure() exists on TextIOWrapper but not on every TextIO.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(Exception):
            reconfigure(encoding="utf-8", errors="replace")


async def main():
    _configure_stdout()

    target_url = input("Enter Target Portal URL: ").strip()
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    scope = prompt_for_scope(target_url)
    engine = WebHarvester(target_url, scope)

    # exclude_addons is load-bearing: Camoufox installs uBlock Origin as a
    # default addon, which silently filters requests out of the capture.
    launch_options = {
        "headless": False,
        "humanize": True,
        "os": "windows",
        "geoip": False,
        "enable_cache": True,
        "exclude_addons": [DefaultAddons.UBO],
    }
    engine.record_launch_options(launch_options)

    print("\n🦊 [CAMOUFOX] Booting active introspection engine...")
    print("    [addons] uBlock Origin EXCLUDED — capturing the app's real requests.")
    try:
        async with AsyncCamoufox(**launch_options) as browser:
            page = await browser.new_page(locale="fr-FR", timezone_id="Europe/Paris")

            await attach_engine_to_page(page, engine)

            print(f"🚀 Infiltrating {target_url}...")
            await page.goto(target_url, wait_until="load")

            scanner_task = asyncio.create_task(background_dom_scanner(page, engine))

            print("\n" + "=" * 60)
            print("🟢 AUTOMATIC SPY IS ACTIVE")
            print("1. Interact with the website normally (process a Garage Conventionné dossier).")
            print("2. The script captures full bodies, OpenAPI specs, and JS functions automatically.")
            print("3. Press ENTER in this terminal ONLY when you are done.")
            print("=" * 60 + "\n")

            await asyncio.to_thread(input, "")
            scanner_task.cancel()
            
            # Final dump of hidden in-memory state
            await engine.extract_active_introspection(page)
            
    except Exception as e:
        print(f"\n⚠️ Session interrupted: {e}")
    finally:
        engine.export()

if __name__ == "__main__":
    asyncio.run(main())