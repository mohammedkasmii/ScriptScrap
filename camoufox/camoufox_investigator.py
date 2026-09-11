import asyncio
import contextlib
import hashlib
import json
import platform
import sys
from collections import Counter
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from camoufox.addons import DefaultAddons
from camoufox.async_api import AsyncCamoufox

# ---------------------------------------------------------------------------
# Event spine.
#
# events.jsonl is the only record a session produces. It was dual-written
# alongside nine legacy JSON outputs while the model was proven against real
# sessions; those were retired once `scriptscrap analyze` derived everything
# they stated, with the event ids behind each conclusion attached. The
# structures in WebHarvester are now the investigator's own running tally --
# they feed the manifest, not a second output contract.
#
# The import is defensive: this script must keep working
# when run directly from a bare venv that has camoufox but not the scriptscrap
# package installed. The supported path is `uv run`.
# ---------------------------------------------------------------------------
EV: Any
SENSORS: Any
FORENSIC: Any
try:
    from scriptscrap import events as EV
    from scriptscrap import extension as FORENSIC
    from scriptscrap import sensors as SENSORS

    EVENTS_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only in a bare venv
    EV = None
    SENSORS = None
    FORENSIC = None
    EVENTS_AVAILABLE = False

# Where a session writes, when nothing else is chosen. Each investigation gets
# its OWN directory: a fixed global path let two sessions append to one
# events.jsonl, which mixed two sessions' evidence into one unreadable log. The
# default is timestamped to microseconds so two captures started in the same
# second still land in separate directories.
DEFAULT_OUTPUT_ROOT = Path("scriptscrap_output")


class OutputInUse(RuntimeError):
    """The chosen output directory already holds another session's log."""


def default_output_dir() -> Path:
    return DEFAULT_OUTPUT_ROOT / datetime.now(UTC).strftime("session-%Y%m%d-%H%M%S-%f")

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
- `events.jsonl`, the append-only record of everything above

## Rules

1. **Do not commit it.** The repository `.gitignore` covers `*_output/` by
   pattern. Verify with `git check-ignore -v <path>` before any commit.
2. **Do not share it** outside the authorized engagement. Use
   `scriptscrap export`, which writes a sanitised dataset to `export/shared/`:
   credentials removed, identifiers pseudonymised, no bodies or screenshots.
3. Read `session_manifest.json` first. It records the browser build, the addon
   configuration, the scope policy and the known blind spots that produced this
   evidence.
4. `scriptscrap workspace` serves this directory over loopback only, and says
   UNREDACTED in its header. Do not screen-share it without checking that.

Deletion is a deliberate operator decision. Nothing here is auto-deleted.
"""

# ============================================================
# CREDENTIAL CLASSIFICATION
# ============================================================
# Header names whose VALUES authenticate the operator's live session. The
# capture records that such a header was PRESENT, by name, and never its value.
# Phase 3's generator reads the same classification so a generated client asks
# for them from the environment instead of carrying a captured session.
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

    const labelText = (el) => {
        try {
            if (el.labels && el.labels.length) {
                return (el.labels[0].textContent || "").trim().slice(0, 120);
            }
            const aria = el.getAttribute && el.getAttribute("aria-label");
            if (aria) return aria.trim().slice(0, 120);
            const by = el.getAttribute && el.getAttribute("aria-labelledby");
            if (by) {
                const t = document.getElementById(by);
                if (t) return (t.textContent || "").trim().slice(0, 120);
            }
            const wrap = el.closest && el.closest("label");
            if (wrap) return (wrap.textContent || "").trim().slice(0, 120);
        } catch (e) { /* ignore */ }
        return null;
    };

    // Same boundary the runtime probe applies: a password/secret/token field's
    // value is never captured, only that it exists. The DOM scan reads el.value
    // directly, so without this a hidden CSRF token or a filled password would
    // land in DOM_FORMS in the clear.
    const SECRET_NAME = /pass|pwd|secret|token|otp|cvv|cvc/i;
    const isSecretField = (el, type) =>
        type === "password" ||
        SECRET_NAME.test(((el.name || "") + " " + (el.id || "")));

    // A structural path, byte-for-byte the same algorithm the runtime probe's
    // domPath uses, so a form's path here equals the form_path a probe event
    // records for a field inside it -- which is how an anonymous form's
    // inventory, inputs and submit are keyed together offline. Works for any
    // element: a form (for its identity) or a field (for structural fallback).
    const domPathOf = (el) => {
        try {
            const parts = [];
            let node = el;
            let depth = 0;
            while (node && node.nodeType === 1 && depth < 8) {
                let part = node.tagName.toLowerCase();
                if (node.id) { parts.unshift(part + "#" + node.id); break; }
                const parent = node.parentElement;
                if (parent) {
                    const same = Array.prototype.filter.call(
                        parent.children, (c) => c.tagName === node.tagName);
                    if (same.length > 1) part += ":nth-of-type(" + (same.indexOf(node) + 1) + ")";
                }
                parts.unshift(part);
                node = node.parentElement;
                depth++;
            }
            return parts.join(" > ");
        } catch (e) { return null; }
    };

    const parseElement = (el) => {
        const tag = el.tagName.toLowerCase();
        const type = (el.type || "").toLowerCase();
        const secret = isSecretField(el, type);
        const base = {
            tag, type,
            name: el.name || el.getAttribute("name") || null,
            id: el.id || null,
            // Structural identity for a control with neither id nor name.
            path: domPathOf(el),
            placeholder: el.placeholder || el.getAttribute("placeholder") || null,
            // So an untouched but visible control is fully described offline.
            label: labelText(el),
            required: !!el.required,
            disabled: !!el.disabled,
            readonly: !!el.readOnly,
        };

        if (tag === "select") {
            // Every option, value AND visible label -- the whole catalog, not
            // just the one the operator happened to choose.
            base.options = Array.from(el.options).map(o => ({
                value: o.value, text: (o.text || "").trim(), selected: !!o.selected
            }));
            base.value = el.value;
            base.multiple = !!el.multiple;
        } else if (["checkbox", "radio"].includes(type)) {
            base.value = el.value;
            base.checked = el.checked;
        } else if (el.value !== undefined) {
            base.value = secret ? null : el.value;
        }
        if (secret) base.secret = true;
        return base;
    };

    const forms = querySelectorAllDeep("form").map((form, idx) => ({
        index: idx,
        id: form.id || null,
        name: form.getAttribute ? form.getAttribute("name") : null,
        path: domPathOf(form),
        action: form.action || window.location.href,
        method: (form.method || "GET").toUpperCase(),
        fields: querySelectorAllDeep("input, select, textarea, button", form).map(parseElement)
    }));

    // The document instance this inventory belongs to. It is the same clock the
    // runtime probe stamps on every event (performance.timeOrigin) and changes
    // on each full navigation, so a form scanned before a navigation and one
    // scanned after -- same frame, same id -- are told apart offline.
    let timeOrigin = null;
    try { timeOrigin = performance.timeOrigin; } catch (e) { timeOrigin = null; }

    return { forms, time_origin: timeOrigin };
})();
"""

class WebHarvester:
    def __init__(self, target_url: str, scope: InvestigationScope,
                 session_id: str | None = None, output_dir=None):
        self.target_url = target_url
        self.scope = scope
        self.output_dir = Path(output_dir) if output_dir is not None else default_output_dir()
        self.endpoints = {}
        self._last_form_inventory = None
        # Pessimistic by default. A session whose teardown raised leaves a
        # manifest that says so; only reaching the end of a clean run sets
        # "clean". A session killed hard writes no manifest at all, and the
        # workspace reports manifest_present: false for that.
        self.outcome = "failed"
        # A COUNT, not a log. `self.network_log` held every request's headers
        # and body in RAM for the whole session and was written nowhere; the
        # events are the record, and the manifest needs only how many.
        self._http_requests = 0

        # Running tallies for the manifest's completeness block. Counts, not
        # buffers: a long session must not accumulate the things it counts.
        self._capture_gaps = 0
        self._sensor_errors = 0
        self._checkpoints = 0
        self._last_checkpoint = None

        # Metadata-only record of everything outside the engagement boundary:
        # which endpoints, never what was in them.
        self.out_of_scope_endpoints: set[str] = set()
        self.skipped_visual_captures = 0

        # Third-party frames are skipped on every scan. Counting them here and
        # emitting one aggregate gap per scan keeps the fact without letting an
        # ad iframe that re-attaches on a timer dominate the event log.
        self._out_of_scope_frame_scans = 0
        self._out_of_scope_frame_hosts: dict[str, int] = {}

        # Credential values stripped from the generated OpenAPI examples. A
        # spec is a shareable artifact; reporting this number makes the claim
        # checkable instead of implied.

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

        # --- optional forensic layer (M4) ----------------------------------
        # Off unless explicitly enabled. Normal capture never touches these.
        self.forensic_config = None
        self.extension_sensor = None
        self.extension_transport = None
        self.blob_store = None
        self.launch_options_record = {}
        self.started_at = datetime.now(UTC)

        # --- event spine ---------------------------------------------------
        # Written incrementally so a crash cannot destroy the session history.
        self.session_id = session_id or datetime.now(UTC).strftime("sess-%Y%m%d-%H%M%S")

        # Refuse to write into a directory that already holds a session log.
        # Appending would interleave two sessions' events under two session ids
        # in one file, which the reader flags as `mixed_sessions` and which no
        # downstream analysis can un-mix. A fresh timestamped directory never
        # trips this; an explicit --output pointing at a used directory does,
        # deliberately. Resume is intentionally NOT supported: continuing a log
        # correctly means restoring the sequence and event counter, and a
        # half-done resume that restarts `seq` at 1 is worse than a clean
        # refusal.
        log_path = self.output_dir / "events.jsonl"
        if log_path.exists() and log_path.stat().st_size > 0:
            raise OutputInUse(
                f"{log_path} already holds a session's events. Each "
                f"investigation writes its own directory; choose an empty "
                f"--output, or move the existing capture aside.")

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.visual_dir = self.output_dir / "visual_traces"
        self.visual_dir.mkdir(parents=True, exist_ok=True)
        self.step_counter = 1

        self.event_log = None
        if EVENTS_AVAILABLE:
            try:
                self.event_log = EV.EventLog(log_path, self.session_id)
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
        self._sensor_errors += 1
        if self.event_log is None:
            return None
        return self.event_log.sensor_error(EV.Source.PLAYWRIGHT, where, exc, **extra)

    def emit_capture_gap(self, reason: str, **extra):
        self._capture_gaps += 1
        if self.event_log is None:
            return None
        return self.event_log.capture_gap(EV.Source.ENGINE, reason, **extra)

    def checkpoint(self, reason: str = "periodic"):
        """A heartbeat recovery point during a long session.

        Records how far the capture has got -- events so far, pages open,
        elapsed seconds -- so an abruptly killed session shows its progress and
        a running one is visibly alive. Cheap: it reads counters, holds nothing.
        """
        if self.event_log is None:
            return None
        self._checkpoints += 1
        self._last_checkpoint = datetime.now(UTC)
        elapsed = (self._last_checkpoint - self.started_at).total_seconds()
        return self.emit_event(
            EV.Source.ENGINE,
            EV.EventType.CHECKPOINT,
            reason=reason,
            events_so_far=self.event_log.count,
            network_events=self._http_requests,
            capture_gaps=self._capture_gaps,
            sensor_errors=self._sensor_errors,
            pages_open=self.registry.snapshot().get("pages") if self.registry else None,
            elapsed_seconds=round(elapsed, 1),
        )

    def close_events(self):
        if self.event_log is None:
            return
        self.event_log.emit(
            EV.Source.ENGINE,
            EV.EventType.SESSION_END,
            counters={
                "endpoints_in_scope": len(self.endpoints),
                "network_events": self._http_requests,
                "out_of_scope_endpoints": len(self.out_of_scope_endpoints),
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
        self.out_of_scope_endpoints.add(key)

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

        # Reserve the step number immediately. With a scanner per page, two
        # pages can snapshot concurrently; reading the counter and incrementing
        # it in one go (no await between) keeps their filenames from colliding.
        step = self.step_counter
        self.step_counter += 1
        page_id = self.registry.page_id(page) if self.registry else None
        timestamp = datetime.now().strftime("%H%M%S")
        file_prefix = self.visual_dir / f"step_{step:03d}_{timestamp}"

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
                page_id=page_id,
                url=page.url,
                step=step,
                artifact=Path(f"{file_prefix}.png").name,
            )
            self.emit_event(
                EV.Source.ENGINE,
                EV.EventType.HTML_SNAPSHOT,
                page_id=page_id,
                url=page.url,
                step=step,
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

            self._http_requests += 1
            
            print(f"[API ->] {method:6} {url_path}")

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
                method = req.method.upper()
                self._record_out_of_scope(method, req.url, status=response.status)
                # The status has to reach the SPINE, not only the in-memory
                # tally. The request side emits its own gap; without this one
                # the log knows a third-party call happened but never how it
                # answered, and the only record of that was a legacy JSON file.
                parsed = urlparse(req.url)
                self.emit_capture_gap(
                    "out_of_scope",
                    method=method,
                    host=parsed.hostname,
                    path=parsed.path or "/",
                    status=response.status,
                    withheld=["headers", "body", "query"],
                )
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

                    if len(self.endpoints.get(key, {}).get("response_samples", [])) < 2:
                        self.endpoints[key]["response_samples"].append(data)
                except json.JSONDecodeError:
                    body_kind = "text"
                    body_for_openapi = resp_text[:500]
                    if len(self.endpoints.get(key, {}).get("response_samples", [])) < 1:
                        self.endpoints[key]["response_samples"].append(resp_text[:500] + "...")

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
    async def scan_all_frames(self, page):
        if not self.scope.contains(page.url):
            return

        page_id = self.registry.page_id(page) if self.registry else None
        results = []
        skipped_hosts: dict[str, int] = {}
        for frame in page.frames:
            # A frame may be third-party even when the top document is in scope.
            if not self.scope.contains(frame.url):
                host = urlparse(frame.url).hostname or "(no host)"
                skipped_hosts[host] = skipped_hosts.get(host, 0) + 1
                continue
            try:
                dom = await frame.evaluate(DOM_PROBE_JS)
                frame_id = self.registry.frame_id(frame) if self.registry else None
                results.append({"frame_url": frame.url, "frame_id": frame_id, "data": dom})
            except Exception as exc:
                # A frame we could not read is a hole, not an empty frame.
                self.emit_sensor_error(
                    "scan_all_frames", exc, frame_id=_frame_id_of(frame), url=frame.url)

        # One gap per scan naming the hosts, not one per frame per scan. An ad
        # network that re-attaches its iframe on a timer produced 802 identical
        # gap events in a six-minute session -- a quarter of the whole log,
        # saying the same thing 802 times and burying the gaps that mattered.
        if skipped_hosts:
            self._out_of_scope_frame_scans += 1
            for host, count in skipped_hosts.items():
                self._out_of_scope_frame_hosts[host] = (
                    self._out_of_scope_frame_hosts.get(host, 0) + count)
            self.emit_capture_gap(
                "frame_out_of_scope",
                hosts=dict(sorted(skipped_hosts.items())),
                frames_skipped=sum(skipped_hosts.values()),
                note="third-party frames are not read; scope is enforced per frame",
            )

        self.emit_event(
            EV.Source.ENGINE,
            EV.EventType.DOM_SNAPSHOT,
            url=page.url,
            frames_captured=len(results),
            frames_total=len(page.frames),
            forms=sum(len(r["data"].get("forms", [])) for r in results),
            # WHICH frames were read, not just how many. dom_structure.json was
            # the only record of that, and without it the log cannot answer
            # "did the scan reach the nested iframe?" -- which is the question
            # a cross-frame form is found or lost by. Every URL here is in
            # scope by construction: the loop above skips the others.
            frame_urls=[r["frame_url"] for r in results],
            forms_by_frame={
                r["frame_url"]: len(r["data"].get("forms", [])) for r in results
            },
        )

        inventory = [
            {"frame_url": r["frame_url"], "frame_id": r["frame_id"],
             # The document instance (performance.timeOrigin) this frame's forms
             # were inventoried in, so a re-scan after a navigation is new
             # evidence and offline keying can separate the two documents.
             "time_origin": r["data"].get("time_origin"),
             "forms": r["data"].get("forms", [])}
            for r in results
        ]
        digest = hashlib.sha256(
            json.dumps(inventory, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        # A scan that found the same structure as the last one is not new
        # evidence. Emitting it anyway would put 124 copies of one inventory in
        # the log and make "when did this form appear?" unanswerable by reading.
        if digest != self._last_form_inventory:
            self._last_form_inventory = digest
            # page_id on the envelope so form identity can be made unique across
            # tabs; per-frame frame_id inside `frames` makes it unique across
            # frames too.
            self.emit_event(
                EV.Source.ENGINE,
                EV.EventType.DOM_FORMS,
                page_id=page_id,
                url=page.url,
                frames=inventory,
                inventory_sha256=digest,
            )

    async def _eval_page_world(self, target, expression, *, default=None):
        """Evaluate an expression against the PAGE's globals, not the driver's.

        `page.evaluate` runs in the isolated world, which shares the document
        but not `window`. Anything reading a global the application or an
        injected hook defined must go through Camoufox's `mw:` prefix, and a
        browser that does not offer it falls back to the plain evaluate rather
        than losing the reading entirely. A failure is recorded as a gap: an
        unreadable buffer is not an empty one.
        """
        try:
            return await target.evaluate("mw:" + expression)
        except Exception as main_world_exc:
            try:
                return await target.evaluate(expression)
            except Exception as exc:
                self.emit_capture_gap(
                    "page_world_read_failed",
                    expression=expression[:120],
                    main_world_error=str(main_world_exc),
                    error=str(exc),
                    note="a page global could not be read in either JS world",
                )
                return default

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

        # jQuery is a PAGE global, and so are the hook buffers below. Reading
        # them from the isolated world returns an empty object every time --
        # which is exactly what the first real capture reported, next to a page
        # that demonstrably used jQuery.
        self.jquery_events = await self._eval_page_world(page, """(() => {
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
        })()""", default={}) or {}

        self.js_hooks = await self._eval_page_world(
            page, "window.functionHookLogs || []", default=[]) or []
        self.mutations = await self._eval_page_world(
            page, "window.domMutations || []", default=[]) or []

        calls_by_function = Counter(
            h.get("function") for h in self.js_hooks if h.get("function"))

        self.emit_event(
            EV.Source.RUNTIME,
            EV.EventType.RUNTIME_HOOKS,
            page_id=self.registry.page_id(page) if self.registry else None,
            url=page.url,
            hook_calls=len(self.js_hooks),
            functions=sorted(calls_by_function),
            # Per call site, not just the set of names. "fetch was patched" and
            # "fetch was called 312 times" are different observations, and the
            # second one was thrown away with js_hooks_and_mutations.json.
            hook_calls_by_function=dict(sorted(calls_by_function.items())),
            dropdown_catalogs=sorted(self.catalogs),
            # The OPTIONS, not just the select names. What values a field
            # accepts is the reason a reader opens a dropdown catalogue, and
            # dropdown_catalogs.json was the only place it lived.
            dropdown_catalog_options=dict(sorted(self.catalogs.items())),
            jquery_bound_selectors=sorted(self.jquery_events),
            # Which events, not just which selectors.
            jquery_bound_events={
                selector: sorted(events)
                for selector, events in sorted(self.jquery_events.items())
            },
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

    # generate_httpx_code lived here. It emitted generated_client.py, which
    # is retired above. Its docstring promised the output carried no captured
    # credentials; nothing in the code enforced that, and the only thing
    # checking it was a golden-master summary of the file's text. Phase 3
    # restores a generator that reads the derived model, with those promises
    # as tests rather than prose.


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

        # The browser is not pinned by uv.lock. Recording the build was not
        # enough -- a reader needs to know whether it is the build the
        # assumptions were verified against, without going to look it up.
        browser_baseline = {"status": "unknown", "note": "scriptscrap not importable"}
        try:
            from scriptscrap.baseline import compare_browser_build
            browser_baseline = compare_browser_build(
                browser_build if isinstance(browser_build, str)
                and not browser_build.startswith("unavailable") else None)
        except ImportError:
            pass

        return {
            "schema": "scriptscrap/session-manifest/1",
            "session_id": self.session_id,
            "target_url": self.target_url,
            "started_at": self.started_at.isoformat(),
            "finished_at": datetime.now(UTC).isoformat(),
            # How the session ended. The repository's own interrupted capture
            # was distinguishable only by its directory name, which is not
            # evidence.
            "outcome": self.outcome,
            "scope": self.scope.as_dict(),
            "environment": {
                "python": sys.version.split()[0],
                "platform": platform.platform(),
                "camoufox_lib": _v("camoufox"),
                "playwright": _v("playwright"),
                "camoufox_browser_build": browser_build,
                "browser_build_baseline": browser_baseline,
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
                "out_of_scope_frame_scans": self._out_of_scope_frame_scans,
                "out_of_scope_frame_hosts": dict(
                    sorted(self._out_of_scope_frame_hosts.items())),
            },
            "forensic": (
                self.forensic_config.to_manifest() if self.forensic_config is not None
                else {"mode": "normal", "note": "forensic layer not enabled"}
            ),
            "sensors": {
                "lifecycle": self.lifecycle_sensor.stats() if self.lifecycle_sensor else None,
                "runtime": self.runtime_sensor.stats() if self.runtime_sensor else None,
                "websocket": self.websocket_sensor.stats() if self.websocket_sensor else None,
                "storage": self.storage_sensor.stats() if self.storage_sensor else None,
                "identity": self.registry.snapshot() if self.registry else None,
                "extension": (
                    self.extension_sensor.stats() if self.extension_sensor else None),
                "extension_transport": (
                    self.extension_transport.stats() if self.extension_transport else None),
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
                "as a change stream. IndexedDB and Cache Storage are INVENTORIED "
                "(database/store names with record counts, cached request URLs) but "
                "their record values and cached response bodies are not read.",
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
                "network_events_logged": self._http_requests,
                "visual_traces": self.step_counter - 1,
                "out_of_scope_endpoints": len(self.out_of_scope_endpoints),
                "visual_captures_skipped_out_of_scope": self.skipped_visual_captures,
                # Page/frame counts and the honesty tallies, so a reader judging
                # a long session sees its shape without parsing the whole log.
                "pages": (self.registry.snapshot().get("pages")
                          if self.registry else None),
                "frames": (self.registry.snapshot().get("frames")
                           if self.registry else None),
                "capture_gaps": self._capture_gaps,
                "sensor_errors": self._sensor_errors,
                "checkpoints": self._checkpoints,
            },
            # A long agency session runs for hours; a reader needs its shape and
            # whether it finished cleanly without reading the whole log. Duration
            # and the completion state make the manifest self-sufficient for that.
            "duration_seconds": round(
                (datetime.now(UTC) - self.started_at).total_seconds(), 1),
            "completion": {
                "outcome": self.outcome,
                "clean": self.outcome == "clean",
                "checkpoints_written": self._checkpoints,
                "last_checkpoint": (
                    self._last_checkpoint.isoformat()
                    if self._last_checkpoint else None),
                "note": (
                    "Events stream to disk as they happen and are fsynced "
                    "periodically, so an abrupt kill leaves everything up to the "
                    "last flush readable. A session killed hard writes no "
                    "manifest at all; the workspace reports manifest_present: "
                    "false for that."
                ),
            },
            "event_spine": {
                "mode": "authoritative",
                "available": EVENTS_AVAILABLE,
                "log": "events.jsonl" if self.event_log is not None else None,
                "events_emitted": self.event_log.count if self.event_log is not None else 0,
                "note": (
                    "events.jsonl is the only record this session produces. Events "
                    "are written incrementally, so an interrupted session still "
                    "leaves a readable history. The counts above are the "
                    "investigator's own tally of what it observed; the knowledge "
                    "derived from the log is produced by `scriptscrap analyze`, "
                    "which cites the event ids behind every conclusion. The nine "
                    "legacy JSON outputs that used to be the authority here were "
                    "retired once the derived layer covered them."
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

        # Nine files used to be written here -- network_traffic.json,
        # dom_structure.json, api_dependencies.json, generated_client.py,
        # dropdown_catalogs.json, jquery_events.json,
        # js_hooks_and_mutations.json, mcma_openapi_spec.json and
        # out_of_scope_metadata.json. They predate the event spine and every
        # fact in them is now derived by `scriptscrap analyze`, which cites the
        # event ids behind each conclusion instead of asserting it.
        #
        # They are gone rather than deprecated because two output contracts
        # means every later change has to be made twice, and a reader has to
        # know which one is current. The out-of-scope statuses those files were
        # the only record of now reach the spine from handle_response.
        #
        # A client generator returns in Phase 3, generated from the derived
        # model and tested -- the retired one asserted its own safety in a
        # docstring with nothing checking it.

        # Session manifest: makes the evidence self-describing.
        (self.output_dir / "session_manifest.json").write_text(
            json.dumps(self.build_manifest(), indent=2, ensure_ascii=False), encoding="utf-8")

        (self.output_dir / "SECURITY.md").write_text(SECURITY_NOTICE, encoding="utf-8")

        # Close the event spine last: it records the session end.
        self.close_events()

        written = sorted(p.name for p in self.output_dir.glob("*.*"))
        print(f"\n🏆 Exported {len(written)} files + visual traces to ./{self.output_dir.name}/")
        print(f"   In-scope endpoints: {len(self.endpoints)} | "
              f"out-of-scope (metadata only): {len(self.out_of_scope_endpoints)}")
        print("   ⚠  This directory contains unredacted authenticated capture. "
              "It is gitignored. Do not share it.")

def start_forensic_layer(engine, forensic_config):
    """Bring up the extension transport before the browser launches.

    Returns launch kwargs to merge (the addon path), or {} when forensic mode
    is off. Called BEFORE launch because the extension must be built with the
    transport port already known -- a background script takes no arguments.

    Failure here is deliberately non-fatal: forensic mode is an addition to
    normal capture, so a transport that cannot bind should cost the extra
    evidence, not the session.
    """
    if not (forensic_config and forensic_config.enabled and EVENTS_AVAILABLE):
        return {}

    engine.forensic_config = forensic_config
    try:
        blob_root = engine.output_dir / "blobs"
        engine.blob_store = SENSORS.BlobStore(
            blob_root, max_bytes=forensic_config.max_blob_bytes)
        engine.extension_sensor = SENSORS.ExtensionSensor(engine, engine.blob_store)
        engine.extension_transport = FORENSIC.ExtensionTransport(
            engine.extension_sensor.on_batch).start()

        extension_dir = FORENSIC.build_extension(
            port=engine.extension_transport.port,
            scope_hosts=sorted(engine.scope.roots),
            max_body_bytes=forensic_config.max_body_bytes,
            capture_bodies=forensic_config.capture_bodies,
            capture_scripts=forensic_config.capture_scripts,
            rewrite_targets=[t.to_dict() for t in forensic_config.rewrite_targets]
            if forensic_config.rewriting_active else [],
        )
        engine.extension_dir = extension_dir
        print(f"    [forensic] extension on port {engine.extension_transport.port}")
        return {"addons": [str(extension_dir)]}
    except Exception as exc:
        engine.emit_sensor_error("forensic_layer_start", exc)
        engine.emit_capture_gap(
            "forensic_layer_unavailable",
            note="extension sensor could not start; capture continues without it",
        )
        return {}


def stop_forensic_layer(engine):
    """Tear down the transport and remove the generated extension directory."""
    if engine.extension_transport is not None:
        engine.emit_event(
            EV.Source.EXTENSION, EV.EventType.FORENSIC_SENSOR_STOPPED,
            **engine.extension_transport.stats(),
        )
        if not engine.extension_transport.connected and engine.extension_sensor \
                and not engine.extension_sensor.started:
            engine.emit_capture_gap(
                "extension_disconnected",
                note="the extension never connected; no forensic evidence was collected",
            )
        engine.extension_transport.stop()
    extension_dir = getattr(engine, "extension_dir", None)
    if extension_dir is not None:
        FORENSIC.cleanup_extension(extension_dir)


async def attach_engine_to_page(page, engine):
    """Wire an engine and all observation sensors to a page and its context.

    Extracted so the interactive entry point and the golden-master harness use
    exactly the same wiring. If these drift apart, the baseline stops describing
    what the tool actually does.

    Listeners go on the CONTEXT wherever Playwright allows, so a popup or a
    window the application opens is observed on the same footing as this page.
    """
    context = page.context
    # The page the operator started on. Its context-level init script installs
    # the isolated probe listeners correctly; a popup or new tab's do NOT (a
    # Camoufox quirk), so those are re-armed per navigation below.
    engine._initial_page = page

    # Legacy named-function hooks. Their parse-time blind spot is documented in
    # the session manifest and is deliberately NOT solved here; source rewriting
    # is a later, gated capability.
    #
    # They hook globals the APPLICATION defines, and buffer into page globals,
    # so like the probe's patched half they only work in the page's own JS
    # world. Installed via `main_world_eval` below; the init script remains as
    # the fallback for a browser that does not isolate worlds.
    await page.add_init_script(HOOK_AND_OBSERVER_JS)

    # Network capture stays on the engine: it also feeds the running tally the
    # session manifest reports.
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

        # The probe's patched half cannot ride an init script: those run in the
        # isolated world, where replacing `fetch` changes a global the
        # application never calls. It goes in through a main-world evaluate
        # instead, which is only possible AFTER a navigation commits -- so it
        # is re-installed on every one, for every in-scope frame.
        async def install_main_world(frame) -> None:
            if not engine.scope.contains(getattr(frame, "url", "") or ""):
                return
            await engine.runtime_sensor.install_main_world(frame)
            # The legacy hooks need the same world for the same reason.
            with contextlib.suppress(Exception):
                await frame.evaluate("mw:" + HOOK_AND_OBSERVER_JS)
            # Isolated-world listeners from the context init script do not fire
            # in a popup or new tab. Re-arm them in the live document of every
            # NON-initial page's main frame. The initial page is skipped: its
            # context-script listeners work, and re-arming there would attach a
            # second set and double every user action.
            try:
                is_main_frame = frame.parent_frame is None
                owner_page = frame.page
            except Exception:
                return
            if is_main_frame and owner_page is not getattr(engine, "_initial_page", None):
                await engine.runtime_sensor.rearm_isolated(frame)

        def on_navigated(frame) -> None:
            asyncio.get_running_loop().create_task(install_main_world(frame))

        page.on("framenavigated", on_navigated)
        context.on("page", lambda p: p.on("framenavigated", on_navigated))
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

class PageCoverage:
    """Full capture coverage for every in-scope page, tab and popup.

    Each page an application opens is worked exactly like the first: its own
    scanner task (visual snapshots, DOM/form inventory, storage snapshots on
    change) plus the context-level sensors and per-navigation main-world
    instrumentation that `attach_engine_to_page` already wires for every page.
    A page's scanner is cancelled AND awaited when the page closes, so a closing
    popup cannot leave a task scanning a dead page. On session end every
    remaining in-scope page is drained and its final state extracted -- not only
    the page the operator started on, which was the previous behaviour and lost
    everything a popup held.

    The checkpoint heartbeat is session-level here, not per page, so a session
    with three tabs open does not write three times the checkpoints.
    """

    def __init__(self, engine, *, checkpoint_interval: float = 30.0):
        self.engine = engine
        self.checkpoint_interval = checkpoint_interval
        self.tasks: dict = {}          # page -> cover Task
        self.pages: list = []          # order of appearance, for a stable drain
        self._observed: set = set()    # guard: observe each page exactly once
        self._closing: list = []       # cancel-and-await tasks for closed pages
        self._was_in_scope: set = set()  # pages we began covering while in scope
        self._captured: set = set()    # pages whose first snapshot completed
        self._checkpoint_task = None

    def start(self, context, initial_page) -> None:
        self.engine._initial_page = initial_page
        # Subscribe FIRST, then enumerate every page that already exists, so a
        # popup opened during the initial navigation -- before or after this
        # call -- is covered. `_observed` makes the two paths idempotent.
        context.on("page", self._observe)
        for page in list(getattr(context, "pages", []) or []):
            self._observe(page)
        self._observe(initial_page)
        self.engine.checkpoint(reason="session_start")
        self._checkpoint_task = asyncio.get_running_loop().create_task(
            self._checkpoint_loop())

    def _observe(self, page) -> None:
        if page in self._observed:
            return
        self._observed.add(page)
        self.pages.append(page)
        page.on("close", lambda p=page: self._on_close(p))
        self.tasks[page] = asyncio.get_running_loop().create_task(
            self._cover_page(page))

    async def _cover_page(self, page) -> None:
        """Cover one page: an eager first snapshot, then the periodic scan.

        The first snapshot does NOT wait for the 2-second poll, so a popup used
        and closed in under two seconds still yields its DOM/form inventory and a
        storage snapshot. A page opened while off-scope (about:blank during
        launch) is picked up by the periodic loop once it navigates in-scope.
        """
        try:
            with contextlib.suppress(Exception):
                await page.wait_for_load_state("load")
            in_scope = self.engine.scope.contains(getattr(page, "url", "") or "")
            if in_scope:
                self._was_in_scope.add(page)
                # A popup/new tab's isolated listeners from the context init
                # script do not fire; re-arm them before the operator can act.
                if page is not getattr(self.engine, "_initial_page", None):
                    with contextlib.suppress(Exception):
                        await self.engine.runtime_sensor.rearm_isolated(page.main_frame)
                await self._snapshot_once(page, reason="page_observed")
                self._captured.add(page)
            await self._scan_loop(page, seeded_in_scope=in_scope)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.engine.emit_sensor_error("page_coverage", exc)

    async def _snapshot_once(self, page, *, reason: str) -> None:
        """One full snapshot of a page: DOM/form inventory, visual, storage."""
        await self.engine.scan_all_frames(page)
        await self.engine.capture_visual_state(page)
        if self.engine.storage_sensor is not None:
            await self.engine.storage_sensor.snapshot(page, reason=reason)

    async def _scan_loop(self, page, *, seeded_in_scope: bool) -> None:
        last_hash = ""
        last_url = page.url if seeded_in_scope else None
        while True:
            await asyncio.sleep(2.0)
            try:
                current_url = page.url
                if not self.engine.scope.contains(current_url or ""):
                    continue
                content = await page.content()
                curr_hash = hashlib.md5(  # noqa: S324
                    content.encode("utf-8"), usedforsecurity=False).hexdigest()
                navigated = current_url != last_url
                if navigated or curr_hash != last_hash:
                    last_hash = curr_hash
                    last_url = current_url
                    if page not in self._was_in_scope:
                        self._was_in_scope.add(page)
                    await self.engine.scan_all_frames(page)
                    await self.engine.capture_visual_state(page)
                    if navigated and self.engine.storage_sensor is not None:
                        await self.engine.storage_sensor.snapshot(page, reason="navigation")
                    self._captured.add(page)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.engine.emit_sensor_error("background_dom_scanner", exc)

    def _on_close(self, page) -> None:
        # A page that was in scope but closed before its first snapshot took its
        # final state with it -- say so rather than letting it look like a page
        # that simply held nothing.
        if page in self._was_in_scope and page not in self._captured:
            self.engine.emit_capture_gap(
                "page_closed_before_capture",
                page_id=(self.engine.registry.page_id(page)
                         if self.engine.registry else None),
                note="an in-scope page closed before its DOM/form and storage "
                     "state could be snapshotted; user actions on it may still "
                     "have been captured live by the probe",
            )
        task = self.tasks.pop(page, None)
        if task is None:
            return
        # Cancel now; await on a helper task, because this runs in a sync event
        # callback where we cannot await. stop() also awaits it, so nothing is
        # left dangling at session end.
        task.cancel()
        self._closing.append(asyncio.get_running_loop().create_task(
            self._await_cancelled(task)))

    @staticmethod
    async def _await_cancelled(task) -> None:
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task

    async def _checkpoint_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self.checkpoint_interval)
                self.engine.checkpoint(reason="periodic")
        except asyncio.CancelledError:
            raise

    async def stop(self) -> None:
        """Cancel every scanner, then drain and extract every in-scope page."""
        if self._checkpoint_task is not None:
            self._checkpoint_task.cancel()
            await self._await_cancelled(self._checkpoint_task)

        for task in list(self.tasks.values()):
            task.cancel()
        for task in list(self.tasks.values()):
            await self._await_cancelled(task)
        for task in self._closing:
            await self._await_cancelled(task)
        self.tasks.clear()

        # Drain and extract EVERY remaining in-scope page, in order of
        # appearance. A popup the operator filled and left open is emptied here.
        for page in self.pages:
            with contextlib.suppress(Exception):
                if page.is_closed():
                    continue
            if not self.engine.scope.contains(getattr(page, "url", "") or ""):
                continue
            try:
                await self.engine.extract_active_introspection(page)
            except Exception as exc:
                self.engine.emit_sensor_error("page_coverage_drain", exc)


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


def announce_browser_baseline(engine) -> dict:
    """Say, before the session starts, whether this browser is the tested one.

    The browser is fetched outside uv.lock, so it can change under a working
    install. When it did, JS world isolation came back and the runtime probe's
    patched instruments went silent for a whole capture -- with nothing in the
    console, the manifest or the health report saying so. This is the warning
    that was missing.
    """
    try:
        from scriptscrap.baseline import compare_browser_build
    except ImportError:
        return {"status": "unknown"}

    comparison = compare_browser_build()
    if comparison["status"] == "match":
        print(f"    [browser] {comparison['found']} — matches the verified baseline.")
        return comparison

    print("\n" + "!" * 72)
    print(f"!! BROWSER BUILD IS NOT THE BASELINE: {comparison['found']} "
          f"(baseline {comparison['baseline']})")
    print(f"!! {comparison['note']}")
    print("!! Run: uv run diagnostics/probes/js_world_probe.py")
    print("!" * 72 + "\n")
    engine.emit_capture_gap(
        "browser_build_not_baseline",
        found=comparison["found"],
        baseline=comparison["baseline"],
        note=comparison["note"],
    )
    return comparison


def parse_cli_args(argv=None):
    """Flags for a real agency session. The URL and scope stay interactive.

    Forensic mode is off by default, and source rewriting -- the one thing that
    changes what the browser executes -- is a SEPARATE flag, because observation
    and intervention must not share a switch.
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="camoufox_investigator",
        description="Record a long agency session for offline analysis.")
    parser.add_argument(
        "--forensic", action="store_true",
        help="enable the Firefox forensic extension: full response bodies, "
             "script source before parse, and the real cookie jar (httpOnly). "
             "Off by default; whatever is enabled is written into the manifest.")
    parser.add_argument(
        "--forensic-max-body-bytes", type=int, default=2 * 1024 * 1024,
        help="largest response body the forensic layer stores (default 2 MiB); "
             "larger bodies are recorded as skipped with a reason.")
    parser.add_argument(
        "--rewrite-source", action="append", default=[], metavar="SCRIPT:fn1,fn2",
        help="INTERVENTION, requires --forensic: instrument named functions in a "
             "matching script from their first execution. This alters the code "
             "the browser runs; every rewritten script records both hashes.")
    parser.add_argument(
        "--headless", action="store_true",
        help="run without a visible window (for an automated capture).")
    parser.add_argument(
        "--output", "-o", default=None, metavar="DIR",
        help="write this session here. Default: a timestamped directory under "
             "scriptscrap_output/. Each investigation gets its own directory; "
             "the tool refuses to write into one that already holds a session.")
    return parser.parse_args(argv)


def forensic_config_from_args(args):
    """Build a ForensicConfig from the parsed flags, or None for normal mode.

    Enforces the gate: source rewriting cannot be requested without forensic
    mode, and it is never turned on as a side effect of enabling forensic mode.
    """
    from scriptscrap.config import ForensicConfig, RewriteTarget

    if args.rewrite_source and not args.forensic:
        raise SystemExit(
            "--rewrite-source requires --forensic: rewriting a response before "
            "the browser parses it is intervention, and it must be asked for "
            "on top of forensic capture, never on its own.")
    if not args.forensic:
        return None

    targets = []
    for spec in args.rewrite_source:
        script, _, functions = spec.partition(":")
        names = [f.strip() for f in functions.split(",") if f.strip()]
        if script and names:
            targets.append(RewriteTarget(script=script.strip(), functions=names))
    return ForensicConfig(
        enabled=True,
        max_body_bytes=args.forensic_max_body_bytes,
        source_rewrite=bool(targets),
        rewrite_targets=targets,
    )


def active_session_banner(forensic_config) -> list[str]:
    """What the running capture is ACTUALLY recording, per mode.

    Normal mode records user actions, network requests with a small SAMPLE of
    each response body, DOM/form inventories, storage snapshots and periodic
    visual snapshots. It does NOT capture full response bodies, script source,
    or the real cookie jar -- claiming it did was the old banner's error.
    Forensic mode adds exactly those, via the extension, and says so.
    """
    forensic = bool(forensic_config and forensic_config.enabled)
    lines = [
        "🟢 CAPTURE IS ACTIVE — " + ("FORENSIC mode" if forensic else "NORMAL mode"),
        "1. Give the browser to the employee; let them work normally.",
    ]
    if forensic:
        lines += [
            "2. Recording: user actions, network traffic, DOM/form inventories,",
            "   storage snapshots, and — via the extension — FULL response bodies,",
            "   script source before parse, and the real cookie jar (incl. httpOnly).",
        ]
        if forensic_config.rewriting_active:
            lines.append("   SOURCE REWRITING is ACTIVE: this session is not pure observation.")
    else:
        lines += [
            "2. Recording: user actions, network requests with a SAMPLE of each",
            "   response body, DOM/form inventories and storage snapshots. This",
            "   mode does NOT capture full bodies, script source or the cookie jar;",
            "   run with --forensic for those.",
        ]
    lines.append("3. Press ENTER in this terminal ONLY when the whole session is done.")
    return lines


async def main(argv=None):
    _configure_stdout()
    args = parse_cli_args(argv)
    forensic_config = forensic_config_from_args(args)

    target_url = input("Enter Target Portal URL: ").strip()
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    scope = prompt_for_scope(target_url)
    output_dir = Path(args.output) if args.output else default_output_dir()
    try:
        engine = WebHarvester(target_url, scope, output_dir=output_dir)
    except OutputInUse as exc:
        raise SystemExit(str(exc)) from None
    print(f"[OUTPUT] This session -> {engine.output_dir}")

    async def interact(page, engine):
        print("\n" + "=" * 60)
        for line in active_session_banner(forensic_config):
            print(line)
        print("=" * 60 + "\n")
        await asyncio.to_thread(input, "")

    await run_capture(engine, target_url=target_url, forensic_config=forensic_config,
                      headless=args.headless, interact=interact, announce=True)


async def run_capture(engine, *, target_url, forensic_config, headless, interact,
                      locale="fr-FR", timezone_id="Europe/Paris", announce=False):
    """The one production capture runner, shared by the CLI and the tests.

    Launch -> attach sensors -> START COVERAGE (before the first navigation, so a
    popup opened during it cannot be missed) -> navigate -> hand control to
    `interact` (the CLI waits for ENTER; a test scripts the workflow) -> stop
    coverage, which drains every in-scope page -> export. Both entry points use
    this, so a test cannot exercise a different page-coverage ordering from
    production.
    """
    # exclude_addons is load-bearing: Camoufox installs uBlock Origin as a
    # default addon, which silently filters requests out of the capture.
    # main_world_eval is equally load-bearing: without it the runtime probe's
    # patched instruments land in the isolated world and observe nothing.
    launch_options = {
        "headless": headless,
        "humanize": True,
        "os": "windows",
        "geoip": False,
        "enable_cache": True,
        "exclude_addons": [DefaultAddons.UBO],
        "main_world_eval": True,
    }
    if forensic_config is not None:
        launch_options.update(start_forensic_layer(engine, forensic_config))
        if announce:
            print("    [forensic] extension enabled — bodies, script source, "
                  "real cookie jar. See the manifest for exactly what is on.")
            if forensic_config.rewriting_active:
                print("    [forensic] SOURCE REWRITING ACTIVE — not pure observation.")
    engine.record_launch_options(launch_options)

    if announce:
        print("\n🦊 [CAMOUFOX] Booting active introspection engine...")
        print("    [addons] uBlock Origin EXCLUDED — capturing real requests.")
    announce_browser_baseline(engine)

    coverage = None
    try:
        async with AsyncCamoufox(**launch_options) as browser:
            page = await browser.new_page(locale=locale, timezone_id=timezone_id)
            await attach_engine_to_page(page, engine)

            # Coverage BEFORE the first navigation: a page the target opens
            # during load is then observed, not missed.
            coverage = PageCoverage(engine)
            coverage.start(page.context, page)

            if announce:
                print(f"🚀 Infiltrating {target_url}...")
            await page.goto(target_url, wait_until="load")

            await interact(page, engine)

            await coverage.stop()
            engine.outcome = "clean"
    except KeyboardInterrupt:
        engine.outcome = "interrupted"
        print("\n⚠️ Session interrupted by the operator")
        if coverage is not None:
            with contextlib.suppress(Exception):
                await coverage.stop()
    except Exception as exc:
        engine.outcome = "failed"
        print(f"\n⚠️ Session ended with an error: {exc}")
    finally:
        if forensic_config is not None:
            stop_forensic_layer(engine)
        engine.export()


if __name__ == "__main__":
    asyncio.run(main())