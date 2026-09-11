/*
 * ScriptScrap runtime probe.
 *
 * Observes user actions, the browser APIs that trigger network activity, SSE
 * streams and DOM mutations, and streams them to Python in batches.
 *
 * TWO ROLES, ONE FILE
 * -------------------
 * Firefox runs injected scripts in an ISOLATED JavaScript world: the DOM is
 * shared with the page, but `window` is not. That distinction decides what can
 * observe what, and it is not stable across browser builds -- a Camoufox update
 * from 152.0.4-beta.28 to beta.29 turned isolation back on and silently killed
 * every monkey-patched instrument here while every listener kept working. A
 * whole capture reported no fetch, no XHR, no beacons and no pushState, and
 * looked healthy doing it.
 *
 * So the probe is split by what each technique NEEDS, and the split is
 * explicit rather than assumed:
 *
 *   role "isolated"  (injected via add_init_script at document_start)
 *       Listeners on the shared DOM -- click, input, change, submit, keydown,
 *       MutationObserver, popstate -- plus the transport: the exposed binding
 *       lives in this world, so this is the only role that can reach Python.
 *
 *   role "main"      (injected via a `mw:` evaluate into the page's own world)
 *       The monkey-patches -- fetch, XMLHttpRequest, sendBeacon, form submit,
 *       pushState/replaceState, EventSource, Storage -- which only work if
 *       they replace the globals the APPLICATION calls. It cannot reach the
 *       binding, so it hands each record to the isolated role over a
 *       CustomEvent on the shared document, as a JSON string.
 *
 * The roles install disjoint instruments, so when a browser does NOT isolate
 * worlds and both run in the same window, nothing is observed twice.
 *
 * THE PRIME DIRECTIVE: the observer must never become the reason the
 * application behaves differently. Every wrapper below therefore:
 *
 *   - calls through to the original with the original `this` and arguments;
 *   - returns exactly what the original returned, unchanged;
 *   - re-throws exactly what the original threw;
 *   - never turns a synchronous API into an asynchronous one;
 *   - never adds, removes or edits a header, body or URL;
 *   - preserves .name, .length and .toString() so identity checks still pass.
 *
 * Anything the probe itself fails at is reported as a sensor error rather than
 * being swallowed, because a silent probe failure looks exactly like an
 * application that did nothing.
 */
(() => {
  "use strict";

  const CFG = Object.assign(
    {
      maxBuffer: 500,        // events held before a forced flush
      flushIntervalMs: 400,
      maxStringBytes: 8192,  // per captured string field
      maxStackFrames: 12,
      maxMutationsPerBatch: 40,
      capturePasswordValues: false,
      role: "isolated",
    },
    window.__scriptscrapConfig || {}
  );

  const ROLE = CFG.role === "main" ? "main" : "isolated";
  const IS_MAIN = ROLE === "main";

  // Separate flags: on a browser that does not isolate worlds both roles share
  // one `window`, and each must still install exactly once.
  const FLAG = IS_MAIN ? "__scriptscrapMainInstalled" : "__scriptscrapProbeInstalled";
  if (window[FLAG]) return;
  window[FLAG] = true;

  const BINDING = "__scriptscrapEmit";
  const BRIDGE_EVENT = "__scriptscrapBridge";

  let buffer = [];
  let dropped = 0;
  let ordinal = 0;
  let timer = null;

  // --- transport ---------------------------------------------------------

  function flush(sync) {
    if (IS_MAIN) return;               // the main role owns no transport
    if (!buffer.length) return;
    const binding = window[BINDING];
    if (typeof binding !== "function") return; // not yet exposed
    const batch = buffer;
    buffer = [];
    if (dropped) {
      batch.push(mk("sensor_error", {
        where: "probe_buffer",
        error: "buffer overflow",
        dropped_events: dropped,
      }));
      dropped = 0;
    }
    try {
      const payload = JSON.stringify(batch);
      // The binding returns a promise. On a synchronous flush (pagehide) we
      // deliberately do not await it: the call has already crossed into the
      // driver, and blocking unload would change application behaviour.
      const r = binding(payload);
      if (!sync && r && typeof r.catch === "function") r.catch(() => {});
    } catch (e) {
      // Re-queueing risks unbounded growth, so account for the loss instead.
      dropped += batch.length;
    }
  }

  function schedule() {
    if (timer !== null) return;
    timer = setTimeout(() => {
      timer = null;
      flush(false);
    }, CFG.flushIntervalMs);
  }

  // Events that trigger network activity are the causality backbone and are
  // low volume, so they get a fast flush rather than waiting for the timer.
  // This narrows -- but cannot close -- the gap between the in-page observation
  // and the network-layer observation of the same request, which arrive through
  // independent channels. `probe_ordinal` and `probe_time_ms` remain the
  // authority on in-page ordering.
  const FAST_FLUSH = {
    runtime_fetch: 1, runtime_xhr: 1, runtime_beacon: 1,
    runtime_form_submit: 1, user_submit: 1,
  };

  function emit(type, payload) {
    if (IS_MAIN) { bridgeSend(mk(type, payload)); return; }
    accept(mk(type, payload));
  }

  // Queue an already-built record. Shared by this world's own instruments and
  // by records arriving from the main world, so both take the same path out.
  function accept(record) {
    if (buffer.length >= CFG.maxBuffer) {
      dropped++;
      flush(false);
      if (buffer.length >= CFG.maxBuffer) return;
    }
    buffer.push(record);
    if (buffer.length >= CFG.maxBuffer || FAST_FLUSH[record.type]) flush(false);
    else schedule();
  }

  // Main -> isolated, over the one thing the two worlds share: the DOM. The
  // payload is a JSON STRING, not an object, so no cross-world wrapper can
  // change what arrives.
  function bridgeSend(record) {
    try {
      document.dispatchEvent(new CustomEvent(BRIDGE_EVENT, {
        detail: JSON.stringify(record),
      }));
    } catch (e) { /* a record that cannot cross is lost, not fatal */ }
  }

  // The document's navigation-start epoch. Both JS worlds of one document
  // share it, and a navigation replaces it -- which makes it exactly the
  // identifier for "same document instance". `ordinal` restarts per document
  // while a frame id survives navigation, so an ordinal is only comparable
  // against another one carrying the same origin.
  const TIME_ORIGIN = (() => {
    try { return performance.timeOrigin; } catch (e) { return null; }
  })();

  function mk(type, payload) {
    return {
      type: type,
      ordinal: ++ordinal,
      // Which world observed this. The two roles count ordinals independently,
      // so an ordinal is only comparable within one world.
      world: ROLE,
      t_origin: TIME_ORIGIN,
      t_page: nowMs(),
      url: location.href,
      frame_url: location.href,
      is_top: window === window.top,
      payload: payload || {},
    };
  }

  function nowMs() {
    try {
      return performance.timeOrigin + performance.now();
    } catch (e) {
      return Date.now();
    }
  }

  function clip(value) {
    if (typeof value !== "string") return value;
    if (value.length <= CFG.maxStringBytes) return value;
    return value.slice(0, CFG.maxStringBytes) + "…[truncated]";
  }

  function safeError(e) {
    try {
      return String((e && (e.message || e.name)) || e);
    } catch (x) {
      return "unserialisable error";
    }
  }

  function guard(where, fn) {
    try {
      return fn();
    } catch (e) {
      try {
        emit("sensor_error", { where: where, error: safeError(e) });
      } catch (x) { /* nothing further can be done */ }
      return undefined;
    }
  }

  // --- native identity preservation --------------------------------------

  const nativeToString = Function.prototype.toString;
  const originals = new WeakMap();

  function disguise(wrapper, original) {
    try {
      originals.set(wrapper, original);
      Object.defineProperty(wrapper, "name", {
        value: original.name, configurable: true,
      });
      Object.defineProperty(wrapper, "length", {
        value: original.length, configurable: true,
      });
      // Not enumerable, so it stays invisible to `Object.keys` and to any page
      // that walks its own globals -- but readable by the driver's self-test,
      // which is the only way to PROVE a patch reached the application's world
      // rather than assume it from the absence of an error.
      Object.defineProperty(wrapper, "__scriptscrapWrapped", {
        value: true, enumerable: false, configurable: true,
      });
    } catch (e) { /* non-fatal */ }
    return wrapper;
  }

  // Make wrapped functions report the original source, so a page that checks
  // `String(window.fetch).includes("[native code]")` still sees what it expects.
  try {
    Function.prototype.toString = disguise(function toString() {
      const original = originals.get(this);
      return nativeToString.call(original || this);
    }, nativeToString);
  } catch (e) { /* leave toString alone if it is locked down */ }

  // --- stacks ------------------------------------------------------------

  // The probe is injected as an init script, which Firefox attributes to
  // "debugger eval code". No application frame ever has that source, so it is a
  // precise way to drop the observer's own frames and leave the top frame as the
  // application function that actually made the call.
  const PROBE_FRAME = /debugger eval code|__scriptscrap|captureStack/;

  function captureStack(skip) {
    try {
      const raw = new Error().stack || "";
      const lines = raw.split("\n").map((l) => l.trim()).filter(Boolean);
      const cleaned = [];
      let hidden = 0;
      for (const line of lines) {
        if (PROBE_FRAME.test(line)) { hidden++; continue; }
        cleaned.push(line);
        if (cleaned.length >= CFG.maxStackFrames) break;
      }
      const result = cleaned.slice(skip || 0);
      // Nothing is hidden silently: if every frame was the observer's, say so
      // rather than reporting an empty stack as though none existed.
      if (!result.length && hidden) return ["<observer frames only: " + hidden + ">"];
      return result;
    } catch (e) {
      return [];
    }
  }

  // --- element fingerprints ----------------------------------------------

  const SECRET_INPUT_TYPES = { password: 1 };

  function isSecretField(el) {
    if (!el || !el.tagName) return false;
    const type = (el.getAttribute && (el.getAttribute("type") || "")).toLowerCase();
    if (SECRET_INPUT_TYPES[type]) return true;
    const name = ((el.name || "") + " " + (el.id || "")).toLowerCase();
    return /pass|pwd|secret|token|otp|cvv|cvc/.test(name);
  }

  function labelFor(el) {
    try {
      if (el.labels && el.labels.length) return clip(el.labels[0].textContent.trim());
      const aria = el.getAttribute && el.getAttribute("aria-label");
      if (aria) return clip(aria);
      const by = el.getAttribute && el.getAttribute("aria-labelledby");
      if (by) {
        const t = document.getElementById(by);
        if (t) return clip(t.textContent.trim());
      }
      const wrapping = el.closest && el.closest("label");
      if (wrapping) return clip(wrapping.textContent.trim());
    } catch (e) { /* ignore */ }
    return null;
  }

  function domPath(el) {
    // A structural path, NOT a recommended selector. Selector-stability
    // scoring is a later milestone; this is raw material for it.
    try {
      const parts = [];
      let node = el;
      let depth = 0;
      while (node && node.nodeType === 1 && depth < 8) {
        let part = node.tagName.toLowerCase();
        if (node.id) {
          parts.unshift(part + "#" + node.id);
          break;
        }
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
    } catch (e) {
      return null;
    }
  }

  // A click frequently lands on a decorative child -- an icon, an SVG path, a
  // <b> inside a button. The actionable thing is the nearest ancestor that a
  // person can operate, so normalise to it. Both are recorded when they differ,
  // because the original target is evidence of exactly where the pointer went.
  const ACTIONABLE = "a,button,input,select,textarea,option,label,summary," +
    "[role],[contenteditable],[tabindex],[onclick]";

  function actionableAncestor(el) {
    try {
      if (!el || el.nodeType !== 1 || !el.closest) return el;
      const found = el.closest(ACTIONABLE);
      return found || el;
    } catch (e) {
      return el;
    }
  }

  // Accessible-state and relationship attributes a custom control uses instead
  // of native state -- an ARIA combobox is `aria-expanded` on a <div>, not an
  // <input> with a real value. Kept verbatim so offline analysis can connect a
  // trigger to the listbox it controls and the option the operator chose.
  const ARIA_STATE = ["aria-expanded", "aria-controls", "aria-selected",
    "aria-checked", "aria-activedescendant", "aria-haspopup", "aria-pressed",
    "aria-current", "aria-disabled"];

  // When an action happens inside a table (native or an ARIA grid), the table
  // is part of what the action MEANS -- a click on a row's Edit button, a sort
  // on a column header, a filter typed above the rows. Captured so offline
  // analysis can reconstruct the table and connect the operator's actions to
  // it. Bounded: a virtualised table can hold thousands of rows, so only the
  // interacted row and the header row are read.
  function tableContext(el) {
    try {
      if (!el || !el.closest) return null;
      let table = el.closest("table,[role=table],[role=grid],[role=treegrid]");
      // A filter box or a pager usually sits OUTSIDE the table it drives and
      // declares the relationship with aria-controls. Resolve it, so those
      // operations attach to the table they act on rather than being lost.
      let via = null;
      if (!table) {
        const controls = el.getAttribute && el.getAttribute("aria-controls");
        if (controls) {
          const target = document.getElementById(controls);
          if (target && target.closest) {
            table = target.closest("table,[role=table],[role=grid],[role=treegrid]")
              || (/(table|grid)/i.test(target.getAttribute("role") || "")
                  || target.tagName === "TABLE" ? target : null);
            if (table) via = "aria-controls";
          }
        }
      }
      if (!table) return null;
      const ctx = {
        table_id: table.id || (table.getAttribute
          && table.getAttribute("aria-label")) || null,
      };
      if (via) ctx.via = via;
      const caption = table.querySelector && table.querySelector("caption");
      if (caption) ctx.caption = clip((caption.textContent || "").trim().slice(0, 120));

      let headers = [];
      const thead = table.querySelector && table.querySelector("thead");
      const scope = thead || table;
      if (scope.querySelectorAll) {
        headers = Array.prototype.slice.call(
          scope.querySelectorAll("th,[role=columnheader]"), 0, 40);
      }
      if (headers.length) {
        ctx.columns = headers.map((h) =>
          clip((h.innerText || h.textContent || "").trim().slice(0, 60)));
      }

      const row = el.closest("tr,[role=row]");
      if (row) {
        ctx.row_id = row.id || (row.getAttribute && (row.getAttribute("data-id")
          || row.getAttribute("data-row-id"))) || null;
        const cells = row.querySelectorAll
          ? Array.prototype.slice.call(
              row.querySelectorAll("td,th,[role=cell],[role=gridcell]"), 0, 40)
          : [];
        if (cells.length) {
          ctx.cells = cells.map((c) =>
            clip((c.innerText || c.textContent || "").trim().slice(0, 80)));
        }
        if (row.parentElement) {
          const kin = Array.prototype.filter.call(
            row.parentElement.children, (r) => r.tagName === row.tagName);
          ctx.row_index = kin.indexOf(row);
        }
        // Whether the interacted element is itself a header cell -- the signal
        // that a click was a column sort rather than a row action.
        ctx.on_header = !!(el.closest && el.closest("th,[role=columnheader],thead"));
      }
      return ctx;
    } catch (e) {
      return null;
    }
  }

  function fingerprint(el) {
    if (!el || el.nodeType !== 1) return null;
    const tag = el.tagName.toLowerCase();
    const type = el.getAttribute ? el.getAttribute("type") : null;
    const fp = {
      tag: tag,
      id: el.id || null,
      name: el.getAttribute ? el.getAttribute("name") : null,
      type: type,
      role: el.getAttribute ? el.getAttribute("role") : null,
      class: el.getAttribute ? clip(el.getAttribute("class")) : null,
      placeholder: el.getAttribute ? el.getAttribute("placeholder") : null,
      label: labelFor(el),
      dom_path: domPath(el),
      disabled: !!el.disabled,
      readonly: !!el.readOnly,
      required: !!el.required,
    };
    try {
      // Control state, so a checkbox/radio/option/expander carries what it was
      // in at the moment it was used.
      const t = (type || "").toLowerCase();
      if ((t === "checkbox" || t === "radio") && typeof el.checked === "boolean") {
        fp.checked = el.checked;
      }
      if (tag === "option") fp.selected = !!el.selected;
      if (tag === "select" && el.multiple) fp.multiple = true;
      const aria = {};
      if (el.getAttribute) {
        for (const attr of ARIA_STATE) {
          const value = el.getAttribute(attr);
          if (value !== null) aria[attr] = clip(value);
        }
      }
      if (Object.keys(aria).length) fp.aria = aria;
      // The listbox an option belongs to, so a combobox trigger's aria-controls
      // can be matched to the exact listbox the chosen option came from --
      // across a portal, where the listbox is not a DOM ancestor of the trigger.
      if (fp.role === "option" && el.closest) {
        const list = el.closest("[role=listbox]");
        if (list && list.id) fp.listbox = list.id;
      }
      // The captured region a control lives in: a real form/fieldset/dialog/
      // section/region, so a "formless" combobox is grouped by an actual
      // container identity rather than by its whole frame.
      if (el.closest) {
        const region = el.closest(
          "[role=form],fieldset,[role=dialog],dialog,section,[role=region]");
        if (region && region.id) fp.region = region.id;
      }
    } catch (e) { /* ignore */ }
    try {
      const text = (el.innerText || el.textContent || "").trim();
      if (text) fp.text = clip(text.slice(0, 120));
    } catch (e) { /* ignore */ }
    try {
      if (el.form) fp.form = el.form.id || el.form.getAttribute("name") || "(unnamed)";
    } catch (e) { /* ignore */ }
    try {
      const data = {};
      if (el.dataset) {
        for (const k in el.dataset) data[k] = clip(String(el.dataset[k]));
      }
      if (Object.keys(data).length) fp.dataset = data;
    } catch (e) { /* ignore */ }
    return fp;
  }

  function valueOf(el) {
    // Password and secret-looking fields are never valued. The presence and
    // length of the entry are still recorded, because "the operator typed
    // something here" is the observation that matters.
    try {
      if (isSecretField(el)) {
        const len = (el.value || "").length;
        return { redacted: true, reason: "secret_field", length: len };
      }
      if (el.type === "checkbox" || el.type === "radio") {
        return { checked: !!el.checked, value: clip(el.value) };
      }
      if (el.type === "file") {
        // File NAMES and sizes only. Content never enters the capture from
        // here; this is the metadata that says which files were chosen.
        const files = el.files ? Array.prototype.map.call(el.files, (f) => ({
          name: clip(f.name), size: f.size, type: f.type || null,
        })) : [];
        return { files: files, count: files.length };
      }
      if (el.tagName === "SELECT") {
        const opts = Array.prototype.filter.call(el.selectedOptions || [], () => true);
        return {
          value: clip(el.value),
          selected: opts.map((o) => ({ value: o.value, text: clip((o.text || "").trim()) })),
        };
      }
      if (typeof el.value === "string") return { value: clip(el.value) };
    } catch (e) { /* ignore */ }
    return null;
  }

  // Currently-visible rows of a table, bounded. Used for virtualized tables,
  // where the DOM holds only the rows near the viewport: harvesting the visible
  // ones as the operator scrolls reconstructs what they actually saw. Capped
  // hard, and each row carries a stable id where the markup offers one so the
  // analysis can deduplicate across scroll events.
  function visibleTableRows(table, max) {
    const out = [];
    try {
      const rows = table.querySelectorAll("tbody tr,[role=row]");
      const vh = window.innerHeight || document.documentElement.clientHeight || 0;
      for (let i = 0; i < rows.length && out.length < max; i++) {
        const row = rows[i];
        let rect;
        try { rect = row.getBoundingClientRect(); } catch (e) { continue; }
        if (rect.bottom < 0 || rect.top > vh || (rect.width === 0 && rect.height === 0)) {
          continue;   // not in the viewport
        }
        const cells = row.querySelectorAll("td,th,[role=cell],[role=gridcell]");
        out.push({
          row_id: row.id || (row.getAttribute && (row.getAttribute("data-id")
            || row.getAttribute("data-row-id"))) || null,
          cells: Array.prototype.slice.call(cells, 0, 40).map((c) =>
            clip((c.innerText || c.textContent || "").trim().slice(0, 80))),
        });
      }
    } catch (e) { /* ignore */ }
    return out;
  }

  // --- user actions ------------------------------------------------------

  const CLICK_TYPES = { user_click: 1, user_dblclick: 1, user_rightclick: 1 };

  function onUserEvent(type, ev) {
    guard("user_event", () => {
      const raw = ev.target;
      if (!raw || raw.nodeType !== 1) return;
      // For a click, resolve to the nearest actionable ancestor; the raw target
      // is kept beside it when they differ, as evidence of where the pointer
      // actually landed.
      const el = CLICK_TYPES[type] ? actionableAncestor(raw) : raw;
      const payload = {
        element: fingerprint(el),
        trusted: !!ev.isTrusted,
      };
      const tctx = tableContext(el);
      if (tctx) {
        // On a table OPERATION -- a sort on a header, a filter/pager wired by
        // aria-controls -- harvest the rows currently visible, so the analysis
        // can attribute the new table state to the operation that produced it.
        if (tctx.on_header || tctx.via === "aria-controls") {
          const table = el.closest && el.closest(
            "table,[role=table],[role=grid],[role=treegrid]");
          const target = table || (tctx.table_id && document.getElementById(tctx.table_id));
          if (target) tctx.visible_rows = visibleTableRows(target, 60);
        }
        payload.table = tctx;
      }
      if (CLICK_TYPES[type] && el !== raw) {
        payload.original_target = fingerprint(raw);
      }
      if (CLICK_TYPES[type]) {
        payload.button = ev.button;
        payload.detail = ev.detail;
      }
      if (type === "user_input" || type === "user_change") {
        payload.value = valueOf(el);
      }
      if (type === "user_key") {
        // The key itself is deliberately not recorded for secret fields, and
        // only structural keys and modifier shortcuts anywhere -- not a
        // keylogger.
        payload.key = isSecretField(el) ? null : ev.key;
        const mods = [];
        if (ev.ctrlKey) mods.push("Control");
        if (ev.metaKey) mods.push("Meta");
        if (ev.altKey) mods.push("Alt");
        if (ev.shiftKey) mods.push("Shift");
        if (mods.length) payload.modifiers = mods;
      }
      if (type === "user_submit") {
        payload.action = el.action || null;
        payload.method = (el.method || "GET").toUpperCase();
        try {
          const fields = [];
          Array.prototype.forEach.call(el.elements || [], (f) => {
            if (!f.name) return;
            fields.push({
              name: f.name,
              tag: f.tagName.toLowerCase(),
              type: f.getAttribute ? f.getAttribute("type") : null,
              value: valueOf(f),
            });
          });
          payload.fields = fields;
        } catch (e) { /* ignore */ }
        // A submit navigates: get it out before the document is torn down.
        emit(type, payload);
        flush(true);
        return;
      }
      emit(type, payload);
    });
  }

  const USER_EVENTS = [
    ["click", "user_click"],
    ["dblclick", "user_dblclick"],
    ["contextmenu", "user_rightclick"],
    ["input", "user_input"],
    ["change", "user_change"],
    ["submit", "user_submit"],
  ];

  if (!IS_MAIN) {
    for (const [dom, mapped] of USER_EVENTS) {
      // Capture phase, so the observation happens even if the application stops
      // propagation. Passive where allowed so the listener cannot delay the page.
      document.addEventListener(dom, (ev) => onUserEvent(mapped, ev), {
        capture: true,
        passive: dom !== "submit",
      });
    }

    document.addEventListener("keydown", (ev) => {
      // Keys that carry workflow meaning: structural navigation keys, and
      // modifier shortcuts (Ctrl+S, Cmd+Enter). Not every keystroke -- the
      // literal character of an ordinary keypress is never recorded here.
      const structural = ev.key === "Enter" || ev.key === "Escape"
        || ev.key === "Tab";
      const shortcut = (ev.ctrlKey || ev.metaKey || ev.altKey)
        && typeof ev.key === "string" && ev.key.length === 1;
      if (structural || shortcut) {
        onUserEvent("user_key", ev);
      }
    }, { capture: true, passive: true });

    // --- hover-opened menus ---------------------------------------------
    // Only elements that OPEN something on hover, and only once each within a
    // window, so a mouse crossing the page cannot flood the log. A menu is
    // recognised by ARIA -- aria-haspopup, or a menu/menubar/menuitem role, or
    // being inside one.
    const hoverSeen = new Map();       // element -> last emit time
    const HOVER_DEDUP_MS = 1500;
    function hoverTarget(el) {
      try {
        return el.closest && el.closest(
          "[aria-haspopup],[role=menu],[role=menubar],[role=menuitem],[role=menuitemcheckbox],[role=menuitemradio]");
      } catch (e) { return null; }
    }
    document.addEventListener("pointerover", (ev) => {
      guard("user_hover", () => {
        const target = hoverTarget(ev.target);
        if (!target) return;
        const now = nowMs();
        const last = hoverSeen.get(target) || 0;
        if (now - last < HOVER_DEDUP_MS) return;
        hoverSeen.set(target, now);
        if (hoverSeen.size > 200) hoverSeen.clear();   // bounded
        emit("user_hover", { element: fingerprint(target), trusted: !!ev.isTrusted });
      });
    }, { capture: true, passive: true });

    // --- drag and drop ---------------------------------------------------
    // Field names avoid `source` deliberately: it collides with the event
    // envelope's own `source` on the Python side.
    let dragSource = null;
    document.addEventListener("dragstart", (ev) => {
      guard("user_drag_start", () => {
        dragSource = fingerprint(ev.target);
        emit("user_drag", { phase: "start", drag_source: dragSource,
                            trusted: !!ev.isTrusted });
      });
    }, { capture: true, passive: true });
    document.addEventListener("drop", (ev) => {
      guard("user_drag_drop", () => {
        const dt = ev.dataTransfer;
        let files = null;
        try {
          if (dt && dt.files && dt.files.length) {
            files = Array.prototype.map.call(dt.files, (f) => ({
              name: clip(f.name), size: f.size, type: f.type || null }));
          }
        } catch (e) { /* ignore */ }
        emit("user_drag", {
          phase: "drop", drag_source: dragSource,
          drag_destination: fingerprint(ev.target), files: files,
          trusted: !!ev.isTrusted,
        });
        dragSource = null;
      });
    }, { capture: true, passive: true });
    document.addEventListener("dragend", (ev) => {
      guard("user_drag_end", () => {
        // A dragend with a source still set means the drag was cancelled (no
        // drop). Recorded so an abandoned drag is distinguishable from one that
        // landed.
        if (dragSource) {
          emit("user_drag", { phase: "cancel", drag_source: dragSource,
                              trusted: !!ev.isTrusted });
          dragSource = null;
        }
      });
    }, { capture: true, passive: true });

    // --- meaningful scrolling / virtualized rows ------------------------
    // Debounced, and only when the scroll is inside a table/grid: the point is
    // to harvest the rows a virtualized table reveals as the operator scrolls,
    // not to log every pixel of page scroll.
    let scrollTimer = null;
    let scrollTarget = null;
    let scrollTrusted = false;
    document.addEventListener("scroll", (ev) => {
      const node = ev.target;
      let table = null;
      try {
        table = node && node.closest
          ? node.closest("table,[role=table],[role=grid],[role=treegrid]")
          : null;
        if (!table && node && node.querySelector) {
          table = node.querySelector("table,[role=table],[role=grid],[role=treegrid]");
        }
      } catch (e) { table = null; }
      if (!table) return;
      scrollTarget = table;
      // Captured now, because the event object is stale inside the debounce.
      // A programmatic scroll (isTrusted === false) is NOT an employee action.
      scrollTrusted = !!ev.isTrusted;
      if (scrollTimer !== null) return;
      scrollTimer = setTimeout(() => {
        scrollTimer = null;
        guard("user_scroll", () => {
          if (!scrollTarget) return;
          const ctx = tableContext(scrollTarget) || {};
          ctx.visible_rows = visibleTableRows(scrollTarget, 60);
          emit("user_scroll", { reason: "scroll", table: ctx, trusted: scrollTrusted });
          scrollTarget = null;
        });
      }, 300);
    }, { capture: true, passive: true });

    // Records observed in the page's own world arrive here.
    document.addEventListener(BRIDGE_EVENT, (ev) => {
      guard("bridge_receive", () => {
        const record = JSON.parse(ev.detail);
        if (record && typeof record.type === "string") accept(record);
      });
    }, { capture: true });
  }

  // --- network-triggering runtime APIs -----------------------------------
  // Everything from here to the end of the Storage section replaces globals
  // the APPLICATION calls, so it only does anything useful in the page's own
  // world. In the isolated world it would patch a `window` nobody uses.
  if (IS_MAIN) {

  function bodyInfo(body) {
    try {
      if (body == null) return null;
      if (typeof body === "string") return { kind: "string", text: clip(body), size: body.length };
      if (typeof FormData !== "undefined" && body instanceof FormData) {
        const fields = [];
        body.forEach((v, k) => {
          fields.push({
            name: k,
            kind: typeof v === "string" ? "text" : "file",
            value: typeof v === "string" ? clip(v) : null,
          });
        });
        return { kind: "FormData", fields: fields };
      }
      if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
        return { kind: "URLSearchParams", text: clip(body.toString()) };
      }
      if (typeof Blob !== "undefined" && body instanceof Blob) {
        return { kind: "Blob", size: body.size, type: body.type || null };
      }
      if (body instanceof ArrayBuffer) return { kind: "ArrayBuffer", size: body.byteLength };
      if (ArrayBuffer.isView(body)) return { kind: "TypedArray", size: body.byteLength };
      return { kind: typeof body };
    } catch (e) {
      return { kind: "unreadable", error: safeError(e) };
    }
  }

  // fetch
  const nativeFetch = window.fetch;
  if (typeof nativeFetch === "function") {
    window.fetch = disguise(function fetch(input, init) {
      let observed = null;
      guard("runtime_fetch", () => {
        let url = null;
        let method = "GET";
        let headerNames = [];
        let body = null;
        if (typeof input === "string") url = input;
        else if (input && input.url) {
          url = input.url;
          method = input.method || "GET";
        }
        if (init) {
          if (init.method) method = init.method;
          if (init.body != null) body = bodyInfo(init.body);
          try {
            if (init.headers) {
              headerNames = (typeof Headers !== "undefined" && init.headers instanceof Headers)
                ? Array.from(init.headers.keys())
                : Object.keys(init.headers);
            }
          } catch (e) { /* ignore */ }
        }
        observed = {
          url: url ? String(new URL(url, location.href)) : null,
          method: String(method).toUpperCase(),
          header_names: headerNames,
          body: body,
          stack: captureStack(0),
        };
        emit("runtime_fetch", observed);
      });
      // Call through untouched. No awaiting, no wrapping of the promise chain.
      return nativeFetch.apply(this, arguments);
    }, nativeFetch);
  }

  // XMLHttpRequest
  const XHR = window.XMLHttpRequest;
  if (XHR && XHR.prototype) {
    const nOpen = XHR.prototype.open;
    const nSend = XHR.prototype.send;
    const nSetHeader = XHR.prototype.setRequestHeader;

    XHR.prototype.open = disguise(function open(method, url) {
      guard("runtime_xhr_open", () => {
        this.__ss = {
          method: String(method || "GET").toUpperCase(),
          url: url ? String(new URL(url, location.href)) : null,
          header_names: [],
          stack: captureStack(0),
        };
      });
      return nOpen.apply(this, arguments);
    }, nOpen);

    XHR.prototype.setRequestHeader = disguise(function setRequestHeader(name) {
      guard("runtime_xhr_header", () => {
        if (this.__ss) this.__ss.header_names.push(String(name));
      });
      return nSetHeader.apply(this, arguments);
    }, nSetHeader);

    XHR.prototype.send = disguise(function send(body) {
      guard("runtime_xhr_send", () => {
        const info = this.__ss || {};
        emit("runtime_xhr", {
          url: info.url || null,
          method: info.method || "GET",
          header_names: info.header_names || [],
          body: bodyInfo(body),
          async: this.__ssAsync !== false,
          stack: info.stack || captureStack(0),
        });
      });
      return nSend.apply(this, arguments);
    }, nSend);
  }

  // sendBeacon
  if (navigator && typeof navigator.sendBeacon === "function") {
    const nBeacon = navigator.sendBeacon;
    navigator.sendBeacon = disguise(function sendBeacon(url, data) {
      guard("runtime_beacon", () => {
        emit("runtime_beacon", {
          url: url ? String(new URL(url, location.href)) : null,
          body: bodyInfo(data),
          stack: captureStack(0),
        });
      });
      return nBeacon.apply(this, arguments);
    }, nBeacon);
    // A beacon is usually the last thing a page does. Do not let it be lost.
    guard("beacon_flush", () => flush(true));
  }

  // Form submission driven from script (bypasses the submit event)
  if (window.HTMLFormElement && HTMLFormElement.prototype) {
    for (const fname of ["submit", "requestSubmit"]) {
      const original = HTMLFormElement.prototype[fname];
      if (typeof original !== "function") continue;
      HTMLFormElement.prototype[fname] = disguise(function () {
        const form = this;
        guard("runtime_form_submit", () => {
          emit("runtime_form_submit", {
            via: fname,
            action: form.action || null,
            method: (form.method || "GET").toUpperCase(),
            form: form.id || form.getAttribute("name") || null,
            stack: captureStack(0),
          });
          flush(true); // navigation is imminent
        });
        return original.apply(this, arguments);
      }, original);
    }
  }

  // SPA route changes. The two halves need different worlds: pushState and
  // replaceState are patches, popstate is a listener.
  if (window.history) {
    for (const hname of ["pushState", "replaceState"]) {
      const original = history[hname];
      if (typeof original !== "function") continue;
      history[hname] = disguise(function (state, title, url) {
        guard("runtime_history", () => {
          emit("runtime_history", {
            via: hname,
            url: url ? String(new URL(url, location.href)) : null,
            from: location.href,
            stack: captureStack(0),
          });
        });
        return original.apply(this, arguments);
      }, original);
    }
  }

  // --- EventSource / SSE --------------------------------------------------
  // Playwright surfaces an SSE stream as one long-lived response whose body
  // never resolves, so incremental messages are only observable from here.
  if (typeof window.EventSource === "function") {
    const NativeES = window.EventSource;
    function ObservedEventSource(url, config) {
      const es = new NativeES(url, config);
      const absolute = url ? String(new URL(url, location.href)) : null;
      guard("sse_open", () => {
        emit("sse_open", { url: absolute, with_credentials: !!(config && config.withCredentials) });
      });
      es.addEventListener("open", () => {
        guard("sse_open_event", () => emit("sse_open", { url: absolute, phase: "opened" }));
      });
      es.addEventListener("error", () => {
        guard("sse_error", () => emit("sse_error", { url: absolute, ready_state: es.readyState }));
      });
      es.addEventListener("message", (ev) => {
        guard("sse_message", () => emit("sse_message", {
          url: absolute,
          event: "message",
          data: clip(String(ev.data)),
          last_event_id: ev.lastEventId || null,
        }));
      });
      // Named events do not arrive on "message"; wrap addEventListener so any
      // event type the application subscribes to is observed too.
      const nAdd = es.addEventListener.bind(es);
      es.addEventListener = function (type, listener, opts) {
        if (type !== "message" && type !== "open" && type !== "error") {
          nAdd(type, (ev) => {
            guard("sse_named", () => emit("sse_message", {
              url: absolute,
              event: type,
              data: clip(String(ev.data)),
              last_event_id: ev.lastEventId || null,
            }));
          });
        }
        return nAdd(type, listener, opts);
      };
      return es;
    }
    ObservedEventSource.prototype = NativeES.prototype;
    for (const k of ["CONNECTING", "OPEN", "CLOSED"]) ObservedEventSource[k] = NativeES[k];
    window.EventSource = disguise(ObservedEventSource, NativeES);
  }

  // --- storage writes -----------------------------------------------------
  guard("storage_hooks", () => {
    if (!window.Storage || !Storage.prototype) return;
    const which = (store) => (store === window.sessionStorage ? "sessionStorage" : "localStorage");
    const nSet = Storage.prototype.setItem;
    const nRemove = Storage.prototype.removeItem;
    const nClear = Storage.prototype.clear;

    Storage.prototype.setItem = disguise(function setItem(key, value) {
      guard("storage_set", () => emit("storage_change", {
        store: which(this), op: "set", key: String(key),
        value_length: value == null ? 0 : String(value).length,
        value: clip(String(value)),
      }));
      return nSet.apply(this, arguments);
    }, nSet);

    Storage.prototype.removeItem = disguise(function removeItem(key) {
      guard("storage_remove", () => emit("storage_change", {
        store: which(this), op: "remove", key: String(key),
      }));
      return nRemove.apply(this, arguments);
    }, nRemove);

    Storage.prototype.clear = disguise(function clear() {
      guard("storage_clear", () => emit("storage_change", { store: which(this), op: "clear" }));
      return nClear.apply(this, arguments);
    }, nClear);
  });

  // A marker the driver can assert from Python: proof the patches landed in
  // the world the application actually calls, instead of assuming they did.
  window.__scriptscrapPatched = {
    fetch: !!(window.fetch && window.fetch.__scriptscrapWrapped),
    xhr_send: !!(window.XMLHttpRequest && XMLHttpRequest.prototype
                 && XMLHttpRequest.prototype.send
                 && XMLHttpRequest.prototype.send.__scriptscrapWrapped),
    history: !!(window.history && history.pushState
                && history.pushState.__scriptscrapWrapped),
    storage: !!(window.Storage && Storage.prototype && Storage.prototype.setItem
                && Storage.prototype.setItem.__scriptscrapWrapped),
  };

  }  // end role "main"

  // --- DOM mutations ------------------------------------------------------
  // Emitted as bounded batches rather than accumulated in a page-side array,
  // so a navigation cannot destroy what was already observed.
  let mutationBatch = [];
  let mutationTimer = null;

  function flushMutations() {
    mutationTimer = null;
    if (!mutationBatch.length) return;
    const batch = mutationBatch.slice(0, CFG.maxMutationsPerBatch);
    const overflow = mutationBatch.length - batch.length;
    mutationBatch = [];
    emit("dom_mutation", {
      count: batch.length,
      overflow: overflow > 0 ? overflow : 0,
      mutations: batch,
    });
  }

  function startObserver() {
    if (!document.body || !window.MutationObserver) return;
    try {
      const observer = new MutationObserver((records) => {
        for (const m of records) {
          if (mutationBatch.length >= CFG.maxMutationsPerBatch * 4) break;
          const target = m.target;
          mutationBatch.push({
            type: m.type,
            target: target && target.nodeType === 1
              ? {
                  tag: target.tagName.toLowerCase(),
                  id: target.id || null,
                  class: target.getAttribute ? clip(target.getAttribute("class")) : null,
                }
              : null,
            attribute: m.attributeName || null,
            added: m.addedNodes ? m.addedNodes.length : 0,
            removed: m.removedNodes ? m.removedNodes.length : 0,
          });
        }
        if (mutationTimer === null) mutationTimer = setTimeout(flushMutations, 250);
      });
      observer.observe(document.body, {
        childList: true, subtree: true, attributes: true, characterData: false,
      });
    } catch (e) {
      emit("sensor_error", { where: "mutation_observer", error: safeError(e) });
    }
  }

  if (!IS_MAIN) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", startObserver, { once: true });
    } else {
      startObserver();
    }

    // popstate is a LISTENER, so it belongs with the shared-DOM half. Its
    // partner patches (pushState/replaceState) live in the main role. When
    // this fired and they did not, that asymmetry was the clearest single
    // signal that world isolation had come back.
    window.addEventListener("popstate", () => {
      guard("runtime_history_pop", () => {
        emit("runtime_history", { via: "popstate", url: location.href, from: null, stack: [] });
      });
    }, { passive: true });

    // --- lifecycle flushes ------------------------------------------------
    // The fix for M1's biggest data-loss problem: everything observed before a
    // navigation is pushed out before the document is torn down.
    window.addEventListener("pagehide", () => {
      guard("pagehide_flush", () => { flushMutations(); flush(true); });
    }, { capture: true });

    window.addEventListener("beforeunload", () => {
      guard("beforeunload_flush", () => { flushMutations(); flush(true); });
    }, { capture: true });

    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "hidden") {
        guard("visibility_flush", () => { flushMutations(); flush(true); });
      }
    }, { capture: true });

    // Python calls this to drain anything still buffered.
    window.__scriptscrapDrain = function () {
      flushMutations();
      flush(true);
      return true;
    };
  }
})();
