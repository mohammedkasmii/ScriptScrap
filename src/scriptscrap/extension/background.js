/*
 * ScriptScrap forensic extension - background page.
 *
 * Observes what Playwright and page JavaScript cannot:
 *
 *   - response BODIES, via webRequest.filterResponseData (Firefox-only), which
 *     works where Playwright's response.body() throws: redirects, evicted
 *     bodies, responses navigated away from;
 *   - every request type, including ones with no page-JS surface;
 *   - Set-Cookie preserved as separate headers, plus the real cookie jar
 *     including httpOnly, which page script can never read;
 *   - script source BEFORE Firefox parses it, which is the only way to see a
 *     function that is declared and called in the same parse.
 *
 * THE PRIME DIRECTIVE, same as the page probe: never become the reason the
 * application behaves differently.
 *
 *   - filterResponseData ALWAYS writes the original bytes through unchanged
 *     and ALWAYS disconnects. A filter that throws or forgets to close hangs
 *     the request forever, which would break the site being investigated.
 *   - webRequest listeners are observational; nothing is blocked or rewritten
 *     unless source rewriting was explicitly enabled by the operator.
 *   - Out-of-scope traffic is reduced to metadata before it leaves the browser.
 */
"use strict";

const CFG = Object.assign(
  {
    port: 0,
    scopeHosts: [],
    maxBodyBytes: 2 * 1024 * 1024,
    captureBodies: true,
    captureScripts: true,
    rewriteTargets: [],      // [{ script: "substring", functions: ["name"] }]
    flushIntervalMs: 300,
    maxBuffer: 400,
  },
  self.__scriptscrapExtensionConfig || {}
);

let socket = null;
let buffer = [];
let dropped = 0;
let ordinal = 0;
let timer = null;
let connected = false;

// --- transport ----------------------------------------------------------

function connect() {
  if (!CFG.port) return;
  try {
    socket = new WebSocket("ws://127.0.0.1:" + CFG.port + "/extension");
  } catch (e) {
    return;
  }
  socket.onopen = function () {
    connected = true;
    emit("forensic_sensor_started", {
      capabilities: capabilities(),
      config: {
        capture_bodies: CFG.captureBodies,
        capture_scripts: CFG.captureScripts,
        max_body_bytes: CFG.maxBodyBytes,
        rewrite_targets: CFG.rewriteTargets.length,
        scope_hosts: CFG.scopeHosts,
      },
    });
    flush();
  };
  socket.onclose = function () {
    connected = false;
    // Reconnect: losing the socket must lose evidence, not the session.
    setTimeout(connect, 500);
  };
  socket.onerror = function () { connected = false; };
}

function capabilities() {
  return {
    filter_response_data: typeof browser !== "undefined" &&
      !!(browser.webRequest && browser.webRequest.filterResponseData),
    cookies: typeof browser !== "undefined" && !!browser.cookies,
    web_navigation: typeof browser !== "undefined" && !!browser.webNavigation,
    manifest_version: (browser.runtime.getManifest() || {}).manifest_version,
  };
}

function emit(type, payload) {
  if (buffer.length >= CFG.maxBuffer) { dropped++; flush(); if (buffer.length >= CFG.maxBuffer) return; }
  buffer.push({ type: type, ordinal: ++ordinal, t_wall: Date.now(), payload: payload || {} });
  if (buffer.length >= CFG.maxBuffer) flush();
  else if (timer === null) timer = setTimeout(function () { timer = null; flush(); }, CFG.flushIntervalMs);
}

function flush() {
  if (!connected || !socket || socket.readyState !== 1 || !buffer.length) return;
  const batch = buffer;
  buffer = [];
  if (dropped) {
    batch.push({ type: "sensor_error", ordinal: ++ordinal, t_wall: Date.now(),
                 payload: { where: "extension_buffer", error: "overflow", dropped: dropped } });
    dropped = 0;
  }
  try {
    socket.send(JSON.stringify(batch));
  } catch (e) {
    dropped += batch.length;
  }
}

// --- scope ---------------------------------------------------------------

function hostOf(url) {
  try { return new URL(url).hostname; } catch (e) { return null; }
}

function isOwnTransport(url) {
  // The sensor's own loopback channel shares a host with the target, so
  // without this the extension observes itself and reports its own evidence
  // stream as application traffic.
  return typeof url === "string" && url.indexOf(":" + CFG.port + "/extension") !== -1;
}

function inScope(url) {
  if (isOwnTransport(url)) return false;
  const host = hostOf(url);
  if (!host) return false;
  if (!CFG.scopeHosts.length) return false;
  return CFG.scopeHosts.some(function (root) {
    return host === root || host.endsWith("." + root);
  });
}

function headerList(headers) {
  // Kept as a LIST, not an object: multiple Set-Cookie headers are the reason
  // this sensor exists, and an object would collapse them.
  return (headers || []).map(function (h) { return { name: h.name, value: h.value }; });
}

// --- request lifecycle ---------------------------------------------------

const pending = new Map();   // requestId -> { url, method, type, scoped }

browser.webRequest.onBeforeRequest.addListener(
  function (details) {
    if (isOwnTransport(details.url)) return {};   // never observe ourselves
    const scoped = inScope(details.url);
    pending.set(details.requestId, {
      url: details.url, method: details.method, type: details.type, scoped: scoped,
    });

    emit("extension_request", {
      request_id: details.requestId,
      method: details.method,
      url: scoped ? details.url : stripUrl(details.url),
      resource_type: details.type,
      tab_id: details.tabId,
      frame_id: details.frameId,
      parent_frame_id: details.parentFrameId,
      origin_url: scoped ? details.originUrl : undefined,
      document_url: scoped ? details.documentUrl : undefined,
      in_scope: scoped,
      // requestBody exists only with the extraInfoSpec below; formData covers
      // urlencoded and multipart, raw covers everything else including JSON.
      body: scoped ? describeBody(details.requestBody) : undefined,
    });
    return {};
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

function stripUrl(url) {
  // Out of scope: host and path only. A query string routinely carries
  // identifiers and credentials, and this is third-party traffic.
  try {
    const u = new URL(url);
    return u.origin + u.pathname;
  } catch (e) { return "(unparseable)"; }
}

function describeBody(body) {
  if (!body) return null;
  if (body.error) return { kind: "error", error: body.error };
  if (body.formData) {
    return { kind: "formData", fields: Object.keys(body.formData) };
  }
  if (body.raw && body.raw.length) {
    let size = 0;
    let text = null;
    try {
      const parts = [];
      for (const chunk of body.raw) {
        if (chunk.bytes) {
          size += chunk.bytes.byteLength;
          parts.push(new TextDecoder("utf-8", { fatal: false }).decode(chunk.bytes));
        } else if (chunk.file) {
          parts.push("<file:" + chunk.file + ">");
        }
      }
      text = parts.join("");
      if (text.length > 16384) text = text.slice(0, 16384) + "…[truncated]";
    } catch (e) { text = null; }
    return { kind: "raw", size: size, text: text };
  }
  return { kind: "empty" };
}

browser.webRequest.onSendHeaders.addListener(
  function (details) {
    if (isOwnTransport(details.url)) return;
    const entry = pending.get(details.requestId);
    if (!entry || !entry.scoped) return;
    emit("extension_request_headers", {
      request_id: details.requestId,
      url: details.url,
      headers: headerList(details.requestHeaders),
    });
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

browser.webRequest.onBeforeRedirect.addListener(
  function (details) {
    if (isOwnTransport(details.url)) return;
    emit("extension_redirect", {
      request_id: details.requestId,
      from_url: inScope(details.url) ? details.url : stripUrl(details.url),
      to_url: inScope(details.redirectUrl) ? details.redirectUrl : stripUrl(details.redirectUrl),
      status: details.statusCode,
    });
  },
  { urls: ["<all_urls>"] }
);

browser.webRequest.onErrorOccurred.addListener(
  function (details) {
    if (isOwnTransport(details.url)) return;
    pending.delete(details.requestId);
    emit("extension_request_failed", {
      request_id: details.requestId,
      url: inScope(details.url) ? details.url : stripUrl(details.url),
      error: details.error,
    });
  },
  { urls: ["<all_urls>"] }
);

// --- response headers + body ---------------------------------------------

browser.webRequest.onHeadersReceived.addListener(
  function (details) {
    if (isOwnTransport(details.url)) return {};
    const entry = pending.get(details.requestId) || {};
    const scoped = entry.scoped !== undefined ? entry.scoped : inScope(details.url);

    emit("extension_response", {
      request_id: details.requestId,
      url: scoped ? details.url : stripUrl(details.url),
      status: details.statusCode,
      status_line: details.statusLine,
      resource_type: details.type,
      from_cache: details.fromCache,
      ip: scoped ? details.ip : undefined,
      // Array form preserves repeated Set-Cookie headers, which an object
      // representation silently collapses.
      headers: scoped ? headerList(details.responseHeaders) : undefined,
      in_scope: scoped,
    });

    if (scoped && CFG.captureBodies) {
      captureBody(details);
    }
    return {};
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders", "blocking"]
);

function headerValue(headers, name) {
  const lower = name.toLowerCase();
  for (const h of headers || []) {
    if ((h.name || "").toLowerCase() === lower) return h.value;
  }
  return null;
}

function captureBody(details) {
  let filter;
  try {
    filter = browser.webRequest.filterResponseData(details.requestId);
  } catch (e) {
    emit("sensor_error", { where: "filterResponseData", error: String(e && e.message || e),
                           url: details.url });
    return;
  }

  const mediaType = headerValue(details.responseHeaders, "content-type") || "";
  const isScript = (details.type === "script") ||
                   mediaType.indexOf("javascript") !== -1;
  const chunks = [];
  let size = 0;
  let overflow = false;

  filter.ondata = function (event) {
    // ALWAYS pass the original bytes through first. Everything after this is
    // observation; if it throws, the response has already been delivered.
    filter.write(event.data);
    size += event.data.byteLength;
    if (overflow) return;
    if (size > CFG.maxBodyBytes) { overflow = true; chunks.length = 0; return; }
    chunks.push(event.data);
  };

  filter.onerror = function () {
    emit("sensor_error", { where: "filter_stream", error: filter.error || "unknown",
                           url: details.url, request_id: details.requestId });
    try { filter.disconnect(); } catch (e) { /* already gone */ }
  };

  filter.onstop = function () {
    // Disconnect FIRST and unconditionally. A body we fail to report is lost
    // evidence; a stream we fail to close is a hung request on a live site.
    try { filter.disconnect(); } catch (e) { /* already gone */ }

    if (overflow) {
      emit("response_body_skipped", {
        request_id: details.requestId, url: details.url, size: size,
        media_type: mediaType, reason: "configured_size_limit",
        limit: CFG.maxBodyBytes,
      });
      return;
    }
    try {
      const merged = concat(chunks, size);
      const text = new TextDecoder("utf-8", { fatal: false }).decode(merged);
      emit("response_body_captured", {
        request_id: details.requestId, url: details.url, size: size,
        media_type: mediaType, body_base64: toBase64(merged),
      });
      if (isScript && CFG.captureScripts) {
        emit("script_source", {
          request_id: details.requestId, url: details.url, size: size,
          media_type: mediaType, source: text,
          source_map: sourceMapRef(text),
        });
      }
    } catch (e) {
      emit("sensor_error", { where: "body_encode", error: String(e && e.message || e),
                             url: details.url });
    }
  };
}

function concat(chunks, size) {
  const out = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(new Uint8Array(chunk), offset);
    offset += chunk.byteLength;
  }
  return out;
}

function toBase64(bytes) {
  let binary = "";
  const step = 0x8000;
  for (let i = 0; i < bytes.length; i += step) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + step));
  }
  return btoa(binary);
}

function sourceMapRef(text) {
  const match = /[#@]\s*sourceMappingURL=([^\s'"]+)/.exec(text || "");
  return match ? match[1] : null;
}

// --- cookies -------------------------------------------------------------
// The change stream page JavaScript cannot have, including httpOnly.

if (browser.cookies && browser.cookies.onChanged) {
  browser.cookies.onChanged.addListener(function (change) {
    const cookie = change.cookie || {};
    if (!inScope("http://" + String(cookie.domain || "").replace(/^\./, ""))) return;
    emit(change.removed ? "cookie_deleted" : "cookie_changed", {
      name: cookie.name,
      domain: cookie.domain,
      path: cookie.path,
      secure: cookie.secure,
      http_only: cookie.httpOnly,
      same_site: cookie.sameSite,
      session: cookie.session,
      expiration: cookie.expirationDate || null,
      value_length: (cookie.value || "").length,
      value: cookie.value,
      cause: change.cause,
      removed: !!change.removed,
      visibility_source: "extension_cookie_api",
    });
  });
}

// --- navigation ----------------------------------------------------------

if (browser.webNavigation && browser.webNavigation.onCommitted) {
  browser.webNavigation.onCommitted.addListener(function (details) {
    if (!inScope(details.url)) return;
    emit("extension_navigation", {
      url: details.url, tab_id: details.tabId, frame_id: details.frameId,
      transition_type: details.transitionType,
      transition_qualifiers: details.transitionQualifiers,
    });
  });
}

connect();
