"""Lightweight inventory of captured JavaScript source.

Regex over text, deliberately. A real parser would be more accurate and would
also be the beginning of a JavaScript reverse-engineering framework, which is
explicitly out of scope. What this needs to answer is narrow:

    what functions does this file declare?
    what URLs does it reference?
    does it reach the network, and how?
    is there a source map?

That is enough to make captured source searchable and to tell an investigator
which file to open. Anything deeper is a job for a human with the blob.

Every result is evidence about TEXT, never about behaviour: a function listed
here may never run, and a URL literal may never be requested.
"""

from __future__ import annotations

import re
from typing import Any

MAX_ITEMS = 60

_FUNC_DECL = re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(")
_FUNC_ASSIGN = re.compile(r"\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\b")
_ARROW_ASSIGN = re.compile(r"\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>")
_CLASS_DECL = re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)")
_GLOBAL_ASSIGN = re.compile(r"\bwindow\.([A-Za-z_$][\w$]*)\s*=")

_URL_LITERAL = re.compile(r"""["'`](https?://[^"'`\s]{4,200}|/[A-Za-z0-9_\-./]{2,120})["'`]""")
_SOURCE_MAP = re.compile(r"[#@]\s*sourceMappingURL=([^\s'\"*]+)")

_NETWORK_APIS = (
    ("fetch", re.compile(r"\bfetch\s*\(")),
    ("XMLHttpRequest", re.compile(r"\bXMLHttpRequest\b")),
    ("WebSocket", re.compile(r"\bnew\s+WebSocket\b")),
    ("EventSource", re.compile(r"\bnew\s+EventSource\b")),
    ("sendBeacon", re.compile(r"\bsendBeacon\s*\(")),
    ("form.submit", re.compile(r"\.submit\s*\(\s*\)")),
)

# Path-ish literals that are almost always assets, not endpoints.
_ASSET_SUFFIX = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                 ".woff", ".woff2", ".ttf", ".map")


def _unique(values, limit: int = MAX_ITEMS) -> list[str]:
    seen: list[str] = []
    for value in values:
        if value not in seen:
            seen.append(value)
        if len(seen) >= limit:
            break
    return seen


def summarise_source(source: str) -> dict[str, Any]:
    """Inventory one script. Never raises; a bad regex result is not worth a crash."""
    if not isinstance(source, str):
        return {}

    functions = _unique(
        m.group(1)
        for pattern in (_FUNC_DECL, _FUNC_ASSIGN, _ARROW_ASSIGN)
        for m in pattern.finditer(source)
    )
    classes = _unique(m.group(1) for m in _CLASS_DECL.finditer(source))
    globals_assigned = _unique(m.group(1) for m in _GLOBAL_ASSIGN.finditer(source))

    literals = [m.group(1) for m in _URL_LITERAL.finditer(source)]
    endpoints = _unique(
        u for u in literals if not u.lower().endswith(_ASSET_SUFFIX)
    )

    network = [name for name, pattern in _NETWORK_APIS if pattern.search(source)]
    source_map = _SOURCE_MAP.search(source)

    return {
        "size": len(source),
        "lines": source.count("\n") + 1,
        "declared_functions": functions,
        "declared_classes": classes,
        "window_assignments": globals_assigned,
        "url_literals": endpoints,
        "network_apis": network,
        "source_map": source_map.group(1) if source_map else None,
        "note": (
            "Static inventory of source TEXT. A listed function may never run "
            "and a URL literal may never be requested."
        ),
    }


def find_parse_time_calls(source: str, names: list[str]) -> list[str]:
    """Names that are both declared and called at top level in this file.

    This is the shape that defeats injected instrumentation: by the time any
    wrapper can replace the function, the call has already happened. Detecting
    it in captured source is how the forensic layer reports the blind spot it
    cannot otherwise close.
    """
    depths = _brace_depths(source)
    found: list[str] = []
    for name in names:
        declared = re.search(rf"\bfunction\s+{re.escape(name)}\s*\(", source)
        if not declared:
            continue
        # A call to it at brace depth zero, i.e. in the file's top-level body,
        # which runs during the same parse that defines it. Position matters,
        # not line layout: `window.x = theFunction()` is still a top-level call.
        #
        # An explicit global receiver counts as a call to the same function:
        # `window.doThing()` IS `doThing()`. Only that receiver is admitted --
        # a bare `.` lookbehind would also match `someObject.doThing()`, which
        # is a different function that happens to share a name. Leaving the
        # `window.` form out meant the commonest way legacy code invokes its
        # own globals was read as "not called at parse time".
        pattern = (rf"(?<![.\w${{])(?:(?:window|globalThis|self)\s*\.\s*)?"
                   rf"{re.escape(name)}\s*\(")
        for call in re.finditer(pattern, source):
            if call.start() <= declared.end():
                continue          # the declaration itself
            if depths[call.start()] == 0:
                found.append(name)
                break
    return found


def _brace_depths(source: str) -> list[int]:
    """Brace nesting depth at every character offset.

    A counter, not a parser: braces inside strings, template literals and
    regex literals are not excluded. That is accurate enough to tell top-level
    statements from function bodies, and stops well short of the JavaScript
    parser this module deliberately does not contain.
    """
    depths = [0] * (len(source) + 1)
    depth = 0
    for index, char in enumerate(source):
        if char == "{":
            depths[index] = depth
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
            depths[index] = depth
        else:
            depths[index] = depth
    depths[len(source)] = depth
    return depths
