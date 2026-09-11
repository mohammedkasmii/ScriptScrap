"""URL reduction at the engagement boundary.

Every sensor that emits a URL needs this, so it lives here rather than inside
one of them.

The rule is the same on every observation path: **out of scope means metadata
only.** An investigation is authorised against particular hosts. A third-party
script's URL parameters, an ad frame's tracking query, an SSO redirect carrying
a token -- none of those are the engagement's to record, and a capture that
keeps them has quietly widened its own scope.

The event itself is never dropped. "A third-party call happened here" is a real
forensic fact, and losing it would make an out-of-scope page look silent.

History: this began as private helpers in `runtime.py`. A real capture of a
public demo site recorded 722 runtime network observations, 504 of them out of
scope and 213 carrying full query strings, because the scope check ran against
the FRAME while the request target was somebody else's analytics endpoint. The
same class of leak was then found in `lifecycle.py`, which emitted `frame.url`
and `page.url` verbatim -- which is what moved this into a shared module.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

# Payload keys that hold a URL. Any of them is stripped of query and fragment
# when its own host is out of scope, wherever it appears.
URL_PAYLOAD_KEYS = ("url", "action", "from", "frame_url")

# Everything a reduced (out-of-scope) event may keep. An allowlist, because a
# denylist silently admits every payload key added later.
REDUCED_KEEP_KEYS = frozenset({
    "method", "status", "via", "op", "store", "async", "count", "overflow",
    "probe_ordinal", "probe_world", "probe_time_ms", "probe_time_origin",
    "is_top_frame",
})

# A URL inside a stack frame, e.g. `handler@https://host/app.js?v=3:12:5`.
_STACK_URL = re.compile(r"https?://[^\s)]+")


def strip_query(url: str) -> str:
    """`https://h/p?a=secret#frag` -> `https://h/p`. Origin and path survive."""
    parsed = urlsplit(url)
    if not parsed.scheme and not parsed.netloc:
        return url.split("?", 1)[0].split("#", 1)[0]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def redact_stack_frame(scope: Any, frame: Any) -> Any:
    """Strip query values from any out-of-scope script URL inside a stack frame.

    A stack is the evidence for WHICH code made a call, and that is worth
    keeping. The parameters on a third-party script's URL are not.
    """
    if not isinstance(frame, str):
        return frame

    def replace(match: re.Match) -> str:
        # A frame is `...url:line:column`; the trailing position is not part of
        # the URL and must survive the strip.
        raw = match.group(0)
        position = ""
        while raw and raw[-1].isdigit():
            head, _, tail = raw.rpartition(":")
            if not head or not tail.isdigit():
                break
            position = ":" + tail + position
            raw = head
        return (raw if scope.contains(raw) else strip_query(raw)) + position

    return _STACK_URL.sub(replace, frame)
