"""One definition of "this path segment is data, not a route name".

Two places decide whether a URL segment is an identifier -- endpoint grouping
and state identity -- and they must agree. When the rule lived in both files it
diverged in effect: a real capture of a public demo site collapsed six distinct
static routes (`/radio-buttons`, `/drag-and-drop`, `/key-presses`, ...) into a
single `/{id}` state, while endpoint templating, running the same rule, escaped
only because a sibling-variance gate happened to reject the same segments.

The rule that failed treated ANY hyphenated word as a code. Route names are
hyphenated far more often than identifiers are, so the discriminator is a
DIGIT: `ITEM-0001` is data, `radio-buttons` is a page. That is deliberately
conservative -- a digitless identifier stays literal, which shows up as an
extra concrete path rather than as a destroyed route.
"""

from __future__ import annotations

import re

NUMERIC_RE = re.compile(r"^\d+$")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
LONG_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
# e.g. ITEM-0001, M-FIXTURE-0001. The digit is load-bearing: without it this
# matches every kebab-case route name in existence.
CODE_RE = re.compile(r"^[A-Za-z]{1,12}[-_][A-Za-z0-9_-]*\d[A-Za-z0-9_-]*$")


def identifier_kind(segment: str) -> str | None:
    """Name the identifier kind, or None if this looks like a fixed route word."""
    if NUMERIC_RE.match(segment):
        return "integer"
    if UUID_RE.match(segment):
        return "uuid"
    if LONG_HEX_RE.match(segment):
        return "hash"
    if CODE_RE.match(segment):
        return "code"
    return None
