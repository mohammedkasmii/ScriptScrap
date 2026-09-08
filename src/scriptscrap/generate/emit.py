"""Turning captured values into Python source.

The one rule this module exists to enforce: **a captured string is data, never
syntax.** Every generator writes source by interpolating values that came from a
target application -- element text, a URL path, a form name -- and the audit
found four sites where that produced a file that did not compile and one where
it produced a file that executed the application's payload.

`repr()` is the escaping. It is Python's own inverse of the parser, it handles
quotes, backslashes, newlines, NUL, U+2028 and every control character, and it
is the only escaping this module trusts. Nothing here hand-rolls one.

Docstrings are the exception with no safe escape: a docstring's delimiter cannot
be escaped without changing what the reader sees, so captured values never enter
one. `py_docstring` refuses text it cannot prove is tool-generated -- that is a
backstop for the rule, not the rule itself.
"""

from __future__ import annotations

import keyword
import re
import unicodedata
from collections.abc import Sequence


class GeneratedSourceError(RuntimeError):
    """A generator was about to emit source that is not valid Python."""


# Control (Cc), format (Cf, which is where bidi overrides and zero-width joiners
# live), line separator (Zl) and paragraph separator (Zp). None of these belong
# in a comment a human reads, and several break the source outright.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})

# `\W` with re.ASCII, so a non-ASCII character becomes `_` rather than a valid
# but unreadable identifier character.
_NON_IDENTIFIER = re.compile(r"\W+", re.ASCII)


def py_str(value: object) -> str:
    """A Python string literal for any captured value.

    Verified against a 25-shape hostile corpus: every literal round-trips
    through `exec` and none contains a raw newline, CR or NUL.
    """
    literal = repr("" if value is None else str(value))
    if any(ch in literal for ch in ("\n", "\r", "\x00")):
        # repr is not expected to produce these. If it ever does, refusing is
        # the only safe answer -- a multi-line literal silently re-indents the
        # block it was emitted into.
        raise GeneratedSourceError(
            f"repr() produced a literal that is not single-line: {literal[:60]!r}")
    return literal


def py_comment(text: object, limit: int = 90) -> str:
    """Collapse a captured value to one safe `#` comment line.

    ASCII ellipsis, not the character: generated source is opened in whatever
    editor the reader has.
    """
    cleaned = "".join(
        " " if unicodedata.category(ch) in _UNSAFE_CATEGORIES else ch
        for ch in str(text)
    )
    flat = " ".join(cleaned.split())
    if len(flat) > limit:
        flat = flat[: max(0, limit - 3)] + "..."
    return flat


def py_docstring(lines: Sequence[str], indent: str = "    ") -> str:
    """A triple-quoted docstring built from tool-generated lines only.

    Raises rather than escaping. A docstring delimiter cannot be escaped without
    changing what the reader sees, so the answer to "can this captured value go
    in a docstring?" is always no.
    """
    for line in lines:
        if '"""' in line or "\\" in line or any(
            unicodedata.category(ch) in _UNSAFE_CATEGORIES for ch in line
        ):
            raise GeneratedSourceError(
                f"docstring line is not tool-generated text: {line[:60]!r}")
    body = f"\n{indent}".join(lines)
    return f'{indent}"""{body}\n{indent}"""'


def py_identifier(raw: str, *, taken: set[str], prefix: str = "call") -> str:
    """A valid, unique Python identifier. Mutates `taken`."""
    cleaned = _NON_IDENTIFIER.sub("_", str(raw)).strip("_").lower()
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"{prefix}_{cleaned}".strip("_")
    if keyword.iskeyword(cleaned) or keyword.issoftkeyword(cleaned):
        cleaned = f"{cleaned}_"
    candidate, suffix = cleaned, 1
    while candidate in taken:
        suffix += 1
        candidate = f"{cleaned}_{suffix}"
    taken.add(candidate)
    return candidate


def py_path_expression(template: str, holes: Sequence[tuple[str, str]]) -> str:
    """`/items/{id}/notes` -> `'/items/' + str(item_id) + '/notes'`.

    An f-string would make the template executable: a captured `{...}` becomes
    an expression the generated client evaluates. Concatenation of `repr()`
    literals cannot.
    """
    parts: list[str] = []
    remaining = str(template)
    for raw, argument in holes:
        head, separator, remaining = remaining.partition("{" + raw + "}")
        if not separator:
            raise GeneratedSourceError(
                f"path hole {raw!r} is not present in {template!r}")
        parts.append(py_str(head))
        parts.append(f"str({argument})")
    parts.append(py_str(remaining))
    return " + ".join(parts)


def assert_compiles(source: str, *, filename: str) -> str:
    """Refuse to hand back source that is not valid Python.

    A generator that writes a file the reader cannot run has failed, and it
    should say so at generation time rather than at `python observed_workflow.py`.
    """
    try:
        compile(source, filename, "exec")
    except (SyntaxError, ValueError) as exc:
        raise GeneratedSourceError(
            f"{filename} would not compile: {type(exc).__name__}: {exc}") from exc
    return source
