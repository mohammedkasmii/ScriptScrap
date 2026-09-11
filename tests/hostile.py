"""The hostile-string corpus.

Every string a target application could put where ScriptScrap will read it. A
plain module rather than a fixture, so both the generator tests and the export
tests import the same corpus and neither can drift.

pytest puts the tests directory on sys.path, so `import hostile` works.

The separator and format characters are built with `chr()` rather than written
as literal bytes. A literal U+2028 or U+202E in this file would make git treat
it as binary and would survive one normalising editor as something else; a
`chr()` call says exactly which code point is meant and keeps the source ASCII.
"""

from __future__ import annotations

MARKER = "hunter2 Passw0rd Marie Dupont 4111111111111111"
"""A value no redaction rule can love: spaces, digits, a name, a card number."""

LINE_SEPARATOR = chr(0x2028)
PARAGRAPH_SEPARATOR = chr(0x2029)
RIGHT_TO_LEFT_OVERRIDE = chr(0x202E)
ZERO_WIDTH_SPACE = chr(0x200B)

HOSTILE: dict[str, str] = {
    "newline": "a\nb",
    "cr": "a\rb",
    "crlf": "a\r\nb",
    "tab": "a\tb",
    "double_quote": 'a"b',
    "single_quote": "a'b",
    "both_quotes": "it's \"both\"",
    "backslash": "a\\b",
    "trailing_backslash": "ab\\",
    "triple_quote": 'a"""b',
    "brace": "a{b}c",
    "open_brace": "a{b",
    "fstring_expr": "a{__import__('os').getcwd()}b",
    "hash_comment": "a # b",
    "docstring_break": 'x"""\n\nimport os\nos.getcwd()\n"""',
    "statement_break": 'x")\nimport os\nif 0: y("',
    "nul": "a\x00b",
    "bell": "a\x07b",
    "line_sep": "a" + LINE_SEPARATOR + "b",
    "para_sep": "a" + PARAGRAPH_SEPARATOR + "b",
    "bidi_override": "a" + RIGHT_TO_LEFT_OVERRIDE + "b",
    "zero_width": "a" + ZERO_WIDTH_SPACE + "b",
    "emoji": "a\U0001f600b",
    "empty": "",
    "only_space": "   ",
}
