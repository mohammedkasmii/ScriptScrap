"""The emitter is the only place a captured value becomes Python source.

Every test here is a property over the whole hostile corpus, not a spot check:
the audit's F3 was found because one site (`_comment_safe`) had been hardened
and four others had not.
"""

from __future__ import annotations

import pytest
from hostile import HOSTILE, RIGHT_TO_LEFT_OVERRIDE, ZERO_WIDTH_SPACE

from scriptscrap.generate.emit import (
    GeneratedSourceError,
    assert_compiles,
    py_comment,
    py_docstring,
    py_identifier,
    py_path_expression,
    py_str,
)


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_py_str_round_trips_and_stays_on_one_line(name):
    """A literal that spans lines breaks the indentation of the block it is in."""
    value = HOSTILE[name]
    literal = py_str(value)
    assert "\n" not in literal and "\r" not in literal
    assert "\x00" not in literal
    namespace: dict = {}
    exec(compile(f"X = {literal}\n", "<gen>", "exec"), namespace)  # noqa: S102
    assert namespace["X"] == value


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_py_str_is_inert_inside_a_generated_call(name):
    """The literal must not be able to close the call it sits in."""
    source = f"def f():\n    return g({py_str(HOSTILE[name])})\n"
    compile(source, "<gen>", "exec")


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_py_comment_is_one_safe_comment_line(name):
    comment = py_comment(HOSTILE[name])
    source = f"def f():\n    # {comment}\n    return 1\n"
    compile(source, "<gen>", "exec")
    assert "\n" not in comment
    assert all(ord(ch) >= 0x20 and ord(ch) != 0x7F for ch in comment)


def test_py_comment_strips_bidi_and_zero_width_characters():
    """A comment is read by a human; a bidi override makes it lie to them."""
    assert RIGHT_TO_LEFT_OVERRIDE not in py_comment("a" + RIGHT_TO_LEFT_OVERRIDE + "b")
    assert ZERO_WIDTH_SPACE not in py_comment("a" + ZERO_WIDTH_SPACE + "b")


def test_py_comment_truncates_with_ascii():
    long = "word " * 100
    assert len(py_comment(long, limit=20)) <= 20
    assert py_comment(long, limit=20).endswith("...")


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_py_docstring_refuses_anything_that_is_not_tool_text(name):
    """Captured values never reach a docstring; this is the backstop."""
    value = HOSTILE[name]
    if value.isprintable() and '"""' not in value and "\\" not in value:
        pytest.skip("this shape is indistinguishable from tool text")
    with pytest.raises(GeneratedSourceError):
        py_docstring(["ok", value])


def test_py_docstring_builds_a_closed_docstring():
    body = py_docstring(["Line one.", "", "Line two."], indent="    ")
    source = f"def f():\n{body}\n    return 1\n"
    compile(source, "<gen>", "exec")


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_py_identifier_is_always_a_valid_unique_identifier(name):
    taken: set[str] = set()
    first = py_identifier(HOSTILE[name], taken=taken)
    second = py_identifier(HOSTILE[name], taken=taken)
    assert first.isidentifier() and second.isidentifier()
    assert first != second, "a repeated input must not collide"
    compile(f"def {first}(): pass\ndef {second}(): pass\n", "<gen>", "exec")


def test_py_identifier_avoids_keywords_and_leading_digits():
    taken: set[str] = set()
    assert py_identifier("class", taken=taken) == "class_"
    assert py_identifier("404", taken=taken).isidentifier()


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_py_path_expression_never_evaluates_the_template(name):
    """`f"{captured}"` made the template executable. Concatenation cannot."""
    template = "/x/" + HOSTILE[name] + "/{id}/y"
    expression = py_path_expression(template, [("id", "item_id")])
    source = f"def f(item_id):\n    return {expression}\n"
    namespace: dict = {}
    exec(compile(source, "<gen>", "exec"), namespace)  # noqa: S102
    assert namespace["f"]("7") == "/x/" + HOSTILE[name] + "/7/y"


def test_assert_compiles_raises_on_broken_source():
    with pytest.raises(GeneratedSourceError) as excinfo:
        assert_compiles("def f(:\n", filename="broken.py")
    assert "broken.py" in str(excinfo.value)


def test_assert_compiles_returns_the_source_unchanged():
    source = "X = 1\n"
    assert assert_compiles(source, filename="ok.py") is source
