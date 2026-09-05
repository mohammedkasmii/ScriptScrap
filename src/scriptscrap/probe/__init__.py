"""The injected runtime probe.

`probe.js` is shipped as data rather than a Python string so it stays readable,
diffable and editable as JavaScript.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from typing import Any

BINDING_NAME = "__scriptscrapEmit"
DRAIN_FUNCTION = "__scriptscrapDrain"
# Set by the main-world role once its patches are in place. Read back from
# Python as the runtime self-test.
PATCH_MARKER = "__scriptscrapPatched"


@lru_cache(maxsize=1)
def probe_source() -> str:
    return files(__package__).joinpath("probe.js").read_text(encoding="utf-8")


def build_init_script(config: dict[str, Any] | None = None) -> str:
    """The probe plus its configuration, as one document_start init script.

    This is the ISOLATED half: listeners, the MutationObserver and the binding
    that carries everything to Python.
    """
    prelude = ""
    if config:
        prelude = f"window.__scriptscrapConfig = {json.dumps(config)};\n"
    return prelude + probe_source()


def build_main_world_script(config: dict[str, Any] | None = None) -> str:
    """The same probe in its `main` role, as a single EXPRESSION.

    Camoufox reaches the page's own JavaScript world only through
    `evaluate("mw:" + script)`, and an evaluate argument must be one
    expression -- so the config assignment and the probe are wrapped together
    in an arrow call rather than concatenated as two statements.
    """
    settings = {**(config or {}), "role": "main"}
    return (
        "(() => {\n"
        f"window.{'__scriptscrapConfig'} = {json.dumps(settings)};\n"
        f"{probe_source()}\n"
        f"return window.{PATCH_MARKER} || null;\n"
        "})()"
    )


__all__ = ["BINDING_NAME", "DRAIN_FUNCTION", "PATCH_MARKER",
           "build_init_script", "build_main_world_script", "probe_source"]
