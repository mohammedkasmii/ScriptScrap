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


INSTALL_FLAG = "__scriptscrapProbeInstalled"


def build_isolated_reinstall_script(config: dict[str, Any] | None = None) -> str:
    """The isolated probe, forced to install NOW in the current document.

    Camoufox's context-level init script defines the probe's globals in a
    popup's isolated world but its DOM listeners do not take effect there --
    verified empirically: a popup's fill fires a manually-added isolated
    listener but never the probe's own. Re-evaluating the probe into the live
    document DOES attach working listeners. The install flag is cleared first so
    the guard at the top of the probe does not short-circuit, and this is
    evaluated per main-frame navigation of a non-initial page: each navigation
    is a fresh document, so exactly one probe attaches per document -- no
    duplicate observers accumulate.
    """
    # The counter is a deterministic signal that the re-arm actually executed
    # in this document -- distinct from the install flag, which the context init
    # script also sets. A caller (or a test) can wait for it to know the working
    # listeners are attached before driving the page.
    prelude = (
        f"try {{ delete window.{INSTALL_FLAG}; "
        f"window.__scriptscrapRearmCount = (window.__scriptscrapRearmCount || 0) + 1; "
        f"}} catch (e) {{}}\n"
    )
    return prelude + build_init_script(config)


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


__all__ = ["BINDING_NAME", "DRAIN_FUNCTION", "INSTALL_FLAG", "PATCH_MARKER",
           "build_init_script", "build_isolated_reinstall_script",
           "build_main_world_script", "probe_source"]
