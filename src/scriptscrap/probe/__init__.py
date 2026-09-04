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


@lru_cache(maxsize=1)
def probe_source() -> str:
    return files(__package__).joinpath("probe.js").read_text(encoding="utf-8")


def build_init_script(config: dict[str, Any] | None = None) -> str:
    """The probe plus its configuration, as one document_start init script."""
    prelude = ""
    if config:
        prelude = f"window.__scriptscrapConfig = {json.dumps(config)};\n"
    return prelude + probe_source()


__all__ = ["BINDING_NAME", "DRAIN_FUNCTION", "build_init_script", "probe_source"]
