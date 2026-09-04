"""Builds the unpacked extension directory Camoufox loads.

Camoufox accepts `addons=[path]` where path is a DIRECTORY containing
`manifest.json`, and installs it through Firefox's temporary-addon path, which
skips signature enforcement. The addon is re-installed on every launch and does
not persist, which suits a forensic sensor: nothing is left behind in a profile.

The extension needs to know the loopback port and the investigation scope, and
a background script cannot be given arguments. So the built directory gets a
generated `config.js` that the manifest loads before `background.js`.

MV2 is deliberate. Firefox still supports it, and it keeps a persistent
background page plus blocking `webRequest` -- which `filterResponseData`
requires -- without MV3's service-worker lifecycle.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from importlib.resources import files
from pathlib import Path
from typing import Any

MANIFEST = "manifest.json"
BACKGROUND = "background.js"
CONFIG = "config.js"

# Files copied verbatim from the package into the built directory.
_STATIC = (MANIFEST, BACKGROUND)


def build_extension(
    *,
    port: int,
    scope_hosts: list[str],
    max_body_bytes: int = 2 * 1024 * 1024,
    capture_bodies: bool = True,
    capture_scripts: bool = True,
    rewrite_targets: list[dict[str, Any]] | None = None,
    target_dir: str | Path | None = None,
) -> Path:
    """Materialise the extension and return its directory.

    The directory is temporary by default: the extension embeds a port and a
    scope, so it is specific to one session and should not be reused.
    """
    root = Path(target_dir) if target_dir else Path(
        tempfile.mkdtemp(prefix="scriptscrap-extension-"))
    root.mkdir(parents=True, exist_ok=True)

    source = files(__package__)
    for name in _STATIC:
        (root / name).write_text(
            source.joinpath(name).read_text(encoding="utf-8"), encoding="utf-8")

    config = {
        "port": port,
        "scopeHosts": sorted(scope_hosts),
        "maxBodyBytes": max_body_bytes,
        "captureBodies": capture_bodies,
        "captureScripts": capture_scripts,
        "rewriteTargets": rewrite_targets or [],
    }
    (root / CONFIG).write_text(
        "// Generated per session by scriptscrap.extension.loader.\n"
        "self.__scriptscrapExtensionConfig = "
        + json.dumps(config, indent=2, sort_keys=True)
        + ";\n",
        encoding="utf-8",
    )
    return root


def cleanup_extension(path: str | Path) -> None:
    """Remove a built extension directory. Safe to call twice."""
    shutil.rmtree(Path(path), ignore_errors=True)
