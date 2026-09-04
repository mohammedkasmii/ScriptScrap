"""The analysis layer must never depend on a browser.

This is the boundary the whole M3 architecture rests on: analysis reads recorded
evidence, so it must run on a machine with no Playwright, no Camoufox and no
sensors. Enforced structurally rather than by convention, because a single
convenience import would silently make every analysis test require a browser.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "scriptscrap"
FORBIDDEN_ROOTS = {"playwright", "camoufox"}
FORBIDDEN_INTERNAL = {"sensors", "probe", "fixture"}

PURE_PACKAGES = ("analysis", "export")


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.module:
                # Relative: `from ..sensors import x` -> "sensors"
                found.add(node.module.split(".")[0])
            elif node.module:
                found.add(node.module.split(".")[0])
                if node.module.startswith("scriptscrap."):
                    found.add(node.module.split(".")[1])
    return found


def _pure_modules() -> list[Path]:
    modules: list[Path] = []
    for package in PURE_PACKAGES:
        modules.extend(sorted((SRC / package).rglob("*.py")))
    return modules


def test_pure_packages_exist():
    assert _pure_modules(), "no analysis/export modules found to check"


def test_analysis_never_imports_a_browser():
    offenders: list[str] = []
    for module in _pure_modules():
        bad = _imports(module) & (FORBIDDEN_ROOTS | FORBIDDEN_INTERNAL)
        if bad:
            offenders.append(f"{module.relative_to(SRC)} imports {sorted(bad)}")
    assert not offenders, "analysis must stay browser-independent:\n" + "\n".join(offenders)


def test_analysis_imports_cleanly_without_playwright_installed():
    """Import the package in a subprocess where playwright/camoufox are blocked.

    A static check catches direct imports; this catches an indirect one, where
    a module we import pulls a browser dependency in behind our back.
    """
    code = (
        "import sys\n"
        "class Blocker:\n"
        "    def find_module(self, name, path=None):\n"
        "        if name.split('.')[0] in ('playwright', 'camoufox'):\n"
        "            raise ImportError('blocked for boundary test: ' + name)\n"
        "        return None\n"
        "sys.meta_path.insert(0, Blocker())\n"
        "import scriptscrap.analysis as a\n"
        "import scriptscrap.export as e\n"
        "import scriptscrap.cli as c\n"
        "assert a.analyze_log and e.DatasetExporter and c.main\n"
        "print('OK')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, (
        "analysis/export/cli pulled in a browser dependency:\n"
        f"{proc.stdout}\n{proc.stderr}"
    )
    assert "OK" in proc.stdout
