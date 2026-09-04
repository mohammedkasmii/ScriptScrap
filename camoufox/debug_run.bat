@echo off
TITLE ScriptScrap Debug Runner
color 0b

REM ---------------------------------------------------------------------------
REM Diagnostic runner. Runs every compatibility probe and the test suite, then
REM stops. Use this when something looks wrong, or after upgrading a dependency.
REM ---------------------------------------------------------------------------

cd /d "%~dp0.."

echo === uv ===
where uv >nul 2>&1
if errorlevel 1 (
    echo [CRITICAL] uv is not on PATH. See README.md.
    goto END
)
uv --version

echo.
echo === Syncing locked environment ===
uv sync --all-groups

echo.
echo === Environment doctor (offline) ===
uv run python diagnostics\check_environment.py

echo.
echo === Offline tests (no browser) ===
uv run pytest -m "not browser" -q

echo.
echo === Compatibility probes (launch Camoufox) ===
echo --- snapshot integrity (F-03) ---
uv run python diagnostics\probes\snapshot_integrity_probe.py
echo --- hook timing / JS world ---
uv run python diagnostics\probes\hook_timing_probe.py
echo --- JS world (file://) ---
uv run python diagnostics\probes\js_world_probe.py
echo --- uBlock default addon (needs network) ---
uv run python diagnostics\probes\addon_filter_probe.py

echo.
echo === Full test suite incl. golden master ===
uv run pytest -q

:END
echo.
echo ========================================================
echo Diagnostics finished. Read the messages above.
echo ========================================================
pause
