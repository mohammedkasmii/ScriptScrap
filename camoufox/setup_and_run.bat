@echo off
TITLE ScriptScrap Investigator
color 0a

REM ---------------------------------------------------------------------------
REM Launches the investigator through the LOCKED environment (uv + uv.lock), so
REM the run uses the exact camoufox/playwright versions the behavioural baseline
REM was verified against.
REM
REM The previous version of this script created its own venv and ran
REM `pip install camoufox httpx` unpinned, which could silently install a
REM different stack than the one the diagnostics and golden master were
REM validated on.
REM ---------------------------------------------------------------------------

cd /d "%~dp0.."

echo ========================================================
echo   [1/4] Checking uv...
echo ========================================================
where uv >nul 2>&1
if errorlevel 1 (
    echo [ERROR] uv is not installed or not on PATH.
    echo Install it from https://docs.astral.sh/uv/getting-started/installation/
    echo   powershell -c "irm https://astral.sh/uv/install.ps1 ^| iex"
    pause
    exit /b 1
)
uv --version

echo.
echo ========================================================
echo   [2/4] Syncing the locked environment...
echo ========================================================
uv sync --all-groups
if errorlevel 1 (
    echo [ERROR] uv sync failed.
    pause
    exit /b 1
)

echo.
echo ========================================================
echo   [3/4] Fetching the Camoufox browser if needed...
echo ========================================================
uv run python -m camoufox fetch

echo.
echo ========================================================
echo   [4/4] Checking environment assumptions...
echo ========================================================
uv run python diagnostics\check_environment.py
if errorlevel 1 (
    echo.
    echo [ERROR] Environment check reported a BLOCKING problem.
    echo Investigation output would not be trustworthy. Fix it first.
    pause
    exit /b 1
)

echo.
echo ========================================================
echo   Launching ScriptScrap Investigator...
echo ========================================================
uv run python camoufox\camoufox_investigator.py

echo.
echo ========================================================
echo   Finished. Output is in v13_investigation_output\
echo   It is UNREDACTED and gitignored. Read its SECURITY.md.
echo ========================================================
pause
