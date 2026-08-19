@echo off
TITLE Debug Runner
color 0b

echo Testing Python availability...
python --version
if %ERRORLEVEL% NEQ 0 (
    echo [CRITICAL ERROR] Python is NOT recognized in this terminal!
    goto END
)

echo.
echo Activating or creating venv...
if not exist "venv\" (
    echo Creating new virtual environment...
    python -m venv venv
)
call venv\Scripts\activate

echo.
echo Upgrading pip...
python -m pip install --upgrade pip

echo.
echo Installing requirements...
pip install camoufox httpx playwright

echo.
echo Fetching Camoufox browser...
python -m camoufox fetch

echo.
echo Installing Windows browser dependencies...
playwright install-deps

echo.
echo Launching script...
if not exist "camoufox_investigator.py" (
    echo [ERROR] camoufox_investigator.py not found in this folder!
    goto END
)
python camoufox_investigator.py

:END
echo.
echo ========================================================
echo Script finished or crashed. Read the messages above.
echo ========================================================
pause