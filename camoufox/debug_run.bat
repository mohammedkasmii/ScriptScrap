@echo off
TITLE Debug Runner
color 0b

echo Testing Python availability...
python --version
if errorlevel 1 (
    echo [CRITICAL ERROR] Python is NOT recognized in this terminal!
    goto END
)

echo.
echo Activating or creating venv...
if not exist "venv" (
    python -m venv venv
)
call venv\Scripts\activate

echo.
echo Upgrading pip...
python -m pip install --upgrade pip

echo.
echo Installing requirements...
pip install camoufox httpx

echo.
echo Fetching Camoufox browser...
python -m camoufox fetch

echo.
echo Launching script...
python camoufox_investigator.py

:END
echo.
echo ========================================================
echo Script finished or crashed. Read the messages above.
echo ========================================================
pause