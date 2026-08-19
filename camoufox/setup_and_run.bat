@echo off
TITLE Camoufox Automated Environment Setup & Runner
color 0a

echo ========================================================
echo   [1/4] Checking Python & Virtual Environment...
echo ========================================================

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not added to PATH. 
    echo Please install Python 3.10+ and make sure to check "Add Python to PATH".
    pause
    exit /b
)

:: Create a local virtual environment named 'venv' if it doesn't exist
if not exist "venv" (
    echo Creating virtual environment (venv)...
    python -m venv venv
) else (
    echo Virtual environment 'venv' already exists.
)

echo ========================================================
echo   [2/4] Activating Virtual Environment & Dependencies...
echo ========================================================

:: Activate virtual environment
call venv\Scripts\activate

:: Upgrade pip to latest version
python -m pip install --upgrade pip

:: Install required packages (Camoufox and HTTPX)
echo Installing Camoufox and dependencies...
pip install camoufox httpx

echo ========================================================
echo   [3/4] Fetching Camoufox Browser Binary...
echo ========================================================

:: Automatically runs the required fetch command to download the browser core
python -m camoufox fetch

echo ========================================================
echo   [4/4] Launching Camoufox Investigator...
echo ========================================================

:: Run your Python investigator script
python camoufox_investigator.py

echo.
echo ========================================================
echo   Execution finished. Check the output folders!
echo ========================================================
pause