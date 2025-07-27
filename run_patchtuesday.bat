@echo off
setlocal

REM Set Python script name
set SCRIPT=PatchTuesday.py

REM Create virtual environment if missing
IF NOT EXIST .venv (
    echo Creating virtual environment...
    python -m venv .venv
    if %ERRORLEVEL% NEQ 0 (
        echo Failed to create virtual environment. Make sure Python is installed and in your PATH.
        pause
        exit /b 1
    )

    echo Installing required packages...
    .venv\Scripts\pip install --upgrade pip
    .venv\Scripts\pip install -r requirements.txt
    if %ERRORLEVEL% NEQ 0 (
        echo Failed to install required packages.
        pause
        exit /b 1
    )
)

REM Run the script with passed arguments
echo Running Patch Tuesday tool...
.venv\Scripts\python %SCRIPT% %*
echo.
echo Done.
pause
