@echo off
REM ===============================================
REM Patch Tuesday CVE Export - Interactive Windows Launcher
REM Supports multiple vendor selection
REM ===============================================

REM 1. Detect portable Python
SET "PORTABLE_PY=%~dp0PythonPortable\python\python.exe"

REM 2. Prompt user for month
:ASK_MONTH
SET /P "MONTH_ARG=Enter target month (e.g., Jul-2025): "
IF "%MONTH_ARG%"=="" (
    echo Please enter a valid month.
    GOTO ASK_MONTH
)

REM 3. Prompt user for vendors
echo.
echo Select vendors to include (separate numbers with commas):
echo 1 - Microsoft
echo 2 - Adobe
echo 3 - SAP
echo 4 - All
:ASK_VENDORS
SET /P "VENDOR_CHOICE=Enter choice(s) [1-4]: "
IF "%VENDOR_CHOICE%"=="" (
    echo Please enter a valid choice.
    GOTO ASK_VENDORS
)

REM 4. Convert choice to flags
SET "VENDOR_FLAGS="
FOR %%A IN (%VENDOR_CHOICE%) DO (
    IF "%%A"=="1" SET "VENDOR_FLAGS=%VENDOR_FLAGS% --microsoft"
    IF "%%A"=="2" SET "VENDOR_FLAGS=%VENDOR_FLAGS% --adobe"
    IF "%%A"=="3" SET "VENDOR_FLAGS=%VENDOR_FLAGS% --sap"
    IF "%%A"=="4" SET "VENDOR_FLAGS=--all"
)

REM 5. Run the script
IF EXIST "%PORTABLE_PY%" (
    echo Using portable Python at "%PORTABLE_PY%"
    "%PORTABLE_PY%" "%~dp0PatchTuesday.py" %MONTH_ARG% %VENDOR_FLAGS%
) ELSE (
    python --version >nul 2>&1
    IF ERRORLEVEL 1 (
        echo Python not found. Please install Python or use a portable version in PythonPortable\ folder.
        pause
        exit /b 1
    ) ELSE (
        echo Using system Python
        python "%~dp0PatchTuesday.py" %MONTH_ARG% %VENDOR_FLAGS%
    )
)

pause
