@echo off
setlocal
cd /d "%~dp0"
title Vertex Sentry

set "PYTHON_EXE=.venv\Scripts\python.exe"
if exist "%PYTHON_EXE%" goto dependencies

where py >nul 2>nul
if not errorlevel 1 (
    py -3 -m venv .venv
) else (
    python -m venv .venv
)
if errorlevel 1 (
    echo Could not create the project environment. Install Python 3.10 or newer.
    goto failed
)

:dependencies
"%PYTHON_EXE%" -c "import django; assert (5, 2, 19) <= django.VERSION[:3] < (5, 3)" >nul 2>nul
if errorlevel 1 (
    "%PYTHON_EXE%" -m pip install -r requirements.txt
    if errorlevel 1 goto failed
)

echo Starting Vertex Sentry. Press Ctrl+C to stop the server.
"%PYTHON_EXE%" server.py
if errorlevel 1 goto failed
exit /b 0

:failed
pause
exit /b 1
