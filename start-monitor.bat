@echo off
setlocal
cd /d "%~dp0"
title Vertex Sentry

set "PYTHON_EXE=.venv\Scripts\python.exe"
set "PULSE_ENABLE_DNS_FORWARDING=1"
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

REM Ensure Django auth tables exist and at least one staff administrator account is set up
"%PYTHON_EXE%" manage.py migrate --noinput >nul 2>nul
"%PYTHON_EXE%" -c "import os, django; os.environ.setdefault('DJANGO_SETTINGS_MODULE','pulse_monitor.django_settings'); django.setup(); from django.contrib.auth.models import User; raise SystemExit(0 if User.objects.filter(is_staff=True, is_active=True).exists() else 1)" >nul 2>nul
if errorlevel 1 (
    echo =======================================================
    echo   First-Time Setup: Create your Vertex Sentry Admin Login
    echo =======================================================
    "%PYTHON_EXE%" manage.py createsuperuser
    if errorlevel 1 goto failed
)

REM Stop any stale background server.py holding port 3000 so this window can start cleanly
for /f "tokens=5" %%p in ('netstat -ano ^| findstr /R /C:":3000 .*LISTENING"') do (
    if not "%%p"=="0" (
        echo Stopping previous Vertex Sentry process on port 3000 ^(PID %%p^)...
        taskkill /F /PID %%p >nul 2>nul
        timeout /t 1 /nobreak >nul
    )
)

set "PULSE_ENABLE_DNS_FORWARDING=1"
echo Starting Vertex Sentry on http://localhost:3000 ^(DNS Sensor active on port 53 -^> 1.1.1.1 / 8.8.8.8^)...
echo Keep this window open while monitoring. Press Ctrl+C to stop the server.
"%PYTHON_EXE%" server.py
if errorlevel 1 goto failed
exit /b 0

:failed
pause
exit /b 1
