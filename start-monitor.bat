@echo off
title Pulse Network Monitoring System (Python)
color 0B
echo ========================================================
echo   Starting Pulse Network Monitoring System
echo   Router Target: http://192.168.0.1
echo ========================================================
echo.
cd /d "%~dp0"

set "PYTHON_EXE="
if exist ".venv\Scripts\python.exe" set "PYTHON_EXE=.venv\Scripts\python.exe"
if "%PYTHON_EXE%"=="" (
  where py >nul 2>nul
  if %errorlevel%==0 set "PYTHON_EXE=py -3"
)
if "%PYTHON_EXE%"=="" (
  where python >nul 2>nul
  if %errorlevel%==0 set "PYTHON_EXE=python"
)

if "%PYTHON_EXE%"=="" (
  echo [ERROR] Python was not found in PATH!
  echo Please install Python 3.9+ from https://www.python.org/downloads/
  pause
  exit /b 1
)

echo [1/3] Starting Host Game & DNS Sensor in background...
start "Pulse Host Game Sensor" /min %PYTHON_EXE% host_game_sensor.py

echo [2/3] Opening web dashboard in your default browser...
start "" "http://localhost:3000"

echo [3/3] Running Pulse Monitor server on http://localhost:3000...
echo.
echo Press Ctrl+C in this window to stop the server.
echo.
%PYTHON_EXE% server.py
pause
