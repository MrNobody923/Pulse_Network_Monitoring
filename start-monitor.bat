@echo off
title Pulse Network Monitoring System (Python)
color 0B
echo ========================================================
echo   Starting Pulse Network Monitoring System
echo   Router Target: http://192.168.0.1
echo ========================================================
echo.
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  start "Pulse Host Game Sensor" /min ".venv\Scripts\python.exe" host_game_sensor.py
) else (
  where py >nul 2>nul
  if %errorlevel%==0 (
    start "Pulse Host Game Sensor" /min py -3 host_game_sensor.py
  ) else (
    start "Pulse Host Game Sensor" /min python host_game_sensor.py
  )
)

where docker >nul 2>nul
if %errorlevel%==0 (
  docker info >nul 2>nul
  if %errorlevel%==0 (
    echo Starting Docker Compose service + Host Game Sensor...
    docker compose up -d
    echo Dashboard running at http://localhost:3000
    pause
    exit /b 0
  )
)

if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" server.py
) else (
  where py >nul 2>nul
  if %errorlevel%==0 (
    py -3 server.py
  ) else (
    python server.py
  )
)
pause
