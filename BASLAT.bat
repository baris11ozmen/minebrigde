@echo off
title MineBridge Agent
echo.
echo  ==========================================
echo       MineBridge Agent Starting...
echo  ==========================================
echo.

REM Check Python
py --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found!
    echo Please download Python from https://python.org
    echo During installation, check "Add Python to PATH"!
    pause
    exit
)

REM Install libraries
echo Checking libraries...
py -m pip install fastapi uvicorn pydantic python-multipart --quiet

echo.
echo Starting API...
echo Open http://localhost:8000 in your browser
echo Close this window to stop.
echo.

py api.py
pause
