@echo off
setlocal
cd /d "%~dp0"
title N1 - NFC Security Live Dashboard
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  py -3 n1_dashboard.py %*
) else (
  python n1_dashboard.py %*
)
if errorlevel 1 (
  echo.
  echo If pyserial is missing, run: py -m pip install -r requirements.txt
  echo If the USB port is not identified, add: --port COM5
  echo.
  pause
)
