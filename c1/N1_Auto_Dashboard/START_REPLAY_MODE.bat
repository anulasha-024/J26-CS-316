@echo off
setlocal
cd /d "%~dp0"
title N1 - Offline Evidence Replay
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  py -3 n1_dashboard.py --mode replay --open-now
) else (
  python n1_dashboard.py --mode replay --open-now
)
if errorlevel 1 pause
