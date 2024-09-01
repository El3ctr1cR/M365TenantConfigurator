@echo off
REM
set "currentDir=%~dp0"

REM
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%currentDir%Main.ps1" -NoExit

REM
pause
