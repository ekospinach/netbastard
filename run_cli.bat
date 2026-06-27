@echo off
title Netbastard CLI

whoami /groups | find "S-1-16-12288" >nul 2>&1
if %errorLevel% == 0 goto :run

echo Requesting administrator privileges...
powershell -Command "Start-Process '%~f0' -Verb RunAs"
exit /b

:run
cd /d "%~dp0"
python netbastard.py
pause
