@echo off
setlocal
title Aetheris - Pack Laptop Scanner Zip
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\pack-laptop-scanner-zip.ps1"
echo.
pause
