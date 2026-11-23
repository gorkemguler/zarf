@echo off
title Zarf — Offline .eml Phishing Autopsy Workbench
cd /d "%~dp0"
echo Starting Zarf Offline Web UI (100%% offline, 0 network calls)...
echo Close this window or press Ctrl+C to stop the local server.
echo.
"%~dp0zarf.exe" app
pause
