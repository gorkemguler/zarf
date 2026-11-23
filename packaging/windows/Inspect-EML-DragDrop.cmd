@echo off
title Zarf — Inspect Dropped .eml File
cd /d "%~dp0"
if "%~1"=="" (
  echo Drag and drop one or more .eml files onto this script to open them directly in Zarf.
  echo Launching empty workbench instead...
  echo.
  "%~dp0zarf.exe" app
) else (
  "%~dp0zarf.exe" app %*
)
pause
