@echo off
REM Flash & Monitor Script for ESP32-S3
REM COM port as first argument (default: COM7)

set PORT=%1
if "%PORT%"=="" set PORT=COM7

echo ============================================
echo  Flashing to %PORT%
echo ============================================

if "%IDF_PATH%"=="" (
    echo ERROR: ESP-IDF environment not set!
    echo Run from ESP-IDF CMD/PowerShell
    pause
    exit /b 1
)

call idf.py -p %PORT% flash monitor

