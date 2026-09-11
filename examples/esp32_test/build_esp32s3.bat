@echo off
REM ESP32 Build & Flash Script for secp256k1 test
REM Run this from ESP-IDF CMD or PowerShell

echo ============================================
echo  UltrafastSecp256k1 ESP32-S3 Build Script
echo ============================================
echo.

REM Check if IDF_PATH is set
if "%IDF_PATH%"=="" (
    echo ERROR: ESP-IDF environment not set!
    echo Please run this from ESP-IDF CMD or PowerShell
    echo Or run: C:\Espressif\idf_cmd_init.bat esp-idf-v5.5.1
    pause
    exit /b 1
)

echo IDF_PATH: %IDF_PATH%
echo.

REM Set target
echo Setting target to esp32s3...
call idf.py set-target esp32s3
if errorlevel 1 (
    echo ERROR: Failed to set target
    pause
    exit /b 1
)

REM Build
echo.
echo Building...
call idf.py build
if errorlevel 1 (
    echo ERROR: Build failed
    pause
    exit /b 1
)

echo.
echo ============================================
echo  Build successful!
echo ============================================
echo.
echo To flash, run:
echo   idf.py -p COM7 flash monitor
echo.
pause

