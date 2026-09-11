# ESP32-S3 Build and Flash Script
# Run this in PowerShell (not from CLion terminal)

param(
    [string]$Port = "COM7",
    [switch]$Flash,
    [switch]$Monitor
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  UltrafastSecp256k1 ESP32-S3 Builder" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ESP-IDF paths
$IDF_PATH = "C:\Espressif\frameworks\esp-idf-v5.5.1"
$IDF_TOOLS_PATH = "C:\Espressif"
$PYTHON_ENV = "C:\Espressif\python_env\idf5.5_py3.11_env"

# Check if ESP-IDF exists
if (-not (Test-Path $IDF_PATH)) {
    Write-Host "ERROR: ESP-IDF not found at $IDF_PATH" -ForegroundColor Red
    exit 1
}

# Set environment
$env:IDF_PATH = $IDF_PATH
$env:IDF_TOOLS_PATH = $IDF_TOOLS_PATH
$env:IDF_PYTHON_ENV_PATH = $PYTHON_ENV

# Add tools to PATH
$TOOLS_PATH = @(
    "$PYTHON_ENV\Scripts",
    "$IDF_TOOLS_PATH\tools\xtensa-esp-elf\esp-14.2.0_20241119\xtensa-esp-elf\bin",
    "$IDF_TOOLS_PATH\tools\xtensa-esp-elf-gdb\14.2_20240403\xtensa-esp-elf-gdb\bin",
    "$IDF_TOOLS_PATH\tools\cmake\3.30.7\bin",
    "$IDF_TOOLS_PATH\tools\ninja\1.12.1",
    "$IDF_TOOLS_PATH\tools\idf-git\2.44.0\cmd"
) -join ";"

$env:PATH = "$TOOLS_PATH;$env:PATH"

Write-Host "IDF_PATH: $env:IDF_PATH" -ForegroundColor Green
Write-Host "Python:   $PYTHON_ENV" -ForegroundColor Green
Write-Host ""

# Change to project directory
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectDir

# Set target if not already set
if (-not (Test-Path "build")) {
    Write-Host "Setting target to ESP32-S3..." -ForegroundColor Yellow
    & "$PYTHON_ENV\Scripts\python.exe" "$IDF_PATH\tools\idf.py" set-target esp32s3
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to set target" -ForegroundColor Red
        exit 1
    }
}

# Build
Write-Host ""
Write-Host "Building..." -ForegroundColor Yellow
& "$PYTHON_ENV\Scripts\python.exe" "$IDF_PATH\tools\idf.py" build
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Build failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Build successful!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green

# Flash if requested
if ($Flash -or $Monitor) {
    Write-Host ""
    Write-Host "Flashing to $Port..." -ForegroundColor Yellow

    $args = @("-p", $Port, "flash")
    if ($Monitor) {
        $args += "monitor"
    }

    & "$PYTHON_ENV\Scripts\python.exe" "$IDF_PATH\tools\idf.py" @args
}
else {
    Write-Host ""
    Write-Host "To flash and monitor, run:" -ForegroundColor Cyan
    Write-Host "  .\build.ps1 -Flash -Monitor -Port COM7" -ForegroundColor White
    Write-Host ""
}

