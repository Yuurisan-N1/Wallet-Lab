# ESP32 Build Script - PowerShell
# This script sets up ESP-IDF environment and builds the ESP32 firmware

param(
    [switch]$Flash,
    [switch]$Monitor,
    [switch]$Clean,
    [string]$Port = "COM3"
)

# Change to ESP32 project directory first
$ESP32_PROJECT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ESP32_PROJECT

Write-Host "===== ESP32 Build Script =====" -ForegroundColor Cyan

# CRITICAL: Force Python 3.12 environment (override system variable)
$env:IDF_PYTHON_ENV_PATH = "C:\Espressif\python_env\idf5.5_py3.12_env"

# Manual ESP-IDF environment setup (bypass export.ps1)
$env:IDF_PATH = "C:\Espressif\frameworks\esp-idf-v5.5.1"
$env:IDF_TOOLS_PATH = "C:\Espressif"
$env:ESP_ROM_ELF_DIR = "C:\Espressif\frameworks\esp-idf-v5.5.1\components\esp_rom"
$PYTHON_ENV = "C:\Espressif\python_env\idf5.5_py3.12_env"
$PYTHON_EXE = "$PYTHON_ENV\Scripts\python.exe"

# Build PATH with all required tools
$env:PATH = "$PYTHON_ENV\Scripts;" +
            "C:\Espressif\tools\xtensa-esp-elf\esp-14.2.0_20241119\xtensa-esp-elf\bin;" +
            "C:\Espressif\tools\ninja\1.12.1;" +
            "C:\Espressif\tools\cmake\3.30.7\bin;" +
            "$env:IDF_PATH\tools;" +
            $env:PATH

Write-Host "Python: $PYTHON_EXE" -ForegroundColor Yellow
Write-Host "Toolchain: xtensa-esp-elf (v14.2.0)" -ForegroundColor Yellow
Write-Host "===============================" -ForegroundColor Cyan
Write-Host ""

# Build arguments
$idf_py = "$env:IDF_PATH\tools\idf.py"
$args_list = @()

if ($Clean) {
    $args_list += "fullclean"
}
elseif ($Flash) {
    $args_list += "-p"
    $args_list += $Port
    $args_list += "flash"

    if ($Monitor) {
        $args_list += "monitor"
    }
}
elseif ($Monitor) {
    $args_list += "-p"
    $args_list += $Port
    $args_list += "monitor"
}
else {
    $args_list += "build"
}

# Execute idf.py with Python 3.12
& $PYTHON_EXE $idf_py @args_list
exit $LASTEXITCODE



