# ESP32 Serial Monitor - PowerShell
# Simple serial monitor using .NET SerialPort (no TTY required)

param(
    [string]$Port = "COM3",
    [int]$BaudRate = 115200
)

Write-Host "`n===== ESP32 Serial Monitor =====" -ForegroundColor Cyan
Write-Host "Port: $Port @ $BaudRate baud" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to exit" -ForegroundColor Yellow
Write-Host "================================`n" -ForegroundColor Cyan

try {
    # Create SerialPort object
    $serial = New-Object System.IO.Ports.SerialPort $Port, $BaudRate, ([System.IO.Ports.Parity]::None), 8, ([System.IO.Ports.StopBits]::One)
    $serial.ReadTimeout = 100
    $serial.Open()

    Write-Host "Connected to $Port!" -ForegroundColor Green
    Write-Host ""

    # Read loop
    while ($true) {
        try {
            if ($serial.BytesToRead -gt 0) {
                $data = $serial.ReadExisting()
                Write-Host -NoNewline $data
            }
            Start-Sleep -Milliseconds 10
        }
        catch [System.TimeoutException] {
            # Normal timeout, continue
        }
        catch {
            Write-Host "`nError reading from serial port: $_" -ForegroundColor Red
            break
        }
    }
}
catch {
    Write-Host "Failed to open $Port : $_" -ForegroundColor Red
    exit 1
}
finally {
    if ($serial -and $serial.IsOpen) {
        $serial.Close()
        Write-Host "`n`nSerial port closed." -ForegroundColor Yellow
    }
}

