# Monitor NVIDIA GPU temperature during forensic pipeline runs (Windows host).
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\gpu-thermal-watch.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\gpu-thermal-watch.ps1 -PauseAt 78 -IntervalSec 3

param(
    [int]$PauseAt = 78,
    [int]$WarnAt = 72,
    [int]$IntervalSec = 3,
    [switch]$BeepOnHot
)

$nvidiaSmi = Get-Command nvidia-smi -ErrorAction SilentlyContinue
if (-not $nvidiaSmi) {
    $candidate = "C:\Windows\System32\nvidia-smi.exe"
    if (Test-Path $candidate) { $nvidiaSmi = $candidate } else {
        Write-Error "nvidia-smi not found. Install NVIDIA drivers."
        exit 1
    }
} else {
    $nvidiaSmi = $nvidiaSmi.Source
}

Write-Host "GPU thermal watch — warn >= ${WarnAt}C, critical >= ${PauseAt}C (every ${IntervalSec}s). Ctrl+C to stop."
Write-Host ""

while ($true) {
    try {
        $line = & $nvidiaSmi --query-gpu=timestamp,name,temperature.gpu,utilization.gpu,power.draw,memory.used,memory.total `
            --format=csv,noheader,nounits 2>$null | Select-Object -First 1
        if (-not $line) {
            Write-Host "$(Get-Date -Format 'HH:mm:ss')  nvidia-smi returned no data"
            Start-Sleep -Seconds $IntervalSec
            continue
        }
        $parts = $line -split ',\s*'
        $ts = $parts[0]
        $name = $parts[1]
        $temp = [int][double]$parts[2]
        $util = [int][double]$parts[3]
        $power = $parts[4]
        $memUsed = $parts[5]
        $memTotal = $parts[6]

        $level = "OK"
        $color = "Green"
        if ($temp -ge $PauseAt) {
            $level = "HOT — pause GPU work"
            $color = "Red"
            if ($BeepOnHot) { [Console]::Beep(880, 200) }
        } elseif ($temp -ge $WarnAt) {
            $level = "WARM"
            $color = "Yellow"
        }

        Write-Host "$(Get-Date -Format 'HH:mm:ss')  " -NoNewline
        Write-Host "$temp°C  util=${util}%  power=${power}W  mem=${memUsed}/${memTotal}MiB  [$level]" -ForegroundColor $color
    } catch {
        Write-Host "$(Get-Date -Format 'HH:mm:ss')  error: $($_.Exception.Message)" -ForegroundColor Red
    }
    Start-Sleep -Seconds $IntervalSec
}
