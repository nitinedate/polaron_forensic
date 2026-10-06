# Writes the Windows host default gateway + /24 into .lan-fingerprint so the
# portable scanner-agent (in Docker NAT) can detect a mid-scan LAN move.
param(
    [string]$Root = "",
    [switch]$Once
)

if (-not $Root) { $Root = Split-Path -Parent $PSScriptRoot }
$out = Join-Path $Root '.lan-fingerprint'

function Get-LanFingerprint {
    $gw = ""
    $subnet = ""
    try {
        $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
            Sort-Object -Property RouteMetric, InterfaceMetric |
            Select-Object -First 1
        if ($route) {
            $gw = [string]$route.NextHop
            $addr = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -notlike '127.*' -and $_.PrefixOrigin -ne 'WellKnown' } |
                Select-Object -First 1
            if ($addr -and $addr.IPAddress) {
                $parts = $addr.IPAddress.Split('.')
                if ($parts.Count -eq 4) {
                    $subnet = "{0}.{1}.{2}.0/24" -f $parts[0], $parts[1], $parts[2]
                }
            }
        }
    } catch {
        $gw = ""
    }
    $payload = @{
        gateway   = $gw
        subnet    = $subnet
        source    = "host"
        updated_at = (Get-Date).ToUniversalTime().ToString("o")
    } | ConvertTo-Json -Compress
    [System.IO.File]::WriteAllText($out, $payload)
}

Get-LanFingerprint
if ($Once) { exit 0 }

while ($true) {
    Start-Sleep -Seconds 10
    try { Get-LanFingerprint } catch { }
}
