<#
Select a free Windows host port for the main/Forensic Redis container and persist
it as REDIS_HOST_PORT in the repository .env file.

Container-to-container Redis traffic is NOT changed: services still use
redis://redis:6379/0 on the private Compose network.
#>
[CmdletBinding()]
param(
    [int]$PreferredPort = 6380,
    [int]$SearchStart = 6380,
    [int]$SearchEnd = 6499,
    [switch]$ForceReselect
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$envPath = Join-Path $root '.env'

# One shared Redis publishes REDIS_HOST_PORT. Product brokers use logical DBs on it.
$reserved = [System.Collections.Generic.HashSet[int]]::new()

function Test-TcpPortAvailable {
    param([Parameter(Mandatory=$true)][int]$Port)

    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
        # ExclusiveAddressUse helps catch ports already owned/reserved by another listener.
        $listener.Server.ExclusiveAddressUse = $true
        $listener.Start()
        return $true
    }
    catch {
        return $false
    }
    finally {
        if ($null -ne $listener) {
            try { $listener.Stop() } catch { }
        }
    }
}

function Get-EnvValue {
    param([string]$Name)
    if (-not (Test-Path $envPath)) { return $null }
    $line = Get-Content $envPath | Where-Object { $_ -match "^\s*$([regex]::Escape($Name))\s*=" } | Select-Object -Last 1
    if (-not $line) { return $null }
    return (($line -split '=', 2)[1]).Trim()
}

function Set-EnvValue {
    param([string]$Name, [string]$Value)

    $lines = if (Test-Path $envPath) { @(Get-Content $envPath) } else { @() }
    $pattern = "^\s*$([regex]::Escape($Name))\s*="
    $found = $false
    $out = foreach ($line in $lines) {
        if ($line -match $pattern) {
            if (-not $found) {
                "$Name=$Value"
                $found = $true
            }
            # Drop duplicate definitions after the first one.
        }
        else {
            $line
        }
    }
    if (-not $found) {
        if ($out.Count -gt 0 -and $out[-1] -ne '') { $out += '' }
        $out += "$Name=$Value"
    }
    Set-Content -Path $envPath -Value $out -Encoding utf8
}

$currentRaw = Get-EnvValue -Name 'REDIS_HOST_PORT'
$current = 0
if ($currentRaw) { [void][int]::TryParse($currentRaw, [ref]$current) }

if (-not $ForceReselect -and $current -gt 0 -and -not $reserved.Contains($current) -and (Test-TcpPortAvailable -Port $current)) {
    Write-Host "REDIS_HOST_PORT=$current is available; keeping it." -ForegroundColor Green
    exit 0
}

$candidates = New-Object System.Collections.Generic.List[int]
if ($PreferredPort -ge $SearchStart -and $PreferredPort -le $SearchEnd) {
    $candidates.Add($PreferredPort)
}
for ($p = $SearchStart; $p -le $SearchEnd; $p++) {
    if ($p -ne $PreferredPort) { $candidates.Add($p) }
}

$selected = $null
foreach ($port in $candidates) {
    if ($reserved.Contains($port)) { continue }
    if (Test-TcpPortAvailable -Port $port) {
        $selected = $port
        break
    }
}

if ($null -eq $selected) {
    throw "No free Redis host port found in range $SearchStart-$SearchEnd."
}

Set-EnvValue -Name 'REDIS_HOST_PORT' -Value ([string]$selected)
Write-Host "Selected free Redis host port: $selected" -ForegroundColor Cyan
Write-Host "Updated: $envPath" -ForegroundColor DarkGray
Write-Host "Redis inside Docker remains redis:6379; no application REDIS_URL changes are required." -ForegroundColor DarkGray
