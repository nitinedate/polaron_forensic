# Configure the Windows HTTP reservation used by the Aetheris HostDrive helper.
# This script is intentionally small and is normally invoked by ensure-host-drive-helper.ps1.
# It needs elevation only when the wildcard URL reservation / firewall rule is missing.
param(
    [int]$Port = $(if ($env:HOST_DRIVE_HELPER_PORT) { [int]$env:HOST_DRIVE_HELPER_PORT } else { 9876 })
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

if (-not (Test-IsAdministrator)) {
    throw "Administrator rights are required to reserve the HostDrive helper URL."
}

$url = "http://+:$Port/"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$userName = [string]$identity.Name
if (-not $userName) {
    throw "Could not determine the current Windows identity for HostDrive URL reservation."
}

# Repair stale URL ACLs left by an older Windows account or another extracted copy.
# HttpListener otherwise fails with Access is denied and the helper silently appears
# offline on port 9876.
$existing = (& netsh.exe http show urlacl url=$url 2>$null | Out-String)
$hasUrl = $existing -match [regex]::Escape($url)
$belongsToCurrentUser = $hasUrl -and ($existing -match [regex]::Escape($userName))
if ($hasUrl -and -not $belongsToCurrentUser) {
    Write-Host "Replacing stale URL ACL for $url (current examiner: $userName) ..." -ForegroundColor Yellow
    & netsh.exe http delete urlacl url=$url | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Could not remove stale URL ACL for $url (netsh exit $LASTEXITCODE)."
    }
    $hasUrl = $false
}

if (-not $hasUrl) {
    Write-Host "Adding URL ACL for $url to $userName ..." -ForegroundColor Cyan
    & netsh.exe http add urlacl url=$url user="$userName" listen=yes | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Could not add URL ACL for $url (netsh exit $LASTEXITCODE)."
    }
} else {
    Write-Host "URL ACL already belongs to the current examiner: $url" -ForegroundColor DarkGray
}

# Docker Desktop/WSL2 reaches the Windows host from private virtual NAT ranges.
# Restrict the helper rule to those ranges instead of exposing it to the whole LAN.
$ruleName = "Aetheris HostDrive Helper (Docker)"
try {
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existingRule) {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    }
    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort $Port `
        -Profile Any `
        -RemoteAddress @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16") | Out-Null
    Write-Host "Firewall rule ready for Docker/WSL2 -> TCP $Port" -ForegroundColor Green
}
catch {
    Write-Warning "Could not create the Docker/WSL firewall rule: $($_.Exception.Message)"
}

Write-Host "HostDrive network reservation is ready: $url" -ForegroundColor Green
exit 0
