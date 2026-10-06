param([switch]$ValidateOnly)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Set-Location -LiteralPath $PSScriptRoot

function Invoke-Compose([string[]]$Arguments) {
    & docker compose @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose failed: $($Arguments -join ' ')" }
}

if (-not (Select-String -LiteralPath '.\scanner-agent\agent\__init__.py' -SimpleMatch '1.5.3-v45.7' -Quiet)) {
    throw 'Extract the v1.5.3 scanner into this folder first.'
}
if (-not (Test-Path -LiteralPath '.env' -PathType Leaf)) {
    throw 'For a first installation run Start-Laptop.cmd to configure and bind the scanner.'
}
& docker info --format '{{.OSType}}'
if ($LASTEXITCODE -ne 0) { throw 'Start Docker Desktop in Linux container mode.' }
Invoke-Compose -Arguments @('config', '--quiet')
if (-not $ValidateOnly) {
    if (-not (Test-Path -LiteralPath '.lan-fingerprint' -PathType Leaf)) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'scripts\Write-LanFingerprint.ps1') -Root $PSScriptRoot -Once
        if ($LASTEXITCODE -ne 0) { throw 'Could not prepare the local LAN fingerprint.' }
    }
    Write-Host 'Rebuilding the agent and bootstrap. Existing Greenbone data and configuration stay in place.'
    Invoke-Compose -Arguments @('build', '--no-cache', 'scanner-agent', 'scanner-bootstrap')
    Invoke-Compose -Arguments @('up', '-d', '--no-deps', '--force-recreate', 'scanner-agent')
}
Invoke-Compose -Arguments @('exec', '-T', 'scanner-agent', 'python', '-m', 'pytest', '-q', '/app/tests')
Invoke-Compose -Arguments @('exec', '-T', 'scanner-agent', 'python', '-c', 'from agent import AGENT_BUILD; from agent.gmp_local import LocalOpenVAS, _effective_scan_policy; s=LocalOpenVAS(); p=_effective_scan_policy(None,s.port_profile,s.udp_profile); print(AGENT_BUILD, "effective PORT_PROFILE="+s.port_profile, "UDP_PROFILE="+s.udp_profile, p["policy_version"], "TCP ports=",p["tcp_port_count"],"UDP ports=",p["udp_port_count"])')
Write-Host 'Scanner source and tests verified. Run a known authorized scan to verify live engine and central progress.'
