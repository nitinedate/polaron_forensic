<#
.SYNOPSIS
  Issue/renew Let's Encrypt IP certificate for the public Aetheris gateway.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\deployment\windows-ip-https\bootstrap-gateway-ip-cert.ps1 -Email you@example.com
#>
param(
    [Parameter(Mandatory = $true)][string]$Email,
    [string]$PublicIp = "122.179.141.248",
    [string]$LanIp = "192.168.1.16",
    [switch]$Staging,
    [switch]$SelfSigned
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$setup = Join-Path $ProjectRoot "scripts\setup-public-https.ps1"

$args = @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", $setup,
    "-ProjectRoot", $ProjectRoot,
    "-PublicIP", $PublicIp,
    "-LanIP", $LanIp,
    "-Email", $Email,
    "-ForceRecreate"
)
if ($Staging) { $args += "-Staging" }
if ($SelfSigned) { $args += "-SelfSigned" }

& powershell.exe @args
exit $LASTEXITCODE
