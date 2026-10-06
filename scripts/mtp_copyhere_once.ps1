# One bounded STA CopyHere of a This PC / MTP folder (device-root or nested path).
# Parent kills this process if Explorer never returns.
param(
    [Parameter(Mandatory = $true)][string]$DestDir,
    [Parameter(Mandatory = $true)][string]$DeviceName,
    [string]$InstanceId = "",
    [string]$TopName = "",
    [string]$RelativePath = "",
    [int]$Flags = 528
)

$ErrorActionPreference = "Continue"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$acquire = Join-Path $here "host-mobile-acquire.ps1"
if (-not (Test-Path -LiteralPath $acquire)) { exit 2 }
. $acquire

if (-not $RelativePath) { $RelativePath = $TopName }
$segments = @($RelativePath -split '[\\/]+' | Where-Object { $_ })
if (-not $segments.Count) { exit 5 }

if (-not (Test-Path -LiteralPath $DestDir)) {
    New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
}
$rootItem = Get-ShellPortableDeviceItem -DeviceName $DeviceName -InstanceId $InstanceId
if (-not $rootItem) { exit 3 }
$current = $rootItem
foreach ($seg in $segments) {
    $folder = $null
    try { $folder = $current.GetFolder } catch { exit 4 }
    if (-not $folder) { exit 4 }
    $next = $null
    foreach ($child in @($folder.Items())) {
        if ([string]$child.Name -eq $seg) { $next = $child; break }
    }
    if (-not $next) { exit 5 }
    $current = $next
}
$shell = New-Object -ComObject Shell.Application
$destNs = $shell.NameSpace($DestDir)
if (-not $destNs) { exit 6 }
$destNs.CopyHere($current, [int]$Flags)
exit 0
