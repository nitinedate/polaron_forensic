# Start the localhost drive-mount helper (Windows examiner workstation).
param(
    [int]$Port = $(if ($env:HOST_DRIVE_HELPER_PORT) { [int]$env:HOST_DRIVE_HELPER_PORT } else { 9876 })
)

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$ensure = Join-Path $root "scripts\ensure-host-drive-helper.ps1"
& $ensure
