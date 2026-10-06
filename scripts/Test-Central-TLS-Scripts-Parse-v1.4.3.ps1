[CmdletBinding()]
param(
    [string]$ScriptsRoot = $PSScriptRoot
)

$ErrorActionPreference = "Stop"
$files = @(
    (Join-Path $ScriptsRoot "Test-Aetheris-Central-TLS-v1.4.3.ps1"),
    (Join-Path $ScriptsRoot "Repair-Aetheris-Central-TLS-v1.4.3.ps1")
)

$failed = $false
foreach ($file in $files) {
    if (-not (Test-Path -LiteralPath $file)) {
        Write-Host "[FAIL] Missing: $file" -ForegroundColor Red
        $failed = $true
        continue
    }
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) {
        Write-Host "[FAIL] $file" -ForegroundColor Red
        foreach ($parseError in $errors) {
            Write-Host ("  Line {0}, Col {1}: {2}" -f $parseError.Extent.StartLineNumber, $parseError.Extent.StartColumnNumber, $parseError.Message) -ForegroundColor Red
        }
        $failed = $true
    }
    else {
        Write-Host "[OK] $file" -ForegroundColor Green
    }
}

if ($failed) { exit 1 }
Write-Host "[OK] PowerShell parser validation passed for all v1.4.3 central TLS scripts." -ForegroundColor Green
exit 0
