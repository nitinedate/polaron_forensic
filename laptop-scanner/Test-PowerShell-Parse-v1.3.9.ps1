$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$files = @(
    (Join-Path $root 'scripts\sync-agent-token.ps1'),
    (Join-Path $root 'scripts\start-laptop.ps1'),
    (Join-Path $root 'Test-Windows-TLS-v1.3.9.ps1')
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
        foreach ($err in $errors) { Write-Host ("       {0}" -f $err.Message) -ForegroundColor Red }
        $failed = $true
    } else {
        Write-Host "[OK] $file" -ForegroundColor Green
    }
}
if ($failed) { exit 1 }
Write-Host '[OK] PowerShell parser validation passed.' -ForegroundColor Green
exit 0
