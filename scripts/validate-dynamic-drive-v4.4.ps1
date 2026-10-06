param(
    [Parameter(Mandatory = $true)][string]$RequiredPath
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

if ($RequiredPath -notmatch '^([A-Za-z]):[\\/]') {
    throw "RequiredPath must be an absolute Windows drive path, for example G:\Evidence"
}
$letter = $Matches[1].ToUpper()

Write-Host "`n=== 1. PowerShell syntax validation ===" -ForegroundColor Cyan
$syntaxFiles = @(
    (Join-Path $Root 'scripts\generate-drive-mounts.ps1'),
    (Join-Path $Root 'scripts\resolve-docker-drive-source.ps1'),
    (Join-Path $Root 'scripts\refresh-drive-mounts-job.ps1'),
    (Join-Path $Root 'scripts\test-dynamic-drive-mounts.ps1')
)
foreach ($file in $syntaxFiles) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count) {
        $errors | ForEach-Object { Write-Host $_.Message -ForegroundColor Red }
        throw "PowerShell syntax validation failed: $file"
    }
    Write-Host "PASS $file" -ForegroundColor Green
}

Write-Host "`n=== 2. Windows path ===" -ForegroundColor Cyan
if (-not (Test-Path -LiteralPath $RequiredPath)) {
    throw "Windows cannot read: $RequiredPath"
}
Write-Host "PASS Windows can read $RequiredPath" -ForegroundColor Green

Write-Host "`n=== 3. Installed WSL distributions ===" -ForegroundColor Cyan
try { wsl.exe --list --verbose } catch { Write-Host "WSL query failed: $($_.Exception.Message)" -ForegroundColor Yellow }

Write-Host "`n=== 4. Resolve Docker-readable source ===" -ForegroundColor Cyan
$tmp = Join-Path $env:TEMP ("aetheris-v44-resolve-{0}.json" -f [guid]::NewGuid().ToString('N'))
try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\resolve-docker-drive-source.ps1" `
        -DriveLetter $letter -RequiredPath $RequiredPath -Root $Root -OutputFile $tmp
    $resolveExit = $LASTEXITCODE
    if (Test-Path -LiteralPath $tmp) {
        $result = Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json
        $result | ConvertTo-Json -Depth 8
        if ($resolveExit -ne 0 -or -not $result.ok) {
            throw ([string]$result.error)
        }
        Write-Host ("PASS resolver mode={0} source={1} distro={2}" -f $result.mode, $result.source, $result.wsl_distro) -ForegroundColor Green
    }
    else {
        throw "Resolver returned no JSON result."
    }
}
finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
}

Write-Host "`n=== 5. End-to-end application mount test ===" -ForegroundColor Cyan
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\scripts\test-dynamic-drive-mounts.ps1" -RequiredPath $RequiredPath
if ($LASTEXITCODE -ne 0) {
    throw "End-to-end dynamic drive test failed."
}

Write-Host "`nPASS - Dynamic Drive v4.4 is working for $RequiredPath" -ForegroundColor Green
