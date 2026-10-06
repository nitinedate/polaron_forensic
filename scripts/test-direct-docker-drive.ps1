param(
    [Parameter(Mandatory = $true)][string]$RequiredPath
)
$ErrorActionPreference = "Stop"
$selected = $RequiredPath.Trim() -replace '/', '\\'
if ($selected -notmatch '^([A-Za-z]):[\\/]') { throw "RequiredPath must be an absolute Windows path such as G:\\Evidence." }
$letter = $Matches[1].ToUpper()
if (-not (Test-Path -LiteralPath $selected)) { throw "Windows cannot see: $selected" }
Write-Host "Windows path OK: $selected" -ForegroundColor Green
$root = "${letter}:/"
$probe = 'set -e; test -d /probe; echo "Docker mount OK"; ls -la /probe | head -n 10'
& docker run --rm --mount "type=bind,source=$root,target=/probe,readonly" alpine:3.20 sh -lc $probe
if ($LASTEXITCODE -ne 0) {
    throw "Docker Desktop cannot bind-mount ${letter}:. This is below the Aetheris app layer. Check Docker Desktop file-sharing/WSL access for ${letter}: and retry."
}
Write-Host "PASS: Docker Desktop can mount ${letter}: read-only." -ForegroundColor Green
