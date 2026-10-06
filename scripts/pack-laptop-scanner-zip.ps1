# Package the canonical laptop source without modifying it or copying legacy agent code.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$pkg = Join-Path $repo 'laptop-scanner'
$agentSrc = Join-Path $pkg "scanner-agent"
$legacy = Join-Path $repo 'scanner-agent'
if (Test-Path $legacy) { Write-Host 'Legacy repo-root scanner-agent detected but intentionally NOT copied.' }
foreach ($relative in @('Dockerfile','requirements.txt','agent\__init__.py','agent\main.py','agent\gmp_local.py','agent\port_discovery.py','agent\target_progress.py','agent\service_policy.py','agent\service_catalog.json','tests\test_service_policy_v153.py','tests\test_target_progress.py','check_greenbone_ready.py','check_greenbone_feed_state.py')) {
    if (-not (Test-Path -LiteralPath (Join-Path $agentSrc $relative) -PathType Leaf)) { throw "Required laptop source missing: $relative" }
}
$dist = Join-Path $repo 'dist'
New-Item -ItemType Directory -Path $dist -Force | Out-Null
$stage = Join-Path $env:TEMP ('aetheris-laptop-pack-' + [guid]::NewGuid().ToString('N'))
$stageRoot = Join-Path $stage 'laptop-scanner'
$zipPath = Join-Path $dist ('Aetheris-Laptop-Scanner-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.zip')
$latestPath = Join-Path $dist 'Aetheris-Laptop-Scanner.zip'
New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null
try {
    Get-ChildItem -LiteralPath $pkg -File -Recurse -Force | ForEach-Object {
        $rel = $_.FullName.Substring($pkg.Length + 1)
        $portable = $rel.Replace('\','/')
        $secret = $portable -match '(^|/)(\.env|\.agent-token|\.agent-recovery-token|\.lan-fingerprint|agent-token|agent-instance-id)$'
        $secret = $secret -or ($_.Name.StartsWith('.env.') -and $_.Name -ne '.env.example')
        $generated = $portable -match '(^|/)(_backup[^/]*|__pycache__|\.pytest_cache|logs|runtime|\.git)(/|$)' -or $portable -match '\.(pyc|pyo|log|jsonl)$'
        if (-not $secret -and -not $generated) {
            $dest = Join-Path $stageRoot $rel
            New-Item -ItemType Directory -Path (Split-Path -Parent $dest) -Force | Out-Null
            Copy-Item -LiteralPath $_.FullName -Destination $dest
        }
    }
    $runtime = Join-Path $stageRoot 'scanner-agent\runtime'
    New-Item -ItemType Directory -Path $runtime -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $runtime '.keep'), '')
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($stage, $zipPath, [IO.Compression.CompressionLevel]::Optimal, $false)
    Copy-Item -LiteralPath $zipPath -Destination $latestPath -Force
    Write-Host "Created $zipPath"
    Write-Host "Latest $latestPath"
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
