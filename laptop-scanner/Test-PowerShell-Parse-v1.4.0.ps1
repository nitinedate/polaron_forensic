$ErrorActionPreference='Stop'
$root=(Resolve-Path $PSScriptRoot).Path
$files=@(
  (Join-Path $root 'scripts\sync-agent-token.ps1'),
  (Join-Path $root 'scripts\start-laptop.ps1'),
  (Join-Path $root 'Test-Docker-TLS-v1.4.0.ps1')
)
$failed=$false
foreach($f in $files){
  $tokens=$null; $errors=$null
  [System.Management.Automation.Language.Parser]::ParseFile($f,[ref]$tokens,[ref]$errors)|Out-Null
  if($errors.Count -gt 0){
    $failed=$true
    Write-Host "[FAIL] $f" -ForegroundColor Red
    $errors|ForEach-Object{Write-Host ("  line {0}: {1}" -f $_.Extent.StartLineNumber,$_.Message)}
  } else { Write-Host "[OK] $f" -ForegroundColor Green }
}
if($failed){exit 1}
Write-Host '[OK] PowerShell parser validation passed.' -ForegroundColor Green
