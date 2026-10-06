[CmdletBinding()]
param([string]$Root=(Get-Location).Path)
$ErrorActionPreference='Stop'
$Root=(Resolve-Path -LiteralPath $Root).Path
Write-Host '=============================================================================='
Write-Host 'Aetheris Laptop Scanner final install check v1.4.5'
Write-Host '=============================================================================='
Write-Host "Root=$Root"
$required=@(
  '.env','.env.example','docker-compose.yml','Start-Laptop.cmd',
  'scripts\start-laptop.ps1','scripts\sync-agent-token.ps1',
  'scripts\Repair-Greenbone-Feed-v1.4.1.ps1','scripts\Write-LanFingerprint.ps1',
  'scanner-agent\Dockerfile','scanner-agent\requirements.txt','scanner-agent\.agent-token',
  '.lan-fingerprint','Test-Docker-TLS-v1.4.0.ps1','Repair-Greenbone-Feed.cmd'
)
$bad=$false
foreach($rel in $required){$p=Join-Path $Root $rel;if(Test-Path -LiteralPath $p){Write-Host "[OK] $rel" -ForegroundColor Green}else{Write-Host "[FAIL] Missing $rel" -ForegroundColor Red;$bad=$true}}
$token=Join-Path $Root 'scanner-agent\.agent-token'
if(Test-Path -LiteralPath $token -PathType Container){Write-Host '[FAIL] scanner-agent\.agent-token is a directory.' -ForegroundColor Red;$bad=$true}
elseif(Test-Path -LiteralPath $token -PathType Leaf){$fs=$null;try{$fs=New-Object IO.FileStream($token,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite);Write-Host '[OK] .agent-token is a writable file.' -ForegroundColor Green}catch{Write-Host "[FAIL] .agent-token not writable: $($_.Exception.Message)" -ForegroundColor Red;$bad=$true}finally{if($null-ne$fs){$fs.Dispose()}}}
$envFile=Join-Path $Root '.env'
if(Test-Path -LiteralPath $envFile){$txt=[IO.File]::ReadAllText($envFile);foreach($expect in @('CENTRAL_API_URL=https://122.179.140.167','TENANT_SLUG=a','VERIFY_TLS=true','AGENT_VERSION=1.4.5')){if($txt -notmatch [regex]::Escape($expect)){Write-Host "[FAIL] .env missing expected: $expect" -ForegroundColor Red;$bad=$true}else{Write-Host "[OK] .env: $expect" -ForegroundColor Green}}}
$compose=Join-Path $Root 'docker-compose.yml'
if(Test-Path -LiteralPath $compose){$dc=& docker.exe compose -f $compose config --services 2>&1;$rc=$LASTEXITCODE;if($rc -eq 0){Write-Host '[OK] docker compose config --services passed.' -ForegroundColor Green}else{Write-Host '[WARN] Docker Compose validation could not run/passed nonzero. Ensure Docker Desktop is running before Start-Laptop.' -ForegroundColor Yellow}}
if($bad){exit 2}
Write-Host '[OK] Final package validation passed.' -ForegroundColor Green
exit 0
