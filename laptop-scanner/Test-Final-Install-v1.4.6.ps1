[CmdletBinding()]
param([string]$Root='D:\laptop-scanner')
$ErrorActionPreference='Stop'
$Root=(Resolve-Path -LiteralPath $Root).Path
$required=@('.env','.env.example','docker-compose.yml','Start-Laptop.cmd','scripts\start-laptop.ps1','scripts\sync-agent-token.ps1','scripts\Repair-Greenbone-Feed-v1.4.1.ps1','scanner-agent\Dockerfile','scanner-agent\requirements.txt','scanner-agent\runtime','.lan-fingerprint','Test-Docker-TLS-v1.4.0.ps1','Test-Agent-Token-Runtime-v1.4.6.ps1')
$bad=$false
Write-Host ('='*78); Write-Host 'Aetheris Laptop Scanner final install validation v1.4.6'; Write-Host ('='*78)
foreach($rel in $required){$p=Join-Path $Root $rel;if(Test-Path -LiteralPath $p){Write-Host "[OK] $rel" -ForegroundColor Green}else{Write-Host "[FAIL] Missing $rel" -ForegroundColor Red;$bad=$true}}
$runtime=Join-Path $Root 'scanner-agent\runtime'; if(Test-Path -LiteralPath $runtime -PathType Container){Write-Host '[OK] token runtime is a directory.' -ForegroundColor Green}else{$bad=$true}
$compose=Get-Content -LiteralPath (Join-Path $Root 'docker-compose.yml') -Raw
if($compose -match 'target:\s*/app/\.agent-token'){Write-Host '[FAIL] legacy token file bind remains.' -ForegroundColor Red;$bad=$true}else{Write-Host '[OK] no legacy token file bind.' -ForegroundColor Green}
if($compose -match 'target:\s*/run/aetheris-agent'){Write-Host '[OK] safe runtime directory bind present.' -ForegroundColor Green}else{Write-Host '[FAIL] runtime directory bind missing.' -ForegroundColor Red;$bad=$true}
$envText=Get-Content -LiteralPath (Join-Path $Root '.env') -Raw
if($envText -match '(?m)^CENTRAL_API_URL=https://122\.179\.140\.167\s*$'){Write-Host '[OK] central IP endpoint configured.' -ForegroundColor Green}else{Write-Host '[WARN] CENTRAL_API_URL differs from packaged production endpoint.' -ForegroundColor Yellow}
if($envText -match '(?m)^VERIFY_TLS=true\s*$'){Write-Host '[OK] TLS verification enabled.' -ForegroundColor Green}else{Write-Host '[FAIL] VERIFY_TLS is not true.' -ForegroundColor Red;$bad=$true}
if($envText -match '(?m)^AGENT_VERSION=1\.4\.6\s*$'){Write-Host '[OK] AGENT_VERSION=1.4.6.' -ForegroundColor Green}else{Write-Host '[FAIL] AGENT_VERSION is not 1.4.6.' -ForegroundColor Red;$bad=$true}
if($bad){exit 1}; Write-Host '[OK] Final package validation passed.' -ForegroundColor Green; exit 0
