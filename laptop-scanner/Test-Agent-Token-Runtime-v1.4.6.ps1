[CmdletBinding()]
param([string]$Root = 'D:\laptop-scanner')
$ErrorActionPreference='Stop'
$Root=(Resolve-Path -LiteralPath $Root).Path
$compose=Join-Path $Root 'docker-compose.yml'
$runtime=Join-Path $Root 'scanner-agent\runtime'
$token=Join-Path $runtime 'agent-token'
$envFile=Join-Path $Root '.env'
$bad=$false
Write-Host ('='*78)
Write-Host 'Aetheris agent token runtime validation v1.4.6'
Write-Host ('='*78)
if(Test-Path -LiteralPath $runtime -PathType Container){Write-Host "[OK] Runtime directory: $runtime" -ForegroundColor Green}else{Write-Host "[FAIL] Missing runtime directory: $runtime" -ForegroundColor Red;$bad=$true}
if(Test-Path -LiteralPath $token -PathType Container){Write-Host '[FAIL] runtime\agent-token is a directory.' -ForegroundColor Red;$bad=$true}else{Write-Host '[OK] runtime\agent-token is not a directory.' -ForegroundColor Green}
if(Test-Path -LiteralPath $compose -PathType Leaf){
  $c=Get-Content -LiteralPath $compose -Raw
  if($c -match 'source:\s*\.\/scanner-agent\/runtime' -and $c -match 'target:\s*\/run\/aetheris-agent'){Write-Host '[OK] Compose uses directory-to-directory token runtime bind.' -ForegroundColor Green}else{Write-Host '[FAIL] Compose runtime bind is missing.' -ForegroundColor Red;$bad=$true}
  if($c -match 'target:\s*\/app\/\.agent-token'){Write-Host '[FAIL] Legacy /app/.agent-token bind is still present.' -ForegroundColor Red;$bad=$true}else{Write-Host '[OK] Legacy /app/.agent-token bind is absent.' -ForegroundColor Green}
}
if(Test-Path -LiteralPath $envFile -PathType Leaf){
  $e=Get-Content -LiteralPath $envFile -Raw
  if($e -match '(?m)^AGENT_TOKEN_FILE=/run/aetheris-agent/agent-token\s*$'){Write-Host '[OK] .env uses the v1.4.6 token file path.' -ForegroundColor Green}else{Write-Host '[FAIL] .env AGENT_TOKEN_FILE is not v1.4.6.' -ForegroundColor Red;$bad=$true}
}
if($bad){exit 1}
Write-Host '[OK] Agent token runtime validation passed.' -ForegroundColor Green
exit 0
