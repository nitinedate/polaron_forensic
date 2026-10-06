param([string]$Root=(Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop'

function V($p,$k){
  $m=Get-Content $p | Where-Object { $_ -match ('^'+[regex]::Escape($k)+'=(.*)$') } | Select-Object -Last 1
  if($m -match ('^'+[regex]::Escape($k)+'=(.*)$')){ return $Matches[1].Trim() }
  return ''
}

. (Join-Path $PSScriptRoot 'sync-agent-token.ps1')

$e = Join-Path $Root '.env'
if(-not (Test-Path -LiteralPath $e)){ throw ".env not found: $e" }
$base = V $e 'CENTRAL_API_URL'; if(!$base){ $base='https://122.170.114.36' }
$tenant = V $e 'TENANT_SLUG'; if(!$tenant){ $tenant='aetheris' }
$verifyRaw = (V $e 'VERIFY_TLS').ToLower()
$verifyTls = -not ($verifyRaw -in @('0','false','no','off'))
$token = V $e 'AGENT_TOKEN'
if(!$token -or $token -eq 'replace-me'){
  Write-Host '[ERROR] AGENT_TOKEN is missing/replace-me.' -ForegroundColor Red
  exit 1
}

$status = Test-AgentToken -Base $base -Tenant $tenant -Token $token -VerifyTls $verifyTls
if($status -ge 200 -and $status -lt 300){
  Write-Host ("[OK] AGENT_TOKEN accepted over .NET HttpClient (HTTP {0})." -f $status) -ForegroundColor Green
  exit 0
}
Write-Host ("[ERROR] AGENT_TOKEN is not accepted by central (HTTP {0})." -f $status) -ForegroundColor Red
exit 1
