$ErrorActionPreference='Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$envPath = Join-Path $root '.env'
if(-not (Test-Path -LiteralPath $envPath)){ throw ".env not found: $envPath" }

function Read-EnvMap([string]$Path){
  $map=@{}
  foreach($line in [IO.File]::ReadAllLines($Path)){
    if($line -match '^\s*#'){continue}
    $i=$line.IndexOf('='); if($i -lt 1){continue}
    $map[$line.Substring(0,$i).Trim()]=$line.Substring($i+1).Trim().Trim('"').Trim("'")
  }
  return $map
}

. (Join-Path $root 'scripts\sync-agent-token.ps1')
$e=Read-EnvMap $envPath
$base=([string]$e['CENTRAL_API_URL']).Trim()
$tenant=([string]$e['TENANT_SLUG']).Trim(); if(!$tenant){$tenant='aetheris'}
$verifyTls=Get-VerifyTls $e
Write-Host "Checking $base without sending any token..."
$r=Resolve-CentralApiBase -Base $base -Tenant $tenant -VerifyTls $verifyTls
Write-Host ("HTTP: {0}" -f $r.HealthStatus)
Write-Host ("Final URL: {0}" -f $r.EffectiveHealthUrl)
Write-Host ("Canonical CENTRAL_API_URL: {0}" -f $r.Base)
Write-Host ("Transport: {0}" -f $r.Transport)
