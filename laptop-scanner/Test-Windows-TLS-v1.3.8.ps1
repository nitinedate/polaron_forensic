$ErrorActionPreference='Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$envPath = Join-Path $root '.env'

function Read-EnvMap([string]$Path){
  $map=@{}
  if(-not (Test-Path -LiteralPath $Path)){return $map}
  foreach($line in [IO.File]::ReadAllLines($Path)){
    if($line -match '^\s*#'){continue}
    $i=$line.IndexOf('='); if($i -lt 1){continue}
    $map[$line.Substring(0,$i).Trim()]=$line.Substring($i+1).Trim().Trim('"').Trim("'")
  }
  return $map
}

Write-Host '============================================================================== '
Write-Host 'Aetheris Windows TLS diagnostic v1.3.8'
Write-Host '============================================================================== '

$e=Read-EnvMap $envPath
$base=([string]$e['CENTRAL_API_URL']).Trim()
$tenant=([string]$e['TENANT_SLUG']).Trim(); if(!$tenant){$tenant='aetheris'}
Write-Host "CENTRAL_API_URL=$base"
Write-Host "TENANT_SLUG=$tenant"
Write-Host ''

Write-Host 'Windows services:'
foreach($name in @('RpcSs','CryptSvc','KeyIso','SamSs')){
  $svc=Get-Service -Name $name -ErrorAction SilentlyContinue
  if($svc){ Write-Host ("  {0,-10} {1}" -f $name,$svc.Status) }
  else { Write-Host ("  {0,-10} NOT FOUND" -f $name) }
}

try{
  $u=[Uri]$base
  $port=if($u.IsDefaultPort){ if($u.Scheme -eq 'https'){443}else{80} } else {$u.Port}
  Write-Host ''
  Write-Host ("TCP test: {0}:{1}" -f $u.Host,$port)
  $tcp=New-Object Net.Sockets.TcpClient
  $ar=$tcp.BeginConnect($u.Host,$port,$null,$null)
  if(-not $ar.AsyncWaitHandle.WaitOne(5000)){ throw 'TCP connect timeout' }
  $tcp.EndConnect($ar)
  Write-Host '  [OK] TCP connection established.' -ForegroundColor Green
  $tcp.Close()
}catch{
  Write-Host ("  [FAIL] {0}" -f $_.Exception.Message) -ForegroundColor Red
}

try{
  . (Join-Path $root 'scripts\sync-agent-token.ps1')
  $verifyTls=Get-VerifyTls $e
  Write-Host ''
  Write-Host '.NET HTTPS test (no token is sent):'
  $r=Resolve-CentralApiBase -Base $base -Tenant $tenant -VerifyTls $verifyTls
  Write-Host ("  [OK] HTTP {0}" -f $r.HealthStatus) -ForegroundColor Green
  Write-Host ("  Final: {0}" -f $r.EffectiveHealthUrl)
  Write-Host ("  Canonical: {0}" -f $r.Base)
  Write-Host ("  Transport: {0}" -f $r.Transport)
}catch{
  Write-Host ("  [FAIL] {0}" -f $_.Exception.Message) -ForegroundColor Red
  Write-Host ''
  Write-Host 'If the error still mentions SEC_E_INTERNAL_ERROR / Local Security Authority:' -ForegroundColor Yellow
  Write-Host '  1. Reboot Windows.'
  Write-Host '  2. Confirm CryptSvc and KeyIso are Running.'
  Write-Host '  3. Install pending Windows updates.'
  Write-Host '  4. Use the HTTPS DNS name or IP actually present in the server certificate.'
  Write-Host '  5. Keep VERIFY_TLS=true for production.'
  exit 1
}
exit 0
