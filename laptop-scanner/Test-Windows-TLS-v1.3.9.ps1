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

Write-Host '=============================================================================='
Write-Host 'Aetheris Windows TLS diagnostic v1.3.9'
Write-Host '=============================================================================='

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

. (Join-Path $root 'scripts\sync-agent-token.ps1')

Write-Host ''
Write-Host 'Low-level TLS 1.2 certificate probe (NO token/HTTP request is sent):'
$peer=Get-AetherisTlsPeerInfo -Base $base -TimeoutSec 10
if($peer.Ok){
  Write-Host ("  [OK] TLS protocol: {0}" -f $peer.Protocol) -ForegroundColor Green
  Write-Host ("  Cipher: {0} ({1}-bit)" -f $peer.Cipher,$peer.CipherStrength)
  Write-Host ("  Subject: {0}" -f $peer.Subject)
  Write-Host ("  Issuer: {0}" -f $peer.Issuer)
  Write-Host ("  DNS name: {0}" -f $peer.DnsName)
  Write-Host ("  SAN: {0}" -f $peer.SubjectAltName)
  Write-Host ("  Valid: {0} -> {1}" -f $peer.NotBefore,$peer.NotAfter)
  if($peer.DnsName -and ([Uri]$base).Host -ne $peer.DnsName){
    Write-Host ''
    Write-Host ("  [ACTION] Current host '{0}' differs from certificate DNS name '{1}'." -f ([Uri]$base).Host,$peer.DnsName) -ForegroundColor Yellow
    Write-Host ("           If that DNS name resolves to this server, set CENTRAL_API_URL=https://{0}" -f $peer.DnsName) -ForegroundColor Yellow
  }
}else{
  Write-Host ("  [FAIL] {0}" -f $peer.Error) -ForegroundColor Red
}

try{
  $verifyTls=Get-VerifyTls $e
  Write-Host ''
  Write-Host '.NET verified HTTPS test (NO token is sent):'
  $r=Resolve-CentralApiBase -Base $base -Tenant $tenant -VerifyTls $verifyTls
  Write-Host ("  [OK] HTTP {0}" -f $r.HealthStatus) -ForegroundColor Green
  Write-Host ("  Final: {0}" -f $r.EffectiveHealthUrl)
  Write-Host ("  Canonical: {0}" -f $r.Base)
  Write-Host ("  Transport: {0}" -f $r.Transport)
}catch{
  Write-Host ("  [FAIL] {0}" -f $_.Exception.Message) -ForegroundColor Red
  if($peer.Ok){
    Write-Host ''
    Write-Host 'The raw TLS handshake works, so this is most likely certificate hostname/trust validation.' -ForegroundColor Yellow
    if($peer.DnsName){
      Write-Host ("Try the certificate DNS name (only if it resolves to this Aetheris server): https://{0}" -f $peer.DnsName) -ForegroundColor Yellow
    }
  } else {
    Write-Host ''
    Write-Host 'The low-level TLS 1.2 handshake also failed. Check server TLS 1.2/cipher configuration and any HTTPS inspection device.' -ForegroundColor Yellow
  }
  exit 1
}
exit 0
