[CmdletBinding()]
param()
$ErrorActionPreference='Stop'

function Read-Env([string]$Path) {
    $map=@{}
    foreach($line in [IO.File]::ReadAllLines($Path)){
        if($line -match '^\s*#'){continue}
        $i=$line.IndexOf('='); if($i -lt 1){continue}
        $k=$line.Substring(0,$i).Trim(); $v=$line.Substring($i+1).Trim()
        if (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'"))) { if($v.Length -ge 2){$v=$v.Substring(1,$v.Length-2)} }
        $map[$k]=$v
    }
    return $map
}

$root=(Resolve-Path $PSScriptRoot).Path
$envPath=Join-Path $root '.env'
if(-not(Test-Path -LiteralPath $envPath -PathType Leaf)){
    $example=Join-Path $root '.env.example'
    if(-not(Test-Path -LiteralPath $example -PathType Leaf)){throw "Neither .env nor .env.example exists under $root"}
    Copy-Item -LiteralPath $example -Destination $envPath -Force
    Write-Host "[OK] Created missing .env from .env.example: $envPath" -ForegroundColor Green
}
$e=Read-Env $envPath
$base=([string]$e['CENTRAL_API_URL']).Trim()
$tenant=([string]$e['TENANT_SLUG']).Trim(); if(-not $tenant){$tenant='aetheris'}
$verify=([string]$e['VERIFY_TLS']).Trim().ToLower() -notin @('0','false','no','off')

Write-Host '=============================================================================='
Write-Host 'Aetheris Docker/OpenSSL TLS diagnostic v1.4.0'
Write-Host '=============================================================================='
Write-Host "CENTRAL_API_URL=$base"
Write-Host "TENANT_SLUG=$tenant"
Write-Host "VERIFY_TLS=$verify"
Write-Host ''

. (Join-Path $root 'scripts\sync-agent-token.ps1')

Write-Host 'Docker engine:'
$old=$ErrorActionPreference
try { $ErrorActionPreference='Continue'; $o=@(& docker.exe info 2>&1); $code=$LASTEXITCODE } finally { $ErrorActionPreference=$old }
if($code -ne 0){
    Write-Host '  [FAIL] Docker Desktop Linux engine is not ready.' -ForegroundColor Red
    Write-Host (($o|ForEach-Object{$_.ToString()}) -join [Environment]::NewLine)
    exit 2
}
Write-Host '  [OK] Docker Linux engine is ready.' -ForegroundColor Green
Write-Host ''

Write-Host 'Certificate inspection from Linux/OpenSSL (NO token is sent):'
$cert=Invoke-DockerBootstrapJson -Root $root -Mode 'inspect-cert' -Base $base -Tenant $tenant -VerifyTls $verify
$c=$cert.certificate
if($null -ne $c){
    if([bool]$c.ok){
        Write-Host ("  [OK] TLS={0} cipher={1}" -f [string]$c.tls_version,[string]$c.cipher) -ForegroundColor Green
        Write-Host ("  Subject: {0}" -f [string]$c.subject)
        Write-Host ("  Issuer:  {0}" -f [string]$c.issuer)
        if($c.san_dns){Write-Host ("  DNS SAN: {0}" -f (@($c.san_dns)-join ', '))}
        if($c.san_ip){Write-Host ("  IP SAN:  {0}" -f (@($c.san_ip)-join ', '))}
        Write-Host ("  Valid:   {0} -> {1}" -f [string]$c.not_before,[string]$c.not_after)
    } else {
        Write-Host ("  [FAIL] {0}" -f [string]$c.error) -ForegroundColor Red
    }
}
if($cert.http_redirect_hint -and [string]$cert.http_redirect_hint.location){
    Write-Host ("  HTTP redirect suggests: {0}" -f [string]$cert.http_redirect_hint.location) -ForegroundColor Yellow
}
Write-Host ''

Write-Host 'Verified HTTPS health check from Linux/OpenSSL (NO token is sent):'
$pre=Invoke-DockerBootstrapJson -Root $root -Mode 'preflight' -Base $base -Tenant $tenant -VerifyTls $verify
if([bool]$pre.ok){
    Write-Host ("  [OK] HTTP {0}" -f [string]$pre.status) -ForegroundColor Green
    Write-Host ("  Canonical: {0}" -f [string]$pre.canonical_url)
    Write-Host ("  Effective: {0}" -f [string]$pre.effective_url)
    Write-Host ("  Transport: {0}" -f [string]$pre.transport)
    Write-Host ''
    Write-Host '[OK] Windows Schannel/LSA is no longer on the scanner authentication path.' -ForegroundColor Green
    exit 0
}
Write-Host '  [FAIL] Linux/OpenSSL verification failed.' -ForegroundColor Red
Write-Host (Format-BootstrapFailure $pre)
Write-Host ''
Write-Host 'If Certificate DNS SAN contains a hostname, use that HTTPS hostname in CENTRAL_API_URL and keep VERIFY_TLS=true.' -ForegroundColor Yellow
exit 3
