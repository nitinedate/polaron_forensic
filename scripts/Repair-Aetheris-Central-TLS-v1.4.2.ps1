[CmdletBinding()]
param(
    [string]$ProjectRoot = "",
    [string]$PublicIP = "122.179.140.167",
    [string]$LanIP = "192.168.1.16",
    [string]$Email = "",
    [switch]$SelfSigned,
    [switch]$SkipCertificateIssue,
    [switch]$AllowExistingDocker443Owner
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$env:COMPOSE_IGNORE_ORPHANS = "true"
$env:COMPOSE_REMOVE_ORPHANS = "false"
$env:COMPOSE_PROGRESS = "plain"
$env:DOCKER_CLI_HINTS = "false"

function Step([string]$m) { Write-Host "`n==== $m ====" -ForegroundColor Cyan }
function Ok([string]$m) { Write-Host "[OK] $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }

function Invoke-NativeCapture {
    param([string]$FilePath,[string[]]$ArgumentList=@())
    $outFile = Join-Path $env:TEMP ("aetheris-out-" + [guid]::NewGuid().ToString("N") + ".txt")
    $errFile = Join-Path $env:TEMP ("aetheris-err-" + [guid]::NewGuid().ToString("N") + ".txt")
    try {
        $quoted = foreach ($a in $ArgumentList) { if ($a -match '[\s"]') { '"' + ($a.Replace('"','\"')) + '"' } else { $a } }
        $p = Start-Process -FilePath $FilePath -ArgumentList ($quoted -join ' ') -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        $lines = @()
        if (Test-Path $outFile) { $lines += @(Get-Content $outFile -ErrorAction SilentlyContinue) }
        if (Test-Path $errFile) { $lines += @(Get-Content $errFile -ErrorAction SilentlyContinue) }
        [pscustomobject]@{ ExitCode=[int]$p.ExitCode; Lines=$lines }
    } finally { Remove-Item $outFile,$errFile -Force -ErrorAction SilentlyContinue }
}
function Show-Lines($r) { if ($r.Lines) { $r.Lines | ForEach-Object { Write-Host $_ } } }
function Assert-Admin {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent(); $p=New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run PowerShell as Administrator." }
}
function ComposeArgs([string]$root) {
    @("compose","--project-directory",$root,"--project-name","aetheris-gateway","-f","services/gateway/docker-compose.yml","-f","deployment/windows-ip-https/docker-compose.gateway-public-https.yml")
}

Assert-Admin
if (-not $ProjectRoot) { $ProjectRoot=(Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }
$baseCompose=Join-Path $ProjectRoot "services\gateway\docker-compose.yml"
$publicCompose=Join-Path $ProjectRoot "deployment\windows-ip-https\docker-compose.gateway-public-https.yml"
$nginxPath=Join-Path $ProjectRoot "deployment\windows-ip-https\nginx.gateway.https.conf"
$setupScript=Join-Path $ProjectRoot "scripts\setup-public-https.ps1"
foreach ($p in @($baseCompose,$publicCompose,$nginxPath,$setupScript)) { if (-not (Test-Path $p)) { throw "Required file missing: $p" } }
Set-Location $ProjectRoot

Write-Host "=============================================================================="
Write-Host "Aetheris Central TLS repair v1.4.2"
Write-Host "=============================================================================="
Write-Host "ProjectRoot=$ProjectRoot"
Write-Host "PublicIP=$PublicIP"
Write-Host "LanIP=$LanIP"

Step "Preflight: who owns Windows TCP 443?"
$listeners=@(Get-NetTCPConnection -State Listen -LocalPort 443 -ErrorAction SilentlyContinue)
if ($listeners.Count) {
    $rows=foreach($l in $listeners){
        $proc=Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $l.OwningProcess) -ErrorAction SilentlyContinue
        [pscustomobject]@{Address=$l.LocalAddress;PID=$l.OwningProcess;Process=if($proc){$proc.Name}else{"<unknown>"};Executable=if($proc){$proc.ExecutablePath}else{""}}
    }
    $rows | Format-Table -AutoSize
}
$dockerPs=Invoke-NativeCapture "docker.exe" @("ps","--format","{{.ID}}|{{.Names}}|{{.Ports}}")
if($dockerPs.ExitCode -ne 0){Show-Lines $dockerPs; throw "docker ps failed."}
$other443=@($dockerPs.Lines | Where-Object { $_ -match ':443->' -and $_ -notmatch 'aetheris-gateway-gateway' })
if($other443.Count -and -not $AllowExistingDocker443Owner){
    $other443 | ForEach-Object { Write-Host $_ }
    throw "Another Docker container already publishes host 443. Stop/reconfigure that container first, or rerun only after confirming the ownership."
}

Step "Back up and update public HTTPS Nginx configuration"
$stamp=Get-Date -Format "yyyyMMdd-HHmmss"; $backup="$nginxPath.v142-$stamp.bak"; Copy-Item $nginxPath $backup -Force
$txt=[IO.File]::ReadAllText($nginxPath)
$txt=[regex]::Replace($txt,'server_name\s+[0-9.]+(?:\s+_)?\s*;',"server_name $PublicIP _;")
$txt=[regex]::Replace($txt,'/etc/letsencrypt/live/[0-9.]+/',"/etc/letsencrypt/live/$PublicIP/")
$txt=[regex]::Replace($txt,'listen\s+443\s+ssl(?:\s+default_server)?\s*;','listen 443 ssl default_server;')
$txt=[regex]::Replace($txt,'listen\s+\[::\]:443\s+ssl(?:\s+default_server)?\s*;','listen [::]:443 ssl default_server;')
if($txt -notmatch 'ssl_protocols\s+TLSv1\.2\s+TLSv1\.3'){ $txt=$txt -replace '(ssl_certificate_key\s+[^;]+;)',"$1`r`n    ssl_protocols TLSv1.2 TLSv1.3;" }
[IO.File]::WriteAllText($nginxPath,$txt,[Text.UTF8Encoding]::new($false))
Ok "Updated $nginxPath for $PublicIP; backup=$backup"

Step "Windows firewall"
foreach($port in @(80,443)){
    $name="Aetheris Public HTTPS $port"; $existing=Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
    if($existing){$existing|Set-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -Profile Any|Out-Null}else{New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -Profile Any|Out-Null}
    Ok "TCP $port allowed."
}

Step "Certificate"
if($SkipCertificateIssue){ Warn "Using existing certificate volume; certificate for $PublicIP must already exist." }
elseif($SelfSigned){
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $setupScript -ProjectRoot $ProjectRoot -PublicIP $PublicIP -LanIP $LanIP -SelfSigned -ForceRecreate
    if($LASTEXITCODE -ne 0){throw "setup-public-https.ps1 failed."}
    Ok "Self-signed certificate installed for diagnostic use."
}elseif($Email){
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $setupScript -ProjectRoot $ProjectRoot -PublicIP $PublicIP -LanIP $LanIP -Email $Email -ForceRecreate
    if($LASTEXITCODE -ne 0){throw "setup-public-https.ps1 failed."}
    Ok "Certificate setup completed."
}else{ Warn "No certificate action requested; existing cert volume will be used." }

Step "Start gateway with BOTH base + public HTTPS compose files"
$c=ComposeArgs $ProjectRoot
$up=Invoke-NativeCapture "docker.exe" @($c + @("up","-d","--force-recreate","gateway"))
Show-Lines $up
if($up.ExitCode -ne 0){ throw "Could not start gateway with the public HTTPS overlay. If error says port 443 is allocated, use the v1.4.2 diagnostic to identify its owner." }
Start-Sleep -Seconds 5

$ids=Invoke-NativeCapture "docker.exe" @("ps","--filter","label=com.docker.compose.project=aetheris-gateway","--filter","label=com.docker.compose.service=gateway","-q")
$gateway=if($ids.Lines.Count){([string]$ids.Lines[0]).Trim()}else{""}; if(-not $gateway){throw "Gateway did not start."}
$ps=Invoke-NativeCapture "docker.exe" @("ps","--filter","id=$gateway","--format","{{.ID}}|{{.Names}}|{{.Ports}}")
Show-Lines $ps
if(($ps.Lines -join " ") -notmatch ':443->443/tcp'){ throw "Gateway started but host 443 is still not published. Verify the HTTPS compose overlay and Docker Compose version." }
Ok "Gateway now publishes host TCP 443."

Step "Validate Nginx without PowerShell STDERR false-failure"
$nginx=Invoke-NativeCapture "docker.exe" @("exec",$gateway,"nginx","-t")
Show-Lines $nginx
if($nginx.ExitCode -ne 0){throw "nginx -t failed."}
Ok "nginx -t passed."

Step "Verify TLS config and certificate"
$dump=Invoke-NativeCapture "docker.exe" @("exec",$gateway,"sh","-c","nginx -T 2>&1 | grep -E 'listen .*443|server_name|ssl_certificate|ssl_protocols' | head -100")
Show-Lines $dump
if(($dump.Lines -join "`n") -notmatch 'listen\s+443\s+ssl'){throw "Nginx still has no TLS 443 server block."}
$cert=Invoke-NativeCapture "docker.exe" @("exec",$gateway,"sh","-c","ls -la '/etc/letsencrypt/live/$PublicIP'")
Show-Lines $cert
if($cert.ExitCode -ne 0){throw "No certificate mounted for $PublicIP. Re-run with -Email <address> or -SelfSigned for diagnostic use."}

Step "Verify local TLS handshake"
$probe=Invoke-NativeCapture "docker.exe" @("exec",$gateway,"sh","-c","wget -S -T 10 -O /dev/null --no-check-certificate https://127.0.0.1/api/health 2>&1")
Show-Lines $probe
if($probe.ExitCode -ne 0){throw "Local TLS handshake still fails. Review gateway logs."}
Ok "Local TLS handshake succeeds."

Write-Host "`n=============================================================================="
Ok "Central gateway repair completed."
Write-Host "From the client laptop rerun: Test-Docker-TLS-v1.4.0.ps1"
