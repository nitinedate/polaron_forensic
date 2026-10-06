[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Read-Env([string]$Path) {
    $map = @{}
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ($line -match '^\s*#') { continue }
        $i = $line.IndexOf('=')
        if ($i -lt 1) { continue }
        $k = $line.Substring(0,$i).Trim(); $v = $line.Substring($i+1).Trim()
        if (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'"))) { if ($v.Length -ge 2) { $v=$v.Substring(1,$v.Length-2) } }
        $map[$k]=$v
    }
    return $map
}
# Authentication/network calls are implemented in sync-agent-token.ps1 via
# the Linux scanner-bootstrap container (Python httpx + OpenSSL). Windows
# curl.exe/.NET Schannel/SSPI is intentionally not used for control-plane TLS.
function Run-Docker([string[]]$A,[switch]$AllowFailure) {
    $old=$ErrorActionPreference
    try { $ErrorActionPreference='Continue'; $o=& docker.exe @A 2>&1; $c=$LASTEXITCODE } finally { $ErrorActionPreference=$old }
    $t=(@($o|ForEach-Object{$_.ToString()})-join [Environment]::NewLine)
    if(-not $AllowFailure -and $c -ne 0){throw "docker command failed ($c): docker $($A -join ' ')`n$t"}
    [pscustomobject]@{ExitCode=$c;Text=$t}
}

. (Join-Path $PSScriptRoot 'sync-agent-token.ps1')

$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$envPath=Join-Path $root '.env'
if(-not(Test-Path -LiteralPath $envPath -PathType Leaf)){
    $example=Join-Path $root '.env.example'
    if(-not(Test-Path -LiteralPath $example -PathType Leaf)){throw "Neither .env nor .env.example exists under $root"}
    Copy-Item -LiteralPath $example -Destination $envPath -Force
    Write-Host "[OK] Created missing .env from .env.example: $envPath" -ForegroundColor Green
}
$e=Read-Env $envPath
$central=([string]$e['CENTRAL_API_URL']).Trim().TrimEnd('/')
$tenant=[string]$e['TENANT_SLUG']; if([string]::IsNullOrWhiteSpace($tenant)){$tenant='aetheris'}

Write-Host ''
Write-Host '============================================================================== '
Write-Host 'Aetheris laptop scanner startup - emailed access token'
Write-Host '============================================================================== '
Write-Host "Root: $root"
Write-Host "CENTRAL_API_URL=$central"
Write-Host "TENANT_SLUG=$tenant"
Write-Host ''
Write-Host '==> Checking Docker Desktop Linux engine (required for TLS bootstrap)'
$info=Run-Docker @('info') -AllowFailure
if($info.ExitCode -ne 0){
    $null=Run-Docker @('desktop','start','--timeout','120') -AllowFailure
    Start-Sleep -Seconds 5
    $info=Run-Docker @('info') -AllowFailure
}
if($info.ExitCode -ne 0){throw "Docker engine is not ready. v1.4.0 uses Linux Docker/OpenSSL for secure server authentication because Windows Schannel/SSPI can fail on this laptop.`n$($info.Text)"}
Write-Host '[OK] Docker engine is ready for Linux/OpenSSL bootstrap.' -ForegroundColor Green

Write-Host ''
Write-Host '==> Emailed access token, then linking laptop to central'
$null = Sync-LaptopAgentToken -Root $root -EnvPath $envPath -EnvMap $e

# v1.4.9: binding is complete only when the durable runtime token was written.
$runtimeToken = Join-Path $root 'scanner-agent\runtime\agent-token'
if(-not (Test-Path -LiteralPath $runtimeToken -PathType Leaf)){ throw "Bound AGENT_TOKEN runtime file is missing: $runtimeToken" }
$runtimeTokenLength = (Get-Item -LiteralPath $runtimeToken -Force).Length
if($runtimeTokenLength -lt 20){ throw "Bound AGENT_TOKEN runtime file is empty/invalid ($runtimeTokenLength bytes): $runtimeToken" }
Write-Host ("[OK] Durable scanner-agent token persisted ({0} bytes)." -f $runtimeTokenLength) -ForegroundColor Green


# v1.4.6 migration: old scanner-agent containers can retain /app/.agent-token
# as a directory in their writable layer. A new file bind then fails at OCI init.
# Remove ONLY that legacy scanner-agent container; all Greenbone containers and
# named volumes are preserved. Compose recreates the agent with the safe
# directory-to-directory /run/aetheris-agent mount below.
$legacyAgent=Run-Docker @('ps','-aq','--filter','name=aetheris-laptop-scanner-agent-1') -AllowFailure
$legacyId=(($legacyAgent.Text -split '\s+') | Where-Object { $_ -match '^[a-f0-9]{8,}$' } | Select-Object -First 1)
if($legacyId){
    $legacyMounts=Run-Docker @('inspect','-f','{{range .Mounts}}{{println .Destination}}{{end}}',$legacyId) -AllowFailure
    if($legacyMounts.Text -match '(?m)^/app/\.agent-token\s*$'){
        Write-Host '[WARN] Legacy scanner-agent uses the old /app/.agent-token file bind. Recreating only scanner-agent with the v1.4.6 runtime-directory mount.' -ForegroundColor Yellow
        $rm=Run-Docker @('rm','-f',$legacyId) -AllowFailure
        if($rm.ExitCode -ne 0){throw "Could not remove legacy scanner-agent container $legacyId. $($rm.Text)"}
        Write-Host '[OK] Legacy scanner-agent removed; Greenbone containers/volumes were not changed.' -ForegroundColor Green
    }
}

Write-Host ''
Write-Host '==> Recording host LAN fingerprint (portable roam detection)'
$fp = Join-Path $root 'scripts\Write-LanFingerprint.ps1'
if (Test-Path $fp) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fp -Root $root -Once
    Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File',$fp,'-Root',$root
    ) | Out-Null
    Write-Host '[OK] LAN fingerprint writer started.'
}

$compose=$null
foreach($n in @('docker-compose.yml','docker-compose.yaml','compose.yml','compose.yaml')){ $p=Join-Path $root $n; if(Test-Path $p){$compose=$p;break} }
if(-not $compose){throw 'Docker Compose file not found.'}

Write-Host ''
Write-Host '==> Clearing leftover scanner-agent recreate containers'
$orph=Run-Docker @('ps','-aq','--filter','name=_aetheris-laptop-scanner-agent') -AllowFailure
$ids=@($orph.Text -split '\s+' | Where-Object { $_ -match '^[a-f0-9]{12,}$' })
if($ids.Count -gt 0){
    $null=Run-Docker (@('rm','-f') + $ids) -AllowFailure
    Write-Host ("[OK] Removed {0} leftover container(s)." -f $ids.Count)
} else {
    Write-Host '[OK] No leftover recreate containers.'
}

Write-Host ''
Write-Host '==> Starting Aetheris laptop scanner stack (starts stopped containers; waits for gvmd socket)'
$agentUp=Run-Docker @('ps','-q','--filter','name=aetheris-laptop-scanner-agent-1','--filter','status=running') -AllowFailure
$gvmdUp=Run-Docker @('ps','-q','--filter','name=aetheris-laptop-gvmd-1','--filter','status=running') -AllowFailure
$agentId=(($agentUp.Text -split '\s+') | Where-Object { $_ -match '^[a-f0-9]{8,}$' } | Select-Object -First 1)
$gvmdId=(($gvmdUp.Text -split '\s+') | Where-Object { $_ -match '^[a-f0-9]{8,}$' } | Select-Object -First 1)
$runningCentral = ''
if ($agentId) {
    $envDump = Run-Docker @('inspect','-f','{{range .Config.Env}}{{println .}}{{end}}','aetheris-laptop-scanner-agent-1') -AllowFailure
    $centralLine = @($envDump.Text -split "`n" | Where-Object { $_ -match '^CENTRAL_API_URL=' } | Select-Object -First 1)
    if ($centralLine) { $runningCentral = ($centralLine -replace '^CENTRAL_API_URL=','').Trim() }
}
if ($agentId -and $runningCentral -and $runningCentral.TrimEnd('/') -ne $central.TrimEnd('/')) {
    Write-Host "scanner-agent is still using $runningCentral" -ForegroundColor Yellow
    Write-Host "Recreating scanner-agent so it uses $central"
    $up = Run-Docker @('compose','-f',$compose,'up','-d','--force-recreate','--no-deps','scanner-agent') -AllowFailure
    if ($up.Text) { Write-Host $up.Text }
    if ($up.ExitCode -ne 0) { throw "docker compose recreate scanner-agent failed with exit code $($up.ExitCode)" }
} elseif($agentId){
    Write-Host '[OK] scanner-agent already running; skipping compose up and docker restart (restart hangs this Docker engine).' -ForegroundColor Green
    Write-Host '[OK] Matched token is already on disk. The running agent reloads it on the next 401/heartbeat cycle — no container restart needed.'
} elseif($gvmdId){
    Write-Host '[OK] Greenbone already running; starting scanner-agent only.'
    $up=Run-Docker @('compose','-f',$compose,'up','-d','--no-recreate','--no-deps','scanner-agent') -AllowFailure
    if($up.Text){Write-Host $up.Text}
    if($up.ExitCode -ne 0){throw "docker compose up failed with exit code $($up.ExitCode)"}
} else {
    Write-Host 'Bringing up the laptop stack (first start can take several minutes)...'
    $up=Run-Docker @('compose','-f',$compose,'up','-d','--no-recreate') -AllowFailure
    if($up.Text){Write-Host $up.Text}
    if($up.ExitCode -ne 0 -and $up.Text -match 'already in use by container'){
        Write-Host '[WARN] Name conflict; removing leftover recreate container and retrying.' -ForegroundColor Yellow
        $orph=Run-Docker @('ps','-aq','--filter','name=_aetheris-laptop-scanner-agent') -AllowFailure
        $ids=@($orph.Text -split '\s+' | Where-Object { $_ -match '^[a-f0-9]{12,}$' })
        if($ids.Count -gt 0){ $null=Run-Docker (@('rm','-f') + $ids) -AllowFailure }
        $up=Run-Docker @('compose','-f',$compose,'up','-d','--no-recreate','--no-deps','scanner-agent') -AllowFailure
        if($up.Text){Write-Host $up.Text}
    }
    if($up.ExitCode -ne 0){throw "docker compose up failed with exit code $($up.ExitCode)"}
}

Write-Host ''
Write-Host '==> Stack status'
$st=Run-Docker @('ps','--filter','name=aetheris-laptop-','--format','table {{.Names}}\t{{.Status}}') -AllowFailure
if($st.Text){Write-Host $st.Text}

Write-Host ''
Write-Host '==> Checking Greenbone GMP socket'
$gvmHealth=Run-Docker @('inspect','-f','{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}','aetheris-laptop-gvmd-1') -AllowFailure
$ospdHealth=Run-Docker @('inspect','-f','{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}','aetheris-laptop-ospd-openvas-1') -AllowFailure
$gvmH=(($gvmHealth.Text -split '\s+') | Where-Object { $_ } | Select-Object -Last 1)
$ospdH=(($ospdHealth.Text -split '\s+') | Where-Object { $_ } | Select-Object -Last 1)
if($gvmH -eq 'healthy' -and $ospdH -eq 'healthy'){
    Write-Host '[OK] Greenbone service sockets are healthy.' -ForegroundColor Green
} else {
    Write-Host ("[WARN] Greenbone not healthy yet (gvmd={0}, ospd={1}); scanner-agent will keep retrying." -f $gvmH,$ospdH) -ForegroundColor Yellow
}

Write-Host ''
Write-Host '==> Checking Greenbone feed-backed scan configuration'
$readyCheck=Run-Docker @('compose','-f',$compose,'exec','-T','scanner-agent','python','/app/check_greenbone_ready.py') -AllowFailure
if($readyCheck.ExitCode -eq 0){
    Write-Host '[OK] Greenbone Full and fast configuration is ready.' -ForegroundColor Green
    if($readyCheck.Text){Write-Host $readyCheck.Text}
} else {
    if($readyCheck.Text){Write-Host $readyCheck.Text}
    $autoRepair=$true
    if($e.ContainsKey('AUTO_REPAIR_GREENBONE')){
        $raw=([string]$e['AUTO_REPAIR_GREENBONE']).Trim().ToLowerInvariant()
        if($raw -in @('0','false','no','off')){$autoRepair=$false}
    }
    if($autoRepair){
        $repairScript=Join-Path $root 'scripts\Repair-Greenbone-Feed-v1.4.1.ps1'
        if(Test-Path $repairScript){
            $initialWait=10
            $recoveryWait=20
            $feedLoadWait=60
            if($e.ContainsKey('GREENBONE_INITIAL_WAIT_MIN')){
                $tmp=0; if([int]::TryParse([string]$e['GREENBONE_INITIAL_WAIT_MIN'],[ref]$tmp)){$initialWait=[Math]::Max(1,$tmp)}
            }
            if($e.ContainsKey('GREENBONE_RECOVERY_WAIT_MIN')){
                $tmp2=0; if([int]::TryParse([string]$e['GREENBONE_RECOVERY_WAIT_MIN'],[ref]$tmp2)){$recoveryWait=[Math]::Max(1,$tmp2)}
            }
            if($e.ContainsKey('GVM_FEED_LOAD_WAIT_MIN')){
                $tmp3=0; if([int]::TryParse([string]$e['GVM_FEED_LOAD_WAIT_MIN'],[ref]$tmp3)){$feedLoadWait=[Math]::Max(1,$tmp3)}
            }
            Write-Host '[INFO] Greenbone is not scan-ready. Running safe feed/import check (no volume deletion and no OSPd restart while VTs load).' -ForegroundColor Yellow
            & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $repairScript -Root $root -InitialWaitMinutes $initialWait -RecoveryWaitMinutes $recoveryWait -FeedLoadWaitMinutes $feedLoadWait
            $repairRc=$LASTEXITCODE
            if($repairRc -eq 0){
                Write-Host '[OK] Greenbone feed repair completed; scanner is ready for jobs.' -ForegroundColor Green
            } elseif($repairRc -eq 10) {
                Write-Host '[WAITING] Greenbone is still loading VTs. Heartbeat stays online; the agent will not claim scans until the feed is ready.' -ForegroundColor Yellow
                Write-Host '[INFO] Leave Docker running. Do not restart OSPd and do not delete volumes. Existing queued jobs will start automatically after readiness.' -ForegroundColor Yellow
            } else {
                Write-Host ("[WARN] Greenbone feed repair exited with code {0}. Heartbeat remains online, but scans stay gated until feed import completes." -f $repairRc) -ForegroundColor Yellow
            }
        } else {
            Write-Host '[WARN] Greenbone repair script is missing; leaving scanner-agent online but not scan-ready.' -ForegroundColor Yellow
        }
    } else {
        Write-Host '[WARN] AUTO_REPAIR_GREENBONE=false; leaving scanner-agent online while Greenbone finishes importing.' -ForegroundColor Yellow
    }
}

Write-Host ''
Write-Host '==> Recent scanner-agent authentication lines'
Write-Host '[OK] Skipping docker logs (can hang on this Docker engine). Scanner-agent is already up.' -ForegroundColor Green

Write-Host ''
Write-Host '============================================================================== '
Write-Host 'STARTUP COMPLETED' -ForegroundColor Green
Write-Host '============================================================================== '
exit 0