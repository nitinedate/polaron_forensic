[CmdletBinding()]
param([string]$Root = (Get-Location).Path)
$ErrorActionPreference='Stop'
$Root=(Resolve-Path -LiteralPath $Root).Path
$compose=$null
foreach($n in @('docker-compose.yml','docker-compose.yaml','compose.yml','compose.yaml')){$p=Join-Path $Root $n;if(Test-Path -LiteralPath $p -PathType Leaf){$compose=$p;break}}
$tokenDir=Join-Path $Root 'scanner-agent'
$tokenFile=Join-Path $tokenDir '.agent-token'
Write-Host '=============================================================================='
Write-Host 'Aetheris AGENT token host-path repair v1.4.4'
Write-Host '=============================================================================='
Write-Host "Root=$Root"
Write-Host "TokenPath=$tokenFile"
if(-not(Test-Path -LiteralPath $tokenDir -PathType Container)){New-Item -ItemType Directory -Force -Path $tokenDir|Out-Null}
if(Test-Path -LiteralPath $tokenFile -PathType Container){
  Write-Host '[WARN] .agent-token is a directory. Removing only scanner-agent container before repairing bind source.' -ForegroundColor Yellow
  if($compose){$old=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$o=@(& docker.exe compose -f $compose rm -f -s scanner-agent 2>&1);$rc=$LASTEXITCODE}finally{$ErrorActionPreference=$old};if($o){$o|ForEach-Object{Write-Host $_}}}
  $backup="$tokenFile.directory-backup-$(Get-Date -Format yyyyMMdd-HHmmss)"
  Move-Item -LiteralPath $tokenFile -Destination $backup -Force
  Write-Host "[OK] Preserved old directory as $backup" -ForegroundColor Green
}
if(-not(Test-Path -LiteralPath $tokenFile -PathType Leaf)){[IO.File]::WriteAllBytes($tokenFile,[byte[]]@())}
$item=Get-Item -LiteralPath $tokenFile -Force
if(($item.Attributes -band [IO.FileAttributes]::ReadOnly)-ne 0){$item.Attributes=($item.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly))}
$fs=$null
try{$fs=New-Object IO.FileStream($tokenFile,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)}finally{if($null-ne$fs){$fs.Dispose()}}
Write-Host '[OK] .agent-token is now a writable file.' -ForegroundColor Green
Write-Host '[OK] No Docker volume was deleted.' -ForegroundColor Green
