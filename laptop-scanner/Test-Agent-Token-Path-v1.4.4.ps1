[CmdletBinding()]
param([string]$Root = (Get-Location).Path)
$ErrorActionPreference='Stop'
$Root=(Resolve-Path -LiteralPath $Root).Path
$path=Join-Path $Root 'scanner-agent\.agent-token'
Write-Host '=============================================================================='
Write-Host 'Aetheris AGENT token path diagnostic v1.4.4'
Write-Host '=============================================================================='
Write-Host "Root=$Root"
Write-Host "TokenPath=$path"
if(Test-Path -LiteralPath $path -PathType Container){
  Write-Host '[FAIL] .agent-token is a DIRECTORY. Apply v1.4.4 repair before Start-Laptop.' -ForegroundColor Red
  exit 2
}
if(-not(Test-Path -LiteralPath $path -PathType Leaf)){
  Write-Host '[WARN] .agent-token file does not exist yet.' -ForegroundColor Yellow
  exit 3
}
$item=Get-Item -LiteralPath $path -Force
Write-Host ("[OK] .agent-token is a file. Attributes={0} Length={1}" -f $item.Attributes,$item.Length) -ForegroundColor Green
$fs=$null
try{$fs=New-Object IO.FileStream($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite);Write-Host '[OK] .agent-token is writable.' -ForegroundColor Green}
catch{Write-Host ("[FAIL] .agent-token is not writable: {0}" -f $_.Exception.Message) -ForegroundColor Red;exit 4}
finally{if($null-ne$fs){$fs.Dispose()}}
exit 0
