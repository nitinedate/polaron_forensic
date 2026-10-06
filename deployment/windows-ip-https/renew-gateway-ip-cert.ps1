<#
.SYNOPSIS
  Renew Let's Encrypt cert for aetheris-gateway public HTTPS and reload Nginx.
#>
$ErrorActionPreference = "Stop"
$env:COMPOSE_IGNORE_ORPHANS = "true"
$env:COMPOSE_REMOVE_ORPHANS = "false"
$env:COMPOSE_PROGRESS = "plain"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $ProjectRoot

$compose = @(
    "compose",
    "--project-directory", $ProjectRoot,
    "--project-name", "aetheris-gateway",
    "-f", "services/gateway/docker-compose.yml",
    "-f", "deployment/windows-ip-https/docker-compose.gateway-public-https.yml"
)

function Invoke-DockerSafe([string[]]$ArgumentList) {
    $docker = (Get-Command docker.exe -ErrorAction SilentlyContinue)
    if (-not $docker) { $docker = Get-Command docker -ErrorAction SilentlyContinue }
    if (-not $docker) { throw "Docker CLI not found." }
    $p = Start-Process -FilePath $docker.Source -ArgumentList $ArgumentList -NoNewWindow -Wait -PassThru
    return [int]$p.ExitCode
}

$rc = Invoke-DockerSafe -ArgumentList ($compose + @("--profile", "certbot", "run", "--rm", "certbot", "renew", "--quiet"))
if ($rc -ne 0) { throw "Certbot renew failed (exit $rc)." }

$rc = Invoke-DockerSafe -ArgumentList ($compose + @("exec", "-T", "gateway", "nginx", "-s", "reload"))
if ($rc -ne 0) { throw "Nginx reload failed (exit $rc)." }

Write-Host "Certificate renewed and gateway Nginx reloaded."
