$ErrorActionPreference = 'Stop'
$env:COMPOSE_IGNORE_ORPHANS = 'true'
$env:COMPOSE_REMOVE_ORPHANS = 'false'
$env:COMPOSE_PROGRESS = 'plain'
$ComposeFile = 'F:\rag_new2\docker-compose.https.yml'
Set-Location 'F:\rag_new2'

function Invoke-DockerSafe {
    param([Parameter(Mandatory=$true)][string]$Arguments)
    $dockerCommand = Get-Command docker.exe -ErrorAction SilentlyContinue
    if (-not $dockerCommand) { $dockerCommand = Get-Command docker -ErrorAction SilentlyContinue }
    if (-not $dockerCommand) { throw 'Docker CLI was not found.' }
    $p = Start-Process -FilePath $dockerCommand.Source -ArgumentList $Arguments -NoNewWindow -Wait -PassThru
    return [int]$p.ExitCode
}

# No --rm and no --remove-orphans: this renewal job deletes no containers.
$rc = Invoke-DockerSafe -Arguments ('compose -f "' + $ComposeFile + '" --profile certbot run certbot renew --quiet')
if ($rc -ne 0) { throw "Certbot renewal failed with Docker exit code $rc." }

$rc = Invoke-DockerSafe -Arguments ('compose -f "' + $ComposeFile + '" exec -T frontend nginx -s reload')
if ($rc -ne 0) { throw "Certificate renewal completed, but Nginx reload failed with Docker exit code $rc." }
