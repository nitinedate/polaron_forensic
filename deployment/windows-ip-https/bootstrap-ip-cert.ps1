param(
    [Parameter(Mandatory=$true)]
    [string]$Email,
    [switch]$Staging
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Base = Join-Path $ProjectRoot "docker-compose.yml"
$Https = Join-Path $ProjectRoot "deployment\windows-ip-https\docker-compose.public-https.yml"
$PublicIp = "122.170.114.36"

Set-Location $ProjectRoot

Write-Host "Starting temporary HTTP server for ACME validation on port 80..."
docker compose -f $Base -f $Https --profile acme-bootstrap up -d acme-bootstrap
if ($LASTEXITCODE -ne 0) { throw "Could not start acme-bootstrap. Check whether port 80 is already in use." }

$extra = @()
$certName = $PublicIp
if ($Staging) {
    $extra += "--staging"
    $certName = "$PublicIp-staging"
    Write-Host "Requesting a Let's Encrypt STAGING certificate. This certificate is intentionally not trusted."
} else {
    Write-Host "Requesting a publicly trusted Let's Encrypt short-lived IP certificate."
}

$args = @(
    "compose", "-f", $Base, "-f", $Https,
    "run", "--rm", "certbot",
    "certonly",
    "--preferred-profile", "shortlived",
    "--webroot",
    "--webroot-path", "/var/www/certbot",
    "--ip-address", $PublicIp,
    "--cert-name", $certName,
    "--email", $Email,
    "--agree-tos",
    "--non-interactive"
) + $extra

& docker @args
$rc = $LASTEXITCODE

Write-Host "Stopping temporary ACME bootstrap server..."
docker compose -f $Base -f $Https --profile acme-bootstrap rm -sf acme-bootstrap | Out-Null

if ($rc -ne 0) {
    throw "Certificate request failed. Verify Airtel WAN IP, router TCP/80 forwarding, Windows Firewall, and test from a network outside your LAN."
}

if ($Staging) {
    Write-Host "Staging validation succeeded. Now run the script again without -Staging to get the trusted certificate."
} else {
    Write-Host "Certificate issued. Next run: docker compose -f docker-compose.yml -f deployment/windows-ip-https/docker-compose.public-https.yml up -d --build"
}
