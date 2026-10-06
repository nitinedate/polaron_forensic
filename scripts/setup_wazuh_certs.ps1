# Generate Wazuh TLS certificates for docker-compose.vuln-scanners.yml
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$WazuhDir = Join-Path $Root "docker\wazuh"
$CertsDir = Join-Path $WazuhDir "config\wazuh_indexer_ssl_certs"

New-Item -ItemType Directory -Force -Path $CertsDir | Out-Null

Write-Host "Generating Wazuh indexer/manager TLS certificates..."
docker run --rm `
  -v "${WazuhDir}/config/wazuh_indexer_ssl_certs:/certificates" `
  -v "${WazuhDir}/config/certs.yml:/config/certs.yml" `
  wazuh/wazuh-certs-generator:0.0.2

if ($LASTEXITCODE -ne 0) {
  throw "Wazuh cert generation failed (exit $LASTEXITCODE)"
}

Write-Host "Certificates written to $CertsDir"
Write-Host "Start Wazuh: docker compose --profile vuln-scanners up -d wazuh-indexer wazuh-manager"
