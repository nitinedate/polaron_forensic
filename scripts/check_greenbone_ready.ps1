param(
    [string]$WorkerContainer = "rag_new2-worker-nessus-1",
    [int]$IntervalSeconds = 15,
    [switch]$Watch
)

$python = @'
from app.config import get_settings
from app.services.greenbone_gmp import gmp_scan_readiness, parse_socket_path
import json
s = get_settings()
sock = parse_socket_path(s.gvm_url) or s.gvm_socket_path
result = gmp_scan_readiness(
    host=s.gvm_host,
    port=s.gvm_port,
    username=s.gvm_username,
    password=s.gvm_password,
    verify=s.gvm_verify_tls,
    socket_path=sock,
)
print(json.dumps(result, indent=2))
'@

do {
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Checking Greenbone readiness..."
    docker exec $WorkerContainer python -c $python
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Readiness command failed. Check that '$WorkerContainer' is running."
        exit $LASTEXITCODE
    }

    if (-not $Watch) {
        break
    }

    Start-Sleep -Seconds $IntervalSeconds
} while ($true)
