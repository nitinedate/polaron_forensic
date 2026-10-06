# Start isolated Aetheris products plus the shared host-capacity coordinator.
param(
    [ValidateSet("forensic", "mobile-android", "mobile-ios", "mobile-extract", "vuln", "all")]
    [string]$Service = "forensic",
    [switch]$NoScanners,
    [switch]$IncludeGvm,
    [switch]$IncludeWazuh,
    [switch]$NoBuild,
    [switch]$SkipGateway,
    # Public deployment exposes the unified gateway on 80/443, with compact UIs local.
    [switch]$LoopbackUi,
    # V45.3: on "cannot stop container ... did not receive an exit event" restart the
    # Docker Desktop engine automatically and retry the wave once.
    [switch]$AutoRecoverEngine
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
. (Join-Path $root "scripts\free-published-ports.ps1")
. (Join-Path $root "scripts\docker-engine-recovery.ps1")

function Get-Docker {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) {
        $dockerExe = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
        if (Test-Path $dockerExe) { return $dockerExe }
        return "docker"
    }
    return $docker.Source
}

function Start-AetherisService {
    param(
        [string]$Name,
        [object]$Docker
    )

    $envFile = Join-Path $root ".env"
    $gvmLiveFromEnv = $false
    if (Test-Path $envFile) {
        $gvmLiveFromEnv = [bool](Select-String -Path $envFile -Pattern '^\s*GVM_LIVE_ENABLED\s*=\s*(true|1|yes)\s*$' -CaseSensitive:$false -Quiet)
    }
    $useGvm = $IncludeGvm -or $gvmLiveFromEnv

    $composeArgs = @("compose", "--project-directory", $root)
    $drivesFile = $null

    if ($Name -eq "forensic") {
        $drivesFile = Join-Path $root "docker-compose.drives.forensic.yml"
        & (Join-Path $root "scripts\generate-drive-mounts.ps1") -OutputPath $drivesFile -ServiceNames @("api", "worker-disk", "worker-parse", "worker-report")
        $composeArgs += @("--project-name", "aetheris-forensic", "-f", "services/forensic/docker-compose.yml", "-f", $drivesFile)
    }
    elseif ($Name -eq "mobile-android") {
        $drivesFile = Join-Path $root "docker-compose.drives.mobile-android.yml"
        & (Join-Path $root "scripts\generate-drive-mounts.ps1") -OutputPath $drivesFile -ServiceNames @("api", "worker-build", "worker-parse")
        $composeArgs += @("--project-name", "aetheris-mobile-android", "-f", "services/mobile-android/docker-compose.yml", "-f", $drivesFile)
        if ($LoopbackUi) { $composeArgs += @("-f", "deployment/windows-ip-https/docker-compose.mobile-android-loopback.yml") }
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "scripts\ensure-examiner-kit.ps1")
    }
    elseif ($Name -eq "mobile-ios") {
        $drivesFile = Join-Path $root "docker-compose.drives.mobile-ios.yml"
        & (Join-Path $root "scripts\generate-drive-mounts.ps1") -OutputPath $drivesFile -ServiceNames @("api", "worker-build", "worker-parse")
        $composeArgs += @("--project-name", "aetheris-mobile-ios", "-f", "services/mobile-ios/docker-compose.yml", "-f", $drivesFile)
        if ($LoopbackUi) { $composeArgs += @("-f", "deployment/windows-ip-https/docker-compose.mobile-ios-loopback.yml") }
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "scripts\ensure-examiner-kit.ps1")
    }
    elseif ($Name -eq "mobile-extract") {
        # Legacy compatibility stack. New deployments should use mobile-android/mobile-ios.
        $drivesFile = Join-Path $root "docker-compose.drives.mobile.yml"
        & (Join-Path $root "scripts\generate-drive-mounts.ps1") -OutputPath $drivesFile -ServiceNames @("api", "worker-mobile")
        $composeArgs += @("--project-name", "aetheris-mobile-extract", "-f", "services/mobile-extract/docker-compose.yml", "-f", $drivesFile)
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "scripts\ensure-examiner-kit.ps1")
    }
    elseif ($Name -eq "vuln") {
        $composeArgs += @("--project-name", "aetheris-vuln", "-f", "services/vuln/docker-compose.yml")
        if (-not $NoScanners) {
            $composeArgs += @("--profile", "vuln-scanners")
            Write-Host "Including network/web auxiliary scanners (ZAP, Trivy) - profile: vuln-scanners"
        }
        if ($useGvm) {
            $composeArgs += @("--profile", "gvm")
            Write-Host "Including Greenbone/OpenVAS (GVM) - profile: gvm"
        }
        if ($IncludeWazuh) {
            $composeArgs += @("--profile", "wazuh")
            Write-Host "Including Wazuh endpoint stack - profile: wazuh"
            $wazuhCa = Join-Path $root "docker\wazuh\config\wazuh_indexer_ssl_certs\root-ca.pem"
            if (-not (Test-Path $wazuhCa)) {
                Write-Host "Wazuh TLS certs missing - generating..."
                & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "scripts\setup_wazuh_certs.ps1")
            }
        }
    }

    $waves = @()
    if ($Name -eq "forensic") {
        $waves = @(
            @("neo4j", "opensearch"),
            @("ollama"),
            @("ollama-init"),
            @("nvidia-cuda"),
            @("api"),
            @("worker-disk", "worker-parse", "worker-report", "worker-progress", "worker-beat", "worker-rag-gpu", "worker-ocr-gpu")
        )
    }
    elseif ($Name -eq "mobile-android" -or $Name -eq "mobile-ios") {
        $waves = @(
            @("nvidia-cuda"),
            @("api"),
            @("worker-build", "worker-parse", "worker-rag", "worker-ocr", "worker-report", "worker-progress", "worker-beat"),
            @("frontend")
        )
    }
    elseif ($Name -eq "mobile-extract") {
        $waves = @(
            @("nvidia-cuda"),
            @("api"),
            @("worker-mobile", "worker-beat", "worker-ocr-gpu", "worker-rag-gpu")
        )
    }
    elseif ($Name -eq "vuln") {
        $infra = @()
        $scanners = @()
        if (-not $NoScanners) { $scanners += @("zap", "trivy") }
        if ($useGvm) {
            # KEEP_ALIVE feed containers stay healthy; only gpg-data / pg-gvm-migrator exit 0.
            $scanners += @(
                "vulnerability-tests", "notus-data", "scap-data", "cert-bund-data",
                "dfn-cert-data", "data-objects", "report-formats",
                "gpg-data", "pg-gvm-migrator", "redis-gvm"
            )
        }
        $engines = @()
        if ($useGvm) {
            $engines += @("pg-gvm", "gvmd", "configure-openvas", "openvas", "openvasd", "ospd-openvas")
        }
        $waves = @(
            $infra,
            $(if ($scanners.Count) { $scanners } else { @() }),
            $(if ($engines.Count) { $engines } else { @() }),
            @("api"),
            @("worker-nessus")
        )
    }

    # True one-shots exit 0 when finished. `compose up --wait` treats that as failure.
    # Feed containers (vulnerability-tests, etc.) use KEEP_ALIVE=1 and must NOT be listed here.
    $oneShotServices = @(
        "ollama-init",
        "gpg-data",
        "pg-gvm-migrator",
        "configure-openvas"
    )

    $buildOnce = -not $NoBuild
    foreach ($wave in $waves) {
        $names = @($wave | Where-Object { $_ })
        if (-not $names.Count) { continue }

        $oneShots = @($names | Where-Object { $oneShotServices -contains $_ })
        $durable = @($names | Where-Object { $oneShotServices -notcontains $_ })

        if ($oneShots.Count) {
            Write-Host "Starting $($Name) one-shots: $($oneShots -join ', ')"
            $upOnce = @("up", "-d", "--remove-orphans", "--pull", "missing")
            if ($NoBuild) { $upOnce += "--no-build" }
            if ($buildOnce) {
                $upOnce += "--build"
                $buildOnce = $false
            }
            $upOnce += $oneShots
            & $Docker @composeArgs @upOnce
            if ($LASTEXITCODE -ne 0) {
                throw "docker compose failed for $Name one-shots [$($oneShots -join ', ')] (exit $LASTEXITCODE)"
            }
            # Resolve container IDs and wait for clean exit (0).
            $ids = @(& $Docker @composeArgs ps -aq @oneShots 2>$null | Where-Object { $_ })
            if (-not $ids.Count) {
                Start-Sleep -Seconds 2
                $ids = @(& $Docker @composeArgs ps -aq @oneShots 2>$null | Where-Object { $_ })
            }
            foreach ($id in $ids) {
                $code = & $Docker wait $id
                if ($LASTEXITCODE -ne 0) {
                    throw "docker wait failed for one-shot container $id"
                }
                if ([int]$code -ne 0) {
                    (Invoke-NativeCapture -Exe $Docker -Arguments @("logs", "--tail", "40", $id)).Lines | ForEach-Object { Write-Host $_ }
                    throw "one-shot container $id exited with code $code"
                }
            }
            Write-Host "One-shots completed cleanly: $($oneShots -join ', ')"
        }

        if (-not $durable.Count) { continue }
        Write-Host "Starting $($Name) wave: $($durable -join ', ')"
        $waitSec = "600"
        if ($durable -contains "ollama" -or $oneShots -contains "ollama-init") {
            $waitSec = "7200"
        }
        elseif ($durable -contains "gvmd") {
            # Covers pg-gvm recovery plus gvmd's 10 minute start period.
            $waitSec = "2400"
        }
        $upArgs = @("up", "-d", "--remove-orphans", "--pull", "missing", "--wait", "--wait-timeout", $waitSec)
        if ($NoBuild) { $upArgs += "--no-build" }
        if ($buildOnce) {
            $upArgs += "--build"
            $buildOnce = $false
        }
        $upArgs += $durable
        # V45.3: workers are stopped with their grace period BEFORE recreate so Celery
        # cold-shutdown can release CUDA/locks; `up -d` alone uses a 10 s default and
        # SIGKILLs mid-task, which is what produced the unkillable container.
        $workerNames = @($durable | Where-Object { $_ -like "worker-*" })
        if ($workerNames.Count) {
            $stopped = Stop-AetherisWorkers -Docker $Docker -ComposeArgs $composeArgs -Services $workerNames -GraceSec 120
            if (-not $stopped) {
                Write-Host "A worker container could not be stopped; invoking recovery." -ForegroundColor Yellow
            }
        }
        $waveOk = Invoke-ComposeWithRecovery -Docker $Docker -ComposeArgs $composeArgs -ComposeCommand $upArgs -AutoRecoverEngine:$AutoRecoverEngine
        if (-not $waveOk) {
            if ($durable -contains "gvmd") {
                Write-Host "Greenbone did not become healthy. Recent gvmd and pg-gvm logs:" -ForegroundColor Yellow
                (Invoke-NativeCapture -Exe $Docker -Arguments ($composeArgs + @("logs", "--tail", "40", "gvmd", "pg-gvm"))).Lines | ForEach-Object { Write-Host $_ }
            }
            throw "docker compose failed for $Name wave [$($durable -join ', ')] (exit $LASTEXITCODE)"
        }
    }

    Write-Host ""
    if ($Name -eq "forensic") {
        Write-Host "Forensic API started on http://localhost:8083"
    }
    elseif ($Name -eq "mobile-android") {
        Write-Host "Android Forensics API: http://localhost:8081"
        Write-Host "Android compact UI:    http://localhost:3002"
    }
    elseif ($Name -eq "mobile-ios") {
        Write-Host "iOS Forensics API:     http://localhost:8084"
        Write-Host "iOS compact UI:        http://localhost:3004"
    }
    elseif ($Name -eq "mobile-extract") {
        Write-Host "Legacy mobile extraction API started on http://localhost:8081"
    }
    elseif ($Name -eq "vuln") {
        Write-Host "Vulnerabilities API started on http://localhost:8082"
        Write-Host "Laptop:   CENTRAL_API_URL=http://host.docker.internal:3000"
        if (-not $NoScanners) {
            Write-Host "ZAP:      http://localhost:8090"
            Write-Host "Trivy:    http://localhost:4954"
        }
        if ($IncludeWazuh) {
            Write-Host "Wazuh:    https://localhost:55000"
        }
        if ($useGvm) {
            Write-Host "GVM:      unix:///run/gvmd/gvmd.sock (shared with worker-nessus)"
        }
    }
}

Push-Location $root
try {
    $docker = Get-Docker

    # Bind-mount ./backend:/app requires real source on the host. An empty backend
    # directory shadows the image and crashes the API with "No module named app".
    $backendMain = Join-Path $root "backend\app\main.py"
    if (-not (Test-Path $backendMain)) {
        throw "Missing $backendMain - restore backend source before starting (bind-mount would hide the image app)."
    }

    Write-Host "Starting shared Postgres, Redis, MinIO, pgAdmin, and MailHog..." -ForegroundColor Cyan
    & (Join-Path $root "scripts\move-processing-data-to-backup.ps1")
    foreach ($volumeName in @("aetheris-forensic_pgdata", "aetheris-forensic_pgadmin_data")) {
        Ensure-DockerVolume -Docker $docker -Name $volumeName
    }
    $commonArgs = @(
        "compose", "--project-directory", $root, "--project-name", "aetheris-common",
        "-f", "services/common/docker-compose.yml"
    )
    & $docker @commonArgs @("up", "-d", "--remove-orphans", "--pull", "missing", "--wait", "--wait-timeout", "180", "postgres", "redis", "minio", "pgadmin", "mailhog")
    if ($LASTEXITCODE -ne 0) { throw "shared infrastructure startup failed (exit $LASTEXITCODE)" }
    & $docker @commonArgs @("up", "-d", "--force-recreate", "--no-deps", "postgres-ensure")
    if ($LASTEXITCODE -ne 0) { throw "database ensure failed to start (exit $LASTEXITCODE)" }
    $ensureId = (& $docker @commonArgs @("ps", "-aq", "postgres-ensure") | Select-Object -First 1)
    if (-not $ensureId) { throw "postgres-ensure container was not created" }
    $ensureCode = & $docker wait $ensureId
    if ($LASTEXITCODE -ne 0 -or [int]$ensureCode -ne 0) {
        & $docker logs --tail 40 $ensureId
        throw "postgres-ensure exited with code $ensureCode"
    }
    Write-Host "Shared infrastructure is up. Postgres 127.0.0.1:5434, Redis 127.0.0.1:6380, MinIO 127.0.0.1:9004, pgAdmin 127.0.0.1:5052." -ForegroundColor Green

    $targets = if ($Service -eq "all") { @("forensic", "mobile-android", "mobile-ios", "vuln") } else { @($Service) }
    foreach ($name in $targets) {
        Start-AetherisService -Name $name -Docker $docker
    }

    if ($SkipGateway) {
        Write-Host "Skipping the port 3000 gateway. Public HTTPS will publish 80, 443, and 127.0.0.1:3001."
    } else {
        Write-Host "Starting API gateway (single UI)..."
        # Ignore missing legacy per-product frontend containers (rm -f still writes stderr).
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
        foreach ($oldUi in @("aetheris-forensic-frontend-1", "aetheris-mobile-extract-frontend-1", "aetheris-vuln-frontend-1")) {
            & $docker rm -f $oldUi 2>&1 | Out-Null
        }
        $ErrorActionPreference = $prevEap
        $gwCompose = @(
            "compose", "--project-directory", $root, "--project-name", "aetheris-gateway",
            "-f", "services/gateway/docker-compose.yml"
        )
        Clear-OccupiedHostPorts -Docker $docker -ComposeArgs $gwCompose -Services @("gateway") -IncludeRunning
        $gwArgs = $gwCompose + @("up", "-d", "--remove-orphans", "--wait", "--wait-timeout", "180")
        if (-not $NoBuild) { $gwArgs += "--build" }
        & $docker @gwArgs
        if ($LASTEXITCODE -ne 0) {
            throw "docker compose failed for gateway (exit $LASTEXITCODE)"
        }
        Write-Host "Disk/Vulnerability gateway UI: http://localhost:3001"
        Write-Host "Gateway alias:              http://localhost:3000"
    }
    if ($targets -contains "mobile-android") { Write-Host "Android compact UI:         http://localhost:3002" }
    if ($targets -contains "mobile-ios") { Write-Host "iOS compact UI:             http://localhost:3004" }

    if ($targets -contains "forensic" -or $targets -contains "mobile-android" -or $targets -contains "mobile-ios" -or $targets -contains "mobile-extract") {
        Write-Host "Ensuring Windows HostDrive/mobile USB helper is online..." -ForegroundColor Cyan
        $ensureHelper = Join-Path $root "scripts\ensure-host-drive-helper.ps1"
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ensureHelper
        if ($LASTEXITCODE -ne 0) {
            Write-Host "WARNING: HostDrive helper startup returned exit $LASTEXITCODE. Android MTP/ADB detection may be unavailable." -ForegroundColor Yellow
        }

        $helperHealth = $null
        try {
            $helperHealth = Invoke-RestMethod -Uri "http://127.0.0.1:9876/health" -TimeoutSec 3
        } catch { $helperHealth = $null }

        if ($helperHealth -and [bool]$helperHealth.ok) {
            Write-Host "Host drive helper online on port 9876 (bind=$($helperHealth.bind_host))." -ForegroundColor Green
        } else {
            Write-Host "HostDrive helper is still offline. Running the one-click repair now..." -ForegroundColor Yellow
            $repairUsb = Join-Path $root "scripts\repair-mobile-usb.ps1"
            if (Test-Path -LiteralPath $repairUsb) {
                & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $repairUsb
                $repairExit = $LASTEXITCODE
                try {
                    $helperHealth = Invoke-RestMethod -Uri "http://127.0.0.1:9876/health" -TimeoutSec 5
                } catch { $helperHealth = $null }
                if ($helperHealth -and [bool]$helperHealth.ok) {
                    Write-Host "HostDrive helper repaired and online (bind=$($helperHealth.bind_host))." -ForegroundColor Green
                } else {
                    Write-Host "WARNING: HostDrive repair returned $repairExit and the helper is still offline. Double-click Repair-Mobile-USB.cmd to view diagnostics." -ForegroundColor Yellow
                }
            } else {
                Write-Host "WARNING: Host drive helper is still offline and the repair script is missing." -ForegroundColor Yellow
            }
        }

        # Keep the helper available after the next Windows logon as well.
        try {
            $task = Get-ScheduledTask -TaskName "AetherisHostDriveHelper" -ErrorAction SilentlyContinue
            if (-not $task) {
                Write-Host "Installing host drive helper autostart (logon task)..."
                & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "scripts\install-host-drive-helper-task.ps1")
            }
        } catch { }
    }
}
finally {
    Pop-Location
}
