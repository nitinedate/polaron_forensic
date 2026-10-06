# Sequential Aetheris premise-server startup (Windows).
# Starts compose services one at a time. Skips anything already running.
# One-shot containers that run once and exit are ignored if already present.
# Does NOT start the client-laptop scanner-agent.
#
# Usage:
#   .\startup.cmd
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\startup.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\startup.ps1 -SkipTests
#
param(
    [switch]$IncludeWazuh,
    [switch]$Build,
    [switch]$SkipTests,
    [switch]$SkipHealthWait
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor Green
}

function Write-Skip {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor DarkGray
}

function Write-Warn {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor Yellow
}

function Resolve-Docker {
    $cmd = Get-Command docker -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }
    $fallback = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
    if (Test-Path $fallback) {
        return $fallback
    }
    throw "Docker not found. Start Docker Desktop and ensure docker.exe is installed."
}

function Wait-HttpOk {
    param(
        [string]$Url,
        [int]$TimeoutSec = 180
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
            if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 500) {
                return $true
            }
        } catch {
            # still starting
        }
        Start-Sleep -Seconds 3
    }
    return $false
}

function New-Svc {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [ValidateSet("long", "oneshot")][string]$Kind = "long",
        [ValidateSet("running", "health", "exit")][string]$Wait = "running",
        [int]$TimeoutSec = 120,
        [switch]$Critical,
        [switch]$Optional
    )
    return [pscustomobject]@{
        Name       = $Name
        Kind       = $Kind
        Wait       = $Wait
        TimeoutSec = $TimeoutSec
        Critical   = [bool]$Critical
        Optional   = [bool]$Optional
    }
}

function Get-ServiceInspect {
    param(
        [string]$DockerExe,
        [string[]]$ComposeArgs,
        [string]$Service
    )
    $cid = (& $DockerExe @ComposeArgs ps -aq -- $Service 2>$null | Select-Object -First 1)
    if (-not $cid) {
        return $null
    }
    $status = (& $DockerExe inspect -f "{{.State.Status}}" $cid 2>$null)
    if (-not $status) {
        return $null
    }
    $exitRaw = (& $DockerExe inspect -f "{{.State.ExitCode}}" $cid 2>$null)
    $health = (& $DockerExe inspect -f "{{if .State.Health}}{{.State.Health.Status}}{{end}}" $cid 2>$null)
    $exitCode = 0
    [void][int]::TryParse(("$exitRaw").Trim(), [ref]$exitCode)
    return [pscustomobject]@{
        Id       = "$cid".Trim()
        Status   = "$status".Trim()
        ExitCode = $exitCode
        Health   = "$health".Trim()
    }
}

function Format-Inspect {
    param($Info)
    if (-not $Info) {
        return "missing"
    }
    $bits = @($Info.Status)
    if ($Info.Health) {
        $bits += $Info.Health
    }
    if ($Info.Status -eq "exited") {
        $bits += "exit=$($Info.ExitCode)"
    }
    return ($bits -join "/")
}

function Wait-ServiceState {
    param(
        [string]$DockerExe,
        [string[]]$ComposeArgs,
        $Spec
    )
    if ($SkipHealthWait) {
        return $true
    }
    $deadline = (Get-Date).AddSeconds($Spec.TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $info = Get-ServiceInspect -DockerExe $DockerExe -ComposeArgs $ComposeArgs -Service $Spec.Name
        if ($Spec.Kind -eq "oneshot" -or $Spec.Wait -eq "exit") {
            if ($info -and $info.Status -eq "exited") {
                return $true
            }
        } elseif ($Spec.Wait -eq "health") {
            if ($info -and $info.Status -eq "running" -and $info.Health -eq "healthy") {
                return $true
            }
            if ($info -and $info.Status -eq "running" -and -not $info.Health) {
                return $true
            }
        } else {
            if ($info -and $info.Status -eq "running") {
                return $true
            }
        }
        Start-Sleep -Seconds 3
    }
    return $false
}

function Show-JunitResults {
    param(
        [string]$Title,
        [string]$JunitPath,
        [int]$ExitCode
    )
    Write-Host ""
    Write-Host "---- $Title ----" -ForegroundColor Cyan
    if (-not (Test-Path $JunitPath)) {
        Write-Warn "No junit report at $JunitPath (pytest exit $ExitCode)."
        return [pscustomobject]@{ Passed = 0; Failed = 0; Errors = 0; Skipped = 0; Total = 0; FailedNames = @() }
    }
    [xml]$xml = Get-Content -Raw -Path $JunitPath
    $suites = @()
    if ($xml.testsuite) {
        $suites += $xml.testsuite
    }
    if ($xml.testsuites -and $xml.testsuites.testsuite) {
        $suites += @($xml.testsuites.testsuite)
    }
    $passed = 0
    $failed = 0
    $errors = 0
    $skipped = 0
    $failedNames = New-Object System.Collections.Generic.List[string]
    foreach ($suite in $suites) {
        $cases = @($suite.testcase)
        foreach ($case in $cases) {
            $name = "$($case.classname)::$($case.name)"
            if ($case.failure) {
                $failed++
                $msg = "$($case.failure.message)"
                if (-not $msg) { $msg = "$($case.failure.'#text')" }
                $failedNames.Add($name)
                Write-Host "  FAIL  $name" -ForegroundColor Red
                if ($msg) {
                    $short = ($msg -split "`n")[0]
                    Write-Host "        $short" -ForegroundColor DarkRed
                }
            } elseif ($case.error) {
                $errors++
                $failedNames.Add($name)
                Write-Host "  ERROR $name" -ForegroundColor Red
            } elseif ($case.skipped) {
                $skipped++
                Write-Host "  SKIP  $name" -ForegroundColor DarkYellow
            } else {
                $passed++
                Write-Host "  PASS  $name" -ForegroundColor Green
            }
        }
    }
    $total = $passed + $failed + $errors + $skipped
    Write-Host ""
    Write-Host ("  Summary: {0} passed, {1} failed, {2} errors, {3} skipped  ({4} total)  pytest exit {5}" -f $passed, $failed, $errors, $skipped, $total, $ExitCode)
    return [pscustomobject]@{
        Passed      = $passed
        Failed      = $failed
        Errors      = $errors
        Skipped     = $skipped
        Total       = $total
        FailedNames = @($failedNames)
    }
}

$dockerExe = $null
$composeArgs = @()
$actions = New-Object System.Collections.Generic.List[object]
$failed = $false
$failMsg = ""
$testExit = 0

Push-Location $root
try {
    Write-Host "Aetheris sequential server startup" -ForegroundColor Green
    Write-Host "Root: $root"

    $dockerExe = Resolve-Docker
    Write-Step "Checking Docker engine"
    & $dockerExe info 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker engine is not running. Start Docker Desktop, wait until it is ready, then re-run."
    }
    Write-Ok "Docker OK: $dockerExe"

    if (-not (Test-Path (Join-Path $root ".env"))) {
        Write-Warn "WARNING: .env missing - copy .env.example to .env before production use."
    }

    Write-Step "Starting three independent products (forensic, mobile-extract, vuln)"
    $stackArgs = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $root "scripts\start-stack.ps1"),
        "-Service", "all",
        "-IncludeGvm"
    )
    if (-not $Build) { $stackArgs += "-NoBuild" }
    if ($IncludeWazuh) { $stackArgs += "-IncludeWazuh" }
    & powershell @stackArgs
    if ($LASTEXITCODE -ne 0) {
        throw "start-stack.ps1 failed (exit $LASTEXITCODE)"
    }
    $actions.Add([pscustomobject]@{ Service = "three-products"; Kind = "long"; Action = "started"; State = "forensic+mobile-extract+vuln"; Ready = $true })

    $composeArgs = @(
        "compose",
        "--project-directory", $root,
        "--project-name", "aetheris-vuln",
        "-f", "services/vuln/docker-compose.yml",
        "--profile", "gvm",
        "--profile", "vuln-scanners"
    )
    Write-Host "    Follow-up inspect/tests use the vuln compose project"

    if ($IncludeWazuh) {
        $composeArgs += @("--profile", "wazuh")
        Write-Host "    Profiles: +wazuh"
    }

    Write-Step "Service actions"
    $fmt = "{0,-22} {1,-10} {2,-10} {3}"
    Write-Host ($fmt -f "SERVICE", "KIND", "ACTION", "STATE")
    Write-Host ($fmt -f "-------", "----", "------", "-----")
    foreach ($row in $actions) {
        $color = "Gray"
        if ($row.Action -eq "skipped" -or $row.Action -eq "ignored") { $color = "DarkGray" }
        elseif ($row.Action -eq "started" -and $row.Ready) { $color = "Green" }
        elseif ($row.Action -eq "failed") { $color = "Red" }
        elseif (-not $row.Ready) { $color = "Yellow" }
        Write-Host ($fmt -f $row.Service, $row.Kind, $row.Action, $row.State) -ForegroundColor $color
    }

    if (-not $SkipHealthWait) {
        Write-Step "Waiting for product API health"
        foreach ($item in @(
            @{ Url = "http://127.0.0.1:8083/health"; Label = "Forensic API" },
            @{ Url = "http://127.0.0.1:8081/health"; Label = "Mobile extraction API" },
            @{ Url = "http://127.0.0.1:8082/health"; Label = "Vuln API" },
            @{ Url = "http://127.0.0.1:3001"; Label = "Forensic UI" }
        )) {
            if (Wait-HttpOk -Url $item.Url -TimeoutSec 120) {
                Write-Ok "$($item.Label): $($item.Url)"
            } else {
                Write-Warn "$($item.Label) not ready yet - $($item.Url)"
            }
        }
    }

    Write-Host ""
    Write-Host "Three independent products are up." -ForegroundColor Green
    Write-Host "  Forensic:          http://localhost:3001  /  :8083"
    Write-Host "  Mobile extraction: http://localhost:3002  /  :8081"
    Write-Host "  Vulnerabilities:   http://localhost:3003  /  :8082"
    Write-Host "  Helper:            http://127.0.0.1:9876/health"
    if ($IncludeWazuh) {
        Write-Host "  Wazuh:  https://localhost:55000"
    }
    Write-Host "  Laptop scanner-agent is NOT started here (client-site only)." -ForegroundColor DarkGray

    if ($SkipTests) {
        Write-Step "Scanner tests skipped (-SkipTests)"
    } else {
        $dataDir = Join-Path $root "data"
        if (-not (Test-Path $dataDir)) {
            New-Item -ItemType Directory -Path $dataDir | Out-Null
        }
        $centralJunit = Join-Path $dataDir "startup-scanner-junit.xml"
        $laptopJunit = Join-Path $dataDir "startup-laptop-scanner-junit.xml"
        $summaries = @()

        $centralFiles = @(
            "tests/test_scanner_credentials.py",
            "tests/test_scanner_agent_auth.py",
            "tests/test_scan_assessment_evidence_edge.py",
            "tests/test_scan_job_network_identity.py",
            "tests/test_edge_evidence_recovery.py",
            "tests/test_edge_ingest_verdict.py",
            "tests/test_vuln_brd_scenarios.py",
            "tests/test_vuln_orchestrator.py",
            "tests/test_vuln_module.py",
            "tests/test_port_range.py"
        )

        $apiInfo = Get-ServiceInspect -DockerExe $dockerExe -ComposeArgs $composeArgs -Service "api"
        if ($apiInfo -and $apiInfo.Status -eq "running") {
            Write-Step "Scanner test cases (central, inside api container)"
            if (Test-Path $centralJunit) {
                Remove-Item -Force $centralJunit -ErrorAction SilentlyContinue
            }
            $prevEa = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            # Isolate unit tests from live GVM/ZAP so stub cases stay stub cases.
            $pytestArgs = @(
                "exec", "-T",
                "-e", "PYTHONDONTWRITEBYTECODE=1",
                "-e", "GVM_LIVE_ENABLED=false",
                "-e", "ZAP_API_URL=",
                "api", "python", "-m", "pytest", "-v", "--tb=line", "--no-header",
                "--junitxml=/app/data/startup-scanner-junit.xml"
            ) + $centralFiles
            & $dockerExe @composeArgs @pytestArgs
            $centralCode = $LASTEXITCODE
            $ErrorActionPreference = $prevEa
            $summaries += Show-JunitResults -Title "Central scanner tests" -JunitPath $centralJunit -ExitCode $centralCode
            if ($centralCode -ne 0) {
                $testExit = 2
            }
        } else {
            Write-Warn "api container is not running - cannot execute central scanner tests inside Docker."
            $testExit = 2
        }

        Write-Step "Scanner preflight (worker-nessus; best effort; no live scan)"
        $nessus = Get-ServiceInspect -DockerExe $dockerExe -ComposeArgs $composeArgs -Service "worker-nessus"
        if ($nessus -and $nessus.Status -eq "running") {
            $prevEa = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            & $dockerExe @composeArgs exec -T worker-nessus python /scripts/scanner_preflight.py
            if ($LASTEXITCODE -ne 0) {
                Write-Warn "Preflight skipped or failed (OpenVAS feeds may still be syncing)."
            }
            $ErrorActionPreference = $prevEa
        } else {
            Write-Warn "worker-nessus is not running - preflight skipped."
        }

        $laptopDir = Join-Path $root "laptop-scanner\scanner-agent"
        $laptopTests = Join-Path $laptopDir "tests"
        $py = Get-Command python -ErrorAction SilentlyContinue
        if ((Test-Path $laptopTests) -and $py) {
            $laptopFiles = @(
                "tests/test_lan_fingerprint.py",
                "tests/test_gmp_report_evidence.py",
                "tests/test_control_plane.py",
                "tests/test_job_identity.py"
            )
            Write-Step "Scanner test cases (laptop agent, on host)"
            if (Test-Path $laptopJunit) {
                Remove-Item -Force $laptopJunit -ErrorAction SilentlyContinue
            }
            $prevEa = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            Push-Location $laptopDir
            try {
                $laptopPytest = @(
                    "-m", "pytest", "-v", "--tb=line", "--no-header",
                    "--junitxml=$laptopJunit"
                ) + $laptopFiles
                & python @laptopPytest
                $laptopCode = $LASTEXITCODE
            } finally {
                Pop-Location
            }
            $ErrorActionPreference = $prevEa
            $summaries += Show-JunitResults -Title "Laptop scanner tests" -JunitPath $laptopJunit -ExitCode $laptopCode
            if ($laptopCode -ne 0) {
                $testExit = 2
            }
        } else {
            Write-Step "Laptop scanner tests"
            if (-not (Test-Path $laptopTests)) {
                Write-Skip "laptop-scanner/scanner-agent/tests not found - skipped"
            } else {
                Write-Skip "python not on PATH - laptop agent tests skipped (central tests still ran in api)"
            }
        }

        Write-Host ""
        Write-Host "==== Scanner test totals ====" -ForegroundColor Cyan
        $tp = 0; $tf = 0; $te = 0; $ts = 0; $tt = 0
        foreach ($s in $summaries) {
            $tp += $s.Passed; $tf += $s.Failed; $te += $s.Errors; $ts += $s.Skipped; $tt += $s.Total
        }
        Write-Host ("  {0} passed, {1} failed, {2} errors, {3} skipped  ({4} total)" -f $tp, $tf, $te, $ts, $tt)
        if ($tf -gt 0 -or $te -gt 0) {
            Write-Host "  Failed tests:" -ForegroundColor Red
            foreach ($s in $summaries) {
                foreach ($n in $s.FailedNames) {
                    Write-Host "    - $n" -ForegroundColor Red
                }
            }
        }
        Write-Host "  JUnit: $centralJunit"
        if (Test-Path $laptopJunit) {
            Write-Host "  JUnit: $laptopJunit"
        }
        Write-Host "  These are unit/regression cases only. No unauthorized live scan is launched." -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "Done."
} catch {
    $failed = $true
    $failMsg = $_.Exception.Message
} finally {
    Pop-Location
}

if ($failed) {
    Write-Host ""
    Write-Host "FAILED: $failMsg" -ForegroundColor Red
    exit 1
}

if ($testExit -ne 0) {
    exit $testExit
}

exit 0
