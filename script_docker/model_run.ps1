# Train the report model from the physical PDFs in document_report_model,
# then reload the report agents so they use the new queries and observation rules.
$ErrorActionPreference = "Stop"
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$modelDir = Join-Path $root "backend\app\knowledge\document_report_model"
$pdfs = @(Get-ChildItem -LiteralPath $modelDir -Filter *.pdf -ErrorAction SilentlyContinue)
if (-not $pdfs.Count) {
    throw "No PDF reports found in $modelDir. Unzip the physical reports into that folder first."
}

$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) { throw "Docker was not found. Start Docker Desktop, then run model_run.cmd again." }
& docker info --format "{{.ServerVersion}}" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Docker is installed but the engine is not running." }

function Invoke-Docker {
    # Docker writes "no such object" to stderr. With ErrorAction Stop that
    # becomes a terminating error before LASTEXITCODE can be checked.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $lines = & docker @args 2>&1
        $code = $LASTEXITCODE
        $text = @($lines | ForEach-Object { "$_" }) -join "`n"
        return [pscustomobject]@{ ExitCode = $code; Text = $text.Trim() }
    }
    finally {
        $ErrorActionPreference = $prev
    }
}

Write-Host "Training the report model from $($pdfs.Count) physical report(s)." -ForegroundColor Cyan
$api = "aetheris-forensic-api-1"
$found = Invoke-Docker inspect --format "{{.State.Running}}" $api
$apiRunning = ($found.ExitCode -eq 0 -and $found.Text -eq "true")

if ($apiRunning) {
    & docker exec $api python /app/scripts/build_document_report_model.py
} else {
    Write-Host "Forensic API is not running. Training with the API image instead."
    $backend = ($root + "\backend") -replace '\\', '/'
    & docker run --rm --entrypoint python -v "${backend}:/app" -w /app rag_new2-api /app/scripts/build_document_report_model.py
}
if ($LASTEXITCODE -ne 0) { throw "Report model training failed (exit $LASTEXITCODE)" }

$reload = @(
    "aetheris-forensic-api-1",
    "aetheris-forensic-worker-report-1",
    "aetheris-forensic-worker-agent-1",
    "aetheris-mobile-android-api-1",
    "aetheris-mobile-android-worker-report-1",
    "aetheris-mobile-ios-api-1",
    "aetheris-mobile-ios-worker-report-1"
)
$running = @()
foreach ($name in $reload) {
    $state = Invoke-Docker inspect --format "{{.State.Running}}" $name
    if ($state.ExitCode -eq 0 -and $state.Text -eq "true") { $running += $name }
}
if ($running.Count) {
    Write-Host "Reloading report agents." -ForegroundColor Cyan
    & docker restart @running | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not reload the report agents." }
}

Write-Host "Report model is ready. Agents will query extracted content and write observations from document_report_model." -ForegroundColor Green
exit 0
