# Pull required Ollama models for detected GPU VRAM, then accuracy extras.
# Preferred: docker compose up ollama-init
$ErrorActionPreference = "Continue"
$OllamaHost = if ($env:OLLAMA_HOST) { $env:OLLAMA_HOST } else { "http://localhost:11434" }

function Get-GpuVramMb {
    $smi = Get-Command nvidia-smi -ErrorAction SilentlyContinue
    if (-not $smi) { return 0 }
    try {
        $raw = & nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>$null
        $first = (@($raw) | Select-Object -First 1)
        return [int]([double]$first)
    } catch {
        return 0
    }
}

function Get-ModelPlan([int]$VramMb) {
    $required = [System.Collections.Generic.List[string]]@("nomic-embed-text", "qwen2.5:7b")
    $accuracy = [System.Collections.Generic.List[string]]@()
    if ($VramMb -le 0) {
        $required.Add("llama3.1:8b") | Out-Null
    } elseif ($VramMb -lt 10000) {
        $required.Add("llama3.1:8b") | Out-Null
        $required.Add("qwen3.5:9b") | Out-Null
    } elseif ($VramMb -lt 12000) {
        foreach ($m in @("llama3.1:8b", "qwen3.5:9b", "qwen2.5:14b", "deepseek-r1:14b")) { $required.Add($m) | Out-Null }
    } else {
        foreach ($m in @("llama3.1:8b", "qwen3.5:9b", "qwen2.5:14b", "deepseek-r1:14b", "gemma4:12b")) { $required.Add($m) | Out-Null }
    }
    if ($VramMb -ge 20000) { $accuracy.Add("qwen2.5:32b") | Out-Null }
    if ($VramMb -ge 24000) { $accuracy.Add("deepseek-r1:32b") | Out-Null }
    if ($VramMb -ge 40000) { $accuracy.Add("qwen2.5:72b") | Out-Null }
    return [pscustomobject]@{ Required = $required; Accuracy = $accuracy }
}

$vram = Get-GpuVramMb
$plan = Get-ModelPlan $vram
$Models = [System.Collections.Generic.List[string]]@()
foreach ($m in @($plan.Required + $plan.Accuracy)) {
    if ($m -and -not $Models.Contains($m)) { $Models.Add($m) | Out-Null }
}
if ($env:OLLAMA_PULL_MODELS) {
    foreach ($m in @($env:OLLAMA_PULL_MODELS -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        if (-not $Models.Contains($m)) { $Models.Add($m) | Out-Null }
    }
}

function Test-ModelPresent([string]$Name) {
    try {
        $list = Invoke-RestMethod -Uri "$OllamaHost/api/tags" -TimeoutSec 10
        $names = @($list.models | ForEach-Object { $_.name })
        return ($names -contains $Name) -or ($names -contains ($Name + ":latest"))
    } catch {
        return $false
    }
}

function Pull-Model {
    param([string]$Name)
    if (Test-ModelPresent $Name) {
        Write-Host "Already present: $Name"
        return
    }
    Write-Host "Pulling $Name ..."
    try {
        $body = @{ name = $Name } | ConvertTo-Json -Compress
        Invoke-RestMethod -Uri "$OllamaHost/api/pull" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 7200 | Out-Null
        Write-Host "  done: $Name"
    } catch {
        Write-Warning "Failed to pull ${Name}: $_"
    }
}

Write-Host "Ollama host: $OllamaHost"
Write-Host "GPU VRAM: ${vram}MB"
Write-Host "Required: $($plan.Required -join ', ')"
Write-Host "Accuracy: $($plan.Accuracy -join ', ')"
foreach ($m in $Models) { Pull-Model $m }
Write-Host "Model pull complete."
