# Sample Vulnerability (Nessus BRD) dry-run against local stack.
# Prerequisites: docker compose up; firm admin with vuln permissions (firm "admin" role).
#
# Usage (PowerShell):
#   cd E:\rag_new2
#   .\scripts\sample_vuln_dry_run.ps1 -Tenant aetheris -Email admin@yourfirm.test -Password 'YourPassword'
#
# Defaults assume API on http://localhost:8080

param(
  [string]$BaseUrl = "http://localhost:8080",
  [Parameter(Mandatory = $true)][string]$Tenant,
  [Parameter(Mandatory = $true)][string]$Email,
  [Parameter(Mandatory = $true)][string]$Password,
  [string]$CaseId = "00000000-0000-4000-8000-000000000001"
)

$ErrorActionPreference = "Stop"
$headers = @{ "Content-Type" = "application/json"; "X-Tenant" = $Tenant }

function Invoke-Api($Method, $Path, $Body = $null) {
  $uri = "$BaseUrl$Path"
  $params = @{ Uri = $uri; Method = $Method; Headers = $headers }
  if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 8) }
  return Invoke-RestMethod @params
}

Write-Host "== 1) Login (firm tenant: $Tenant) ==" -ForegroundColor Cyan
$login = Invoke-Api POST "/api/auth/login" @{ email = $Email; password = $Password }
$token = $login.access_token
if (-not $token) { $token = $login.accessToken }
if (-not $token) { throw "Login failed — check tenant/email/password. Response: $($login | ConvertTo-Json -Depth 4)" }
$headers["Authorization"] = "Bearer $token"
Write-Host "OK logged in"

Write-Host "== 2) Overview KPIs ==" -ForegroundColor Cyan
$ov = Invoke-Api GET "/api/vuln/overview"
$ov | ConvertTo-Json -Depth 5

Write-Host "== 3) Register scanner ==" -ForegroundColor Cyan
$scanner = Invoke-Api POST "/api/scanners" @{
  name = "Sample Nessus Lab"
  url = "https://nessus.lab.local:8834"
  edition = "professional"
  api_key_ref = "vault://lab/nessus/api"
}
$scannerId = $scanner.id
Write-Host "scanner_id=$scannerId"

Write-Host "== 4) Register agent (BRD lifecycle) ==" -ForegroundColor Cyan
$agentUuid = [guid]::NewGuid().ToString()
$agent = Invoke-Api POST "/api/vuln/agents" @{
  agent_uuid = $agentUuid
  name = "lab-endpoint-01"
  hostname = "WIN-LAB-01"
  platform = "windows"
  scanner_id = $scannerId
  lifecycle_state = "planned"
  device_class = "laptop"
}
$agentId = $agent.id
Write-Host "agent_id=$agentId uuid=$agentUuid"

# Planned -> Installed -> Linked -> Healthy
Invoke-Api POST "/api/vuln/agents/$agentId/transition" @{ lifecycle_state = "installed"; evidence_note = "MSI installed" } | Out-Null
Invoke-Api POST "/api/vuln/agents/$agentId/transition" @{ lifecycle_state = "linked"; evidence_note = "Linked to scanner" } | Out-Null
Invoke-Api POST "/api/vuln/agents/$agentId/transition" @{ lifecycle_state = "healthy"; evidence_note = "First check-in OK" } | Out-Null
Write-Host "Agent transitioned to healthy"

Write-Host "== 5) Credential vault ref (no plaintext) ==" -ForegroundColor Cyan
$cred = Invoke-Api POST "/api/vuln/credentials" @{
  name = "Windows local admin (lab)"
  vault_ref = "vault://lab/nessus/win-scan-acct"
  credential_type = "windows"
  privilege_scope = "local_admin"
}
$credId = $cred.id
Write-Host "credential_id=$credId"
Invoke-Api PATCH "/api/vuln/credentials/$credId" @{
  lifecycle_state = "tested"
  last_test_result = "ok"
} | Out-Null

Write-Host "== 6) Scan policy ==" -ForegroundColor Cyan
$policy = Invoke-Api POST "/api/scan-policies" @{
  name = "Q-Lab Basic Network"
  policy_type = "basic_network"
  case_id = $CaseId
  scanner_id = $scannerId
  settings_json = @{ discovery = "default"; do_not_scan_dos = $true }
  compliance_framework = "ISO27001"
}
$policyId = $policy.id
Write-Host "policy_id=$policyId"

Write-Host "== 7) Launch scan (preflight required) ==" -ForegroundColor Cyan
$job = Invoke-Api POST "/api/cases/$CaseId/scan-jobs" @{
  policy_id = $policyId
  scanner_id = $scannerId
  authorization_ref = "CHG-LAB-2026-001"
  preflight_confirmed = $true
  targets = @(
    @{ target = "10.10.10.25"; target_type = "host"; credential_ref = $cred.vault_ref; excluded = $false }
    @{ target = "10.10.10.26"; target_type = "host"; excluded = $false }
    @{ target = "10.10.10.1"; target_type = "host"; excluded = $true }
  )
}
$jobId = $job.id
Write-Host "scan_job_id=$jobId status=$($job.status)"

Write-Host "== 8) Wait briefly for nessus-sync worker ==" -ForegroundColor Cyan
Start-Sleep -Seconds 5
$job2 = Invoke-Api GET "/api/scan-jobs/$jobId"
Write-Host "scan status now: $($job2.status)"

Write-Host "== 9) Assets / findings / results ==" -ForegroundColor Cyan
$assets = Invoke-Api GET "/api/assets?case_id=$CaseId&page=1&page_size=20"
Write-Host "assets=$($assets.total)"
$vulns = Invoke-Api GET "/api/cases/$CaseId/vulnerabilities?page=1&page_size=20"
Write-Host "findings=$($vulns.total)"
$results = Invoke-Api GET "/api/vuln/scan-jobs/$jobId/results"
Write-Host "scan_results=$($results.Count)"

Write-Host "== 10) Dashboard layers + snapshot ==" -ForegroundColor Cyan
$exec = Invoke-Api GET "/api/vuln/dashboards/executive"
Write-Host "executive KPIs: $($exec.widgets.kpis | ConvertTo-Json -Compress)"
$health = Invoke-Api GET "/api/vuln/dashboards/scanner_health"
Write-Host "agent_coverage: $($health.widgets.agent_coverage | ConvertTo-Json -Compress)"
$snap = Invoke-Api POST "/api/vuln/dashboards/executive/snapshot" @{}
Write-Host "snapshot_id=$($snap.id)"

Write-Host "== 11) Remediation + exception SoD note ==" -ForegroundColor Cyan
if ($vulns.total -gt 0 -and $vulns.items.Count -gt 0) {
  $fid = $vulns.items[0].id
  $task = Invoke-Api POST "/api/remediation-tasks" @{
    finding_id = $fid
    status = "open"
    sla_due = (Get-Date).AddDays(7).ToString("o")
  }
  Write-Host "remediation_task=$($task.id)"
  $ex = Invoke-Api POST "/api/vuln/exceptions" @{
    finding_id = $fid
    reason = "Compensating WAF control until next patch window"
    compensating_controls = "WAF rule-set v3"
    expires_at = (Get-Date).AddDays(30).ToString("o")
    residual_risk = "medium"
  }
  Write-Host "exception_id=$($ex.id) (approve with a DIFFERENT user who has exception:approve)"
} else {
  Write-Host "No findings yet (expected if Nessus stub has empty vuln list). Assets from targets should still exist."
  if ($assets.total -gt 0) {
    $aid = $assets.items[0].id
    Invoke-Api POST "/api/vuln/assets/$aid/owners" @{
      owner_role = "technical"
      owner_email = "owner.lab@example.com"
      source = "manual"
    } | Out-Null
    Write-Host "Assigned technical owner on asset $aid"
  }
}

Write-Host "== 12) Evidence package ==" -ForegroundColor Cyan
$ev = Invoke-Api POST "/api/vuln/evidence" @{
  case_id = $CaseId
  framework = "ISO27001"
  control_id = "A.12.6.1"
  title = "Lab vulnerability scan evidence - Q dry-run"
  metadata_json = @{ scan_job_id = $jobId; authorization_ref = "CHG-LAB-2026-001" }
}
Write-Host "evidence_id=$($ev.id) hash=$($ev.integrity_hash)"

Write-Host ""
Write-Host "DONE. UI checks:" -ForegroundColor Green
Write-Host "  http://localhost:3000/          (Overview hubs)"
Write-Host "  http://localhost:3000/vuln/dashboards"
Write-Host "  http://localhost:3000/vuln/ops"
Write-Host "  http://localhost:3000/vuln/agents"
Write-Host "  http://localhost:3000/vuln/scans"
Write-Host "  CaseId used: $CaseId"
