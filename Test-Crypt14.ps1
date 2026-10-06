param(
  [string]$CaseFolder = "",
  [string]$OutputFolder = "",
  [string[]]$KeyFile = @(),
  [switch]$ExportKeyHex,
  [string]$Python = "python"
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not $CaseFolder) {
  & $Python -m pytest -q backend/tests/test_crypt_family.py backend/tests/test_crypt14_pipeline_delivery.py backend/tests/test_whatsapp_crypt.py backend/tests/test_whatsapp_crypt_v45.py backend/tests/test_whatsapp_recovery.py backend/tests/test_whatsapp_key_intake.py backend/tests/test_whatsapp_payloads.py backend/tests/test_whatsapp_derivation.py
  exit $LASTEXITCODE
}
if (-not $OutputFolder) { throw "Specify -OutputFolder for a real case. Keep output separate from original evidence." }
$argsList = @("backend/scripts/test_crypt14_case.py", "--case-folder", $CaseFolder, "--output", $OutputFolder)
foreach ($path in $KeyFile) { $argsList += @("--key-file", $path) }
if ($ExportKeyHex) { $argsList += "--export-key-hex" }
& $Python @argsList
exit $LASTEXITCODE
