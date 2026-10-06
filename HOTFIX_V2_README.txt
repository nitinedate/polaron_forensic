Aetheris Dynamic Drive Mount Hotfix v2
======================================
Fixes PowerShell quoting at scripts/generate-drive-mounts.ps1 line 122.

Broken v1 line:
  $lines.Add("        source: \"${letter}:/\"") | Out-Null

Fixed line:
  $lines.Add(('        source: "{0}:/"' -f $letter)) | Out-Null

Why: PowerShell does not use backslash to escape embedded double quotes.
The v1 script therefore failed before it could write docker-compose.drives.generated.yml.

Apply: extract this ZIP over the project root and replace files.
Do NOT run docker compose down -v.

Then run:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-dynamic-drive-mounts.ps1 -RequiredPath "G:\Ex.1 Darshan SSD 256"
