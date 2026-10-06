Aetheris Dynamic Drive Hotfix v3
================================

Fixes two issues:
1. False-negative UI mount failure during Register & start.
   The v2 UI performed a second generic root browse even after the host refresh
   job had already verified the exact selected evidence path inside Docker.
   That second browse could fail for an unrelated drive and display
   "Windows can see ..., but Docker could not mount that drive" incorrectly.
   v3 trusts the exact required-path verification from the refresh job.

2. AetherisHostDriveAgent Task Scheduler state.
   The installer previously started a separate hidden PowerShell watcher, so
   Task Scheduler could stay Ready. v3 starts the registered scheduled task
   itself, so the long-running watcher is owned by Task Scheduler.

Diagnostic:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-direct-docker-drive.ps1 -RequiredPath "G:\Ex.1 Darshan SSD 256"

After applying:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-hostdrive-agent.ps1
  docker compose -f .\docker-compose.yml -f .\docker-compose.drives.generated.yml build frontend
  docker compose -f .\docker-compose.yml -f .\docker-compose.drives.generated.yml up -d frontend
